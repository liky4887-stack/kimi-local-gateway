const PORT = Number(Deno.env.get("PORT") ?? "8088");
const LOCAL_KEY = Deno.env.get("LOCAL_KEY") ?? "sk-local-kimi";
const CREDS = Deno.env.get("KIMI_CREDS") ?? `${Deno.env.get("HOME")}/cookies/kimi-creds.json`;
const UPSTREAM = "https://www.kimi.ai/apiv2/kimi.gateway.chat.v1.ChatService/Chat";
const SEED = `${Deno.env.get("HOME")}/cookies/kimi-tokens.json`;

type Creds = { bearerToken: string; cookies: string; extraHeaders?: Record<string,string>; deviceId?: string; sessionId?: string; trafficId?: string };

function loadCreds(): Creds {
  return JSON.parse(Deno.readTextFileSync(CREDS)) as Creds;
}

function decodeJwtExp(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const j = JSON.parse(new TextDecoder().decode(
      Uint8Array.from(atob(pad), c => c.charCodeAt(0))
    ));
    return typeof j.exp === "number" ? j.exp : null;
  } catch {
    return null;
  }
}

// Copy tokens from kimi-tokens.json into kimi-creds.json whenever
// the seed file has a newer, valid pair. Called on every request and
// again after a failed refresh. Idempotent — no-ops if already in sync.
function decodeJwtIat(token: string): number | null {
  try {
    const payload = token.split(".")[1];
    const b64 = payload.replace(/-/g, "+").replace(/_/g, "/");
    const pad = b64 + "=".repeat((4 - (b64.length % 4)) % 4);
    const j = JSON.parse(new TextDecoder().decode(
      Uint8Array.from(atob(pad), c => c.charCodeAt(0))
    ));
    return typeof j.iat === "number" ? j.iat : null;
  } catch {
    return null;
  }
}

// Copy tokens from kimi-tokens.json into kimi-creds.json ONLY when the
// seed file is strictly newer than what's already in creds.
//
// Rationale: the gateway refreshes its own access token every ~15 min
// and writes the new pair to kimi-creds.json. The seed file is only
// updated when the user pastes a fresh pair by hand. If we blindly
// overwrote creds with seed on every request, we'd roll back good
// refreshed tokens to a stale paste and break the next call.
function syncFromSeed(): boolean {
  try {
    const seed = JSON.parse(Deno.readTextFileSync(SEED));
    const seedAccess = typeof seed.access_token === "string" ? seed.access_token.trim() : "";
    const seedRefresh = typeof seed.refresh_token === "string" ? seed.refresh_token.trim() : "";
    if (!seedAccess.startsWith("eyJ") || !seedRefresh.startsWith("eyJ")) return false;

    const creds = JSON.parse(Deno.readTextFileSync(CREDS));

    // Already identical — nothing to do.
    if (creds.bearerToken === seedAccess && creds.refreshToken === seedRefresh) {
      return false;
    }

    // Only use the seed if its access token was minted AFTER the creds
    // one. Otherwise creds is fresher (via auto-refresh) and we must not
    // overwrite it.
    const seedIat = decodeJwtIat(seedAccess);
    const credsIat = creds.bearerToken ? decodeJwtIat(creds.bearerToken) : null;
    if (seedIat !== null && credsIat !== null && seedIat <= credsIat) {
      return false;
    }

    creds.bearerToken = seedAccess;
    creds.refreshToken = seedRefresh;
    creds.acquiredAt = Date.now();
    Deno.writeTextFileSync(CREDS, JSON.stringify(creds, null, 2));
    console.log("seed.sync", {
      seedIat,
      credsIat,
      accessExp: decodeJwtExp(seedAccess),
      refreshExp: decodeJwtExp(seedRefresh),
    });
    return true;
  } catch {
    return false;
  }
}

const REFRESH_URL = "https://auth.kimi.ai/api/account.gateway.v1.AuthService/RefreshToken";

// ─── Token cache + refresh queue (kimi-free-api model) ─────────────
// Access tokens live 300s. Cache them keyed by the refresh token that
// produced them, and coalesce concurrent refreshes so two parallel
// requests never spend the same one-shot refresh token twice.
const tokenCache = new Map<string, { access: string; expiresAt: number }>();
const inflight = new Map<string, Promise<string>>();

function pickRefreshToken(raw: string): string {
  // Multi-account support: comma-separated refresh tokens rotate.
  const list = raw.split(",").map((s) => s.trim()).filter(Boolean);
  if (list.length <= 1) return list[0] ?? "";
  return list[Math.floor(Math.random() * list.length)];
}

async function refreshOnce(refreshToken: string, cookies: string, deviceId?: string, sessionId?: string, extraHeaders?: Record<string, string>): Promise<{ access: string; refresh: string }> {
  const r = await fetch(REFRESH_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "*/*",
      "origin": "https://www.kimi.ai",
      "referer": "https://www.kimi.ai/",
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
      "authorization": `Bearer ${refreshToken}`,
      "cookie": cookies ?? "",
      "connect-protocol-version": "1",
      "x-msh-platform": "web",
      "x-msh-version": "2.3.0",
      ...(deviceId ? { "x-msh-device-id": deviceId } : {}),
      ...(sessionId ? { "x-msh-session-id": sessionId } : {}),
      ...(extraHeaders ?? {}),
    },
    body: JSON.stringify({ refresh_token: refreshToken }),
  });
  const text = await r.text();
  let j: any = null;
  try { j = JSON.parse(text); } catch {}
  const newAccess =
    (j && (j.access_token || j.accessToken)) ||
    (j && j.data && (j.data.access_token || j.data.accessToken));
  const newRefresh =
    (j && (j.refresh_token || j.refreshToken)) ||
    (j && j.data && (j.data.refresh_token || j.data.refreshToken)) ||
    refreshToken;
  if (!newAccess || typeof newAccess !== "string") {
    throw new Error("refresh HTTP " + r.status + ": " + text.slice(0, 200));
  }
  return { access: newAccess, refresh: newRefresh };
}

async function acquireAccessToken(creds: any): Promise<string> {
  const raw = String(creds.refreshToken || "");
  if (!raw) throw new Error("no refreshToken in creds file");
  const refreshToken = pickRefreshToken(raw);

  const now = Math.floor(Date.now() / 1000);

  // 1. Cache hit — still has >60s of life.
  const cached = tokenCache.get(refreshToken);
  if (cached && cached.expiresAt - now > 60) {
    return cached.access;
  }

  // 2. Queue — someone else is already refreshing this exact token.
  const existing = inflight.get(refreshToken);
  if (existing) return existing;

  // 3. Fire one refresh, share the promise with every concurrent caller.
  const promise = (async () => {
    try {
      const { access, refresh } = await refreshOnce(
        refreshToken,
        creds.cookies,
        creds.deviceId,
        creds.sessionId,
        creds.extraHeaders,
      );

      const exp = decodeJwtExp(access) ?? (now + 300);
      tokenCache.set(refreshToken, { access, expiresAt: exp });

      // Persist BOTH tokens to disk so the next request's freshness check
      // short-circuits and no refresh fires at all. Without this, every
      // request re-reads the stale bearerToken and refreshes again.
      const store = JSON.parse(Deno.readTextFileSync(CREDS));
      store.bearerToken = access;
      if (refresh !== refreshToken) {
        if (typeof store.refreshToken === "string" && store.refreshToken.includes(",")) {
          store.refreshToken = store.refreshToken
            .split(",")
            .map((s: string) => s.trim() === refreshToken ? refresh : s.trim())
            .join(",");
        } else {
          store.refreshToken = refresh;
        }
        console.log("refresh.rotated", { newExp: decodeJwtExp(refresh) });
      }
      store.acquiredAt = Date.now();
      Deno.writeTextFileSync(CREDS, JSON.stringify(store, null, 2));

      console.log("token.acquired", { exp, ttl: exp - now });
      return access;
    } catch (e) {
      // Remove from cache so the next call re-tries cleanly.
      tokenCache.delete(refreshToken);
      throw e;
    } finally {
      inflight.delete(refreshToken);
    }
  })();

  inflight.set(refreshToken, promise);
  return promise;
}

async function ensureFreshToken(): Promise<Creds> {
  // 1. Pick up any token pair the user dropped into kimi-tokens.json
  //    since the last request. Idempotent.
  syncFromSeed();

  const fresh = loadCreds() as any;
  const now = Math.floor(Date.now() / 1000);
  const exp = fresh.bearerToken ? decodeJwtExp(fresh.bearerToken) : null;

  // 2. Still fresh — nothing to do.
  if (exp !== null && exp - now > 120) {
    return fresh;
  }

  // 3. Refresh via the cache + queue. If the whole thing fails with a
  //    dead refresh token, acquireAccessToken throws and the caller
  //    surfaces a 503 telling the user to refresh the seed.
  console.log("ensureFreshToken: acquiring, access left:", exp ? exp - now : null);
  fresh.bearerToken = await acquireAccessToken(fresh);
  return fresh;
}

// Connect-RPC frame: 1 byte flags + 4 byte BE length + JSON
function frame(obj: unknown): Uint8Array<ArrayBuffer> {
  const json = new TextEncoder().encode(JSON.stringify(obj));
  const buf = new ArrayBuffer(5 + json.length);
  const out = new Uint8Array(buf);
  new DataView(buf).setUint32(1, json.length, false);
  out.set(json, 5);
  return out;
}

function* unframe(buf: Uint8Array): Generator<{ flag: number; data: any }> {
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength);
  let i = 0;
  while (i + 5 <= buf.length) {
    const flag = buf[i];
    const len = view.getUint32(i + 1, false);
    i += 5;
    if (i + len > buf.length) break;
    const slice = buf.subarray(i, i + len);
    i += len;
    try { yield { flag, data: JSON.parse(new TextDecoder().decode(slice)) }; } catch {}
  }
}

Deno.serve({ port: PORT, hostname: "0.0.0.0" }, async (req) => {
  const url = new URL(req.url);

  // ─── CORS preflight for the browser extension ─────────────────
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: {
        "access-control-allow-origin": "*",
        "access-control-allow-methods": "POST, OPTIONS",
        "access-control-allow-headers": "content-type",
        "access-control-max-age": "600",
      },
    });
  }

  if (url.pathname === "/health") {
    return new Response("ok", {
      headers: { "access-control-allow-origin": "*" },
    });
  }

  // ─── Token sync endpoint (called by the browser extension) ────
  // No auth: the extension runs inside the user's own browser, and
  // the gateway is loopback-only. If the machine is compromised the
  // creds file is already exposed; this adds no new surface.
  if (url.pathname === "/token" && req.method === "POST") {
    try {
      const j = await req.json();
      const access = typeof j.access_token === "string" ? j.access_token.trim() : "";
      const refresh = typeof j.refresh_token === "string" ? j.refresh_token.trim() : "";
      if (!access.startsWith("eyJ") || !refresh.startsWith("eyJ")) {
        return new Response(
          JSON.stringify({ ok: false, error: "tokens must be JWTs" }),
          { status: 400, headers: { "content-type": "application/json", "access-control-allow-origin": "*" } },
        );
      }
      const existing = loadCreds() as any;
      existing.bearerToken = access;
      existing.refreshToken = refresh;
      existing.acquiredAt = Date.now();
      Deno.writeTextFileSync(CREDS, JSON.stringify(existing, null, 2));
      console.log("token.sync", {
        accessLen: access.length,
        refreshLen: refresh.length,
        accessExp: decodeJwtExp(access),
      });
      return new Response(
        JSON.stringify({ ok: true, at: Date.now() }),
        { headers: { "content-type": "application/json", "access-control-allow-origin": "*" } },
      );
    } catch (e) {
      return new Response(
        JSON.stringify({ ok: false, error: e instanceof Error ? e.message : String(e) }),
        { status: 500, headers: { "content-type": "application/json", "access-control-allow-origin": "*" } },
      );
    }
  }

  // Validate a refresh token without touching the cache.
  if (url.pathname === "/token/check" && req.method === "POST") {
    try {
      const { token } = await req.json();
      if (typeof token !== "string" || !token.startsWith("eyJ")) {
        return new Response(JSON.stringify({ live: false, error: "not a JWT" }), {
          status: 400, headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
        });
      }
      const creds = loadCreds() as any;
      const { access } = await refreshOnce(token, creds.cookies, creds.deviceId, creds.sessionId, creds.extraHeaders);
      return new Response(JSON.stringify({ live: true, accessExp: decodeJwtExp(access) }), {
        headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
      });
    } catch (e) {
      return new Response(JSON.stringify({ live: false, error: e instanceof Error ? e.message : String(e) }), {
        status: 200, headers: { "content-type": "application/json", "access-control-allow-origin": "*" },
      });
    }
  }

  if ((req.headers.get("authorization") ?? "") !== `Bearer ${LOCAL_KEY}`) {
    return new Response(JSON.stringify({ error: "unauthorized" }), { status: 401, headers: { "content-type": "application/json" } });
  }
  if (url.pathname !== "/v1/chat/completions" || req.method !== "POST") {
    return new Response("Not found", { status: 404 });
  }

  const body = await req.json();

  let creds: Creds;
  try {
    creds = await ensureFreshToken();
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return new Response(
      JSON.stringify({ error: { message: "kimi auth failed", detail: msg } }),
      { status: 503, headers: { "content-type": "application/json" } },
    );
  }
  const lastUser = [...(body.messages ?? [])].reverse().find((m: any) => m.role !== "assistant");
  const prompt = String(lastUser?.content ?? "");

  const reqObj = {
    chat_id: (creds as any).chatId ?? "1a0e409c-5752-832a-8000-09f167aad74b",
    scenario: "SCENARIO_CHAT",
    tools: [{ type: "TOOL_TYPE_SEARCH", search: {} }, { type: "TOOL_TYPE_CRON_JOB" }],
    message: {
      parent_id: (creds as any).parentId ?? "",
      role: "user",
      blocks: [{ message_id: "", text: { content: prompt } }],
      scenario: "SCENARIO_CHAT",
      is_goal: false,
    },
    options: {
      thinking: true,
      enable_plugin: true,
      reasoning_effort: "REASONING_EFFORT_LOW",
      model: "k2d6-chat",
    },
    project_id: "",
  };

  const headers: Record<string,string> = {
    "accept": "*/*",
    "content-type": "application/connect+json",
    "connect-protocol-version": "1",
    "authorization": `Bearer ${creds.bearerToken}`,
    "cookie": creds.cookies,
    "origin": "https://www.kimi.ai",
    "referer": "https://www.kimi.ai/",
    "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "x-language": "en-US",
    "x-msh-platform": "web",
    "x-msh-version": "2.3.0",
    ...(creds.deviceId ? { "x-msh-device-id": creds.deviceId } : {}),
    ...(creds.sessionId ? { "x-msh-session-id": creds.sessionId } : {}),
    ...(creds.trafficId ? { "x-traffic-id": creds.trafficId } : {}),
    ...(creds.extraHeaders ?? {}),
  };

  const up = await fetch(UPSTREAM, { method: "POST", headers, body: frame(reqObj) });

  if (!up.ok) {
    const detail = await up.text();
    return new Response(JSON.stringify({ error: { message: `upstream ${up.status}`, detail: detail.slice(0, 800) } }),
      { status: up.status, headers: { "content-type": "application/json" } });
  }

  const buf = new Uint8Array(await up.arrayBuffer());
  let text = "", think = "", msgId = "", streamErr: any = null;
  for (const { flag, data: evt } of unframe(buf)) {
    if (flag & 0x02) {
      const e = evt?.error;
      if (e) streamErr = e;
      continue;
    }
    const t = evt?.block?.text?.content;
    if (typeof t === "string") text = evt.op === "set" ? t : text + t;
    const k = evt?.block?.think?.content;
    if (typeof k === "string") think = evt.op === "set" ? k : think + k;
    if (evt?.message?.role === "assistant" && evt.message.id) msgId = evt.message.id;
  }

  if (streamErr) {
    return new Response(JSON.stringify({
      error: { message: "upstream connect-rpc error", detail: streamErr }
    }), { status: 502, headers: { "content-type": "application/json" } });
  }

  if (msgId) {
    try {
      const store = JSON.parse(Deno.readTextFileSync(CREDS));
      store.parentId = msgId;
      Deno.writeTextFileSync(CREDS, JSON.stringify(store, null, 2));
    } catch (e) { console.error("store update failed:", e); }
  }

  return new Response(JSON.stringify({
    id: `chatcmpl-${msgId || Date.now()}`,
    object: "chat.completion",
    created: Math.floor(Date.now() / 1000),
    model: body.model ?? "k2d6-chat",
    choices: [{ index: 0, message: { role: "assistant", content: text || think || "" }, finish_reason: "stop" }],
    usage: { prompt_tokens: 0, completion_tokens: 0, total_tokens: 0 },
  }), { headers: { "content-type": "application/json" } });
});

function fmtExp(exp: number | null): string {
  if (exp === null) return "?";
  const now = Math.floor(Date.now() / 1000);
  const secs = exp - now;
  if (secs <= 0) return "EXPIRED";
  const d = Math.floor(secs / 86400);
  const h = Math.floor((secs % 86400) / 3600);
  return d + "d " + h + "h";
}

try {
  const c = loadCreds() as any;
  const now = Math.floor(Date.now() / 1000);
  const aExp = c.bearerToken ? decodeJwtExp(c.bearerToken) : null;
  const rExp = c.refreshToken ? decodeJwtExp(c.refreshToken) : null;
  console.log(`token status: access ${fmtExp(aExp)} | refresh ${fmtExp(rExp)}`);
  if (rExp && rExp - now < 7 * 86400) {
    console.warn("refresh token expires in <7 days — grab a fresh pair from www.kimi.ai");
  }
} catch (e) {
  console.warn("could not read creds at startup:", e);
}

console.log(`✅ gateway :${PORT} → ${UPSTREAM}`);
