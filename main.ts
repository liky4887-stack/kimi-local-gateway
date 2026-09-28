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

async function ensureFreshToken(): Promise<Creds> {
  // 1. Pick up any token pair the user dropped into kimi-tokens.json
  // since the last request. Idempotent.
  syncFromSeed();

  const fresh = loadCreds();
  const now = Math.floor(Date.now() / 1000);
  const exp = fresh.bearerToken ? decodeJwtExp(fresh.bearerToken) : null;
  const remaining = exp ? exp - now : null;

  // Still fresh — nothing to do.
  if (remaining !== null && remaining > 120) {
    return fresh;
  }

  const rt = (fresh as any).refreshToken;
  if (!rt) {
    throw new Error(
      "kimi access token expired and no refreshToken in creds file. " +
      "Drop a fresh pair into ~/cookies/kimi-tokens.json and retry — no restart needed.",
    );
  }

  const refreshExp = decodeJwtExp(rt);
  const refreshDays = refreshExp ? Math.floor((refreshExp - now) / 86400) : null;
  console.log("refreshing token, access left:", remaining, "s | refresh expires in:", refreshDays, "days");
  const r = await fetch(REFRESH_URL, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      "accept": "*/*",
      "origin": "https://www.kimi.ai",
      "referer": "https://www.kimi.ai/",
      "user-agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
      "authorization": `Bearer ${fresh.bearerToken}`,
      "cookie": fresh.cookies ?? "",
      "connect-protocol-version": "1",
      "x-msh-platform": "web",
      "x-msh-version": "2.3.0",
      ...(fresh.deviceId ? { "x-msh-device-id": fresh.deviceId } : {}),
      ...(fresh.sessionId ? { "x-msh-session-id": fresh.sessionId } : {}),
      ...(fresh.extraHeaders ?? {}),
    },
    body: JSON.stringify({ refresh_token: rt }),
  });
  const text = await r.text();
  console.log("refresh status:", r.status);

  let j: any = null;
  try { j = JSON.parse(text); } catch {}
  const newToken =
    (j && (j.access_token || j.accessToken)) ||
    (j && j.data && (j.data.access_token || j.data.accessToken));

  if (!newToken || typeof newToken !== "string") {
    // Refresh failed. Before throwing, check if the user just dropped
    // a fresh pair into kimi-tokens.json. If yes, use it.
    if (syncFromSeed()) {
      const recovered = loadCreds();
      if (recovered.bearerToken !== fresh.bearerToken) {
        console.log("refresh failed but seed recovered — using seed tokens");
        return recovered;
      }
    }
    throw new Error(
      "kimi token refresh failed (HTTP " + r.status + "): " + text.slice(0, 200) +
      ". The refresh token is likely dead. Drop a fresh access+refresh pair into " +
      "~/cookies/kimi-tokens.json and retry — no restart needed.",
    );
  }

  fresh.bearerToken = newToken;
  Deno.writeTextFileSync(CREDS, JSON.stringify(fresh, null, 2));
  console.log("token refreshed, new exp:", decodeJwtExp(newToken));
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
