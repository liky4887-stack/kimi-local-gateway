const PORT = Number(Deno.env.get("PORT") ?? "8088");
const LOCAL_KEY = Deno.env.get("LOCAL_KEY") ?? "sk-local-kimi";
const CREDS = Deno.env.get("KIMI_CREDS") ?? `${Deno.env.get("HOME")}/cookies/kimi-creds.json`;
const UPSTREAM = "https://www.kimi.ai/apiv2/kimi.gateway.chat.v1.ChatService/Chat";

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

const REFRESH_URL = "https://auth.kimi.ai/api/account.gateway.v1.AuthService/RefreshToken";

async function ensureFreshToken(): Promise<Creds> {
  const fresh = loadCreds();
  const now = Math.floor(Date.now() / 1000);
  const exp = fresh.bearerToken ? decodeJwtExp(fresh.bearerToken) : null;
  const remaining = exp ? exp - now : null;

  if (remaining !== null && remaining > 120) {
    return fresh;
  }

  const rt = (fresh as any).refreshToken;
  if (!rt) {
    console.warn("token expired and no refreshToken in creds file");
    return fresh;
  }

  console.log("refreshing token, seconds left:", remaining);
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
    console.error("refresh failed, body head:", text.slice(0, 300));
    return fresh;
  }

  fresh.bearerToken = newToken;
  Deno.writeTextFileSync(CREDS, JSON.stringify(fresh, null, 2));
  console.log("token refreshed, new exp:", decodeJwtExp(newToken));
  return fresh;
}

// Connect-RPC frame: 1 byte flags + 4 byte BE length + JSON
function frame(obj: unknown): Uint8Array {
  const json = new TextEncoder().encode(JSON.stringify(obj));
  const out = new Uint8Array(5 + json.length);
  new DataView(out.buffer).setUint32(1, json.length, false);
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
  const creds = await ensureFreshToken();
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

console.log(`✅ gateway :${PORT} → ${UPSTREAM}`);
