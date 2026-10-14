const COOKIE_NAME = "__Host-m3u_session";
const TOKEN_TTL = 15 * 60; // 15 minutes

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra
    }
  });
}

function b64url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decode64(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
  return Uint8Array.from(
    atob(base64 + "=".repeat((4 - base64.length % 4) % 4)),
    c => c.charCodeAt(0)
  );
}

async function sign(payload, secret) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  const data = b64url(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const signature = await crypto.subtle.sign(
    "HMAC", key, new TextEncoder().encode(data)
  );

  return data + "." + b64url(new Uint8Array(signature));
}

async function verify(token, secret) {
  try {
    const parts = token.split(".");
    if (parts.length !== 2) return false;

    const [data, signature] = parts;
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );

    const valid = await crypto.subtle.verify(
      "HMAC",
      key,
      decode64(signature),
      new TextEncoder().encode(data)
    );

    if (!valid) return false;

    const payload = JSON.parse(
      new TextDecoder().decode(decode64(data))
    );

    return payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function getCookie(request, name) {
  const cookies = request.headers.get("Cookie") || "";
  for (const item of cookies.split(";")) {
    const index = item.indexOf("=");
    if (index < 0) continue;

    if (item.slice(0, index).trim() === name) {
      return item.slice(index + 1).trim();
    }
  }
  return "";
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const requestId = crypto.randomUUID();

    // Never log passwords, cookies or tokens.
    const log = status => console.log(JSON.stringify({
      requestId,
      path: url.pathname,
      method: request.method,
      status,
      time: new Date().toISOString()
    }));

    const origin = request.headers.get("Origin");
    const allowedOrigin = env.ALLOWED_ORIGIN || "";

    const cors = {};
    if (origin && allowedOrigin && origin === allowedOrigin) {
      cors["Access-Control-Allow-Origin"] = allowedOrigin;
      cors["Access-Control-Allow-Credentials"] = "true";
      cors["Vary"] = "Origin";
    }

    if (origin && allowedOrigin && origin !== allowedOrigin) {
      log(403);
      return json({ error: "Origin denied" }, 403);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...cors,
          "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "600"
        }
      });
    }

    if (!env.ACCESS_PASSWORD || !env.SIGNING_SECRET ||
        !env.UPSTREAM_URL) {
      log(503);
      return json({ error: "Server configuration missing" }, 503, cors);
    }

    // Validate the fixed upstream configuration.
    let upstream;
    try {
      upstream = new URL(env.UPSTREAM_URL);
      if (upstream.protocol !== "https:") throw new Error();
    } catch {
      log(503);
      return json({ error: "Invalid upstream configuration" }, 503, cors);
    }

    // Browser login: POST JSON { "password": "..." }
    if (url.pathname === "/login" && request.method === "POST") {
      if (!request.headers.get("Content-Type")?.includes("application/json")) {
        log(415);
        return json({ error: "JSON required" }, 415, cors);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        log(400);
        return json({ error: "Invalid JSON" }, 400, cors);
      }

      if (
        typeof body.password !== "string" ||
        body.password.length > 512 ||
        body.password !== env.ACCESS_PASSWORD
      ) {
        log(401);
        return json({ error: "Unauthorized" }, 401, cors);
      }

      const token = await sign({
        exp: Math.floor(Date.now() / 1000) + TOKEN_TTL
      }, env.SIGNING_SECRET);

      log(200);
      return json({ authenticated: true }, 200, {
        ...cors,
        "Set-Cookie":
          `${COOKIE_NAME}=${token}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=${TOKEN_TTL}`
      });
    }

    // IPTV clients: POST JSON password to obtain a short-lived token.
    if (url.pathname === "/token" && request.method === "POST") {
      if (!request.headers.get("Content-Type")?.includes("application/json")) {
        log(415);
        return json({ error: "JSON required" }, 415, cors);
      }

      let body;
      try {
        body = await request.json();
      } catch {
        log(400);
        return json({ error: "Invalid JSON" }, 400, cors);
      }

      if (
        typeof body.password !== "string" ||
        body.password.length > 512 ||
        body.password !== env.ACCESS_PASSWORD
      ) {
        log(401);
        return json({ error: "Unauthorized" }, 401, cors);
      }

      const token = await sign({
        exp: Math.floor(Date.now() / 1000) + TOKEN_TTL
      }, env.SIGNING_SECRET);

      log(200);
      return json({ token, expires_in: TOKEN_TTL }, 200, cors);
    }

    if (!["GET", "HEAD"].includes(request.method)) {
      log(405);
      return json({ error: "Method not allowed" }, 405, cors);
    }

    // Cookie for browsers; Bearer token or ?token= for IPTV.
    const bearer = request.headers.get("Authorization") || "";
    const queryToken = url.searchParams.get("token") || "";
    const cookieToken = getCookie(request, COOKIE_NAME);

    const token = bearer.startsWith("Bearer ")
      ? bearer.slice(7)
      : queryToken || cookieToken;

    if (!token || !(await verify(token, env.SIGNING_SECRET))) {
      log(401);
      return json({ error: "Authentication required or expired" }, 401, {
        ...cors,
        "WWW-Authenticate": "Bearer",
        "Cache-Control": "no-store"
      });
    }

    // Fixed upstream only; no user-supplied upstream URL.
    if (url.pathname !== "/playlist.m3u8") {
      log(404);
      return json({ error: "Not found" }, 404, cors);
    }

    const headers = new Headers({
      "Accept": "*/*",
      "User-Agent": "M3U8-Security-Lab/1.0"
    });

    let response;
    try {
      response = await fetch(upstream.href, {
        method: request.method,
        headers,
        redirect: "manual"
      });
    } catch {
      log(502);
      return json({ error: "Upstream unavailable" }, 502, cors);
    }

    // Do not follow redirects to arbitrary hosts.
    if (response.status >= 300 && response.status < 400) {
      log(502);
      return json({ error: "Upstream redirect blocked" }, 502, cors);
    }

    const outputHeaders = {
      ...cors,
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff"
    };

    const contentType = response.headers.get("Content-Type");
    if (contentType) outputHeaders["Content-Type"] = contentType;

    log(response.status);
    return new Response(
      request.method === "HEAD" ? null : response.body,
      { status: response.status, headers: outputHeaders }
    );
  }
};
