const UPSTREAM_URL =
  "https://github.com/newzooplay/ZooHost/raw/refs/heads/main/hls/index.m3u8";

const COOKIE_NAME = "__Host-m3u_session";
const TOKEN_TTL = 15 * 60;

function json(data, status = 200, extra = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      "Content-Type": "application/json; charset=utf-8",
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      ...extra
    }
  });
}

function encode64(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function decode64(value) {
  const base64 = value.replace(/-/g, "+").replace(/_/g, "/");

  return Uint8Array.from(
    atob(base64 + "=".repeat((4 - base64.length % 4) % 4)),
    char => char.charCodeAt(0)
  );
}

async function getKey(secret) {
  return crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign", "verify"]
  );
}

async function createToken(secret) {
  const payload = {
    exp: Math.floor(Date.now() / 1000) + TOKEN_TTL
  };

  const data = encode64(
    new TextEncoder().encode(JSON.stringify(payload))
  );

  const signature = await crypto.subtle.sign(
    "HMAC",
    await getKey(secret),
    new TextEncoder().encode(data)
  );

  return `${data}.${encode64(new Uint8Array(signature))}`;
}

async function verifyToken(token, secret) {
  try {
    if (typeof token !== "string" || token.length > 2048) {
      return false;
    }

    const parts = token.split(".");
    if (parts.length !== 2) return false;

    const [data, signature] = parts;

    const valid = await crypto.subtle.verify(
      "HMAC",
      await getKey(secret),
      decode64(signature),
      new TextEncoder().encode(data)
    );

    if (!valid) return false;

    const payload = JSON.parse(
      new TextDecoder().decode(decode64(data))
    );

    return Number.isInteger(payload.exp) &&
      payload.exp > Math.floor(Date.now() / 1000);
  } catch {
    return false;
  }
}

function readCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";

  for (const part of cookieHeader.split(";")) {
    const index = part.indexOf("=");

    if (
      index >= 0 &&
      part.slice(0, index).trim() === name
    ) {
      return part.slice(index + 1).trim();
    }
  }

  return "";
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const requestId = crypto.randomUUID();

    function log(status) {
      console.log(JSON.stringify({
        requestId,
        path: url.pathname,
        method: request.method,
        status,
        timestamp: new Date().toISOString()
      }));
    }

    const allowedOrigin = env.ALLOWED_ORIGIN || "";
    const origin = request.headers.get("Origin");

    const corsHeaders = {};

    if (origin && origin === allowedOrigin && allowedOrigin) {
      corsHeaders["Access-Control-Allow-Origin"] = allowedOrigin;
      corsHeaders["Access-Control-Allow-Credentials"] = "true";
      corsHeaders["Vary"] = "Origin";
    }

    if (origin && allowedOrigin && origin !== allowedOrigin) {
      log(403);
      return json({ error: "Origin denied" }, 403);
    }

    if (!env.ACCESS_PASSWORD || !env.SIGNING_SECRET) {
      log(503);
      return json({ error: "Missing server secrets" }, 503);
    }

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: {
          ...corsHeaders,
          "Access-Control-Allow-Methods": "GET, POST, HEAD, OPTIONS",
          "Access-Control-Allow-Headers": "Content-Type, Authorization",
          "Access-Control-Max-Age": "600"
        }
      });
    }

    // Browser login: POST /login
    if (url.pathname === "/login" && request.method === "POST") {
      if (!request.headers.get("Content-Type")?.includes("application/json")) {
        log(415);
        return json({ error: "JSON required" }, 415, corsHeaders);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        log(400);
        return json({ error: "Invalid JSON" }, 400, corsHeaders);
      }

      if (
        typeof body.password !== "string" ||
        body.password.length > 512 ||
        body.password !== env.ACCESS_PASSWORD
      ) {
        log(401);
        return json({ error: "Unauthorized" }, 401, corsHeaders);
      }

      const token = await createToken(env.SIGNING_SECRET);

      log(200);

      return json({ authenticated: true }, 200, {
        ...corsHeaders,
        "Set-Cookie":
          `${COOKIE_NAME}=${token}; Path=/; Max-Age=${TOKEN_TTL}; HttpOnly; Secure; SameSite=Strict`
      });
    }

    // IPTV token: POST /token
    if (url.pathname === "/token" && request.method === "POST") {
      if (!request.headers.get("Content-Type")?.includes("application/json")) {
        log(415);
        return json({ error: "JSON required" }, 415, corsHeaders);
      }

      let body;

      try {
        body = await request.json();
      } catch {
        log(400);
        return json({ error: "Invalid JSON" }, 400, corsHeaders);
      }

      if (
        typeof body.password !== "string" ||
        body.password.length > 512 ||
        body.password !== env.ACCESS_PASSWORD
      ) {
        log(401);
        return json({ error: "Unauthorized" }, 401, corsHeaders);
      }

      const token = await createToken(env.SIGNING_SECRET);

      log(200);

      return json({
        token,
        expires_in: TOKEN_TTL
      }, 200, corsHeaders);
    }

    if (!["GET", "HEAD"].includes(request.method)) {
      log(405);
      return json({ error: "Method not allowed" }, 405, corsHeaders);
    }

    if (url.pathname !== "/playlist.m3u8") {
      log(404);
      return json({ error: "Not found" }, 404, corsHeaders);
    }

    // Browser cookie, IPTV Bearer token, or IPTV query token.
    const authorization = request.headers.get("Authorization") || "";
    const bearer = authorization.startsWith("Bearer ")
      ? authorization.slice(7)
      : "";

    const token =
      bearer ||
      url.searchParams.get("token") ||
      readCookie(request, COOKIE_NAME);

    if (!await verifyToken(token, env.SIGNING_SECRET)) {
      log(401);

      return json({ error: "Invalid or expired token" }, 401, {
        ...corsHeaders,
        "WWW-Authenticate": "Bearer"
      });
    }

    // Fixed upstream: never accept an arbitrary URL from the client.
    let upstream;

    try {
      upstream = new URL(UPSTREAM_URL);

      if (upstream.protocol !== "https:") {
        throw new Error("HTTPS required");
      }
    } catch {
      log(500);
      return json({ error: "Invalid upstream configuration" }, 500);
    }

    let upstreamResponse;

    try {
      upstreamResponse = await fetch(upstream.href, {
        method: request.method,
        headers: {
          "Accept": "application/vnd.apple.mpegurl, application/x-mpegURL, */*"
        },
        redirect: "follow"
      });
    } catch {
      log(502);
      return json({ error: "Upstream unavailable" }, 502, corsHeaders);
    }

    if (!upstreamResponse.ok) {
      log(upstreamResponse.status);

      return json({
        error: "Upstream request failed",
        upstreamStatus: upstreamResponse.status
      }, upstreamResponse.status, corsHeaders);
    }

    const outputHeaders = {
      ...corsHeaders,
      "Cache-Control": "private, no-store",
      "X-Content-Type-Options": "nosniff"
    };

    const contentType = upstreamResponse.headers.get("Content-Type");

    outputHeaders["Content-Type"] =
      contentType || "application/vnd.apple.mpegurl";

    log(200);

    return new Response(
      request.method === "HEAD" ? null : upstreamResponse.body,
      {
        status: 200,
        headers: outputHeaders
      }
    );
  }
};
