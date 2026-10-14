
const UPSTREAM_BASE =
  "https://raw.githubusercontent.com/newzooplay/ZooHost/main/hls/";

const COOKIE_NAME = "stream_session";

const CORS_HEADERS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "GET, HEAD, OPTIONS",
  "Access-Control-Allow-Headers": "Range, Origin, Accept",
  "Access-Control-Expose-Headers":
    "Content-Length, Content-Range, Accept-Ranges",
};

function responseHeaders(extra = {}) {
  return {
    ...CORS_HEADERS,
    "X-Content-Type-Options": "nosniff",
    "Cache-Control": "no-store",
    ...extra,
  };
}

function workerUrlFor(upstreamUrl, requestUrl) {
  const upstream = new URL(upstreamUrl);
  const base = new URL(UPSTREAM_BASE);

  if (
    upstream.origin !== base.origin ||
    !upstream.pathname.startsWith(base.pathname)
  ) {
    return null;
  }

  const relativePath = upstream.pathname.slice(base.pathname.length);

  if (
    relativePath.split("/").some(
      part => part === ".." || part === "." || !part
    )
  ) {
    return null;
  }

  const worker = new URL(requestUrl);
  worker.pathname = "/hls/" + relativePath;
  worker.search = upstream.search;

  return worker.toString();
}

function rewritePlaylist(text, upstreamUrl, requestUrl) {
  const lines = text.split(/\r?\n/);

  return lines.map(line => {
    const trimmed = line.trim();

    if (!trimmed) return line;

    // Rewrite URI="..." attributes in HLS tags.
    if (trimmed.startsWith("#")) {
      return line.replace(/URI="([^"]+)"/g, (match, uri) => {
        try {
          const absolute = new URL(uri, upstreamUrl).toString();
          const proxied = workerUrlFor(absolute, requestUrl);
          return proxied ? `URI="${proxied}"` : match;
        } catch {
          return match;
        }
      });
    }

    // Rewrite segment and child-playlist lines.
    try {
      const absolute = new URL(trimmed, upstreamUrl).toString();
      const proxied = workerUrlFor(absolute, requestUrl);
      return proxied || line;
    } catch {
      return line;
    }
  }).join("\n");
}

export default {
  async fetch(request) {
    const url = new URL(request.url);

    if (request.method === "OPTIONS") {
      return new Response(null, {
        status: 204,
        headers: responseHeaders(),
      });
    }

    if (!["GET", "HEAD"].includes(request.method)) {
      return Response.json(
        { error: "Method not allowed" },
        { status: 405, headers: responseHeaders({ Allow: "GET, HEAD, OPTIONS" }) }
      );
    }

    if (url.pathname === "/") {
      const headers = responseHeaders({
        "Content-Type": "application/json; charset=utf-8",
      });

      // Informational cookie only; it is NOT authentication.
      if (!request.headers.get("Cookie")?.includes(COOKIE_NAME + "=")) {
        headers["Set-Cookie"] =
          `${COOKIE_NAME}=1; Path=/; Secure; HttpOnly; SameSite=None; Max-Age=86400`;
      }

      return Response.json({
        service: "HLS Streaming Proxy",
        playlist: `${url.origin}/hls/index.m3u8`,
        cookie: "Informational only; does not restrict access",
      }, { headers });
    }

    if (!url.pathname.startsWith("/hls/")) {
      return Response.json(
        { error: "Not found" },
        { status: 404, headers: responseHeaders() }
      );
    }

    const relativePath = url.pathname.slice("/hls/".length);

    if (
      !relativePath ||
      relativePath.split("/").some(
        part => !part || part === "." || part === ".."
      ) ||
      /[%\\]/.test(relativePath)
    ) {
      return Response.json(
        { error: "Invalid path" },
        { status: 400, headers: responseHeaders() }
      );
    }

    const upstream = new URL(relativePath, UPSTREAM_BASE);
    upstream.search = url.search;

    try {
      const upstreamResponse = await fetch(upstream.toString(), {
        method: request.method,
        headers: {
          Accept: request.headers.get("Accept") || "*/*",
          ...(request.headers.has("Range")
            ? { Range: request.headers.get("Range") }
            : {}),
        },
        redirect: "error",
      });

      if (!upstreamResponse.ok) {
        return new Response("Upstream request failed", {
          status: upstreamResponse.status,
          headers: responseHeaders({
            "Content-Type": "text/plain; charset=utf-8",
          }),
        });
      }

      const contentType =
        upstreamResponse.headers.get("Content-Type") || "";

      const isPlaylist =
        relativePath.toLowerCase().endsWith(".m3u8") ||
        contentType.includes("mpegurl");

      if (isPlaylist && request.method === "GET") {
        const original = await upstreamResponse.text();
        const rewritten = rewritePlaylist(
          original,
          upstream.toString(),
          request.url
        );

        return new Response(rewritten, {
          status: 200,
          headers: responseHeaders({
            "Content-Type": "application/vnd.apple.mpegurl",
          }),
        });
      }

      const headers = responseHeaders({
        "Content-Type": contentType || "application/octet-stream",
      });

      for (const name of [
        "Accept-Ranges",
        "Content-Length",
        "Content-Range",
      ]) {
        const value = upstreamResponse.headers.get(name);
        if (value) headers[name] = value;
      }

      return new Response(
        request.method === "HEAD" ? null : upstreamResponse.body,
        {
          status: upstreamResponse.status,
          headers,
        }
      );
    } catch {
      return Response.json(
        { error: "Unable to fetch upstream file" },
        { status: 502, headers: responseHeaders() }
      );
    }
  },
};
