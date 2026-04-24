/** * _middleware.js — 全局中间件 * 拦截所有 HTML 页面请求，未登录则重定向到 /login.html */

export async function onRequest(context) {
  const { request, env, next } = context;
  const url = new URL(request.url);
  const path = url.pathname;

  // 没有设置密码，直接放行
  const SITE_PASSWORD = env.SITE_PASSWORD;
  if (!SITE_PASSWORD) {
    return next();
  }

  // ✅ 登录页和认证接口：直接放行，绝不拦截
  if (path === "/login.html" || path.startsWith("/api/auth")) {
    return next();
  }

  // ✅ 所有静态资源放行
  if (
    path.match(
      /\.(js|css|png|jpg|jpeg|gif|ico|svg|woff|woff2|ttf|json|txt|webp)$/
    )
  ) {
    return next();
  }

  // 读取 Cookie
  const cookieHeader = request.headers.get("Cookie") || "";
  const token = parseCookie(cookieHeader, "auth_token");

  const TOKEN_SECRET = env.TOKEN_SECRET || "default_secret_change_me";
  const valid = await verifyToken(token, TOKEN_SECRET);

  if (valid) {
    return next();
  }

  // 未登录：如果是 API 请求返回 401，否则重定向登录页
  if (path.startsWith("/api/")) {
    return new Response(JSON.stringify({ ok: false, msg: "未授权" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  return Response.redirect(
    `${url.origin}/login.html?from=${encodeURIComponent(path)}`,
    302
  );
}

function parseCookie(cookieStr, name) {
  const match = cookieStr.match(new RegExp(`(?:^|;\\s*)${name}=([^;]*)`));
  return match ? match[1] : null;
}

async function verifyToken(token, secret) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [payload, sigHex] = parts;

  const ts = parseInt(payload, 10);
  if (isNaN(ts) || Date.now() - ts > 86400_000) return false;

  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign(
    "HMAC",
    key,
    new TextEncoder().encode(payload)
  );
  const expectedHex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return sigHex === expectedHex;
}
