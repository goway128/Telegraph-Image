/**
 * POST /api/auth
 * Body: { password: "xxx" }
 * 验证密码，成功后设置 HttpOnly Cookie
 */
export async function onRequestPost(context) {
  const { request, env } = context;

  // 从环境变量读取密码（在 Cloudflare Pages 控制台设置 SITE_PASSWORD）
  const SITE_PASSWORD = env.SITE_PASSWORD;
  // 用于签名 Token 的密钥（在控制台设置 TOKEN_SECRET，随机字符串即可）
  const TOKEN_SECRET = env.TOKEN_SECRET || "default_secret_change_me";

  if (!SITE_PASSWORD) {
    return new Response(JSON.stringify({ ok: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }

  let body;
  try {
    body = await request.json();
  } catch {
    return new Response(JSON.stringify({ ok: false, msg: "Invalid request" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  if (body.password !== SITE_PASSWORD) {
    // 密码错误，延迟 500ms 防止暴力破解
    await new Promise((r) => setTimeout(r, 500));
    return new Response(JSON.stringify({ ok: false, msg: "密码错误" }), {
      status: 401,
      headers: { "Content-Type": "application/json" },
    });
  }

  // 生成 Token：base64(timestamp) + HMAC 签名
  const token = await generateToken(TOKEN_SECRET);

  const isProd = !request.url.includes("localhost");
  return new Response(JSON.stringify({ ok: true }), {
    headers: {
      "Content-Type": "application/json",
      "Set-Cookie": [
        `auth_token=${token}`,
        "Path=/",
        "HttpOnly",
        "SameSite=Lax",
        isProd ? "Secure" : "",
        "Max-Age=86400", // 24小时
      ]
        .filter(Boolean)
        .join("; "),
    },
  });
}

/**
 * 生成 HMAC-SHA256 签名 Token
 */
async function generateToken(secret) {
  const payload = Date.now().toString();
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
  const sigHex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `${payload}.${sigHex}`;
}

/**
 * 验证 Token 是否合法（供其他模块调用）
 */
export async function verifyToken(token, secret) {
  if (!token) return false;
  const parts = token.split(".");
  if (parts.length !== 2) return false;
  const [payload, sigHex] = parts;

  // 检查是否过期（24小时）
  const ts = parseInt(payload, 10);
  if (isNaN(ts) || Date.now() - ts > 86400_000) return false;

  // 验签
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
