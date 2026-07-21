// _worker.js — sert le site (dossier public/), le chat IA (/api/chat),
// l'authentification (/api/auth/*), le paiement KKiaPay (/api/payment/*)
// et le panneau d'administration (/api/admin/*).
//
// Variables d'environnement à configurer dans Cloudflare (Settings > Variables and Secrets) :
//   ANTHROPIC_API_KEY   -> clé Claude (sk-ant-...)
//   SESSION_SECRET      -> une longue chaîne aléatoire secrète, inventée par toi (ex: 40+ caractères)
//   ADMIN_KEY           -> un mot de passe secret que TOI seul connais, pour accéder au panneau admin
//   KKIAPAY_PUBLIC_KEY  -> clé publique KKiaPay
//   KKIAPAY_PRIVATE_KEY -> clé privée KKiaPay
//   KKIAPAY_SANDBOX     -> "true" en mode test, "false" en production réelle
//
// Binding D1 (Settings > Bindings) :
//   DB -> ta base voix-juste-db

const ALLOWED_ORIGINS = "*";
const MODEL = "claude-haiku-4-5-20251001";
const MAX_TOKENS = 1000;
const FREE_MESSAGE_LIMIT = 20;
const SESSION_DAYS = 30;

/* ================== Utilitaires génériques ================== */

function corsHeaders() {
  return {
    "Access-Control-Allow-Origin": ALLOWED_ORIGINS,
    "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
    "Access-Control-Allow-Headers": "Content-Type",
    "Access-Control-Allow-Credentials": "true",
  };
}

function jsonResponse(obj, status, extraHeaders) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { "Content-Type": "application/json", ...corsHeaders(), ...(extraHeaders || {}) },
  });
}

function bytesToHex(bytes) {
  return [...bytes].map((b) => b.toString(16).padStart(2, "0")).join("");
}
function hexToBytes(hex) {
  const arr = new Uint8Array(hex.length / 2);
  for (let i = 0; i < arr.length; i++) arr[i] = parseInt(hex.substr(i * 2, 2), 16);
  return arr;
}
function randomHex(len) {
  const arr = new Uint8Array(len);
  crypto.getRandomValues(arr);
  return bytesToHex(arr);
}
function b64url(str) {
  return btoa(unescape(encodeURIComponent(str))).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function b64urlDecode(str) {
  str = str.replace(/-/g, "+").replace(/_/g, "/");
  while (str.length % 4) str += "=";
  return decodeURIComponent(escape(atob(str)));
}

/* ================== Mots de passe (PBKDF2) ================== */

async function hashPassword(password, saltHex) {
  const enc = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey("raw", enc.encode(password), { name: "PBKDF2" }, false, ["deriveBits"]);
  const salt = hexToBytes(saltHex);
  const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: 100000, hash: "SHA-256" }, keyMaterial, 256);
  return bytesToHex(new Uint8Array(bits));
}

/* ================== Sessions signées (HMAC) ================== */

async function hmacSign(data, secret) {
  const enc = new TextEncoder();
  const key = await crypto.subtle.importKey("raw", enc.encode(secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
  const sig = await crypto.subtle.sign("HMAC", key, enc.encode(data));
  return bytesToHex(new Uint8Array(sig));
}

async function createSessionToken(userId, secret) {
  const payload = JSON.stringify({ uid: userId, exp: Date.now() + 1000 * 60 * 60 * 24 * SESSION_DAYS });
  const payloadB64 = b64url(payload);
  const sig = await hmacSign(payloadB64, secret);
  return payloadB64 + "." + sig;
}

async function verifySessionToken(token, secret) {
  if (!token) return null;
  const parts = token.split(".");
  if (parts.length !== 2) return null;
  const [payloadB64, sig] = parts;
  const expectedSig = await hmacSign(payloadB64, secret);
  if (sig !== expectedSig) return null;
  let payload;
  try {
    payload = JSON.parse(b64urlDecode(payloadB64));
  } catch (e) {
    return null;
  }
  if (!payload.exp || Date.now() > payload.exp) return null;
  return payload.uid;
}

function getCookie(request, name) {
  const cookie = request.headers.get("Cookie") || "";
  const match = cookie.match(new RegExp("(?:^|; )" + name + "=([^;]*)"));
  return match ? decodeURIComponent(match[1]) : null;
}

function sessionCookieHeader(token) {
  const maxAge = 60 * 60 * 24 * SESSION_DAYS;
  return `session=${encodeURIComponent(token)}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=${maxAge}`;
}
function clearCookieHeader() {
  return `session=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

/* ================== Auth : middlewares ================== */

async function getUserFromRequest(request, env) {
  const token = getCookie(request, "session");
  if (!token) return null;
  const uid = await verifySessionToken(token, env.SESSION_SECRET);
  if (!uid) return null;
  const user = await env.DB.prepare("SELECT id, email, is_pro, messages_used FROM users WHERE id = ?").bind(uid).first();
  return user || null;
}

function userPublicShape(user) {
  return {
    email: user.email,
    isPro: !!user.is_pro,
    messagesUsed: user.messages_used,
    freeLimit: FREE_MESSAGE_LIMIT,
  };
}

/* ================== Routes : Auth ================== */

async function handleSignup(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Requête invalide." }, 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  if (!email || !email.includes("@")) return jsonResponse({ error: "Email invalide." }, 400);
  if (password.length < 6) return jsonResponse({ error: "Le mot de passe doit contenir au moins 6 caractères." }, 400);

  const existing = await env.DB.prepare("SELECT id FROM users WHERE email = ?").bind(email).first();
  if (existing) return jsonResponse({ error: "Un compte existe déjà avec cet email." }, 409);

  const salt = randomHex(16);
  const hash = await hashPassword(password, salt);
  const result = await env.DB.prepare(
    "INSERT INTO users (email, password_hash, salt) VALUES (?, ?, ?)"
  ).bind(email, hash, salt).run();

  const userId = result.meta.last_row_id;
  const token = await createSessionToken(userId, env.SESSION_SECRET);
  return jsonResponse(
    { email, isPro: false, messagesUsed: 0, freeLimit: FREE_MESSAGE_LIMIT },
    200,
    { "Set-Cookie": sessionCookieHeader(token) }
  );
}

async function handleLogin(request, env) {
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Requête invalide." }, 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  const password = body.password || "";
  const user = await env.DB.prepare("SELECT * FROM users WHERE email = ?").bind(email).first();
  if (!user) return jsonResponse({ error: "Email ou mot de passe incorrect." }, 401);

  const computedHash = await hashPassword(password, user.salt);
  if (computedHash !== user.password_hash) {
    return jsonResponse({ error: "Email ou mot de passe incorrect." }, 401);
  }

  const token = await createSessionToken(user.id, env.SESSION_SECRET);
  return jsonResponse(userPublicShape(user), 200, { "Set-Cookie": sessionCookieHeader(token) });
}

async function handleLogout() {
  return jsonResponse({ ok: true }, 200, { "Set-Cookie": clearCookieHeader() });
}

async function handleMe(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) return jsonResponse({ error: "Non connecté." }, 401);
  return jsonResponse(userPublicShape(user), 200);
}

/* ================== Route : Chat (protégée + limite) ================== */

async function handleChat(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) return jsonResponse({ error: "Connecte-toi pour discuter avec le tuteur." }, 401);

  if (!user.is_pro && user.messages_used >= FREE_MESSAGE_LIMIT) {
    return jsonResponse(
      { error: "Limite de messages gratuits atteinte.", upgradeRequired: true },
      402
    );
  }

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Corps de requête JSON invalide." }, 400);
  }

  const { system, messages } = body;
  if (!Array.isArray(messages) || messages.length === 0) {
    return jsonResponse({ error: "Le champ 'messages' est requis." }, 400);
  }
  if (messages.length > 60) {
    return jsonResponse({ error: "Conversation trop longue, démarre une nouvelle session." }, 400);
  }

  const apiKey = env.ANTHROPIC_API_KEY;
  if (!apiKey) {
    return jsonResponse({ error: "Clé API non configurée côté serveur (ANTHROPIC_API_KEY manquante)." }, 500);
  }

  try {
    const upstream = await fetch("https://api.anthropic.com/v1/messages", {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": apiKey,
        "anthropic-version": "2023-06-01",
      },
      body: JSON.stringify({ model: MODEL, max_tokens: MAX_TOKENS, system: system || "", messages }),
    });

    const data = await upstream.json();
    if (!upstream.ok) {
      return jsonResponse({ error: data?.error?.message || "Erreur de l'API Anthropic." }, upstream.status);
    }

    if (!user.is_pro) {
      await env.DB.prepare("UPDATE users SET messages_used = messages_used + 1 WHERE id = ?").bind(user.id).run();
    }

    return jsonResponse(data, 200);
  } catch (err) {
    return jsonResponse({ error: "Impossible de contacter l'API Anthropic." }, 502);
  }
}

/* ================== Route : Paiement KKiaPay ================== */

async function handlePaymentVerify(request, env) {
  const user = await getUserFromRequest(request, env);
  if (!user) return jsonResponse({ error: "Connecte-toi d'abord." }, 401);

  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Requête invalide." }, 400);
  }
  const transactionId = body.transactionId;
  if (!transactionId) return jsonResponse({ error: "transactionId manquant." }, 400);

  const sandbox = (env.KKIAPAY_SANDBOX || "true") === "true";
  const verifyUrl = sandbox
    ? "https://api-sandbox.kkiapay.me/api/v1/transactions/status"
    : "https://api.kkiapay.me/api/v1/transactions/status";

  try {
    const upstream = await fetch(verifyUrl, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "x-api-key": env.KKIAPAY_PUBLIC_KEY,
        "x-private-key": env.KKIAPAY_PRIVATE_KEY,
      },
      body: JSON.stringify({ transactionId }),
    });
    const data = await upstream.json();

    if (!upstream.ok) {
      return jsonResponse({ error: "Impossible de vérifier la transaction auprès de KKiaPay.", details: data }, 502);
    }

    if (data.status === "SUCCESS") {
      await env.DB.prepare("UPDATE users SET is_pro = 1 WHERE id = ?").bind(user.id).run();
      return jsonResponse({ ok: true, isPro: true }, 200);
    }
    return jsonResponse({ ok: false, status: data.status || "inconnu" }, 200);
  } catch (err) {
    return jsonResponse({ error: "Erreur réseau lors de la vérification KKiaPay." }, 502);
  }
}

/* ================== Routes : Admin (protégées par ADMIN_KEY) ================== */

function checkAdminKey(request, env) {
  const url = new URL(request.url);
  const keyFromQuery = url.searchParams.get("key");
  const keyFromHeader = request.headers.get("x-admin-key");
  const providedKey = keyFromHeader || keyFromQuery;
  return !!env.ADMIN_KEY && providedKey === env.ADMIN_KEY;
}

async function handleAdminUsers(request, env) {
  if (!checkAdminKey(request, env)) return jsonResponse({ error: "Clé admin invalide." }, 403);
  const { results } = await env.DB.prepare(
    "SELECT id, email, is_pro, messages_used, created_at FROM users ORDER BY created_at DESC"
  ).all();
  return jsonResponse({ users: results }, 200);
}

async function handleAdminSetPro(request, env, makePro) {
  if (!checkAdminKey(request, env)) return jsonResponse({ error: "Clé admin invalide." }, 403);
  let body;
  try {
    body = await request.json();
  } catch (e) {
    return jsonResponse({ error: "Requête invalide." }, 400);
  }
  const email = (body.email || "").trim().toLowerCase();
  if (!email) return jsonResponse({ error: "Email manquant." }, 400);
  await env.DB.prepare("UPDATE users SET is_pro = ? WHERE email = ?").bind(makePro ? 1 : 0, email).run();
  return jsonResponse({ ok: true }, 200);
}

/* ================== Routeur principal ================== */

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;

    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders() });
    }

    try {
      if (path === "/api/auth/signup" && request.method === "POST") return await handleSignup(request, env);
      if (path === "/api/auth/login" && request.method === "POST") return await handleLogin(request, env);
      if (path === "/api/auth/logout" && request.method === "POST") return await handleLogout();
      if (path === "/api/me" && request.method === "GET") return await handleMe(request, env);
      if (path === "/api/chat" && request.method === "POST") return await handleChat(request, env);
      if (path === "/api/payment/verify" && request.method === "POST") return await handlePaymentVerify(request, env);
      if (path === "/api/admin/users" && request.method === "GET") return await handleAdminUsers(request, env);
      if (path === "/api/admin/upgrade" && request.method === "POST") return await handleAdminSetPro(request, env, true);
      if (path === "/api/admin/downgrade" && request.method === "POST") return await handleAdminSetPro(request, env, false);
    } catch (err) {
      return jsonResponse({ error: "Erreur serveur inattendue : " + (err && err.message ? err.message : String(err)) }, 500);
    }

    // Toute autre requête : servir les fichiers statiques du dossier public/
    return env.ASSETS.fetch(request);
  },
};
