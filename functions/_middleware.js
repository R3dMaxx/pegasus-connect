// Pegasus Connect: access gateway for Cloudflare Pages.
// Public: /__pc/login, /config.js. Everything else requires a signed session.
// This file belongs in repository root: functions/_middleware.js (NOT docs/functions).

const PROJECT = 'pegasus-connect-hub';
const ALLOWED_UID = 'YcDZafvhgBVpHYEbIfTZIAv2fD83';
const COOKIE = '__Host-pegasus_access';
const MAX_AGE = 4 * 60 * 60; // Four hours; key rotation invalidates sessions.
const KEY_URL = 'https://www.googleapis.com/service_accounts/v1/jwk/securetoken@system.gserviceaccount.com';
const encoder = new TextEncoder();

function bytesFromBase64url(value) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) throw Error('Invalid encoding');
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - value.length % 4) % 4);
  const decoded = atob(padded);
  return Uint8Array.from(decoded, c => c.charCodeAt(0));
}
function base64urlFromBytes(bytes) {
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}
function jsonFromBase64url(value) {
  return JSON.parse(new TextDecoder().decode(bytesFromBase64url(value)));
}
function headers(extra = {}) {
  return {
    'Cache-Control': 'private, no-store, max-age=0',
    'X-Content-Type-Options': 'nosniff',
    'Referrer-Policy': 'no-referrer',
    'X-Frame-Options': 'DENY',
    ...extra
  };
}
function responseText(message, status) {
  return new Response(message, { status, headers: headers({'Content-Type':'text/plain; charset=utf-8'}) });
}
function isSameOrigin(request) {
  const origin = request.headers.get('Origin');
  return origin === new URL(request.url).origin;
}
function getCookie(request) {
  const line = request.headers.get('Cookie') || '';
  const item = line.split(';').map(s => s.trim()).find(s => s.startsWith(COOKIE + '='));
  return item ? item.slice(COOKIE.length + 1) : '';
}
async function sessionKey(secret) {
  if (typeof secret !== 'string' || secret.length < 32) throw Error('Missing session secret');
  return crypto.subtle.importKey('raw', encoder.encode(secret), { name:'HMAC', hash:'SHA-256' }, false, ['sign', 'verify']);
}
async function signSession(secret) {
  const expires = Math.floor(Date.now() / 1000) + MAX_AGE;
  const body = `v1.${expires}`;
  const signature = await crypto.subtle.sign('HMAC', await sessionKey(secret), encoder.encode(`${PROJECT}|${ALLOWED_UID}|${body}`));
  return `${body}.${base64urlFromBytes(new Uint8Array(signature))}`;
}
async function validSession(request, secret) {
  const cookie = getCookie(request);
  const match = /^v1\.(\d{10})\.([A-Za-z0-9_-]{43})$/.exec(cookie);
  if (!match) return false;
  const exp = Number(match[1]);
  const now = Math.floor(Date.now() / 1000);
  if (!Number.isSafeInteger(exp) || exp <= now || exp > now + MAX_AGE) return false;
  try {
    const key = await sessionKey(secret);
    return crypto.subtle.verify('HMAC', key, bytesFromBase64url(match[2]), encoder.encode(`${PROJECT}|${ALLOWED_UID}|v1.${exp}`));
  } catch {
    return false;
  }
}
async function verifyFirebaseIdToken(token) {
  if (typeof token !== 'string' || token.length > 12000) return false;
  const parts = token.split('.');
  if (parts.length !== 3) return false;
  try {
    const header = jsonFromBase64url(parts[0]);
    const payload = jsonFromBase64url(parts[1]);
    if (header.alg !== 'RS256' || typeof header.kid !== 'string' || header.kid.length > 200) return false;
    const now = Math.floor(Date.now() / 1000);
    if (payload.aud !== PROJECT || payload.iss !== `https://securetoken.google.com/${PROJECT}` ||
        payload.sub !== ALLOWED_UID || typeof payload.exp !== 'number' || payload.exp <= now ||
        typeof payload.iat !== 'number' || payload.iat > now ||
        typeof payload.auth_time !== 'number' || payload.auth_time > now ||
        payload.sub.length > 128) return false;

    const res = await fetch(KEY_URL, { signal: AbortSignal.timeout(7000), cf: { cacheEverything: true, cacheTtl: 300 } });
    if (!res.ok) return false;
    const jwks = await res.json();
    const jwk = jwks.keys?.find(k => k.kid === header.kid && k.kty === 'RSA' && (!k.alg || k.alg === 'RS256') && (!k.use || k.use === 'sig'));
    if (!jwk) return false;
    const key = await crypto.subtle.importKey('jwk', jwk, { name:'RSASSA-PKCS1-v1_5', hash:'SHA-256' }, false, ['verify']);
    return crypto.subtle.verify('RSASSA-PKCS1-v1_5', key, bytesFromBase64url(parts[2]), encoder.encode(`${parts[0]}.${parts[1]}`));
  } catch {
    return false;
  }
}
function loginPage() {
  const nonce = base64urlFromBytes(crypto.getRandomValues(new Uint8Array(18)));
  // All script is static or protected by the fresh nonce; no user data interpolated into HTML.
  const body = `<!doctype html><html lang="it"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>Pegasus Connect - Accesso</title>
<style>:root{color-scheme:dark;font:16px system-ui,sans-serif;background:#151a1c;color:#eef3f4}main{max-width:430px;margin:10vh auto;padding:25px;border:1px solid #445358;border-radius:12px}h1{font-size:24px}label{display:block;margin-top:16px}input,button{box-sizing:border-box;width:100%;margin-top:6px;padding:13px;border:1px solid #64777c;border-radius:7px;background:#253236;color:inherit;font:inherit}button{cursor:pointer;margin-top:22px;background:#245c67}button:disabled{opacity:.6}#status{min-height:24px;color:#e9b8a4;font-size:14px}small{color:#abbfc4}</style>
</head><body><main><h1>Pegasus Connect</h1><p>Accesso riservato.</p><form id="signin"><label>Email<input type="email" id="email" autocomplete="username" required></label><label>Password<input type="password" id="password" autocomplete="current-password" required></label><button id="submit" type="submit">Accedi</button></form><p id="status" role="status"></p><small>Autenticazione Firebase. Le credenziali non vengono salvate da questa pagina.</small></main>
<script src="/config.js"></script><script nonce="${nonce}">
const form=document.querySelector('#signin'), status=document.querySelector('#status'), button=document.querySelector('#submit');
form.addEventListener('submit', async event => {
 event.preventDefault(); button.disabled=true; status.textContent='Verifica credenziali…';
 try {
  const key=window.PEGASUS_CONFIG?.apiKey;
  if(typeof key!=='string'||!key) throw Error('Configurazione mancante');
  const login=await fetch('https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword?key='+encodeURIComponent(key), {
   method:'POST',headers:{'Content-Type':'application/json'},cache:'no-store',body:JSON.stringify({email:document.querySelector('#email').value,password:document.querySelector('#password').value,returnSecureToken:true})
  });
  
  const data=await login.json(); document.querySelector('#password').value='';
  const confirm=await fetch('/__pc/session',{method:'POST',headers:{'Content-Type':'application/json'},cache:'no-store',credentials:'same-origin',body:JSON.stringify({idToken:data.idToken})});
  if(!confirm.ok) throw Error(confirm.status===403?'Utente non autorizzato':'Verifica non riuscita');
  location.replace('/');
 } catch(e) { status.textContent=e.message || 'Accesso non riuscito'; button.disabled=false; document.querySelector('#password').value=''; }
});</script></body></html>`;
  return new Response(body, { status:200, headers: headers({
    'Content-Type':'text/html; charset=utf-8',
    'Content-Security-Policy': `default-src 'none'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'; script-src 'self' 'nonce-${nonce}'; style-src 'unsafe-inline'; connect-src 'self' https://identitytoolkit.googleapis.com`
  }) });
}

if (!login.ok) {
  const error = await login.json().catch(() => ({}));
  const code = error.error?.message || 'ERRORE_SCONOSCIUTO';
  throw Error(`Firebase HTTP ${login.status}: ${code}`);
}

export async function onRequest(context) {
  const {request, env} = context;
  const url = new URL(request.url);
  const path = url.pathname;
  const method = request.method.toUpperCase();
  // An unavailable or weak secret must lock down every route (fail closed).
  if (!env.PEGASUS_SESSION_SECRET || env.PEGASUS_SESSION_SECRET.length < 32)
    return responseText('Servizio temporaneamente non configurato.', 503);

  if (path === '/__pc/session') {
    if (method !== 'POST') return responseText('Metodo non consentito',405);
    if (!isSameOrigin(request) || !request.headers.get('Content-Type')?.toLowerCase().startsWith('application/json')) return responseText('Richiesta non valida',403);
    try {
      const raw = await request.text();
      if (raw.length > 15000) return responseText('Richiesta troppo grande',413);
      const {idToken} = JSON.parse(raw);
      if (!await verifyFirebaseIdToken(idToken)) return responseText('Non autorizzato',403);
      const cookie = await signSession(env.PEGASUS_SESSION_SECRET);
      return new Response(null, {status:204,headers:headers({'Set-Cookie':`${COOKIE}=${cookie}; Path=/; Max-Age=${MAX_AGE}; HttpOnly; Secure; SameSite=Strict`})});
    } catch { return responseText('Verifica non riuscita',503); }
  }

  if (path === '/__pc/logout') {
    // A navigation can explicitly end the Cloudflare session, including after Firebase logout.
    if (method !== 'GET' && method !== 'POST') return responseText('Metodo non consentito',405);
    if (method === 'POST' && !isSameOrigin(request)) return responseText('Richiesta non valida',403);
    return new Response(null,{status:303,headers:headers({'Location':'/__pc/login','Set-Cookie':`${COOKIE}=; Path=/; Max-Age=0; HttpOnly; Secure; SameSite=Strict`})});
  }

  if (path === '/__pc/login') {
    if (method !== 'GET' && method !== 'HEAD') return responseText('Metodo non consentito',405);
    if (await validSession(request, env.PEGASUS_SESSION_SECRET))
      return Response.redirect(url.origin+'/',302);
    const page = loginPage();
    return method === 'HEAD' ? new Response(null,{status:200,headers:page.headers}):page;
  }

  // Firebase's client API key is publicly embedded by design. Do not expose other assets.
  if (path === '/config.js' && (method === 'GET' || method === 'HEAD')) {
    const res = await context.next();
    const h = new Headers(res.headers);
    for (const [k,v] of Object.entries(headers())) h.set(k,v);
    return new Response(method === 'HEAD'?null:res.body,{status:res.status,headers:h});
  }

  if (!await validSession(request, env.PEGASUS_SESSION_SECRET)) {
    if (method !== 'GET' && method !== 'HEAD') return responseText('Non autorizzato',401);
    return new Response(null,{status:302,headers:headers({'Location':'/__pc/login'})});
  }
  if (method !== 'GET' && method !== 'HEAD') return responseText('Metodo non consentito',405);
  try {
    const res = await context.next();
    const h = new Headers(res.headers);
    for (const [k,v] of Object.entries(headers())) h.set(k,v);
    return new Response(method === 'HEAD'?null:res.body,{status:res.status,headers:h});
  } catch { return responseText('Risorsa non disponibile',503); }
}
