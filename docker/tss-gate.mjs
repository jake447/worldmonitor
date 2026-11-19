/**
 * The Survival Summit members gate.
 *
 * Not upstream World Monitor code. This file exists only in jake447/worldmonitor
 * so that map.thesurvivalsummit.com is reachable by paying members and admins
 * and by nobody else.
 *
 * nginx asks this process about every request it is told to protect, through
 * `auth_request /gate/check`. The answer is 204 or 401, and nothing else about
 * the request is read, so a wrong answer here can only ever deny.
 *
 * Two flows arrive:
 *
 *   /gate/check     nginx's subrequest. 204 when the caller carries a valid
 *                   gate cookie, 401 otherwise. Never sets a cookie.
 *   /gate/callback  The member's browser, redirected here by
 *                   thesurvivalsummit.com/api/sso/map carrying a one-shot
 *                   token. Validated, exchanged for a 12 hour cookie.
 *
 * The inbound token is the ss-gate format minted in the TSS codebase at
 * src/app/api/sso/map/route.ts, which is NOT a JWT:
 *
 *   base64url(JSON claims) + "." + base64url(HMAC-SHA256 over that
 *   base64url string, keyed with MAP_SSO_SECRET as utf8 bytes)
 *
 * The gate cookie is a second token in the same shape, signed with a key
 * derived from the same secret, so one Railway variable configures both and
 * the two signatures can never be swapped for one another.
 */
import { createServer } from 'node:http';
import { createHmac, timingSafeEqual, createHash } from 'node:crypto';

const PORT = Number(process.env.TSS_GATE_PORT || 46124);
const SECRET = (process.env.MAP_SSO_SECRET || '').trim();
const LOGIN_BASE = (process.env.TSS_GATE_LOGIN_URL || 'https://thesurvivalsummit.com/api/sso/map').trim();
const COOKIE = 'tss_gate';
const SESSION_SECONDS = 12 * 60 * 60;
/** Bound on an inbound SSO token's lifetime, whatever exp it carries. */
const MAX_TOKEN_AGE_SECONDS = 600;

/**
 * A distinct key for our own cookie. Without this, a 300-second SSO token
 * would verify as a 12-hour session cookie and vice versa, since both are the
 * same payload.signature shape over the same secret.
 */
const COOKIE_SECRET = SECRET
  ? createHash('sha256').update(`tss-gate-cookie:${SECRET}`).digest('hex')
  : '';

const b64url = (input) =>
  Buffer.from(input).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');

function sign(payload, key) {
  return b64url(createHmac('sha256', key).update(payload).digest());
}

/** Constant-time compare that does not leak length through an exception. */
function sameSignature(a, b) {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Verify a payload.signature token and return its claims, or null.
 * Every rejection returns null: callers must not be able to tell a bad
 * signature from expired claims from malformed JSON.
 */
function verify(token, key) {
  if (!key || typeof token !== 'string') return null;
  const dot = token.indexOf('.');
  if (dot <= 0 || dot !== token.lastIndexOf('.')) return null;
  const payload = token.slice(0, dot);
  if (!sameSignature(token.slice(dot + 1), sign(payload, key))) return null;
  let claims;
  try {
    claims = JSON.parse(Buffer.from(payload, 'base64url').toString('utf8'));
  } catch {
    return null;
  }
  if (!claims || typeof claims !== 'object') return null;
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.exp !== 'number' || claims.exp <= now) return null;
  return claims;
}

/** An SSO token from TSS, which must additionally prove paid membership. */
function verifySsoToken(token) {
  const claims = verify(token, SECRET);
  if (!claims) return null;
  if (claims.iss !== 'ss-gate') return null;
  // An attacker who ever obtains the secret should not also get an
  // indefinitely valid token, so cap age regardless of the issuer's exp.
  const now = Math.floor(Date.now() / 1000);
  if (typeof claims.iat !== 'number' || claims.iat > now + 60) return null;
  if (now - claims.iat > MAX_TOKEN_AGE_SECONDS) return null;
  // TSS sets member true for active members and for admins. Anything else is
  // a signed-in non-member, who gets sent to the membership page.
  if (claims.member !== true) return { member: false, claims };
  return { member: true, claims };
}

function cookieValue(name, header) {
  if (typeof header !== 'string') return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() !== name) continue;
    return decodeURIComponent(part.slice(eq + 1).trim());
  }
  return null;
}

function mintCookie(claims) {
  const now = Math.floor(Date.now() / 1000);
  const payload = b64url(
    JSON.stringify({
      sub: claims.sub,
      email: claims.email,
      plan: claims.plan,
      iat: now,
      exp: now + SESSION_SECONDS,
    }),
  );
  return `${payload}.${sign(payload, COOKIE_SECRET)}`;
}

/**
 * state is attacker-influenced: it arrives on the query string of a public
 * endpoint. Only a site-relative path may ever reach a Location header, or
 * the gate becomes an open redirector on the members' own domain.
 */
function safePath(state) {
  if (typeof state !== 'string' || !state.startsWith('/')) return '/';
  // "//evil.com" and "/\evil.com" are both protocol-relative to a browser.
  if (/^\/[/\\]/.test(state)) return '/';
  return state;
}

function loginRedirect(req, state) {
  const host = req.headers['x-forwarded-host'] || req.headers.host || 'map.thesurvivalsummit.com';
  const proto = req.headers['x-forwarded-proto'] || 'https';
  const callback = `${proto}://${host}/gate/callback`;
  const url = new URL(LOGIN_BASE);
  url.searchParams.set('redirect', callback);
  url.searchParams.set('state', safePath(state));
  return url.toString();
}

const server = createServer((req, res) => {
  const url = new URL(req.url || '/', 'http://gate.invalid');
  const path = url.pathname;

  if (path === '/gate/check') {
    const token = cookieValue(COOKIE, req.headers.cookie);
    if (token && verify(token, COOKIE_SECRET)) {
      res.writeHead(204).end();
    } else {
      res.writeHead(401).end();
    }
    return;
  }

  if (path === '/gate/callback') {
    const state = safePath(url.searchParams.get('state'));
    if (!SECRET) {
      // Fail closed and say so in the log. A gate with no secret that let
      // people through would be worse than a broken map.
      console.error('[tss-gate] MAP_SSO_SECRET is not set; refusing every caller');
      res.writeHead(503, { 'content-type': 'text/plain' }).end('The members gate is not configured.');
      return;
    }
    // TSS reports its own failures here rather than minting a token.
    const error = url.searchParams.get('error');
    if (error) {
      res.writeHead(302, { location: loginRedirect(req, state) }).end();
      return;
    }
    const result = verifySsoToken(url.searchParams.get('token') || '');
    if (!result) {
      res.writeHead(302, { location: loginRedirect(req, state) }).end();
      return;
    }
    if (!result.member) {
      const where = typeof result.claims.subscribe_url === 'string' && /^https:\/\//.test(result.claims.subscribe_url)
        ? result.claims.subscribe_url
        : 'https://thesurvivalsummit.com/membership';
      res.writeHead(302, { location: where }).end();
      return;
    }
    const secure = (req.headers['x-forwarded-proto'] || 'https') === 'https';
    res
      .writeHead(302, {
        location: state,
        // Lax, not Strict: the browser arrives here on a cross-site redirect
        // from thesurvivalsummit.com, and Strict would withhold the cookie on
        // that first navigation and loop the member back through login.
        'set-cookie': `${COOKIE}=${mintCookie(result.claims)}; Path=/; Max-Age=${SESSION_SECONDS}; HttpOnly; SameSite=Lax${secure ? '; Secure' : ''}`,
        'cache-control': 'no-store',
      })
      .end();
    return;
  }

  if (path === '/gate/logout') {
    res
      .writeHead(302, {
        location: 'https://thesurvivalsummit.com/dashboard',
        'set-cookie': `${COOKIE}=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure`,
      })
      .end();
    return;
  }

  res.writeHead(404).end();
});

// Loopback only. nginx is the sole caller; binding wider would publish the
// gate's own endpoints on the container's network.
server.listen(PORT, '127.0.0.1', () => {
  console.log(`[tss-gate] listening on 127.0.0.1:${PORT}${SECRET ? '' : ' WITHOUT a secret: every caller will be refused'}`);
});
