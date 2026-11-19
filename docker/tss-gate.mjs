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

/**
 * Routes the dashboard fetches WITHOUT credentials, which therefore cannot
 * carry the gate cookie however the member signed in.
 *
 * This is not a hole punched for convenience. World Monitor's frontend has an
 * enumerated anonymous-access set, and these calls deliberately opt out of its
 * own session interceptor: src/shared/public-rpc-cache.ts says "a path listed
 * here is reachable with no credential whatever ENDPOINT_ENTITLEMENTS says",
 * and each one "is already shown to anonymous dashboard visitors" on
 * worldmonitor.app. Refusing them here does not protect anything that is not
 * already public upstream; it only breaks those panels for paying members.
 *
 * What stays members-only is everything that makes the map worth paying for:
 * the dashboard page itself, every deep link, military flights, vessels,
 * conflict events, and every other route not named here. Tier policy within
 * these routes is still the sidecar's job, not this gate's.
 *
 * Keep in step with src/shared/public-rpc-cache.ts when merging upstream.
 */
const PUBLIC_PATHS = new Set([
  // PUBLIC_SHARED_RPC_PATHS and LIVE_TOPIC_RPC_PATHS.
  '/api/news/v1/list-feed-digest',
  '/api/displacement/v1/get-displacement-summary',
  '/api/displacement/v1/get-cross-border-movements',
  '/api/forecast/v1/get-forecasts',
  '/api/supply-chain/v1/get-chokepoint-status',
  '/api/intelligence/v1/get-pizzint-status',
  '/api/market/v1/get-fear-greed-index',
  '/api/infrastructure/v1/list-internet-outages',
  '/api/prediction/v1/list-prediction-markets',
  '/api/economic/v1/get-national-debt',
  '/api/economic/v1/get-us-treasury-par-yield-curve',
  '/api/economic/v1/get-oil-inventories',
  '/api/intelligence/v1/list-security-advisories',
  '/api/news/v1/search-fact-checks',
  // Utility routes that carry no intel of their own.
  '/api/reverse-geocode',
  '/api/analytics-health',
  '/api/miit-news',
  '/api/gpsjam',
  '/api/oref-alerts',
]);

/**
 * True when nginx is asking about a route the dashboard reaches without a
 * cookie. `public=1` is upstream's own marker for an anonymous bootstrap read,
 * and the sidecar still decides which keys that marker is valid for
 * (src/services/wm-session.ts), so honouring it here cannot widen access
 * beyond what upstream already allows. The pathname is checked exactly, so
 * tacking public=1 onto a gated route does not get past this.
 */
function isPublicRoute(originalUri) {
  if (typeof originalUri !== 'string' || !originalUri.startsWith('/')) return false;
  // "//evil.com/api/gpsjam" is protocol-relative, so resolving it yields the
  // pathname /api/gpsjam and would have passed the allowlist. nginx routes
  // such a request line to the SPA, so letting it through served the
  // dashboard to an anonymous caller. Same rule as safePath.
  if (/^\/[/\\]/.test(originalUri)) return false;
  let url;
  try {
    url = new URL(originalUri, 'http://gate.invalid');
  } catch {
    return false;
  }
  if (PUBLIC_PATHS.has(url.pathname)) return true;
  return url.pathname === '/api/bootstrap' && url.searchParams.get('public') === '1';
}
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
    // nginx forwards the request it is really asking about; this subrequest's
    // own path is always /gate/check.
    if (isPublicRoute(req.headers['x-original-uri'])) {
      res.writeHead(204).end();
      return;
    }
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
