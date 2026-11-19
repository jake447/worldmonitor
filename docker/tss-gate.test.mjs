/**
 * End-to-end check on the TSS members gate. Boots the real server on a spare
 * port and drives it over HTTP, so the nginx contract (204 / 401 / 302) is
 * what gets asserted, not the internals.
 *
 * Run: node docker/tss-gate.test.mjs
 */
import { spawn } from 'node:child_process';
import { createHmac, createHash } from 'node:crypto';
import assert from 'node:assert/strict';

const PORT = 46199;
const SECRET = 'test-secret-at-least-32-characters-long!!';
const BASE = `http://127.0.0.1:${PORT}`;

const b64url = (i) =>
  Buffer.from(i).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const sign = (p, k) => b64url(createHmac('sha256', k).update(p).digest());
const cookieKey = createHash('sha256').update(`tss-gate-cookie:${SECRET}`).digest('hex');

/** Mint exactly as TSS src/app/api/sso/map/route.ts does. */
function ssoToken(overrides = {}, key = SECRET) {
  const now = Math.floor(Date.now() / 1000);
  const claims = {
    iss: 'ss-gate', sub: 123456789, email: 'member@example.com', name: 'A Member',
    member: true, plan: 'Elite Subscription', iat: now, exp: now + 300,
    jti: `x-${now}`, subscribe_url: 'https://thesurvivalsummit.com/membership',
    ...overrides,
  };
  const payload = b64url(JSON.stringify(claims));
  return `${payload}.${sign(payload, key)}`;
}

const child = spawn(process.execPath, [new URL('./tss-gate.mjs', import.meta.url).pathname], {
  env: { ...process.env, TSS_GATE_PORT: String(PORT), MAP_SSO_SECRET: SECRET },
  stdio: ['ignore', 'pipe', 'inherit'],
});

async function waitUp() {
  for (let i = 0; i < 50; i++) {
    try { await fetch(`${BASE}/gate/check`); return; } catch { await new Promise((r) => setTimeout(r, 100)); }
  }
  throw new Error('gate did not start');
}

const get = (path, cookie) =>
  fetch(`${BASE}${path}`, { redirect: 'manual', headers: cookie ? { cookie } : {} });

let failures = 0;
const check = async (name, fn) => {
  try { await fn(); console.log(`  ok   ${name}`); }
  catch (e) { failures++; console.error(`  FAIL ${name}: ${e.message}`); }
};

try {
  await waitUp();

  await check('no cookie is refused', async () => {
    assert.equal((await get('/gate/check')).status, 401);
  });

  await check('a garbage cookie is refused', async () => {
    assert.equal((await get('/gate/check', 'tss_gate=nonsense')).status, 401);
  });

  // The happy path, and the cookie it mints must then satisfy nginx.
  let sessionCookie = '';
  await check('a valid member token mints a session and lands on state', async () => {
    const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken())}&state=%2Fdashboard`);
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), '/dashboard');
    const setCookie = r.headers.get('set-cookie') || '';
    assert.match(setCookie, /^tss_gate=/);
    assert.match(setCookie, /HttpOnly/);
    assert.match(setCookie, /SameSite=Lax/);
    sessionCookie = setCookie.split(';')[0];
  });

  await check('the minted session cookie passes the nginx check', async () => {
    assert.equal((await get('/gate/check', sessionCookie)).status, 204);
  });

  await check('a tampered signature is refused', async () => {
    const t = ssoToken();
    const bad = `${t.slice(0, t.indexOf('.'))}.${'A'.repeat(43)}`;
    const r = await get(`/gate/callback?token=${encodeURIComponent(bad)}&state=%2F`);
    assert.equal(r.status, 302);
    assert.match(r.headers.get('location'), /thesurvivalsummit\.com\/api\/sso\/map/);
    assert.equal(r.headers.get('set-cookie'), null);
  });

  await check('a token signed with the wrong key is refused', async () => {
    const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken({}, 'other-secret'))}&state=%2F`);
    assert.equal(r.headers.get('set-cookie'), null);
  });

  await check('an expired token is refused', async () => {
    const now = Math.floor(Date.now() / 1000);
    const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken({ iat: now - 400, exp: now - 100 }))}&state=%2F`);
    assert.equal(r.headers.get('set-cookie'), null);
  });

  await check('a token older than the age cap is refused even if exp is far off', async () => {
    const now = Math.floor(Date.now() / 1000);
    const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken({ iat: now - 4000, exp: now + 99999 }))}&state=%2F`);
    assert.equal(r.headers.get('set-cookie'), null);
  });

  await check('a foreign issuer is refused', async () => {
    const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken({ iss: 'somebody-else' }))}&state=%2F`);
    assert.equal(r.headers.get('set-cookie'), null);
  });

  await check('a signed-in non-member goes to the membership page, not the map', async () => {
    const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken({ member: false }))}&state=%2F`);
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), 'https://thesurvivalsummit.com/membership');
    assert.equal(r.headers.get('set-cookie'), null);
  });

  await check('member must be exactly true, not merely truthy', async () => {
    for (const v of ['true', 1, 'yes', {}]) {
      const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken({ member: v }))}&state=%2F`);
      assert.equal(r.headers.get('set-cookie'), null, `member=${JSON.stringify(v)} minted a cookie`);
    }
  });

  await check('an SSO token is not accepted as a session cookie', async () => {
    assert.equal((await get('/gate/check', `tss_gate=${ssoToken()}`)).status, 401);
  });

  await check('a session cookie is not accepted as an SSO token', async () => {
    const now = Math.floor(Date.now() / 1000);
    const payload = b64url(JSON.stringify({ sub: 1, iat: now, exp: now + 300 }));
    const forged = `${payload}.${sign(payload, cookieKey)}`;
    const r = await get(`/gate/callback?token=${encodeURIComponent(forged)}&state=%2F`);
    assert.equal(r.headers.get('set-cookie'), null);
  });

  await check('state cannot be turned into an open redirect', async () => {
    for (const [raw, want] of [
      ['%2F%2Fevil.com', '/'],
      ['%2F%5Cevil.com', '/'],
      ['https%3A%2F%2Fevil.com', '/'],
      ['%2Fcountries%2Firan', '/countries/iran'],
    ]) {
      const r = await get(`/gate/callback?token=${encodeURIComponent(ssoToken())}&state=${raw}`);
      assert.equal(r.headers.get('location'), want, `state=${raw}`);
    }
  });

  await check('TSS reporting login_required sends the member back to login', async () => {
    const r = await get('/gate/callback?error=login_required&state=%2F');
    assert.equal(r.status, 302);
    assert.match(r.headers.get('location'), /thesurvivalsummit\.com\/api\/sso\/map/);
  });

  await check('an unknown path is a 404, not a pass', async () => {
    assert.equal((await get('/anything-else')).status, 404);
  });

  // The allowlist: routes the dashboard fetches without credentials.
  const checkUri = (uri, cookie) =>
    fetch(`${BASE}/gate/check`, {
      redirect: 'manual',
      headers: { ...(cookie ? { cookie } : {}), 'x-original-uri': uri },
    });

  await check('an upstream-public RPC passes with no cookie', async () => {
    for (const uri of [
      '/api/news/v1/list-feed-digest?lang=en',
      '/api/forecast/v1/get-forecasts',
      '/api/market/v1/get-fear-greed-index',
      '/api/reverse-geocode?lat=1&lon=2',
      '/api/bootstrap?keys=weatherAlerts&public=1',
    ]) {
      assert.equal((await checkUri(uri)).status, 204, uri);
    }
  });

  await check('a members-only route is still refused with no cookie', async () => {
    for (const uri of [
      '/',
      '/countries/iran',
      '/api/military/v1/list-military-flights?sw_lat=1',
      '/api/maritime/v1/get-vessel-snapshot?sw_lat=1',
      '/api/conflict/v1/list-acled-events',
      '/api/wm-session',
      '/api/bootstrap?keys=aaiiSentiment',
    ]) {
      assert.equal((await checkUri(uri)).status, 401, uri);
    }
  });

  await check('public=1 cannot be tacked onto a gated route', async () => {
    for (const uri of [
      '/api/military/v1/list-military-flights?public=1',
      '/api/maritime/v1/get-vessel-snapshot?public=1',
      '/?public=1',
      '/api/wm-session?public=1',
    ]) {
      assert.equal((await checkUri(uri)).status, 401, uri);
    }
  });

  await check('a path cannot be smuggled past the allowlist', async () => {
    for (const uri of [
      '/api/gpsjam/../military/v1/list-military-flights',
      '/api/reverse-geocode/../../api/wm-session',
      '/api/news/v1/list-feed-digest/../../../api/wm-session',
    ]) {
      assert.equal((await checkUri(uri)).status, 401, uri);
    }
  });

  await check('a missing or junk original URI is refused', async () => {
    assert.equal((await fetch(`${BASE}/gate/check`, { redirect: 'manual' })).status, 401);
    for (const uri of ['', 'not-a-path', 'http://evil.com/api/gpsjam', '//evil.com/api/gpsjam']) {
      assert.equal((await checkUri(uri)).status, 401, JSON.stringify(uri));
    }
  });
} finally {
  child.kill();
}

console.log(failures ? `\n${failures} FAILED` : '\nall gate checks passed');
process.exit(failures ? 1 : 0);
