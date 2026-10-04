/**
 * End-to-end tests over real HTTP: a real Express server on a random port.
 * These prove the pieces work TOGETHER, including forwarding and admin auth.
 */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { ServiceClient } from '../src/identity/serviceClient.js';
import { createApp, type App } from '../src/server.js';
import { runAll } from '../src/simulator/attacks.js';

let app: App;
let base: string;

before(async () => {
  app = await createApp(loadConfig({ ADMIN_API_KEY: 'e2e-admin-key', PORT: '0' }));
  base = `http://127.0.0.1:${await app.listen(0)}`;
});
after(async () => app.close());

const callProxy = async (from: string, to: string, path: string, init: RequestInit = {}) => {
  const token = await app.clients.get(from)!.signToken();
  return fetch(`${base}/api/proxy${path}`, { ...init, headers: { authorization: `Bearer ${token}`, 'x-destination-service': to, ...(init.headers ?? {}) } });
};

test('allowed requests are really forwarded and the backend sees the authenticated identity', async () => {
  const res = await callProxy('frontend-service', 'orders-service', '/orders/list');
  assert.equal(res.status, 200);
  assert.equal(res.headers.get('x-zt-decision'), 'ALLOW');
  const body = (await res.json()) as { service: string; receivedFrom: string; orders: unknown[] };
  assert.equal(body.service, 'orders-service');
  assert.equal(body.receivedFrom, 'frontend-service');
  assert.ok(body.orders.length > 0);
});

test('blocked requests return 403 and never reach the backend', async () => {
  const res = await callProxy('frontend-service', 'database-service', '/database/query', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{}' });
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('x-zt-decision'), 'BLOCK');
});

test('no token -> 401', async () => {
  const res = await fetch(`${base}/api/proxy/orders/list`, { headers: { 'x-destination-service': 'orders-service' } });
  assert.equal(res.status, 401);
});

test('step-up responses are 401 with a WWW-Authenticate challenge', async () => {
  let n: unknown = 'x'.repeat(120_000);
  for (let i = 0; i < 25; i++) n = { n };
  const res = await callProxy('payments-service', 'database-service', '/database/query', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(n) });
  assert.equal(res.status, 401);
  assert.match(res.headers.get('www-authenticate') ?? '', /ZT-TOTP/);
});

test('downstream services cannot be reached directly, bypassing the proxy', async () => {
  const res = await fetch(`${base}/downstream/database-service/database/rows`);
  assert.equal(res.status, 403);
  assert.equal(((await res.json()) as { error: string }).error, 'DIRECT_ACCESS_FORBIDDEN');
});

test('malformed JSON and oversized bodies get clean JSON errors', async () => {
  const bad = await callProxy('frontend-service', 'orders-service', '/orders/create', { method: 'POST', headers: { 'content-type': 'application/json' }, body: '{oops' });
  assert.equal(bad.status, 400);
  const huge = await callProxy('frontend-service', 'orders-service', '/orders/create', { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ a: 'x'.repeat(3_000_000) }) });
  assert.equal(huge.status, 413);
});

test('admin routes need the admin key; there is NO unauthenticated token-minting endpoint', async () => {
  assert.equal((await fetch(`${base}/admin/services`, { method: 'POST' })).status, 401);
  assert.equal((await fetch(`${base}/admin/quarantine/x/release`, { method: 'POST', headers: { 'x-admin-key': 'wrong' } })).status, 401);
  assert.equal((await fetch(`${base}/api/tokens/generate`, { method: 'POST' })).status, 404);
});

test('admin can onboard a new service end-to-end and it can then call through the proxy', async () => {
  const svc = await ServiceClient.create('reports-service', { audience: 'zero-trust-mesh' });
  const reg = await fetch(`${base}/admin/services`, {
    method: 'POST',
    headers: { 'x-admin-key': 'e2e-admin-key', 'content-type': 'application/json' },
    body: JSON.stringify({ serviceId: 'reports-service', displayName: 'Reports', publicJwk: svc.publicJwk, kid: svc.kid }),
  });
  assert.equal(reg.status, 201);
  assert.ok(((await reg.json()) as { totpSecret: string }).totpSecret.length >= 32);

  // Registered, but no policy yet -> default deny proves nothing is implicitly trusted.
  const res = await fetch(`${base}/api/proxy/orders/list`, { headers: { authorization: `Bearer ${await svc.signToken()}`, 'x-destination-service': 'orders-service' } });
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('x-zt-reason'), 'NO_POLICY');
});

test('revoking a token over the admin API blocks it', async () => {
  const token = await app.clients.get('frontend-service')!.signToken({ jti: 'revoke-me' });
  const r = await fetch(`${base}/admin/tokens/revoke`, { method: 'POST', headers: { 'x-admin-key': 'e2e-admin-key', 'content-type': 'application/json' }, body: JSON.stringify({ jti: 'revoke-me' }) });
  assert.equal(r.status, 200);
  const res = await fetch(`${base}/api/proxy/orders/list`, { headers: { authorization: `Bearer ${token}`, 'x-destination-service': 'orders-service' } });
  assert.equal(res.headers.get('x-zt-reason'), 'TOKEN_REVOKED');
});

test('the full attack simulator: every scenario behaves as expected', async () => {
  const results = await runAll({ mesh: app.mesh, clients: app.clients, baseUrl: () => base });
  for (const r of results) assert.equal(r.passed, true, `scenario "${r.title}" failed: ${JSON.stringify(r.steps)}`);
  assert.equal(results.length, 13);
});

test('after all that traffic the audit chain is still intact and metrics add up', async () => {
  const verify = (await (await fetch(`${base}/api/audit/verify`)).json()) as { valid: boolean };
  assert.equal(verify.valid, true);
  const m = (await (await fetch(`${base}/api/metrics`)).json()) as { total: number; byDecision: Record<string, number> };
  assert.equal(Object.values(m.byDecision).reduce((a, b) => a + b, 0), m.total);
});

test('private dashboard mode hides data without the admin key and hides internals from attackers', async () => {
  const priv = await createApp(loadConfig({ ADMIN_API_KEY: 'k', PUBLIC_DASHBOARD: 'false', PORT: '0' }));
  const p = await priv.listen(0);
  const u = `http://127.0.0.1:${p}`;
  try {
    assert.equal((await fetch(`${u}/api/metrics`)).status, 401);
    assert.equal((await fetch(`${u}/api/metrics`, { headers: { 'x-admin-key': 'k' } })).status, 200);
    assert.equal((await fetch(`${u}/api/simulator/run-all`, { method: 'POST' })).status, 401);
    const token = await priv.clients.get('frontend-service')!.signToken();
    const denied = await fetch(`${u}/api/proxy/x`, { headers: { authorization: `Bearer ${token}`, 'x-destination-service': 'database-service' } });
    const body = (await denied.json()) as Record<string, unknown>;
    assert.equal(denied.status, 403);
    assert.equal('stages' in body, false);
  } finally {
    await priv.close();
  }
});
