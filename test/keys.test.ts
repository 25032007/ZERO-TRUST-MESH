import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { startAutoRotation, type Timers } from '../src/identity/rotation.js';
import { ServiceClient } from '../src/identity/serviceClient.js';
import { createApp } from '../src/server.js';
import { setup } from './helpers.js';

const bearer = (t: string) => `Bearer ${t}`;

test('ServiceClient.rotate switches to a new key only AFTER registration succeeds', async () => {
  const c = await ServiceClient.create('svc-one');
  const oldKid = c.kid;
  let registered: string | undefined;
  const r = await c.rotate(async (_jwk, kid) => void (registered = kid));
  assert.equal(registered, r.kid);
  assert.notEqual(c.kid, oldKid);
  assert.equal(c.publicJwk.kid, c.kid);
});

test('a FAILED registration keeps the old key (a failed rotation never locks a service out)', async () => {
  const c = await ServiceClient.create('svc-one');
  const oldKid = c.kid;
  const oldJwk = c.publicJwk;
  await assert.rejects(c.rotate(async () => { throw new Error('proxy down'); }), /proxy down/);
  assert.equal(c.kid, oldKid);
  assert.equal(c.publicJwk, oldJwk);
  assert.ok(await c.signToken()); // still able to sign
});

test('rotation end-to-end: tokens from the old key work during grace, the new key works immediately, old key dies after grace', async () => {
  const { mesh, clients, clock, nowSec } = await setup();
  const c = clients.get('orders-service')!;
  const oldToken = await c.signToken({ nowSec: nowSec() });
  const oldToken2 = await c.signToken({ nowSec: nowSec() });
  await c.rotate((jwk, kid) => mesh.registry.rotateKey('orders-service', jwk, kid, 60_000));

  assert.equal((await mesh.verifier.verify(bearer(await c.signToken({ nowSec: nowSec() })))).ok, true);
  assert.equal((await mesh.verifier.verify(bearer(oldToken))).ok, true); // inside grace

  clock.advance(61_000);
  const late = await mesh.verifier.verify(bearer(oldToken2));
  assert.equal(!late.ok && late.code, 'UNKNOWN_KEY'); // grace is over
  assert.equal((await mesh.verifier.verify(bearer(await c.signToken({ nowSec: nowSec() })))).ok, true);
});

test('revokeKey kills a key immediately with no grace period', async () => {
  const { mesh, clients, nowSec } = await setup();
  const c = clients.get('orders-service')!;
  const compromisedKid = c.kid;
  const token = await c.signToken({ nowSec: nowSec() });
  await c.rotate((jwk, kid) => mesh.registry.rotateKey('orders-service', jwk, kid, 3_600_000));
  assert.equal(mesh.registry.revokeKey('orders-service', compromisedKid), true);
  const r = await mesh.verifier.verify(bearer(token));
  assert.equal(!r.ok && r.code, 'UNKNOWN_KEY');
  assert.equal(mesh.registry.revokeKey('orders-service', 'no-such-kid'), false);
});

test('JWKS lists only valid PUBLIC keys: no private members, expired keys and disabled services excluded', async () => {
  const { mesh, clients, clock } = await setup();
  const c = clients.get('orders-service')!;
  await c.rotate((jwk, kid) => mesh.registry.rotateKey('orders-service', jwk, kid, 10_000));

  let jwks = mesh.registry.publicJwks();
  assert.equal(jwks.keys.filter((k) => k.service === 'orders-service').length, 2); // old (grace) + new
  for (const k of jwks.keys) {
    assert.equal(k.kty, 'OKP');
    assert.equal(k.crv, 'Ed25519');
    assert.equal(k.alg, 'EdDSA');
    assert.ok(k.kid);
    assert.equal('d' in k, false, 'a private component must never be published');
    assert.deepEqual(Object.keys(k).sort(), ['alg', 'crv', 'kid', 'kty', 'service', 'use', 'x']);
  }

  clock.advance(11_000);
  jwks = mesh.registry.publicJwks();
  assert.equal(jwks.keys.filter((k) => k.service === 'orders-service').length, 1);

  mesh.registry.setStatus('orders-service', 'DISABLED');
  assert.equal(mesh.registry.publicJwks().keys.some((k) => k.service === 'orders-service'), false);
});

test('registry only publishes the public members even if the registrant sent extras', async () => {
  const { mesh } = await setup();
  const svc = await ServiceClient.create('extra-service');
  await mesh.registry.register({ serviceId: 'extra-service', displayName: 'x', kid: svc.kid, publicJwk: { ...svc.publicJwk, secretNote: 'leak?' } as never });
  const k = mesh.registry.publicJwks().keys.find((x) => x.service === 'extra-service')!;
  assert.equal('secretNote' in k, false);
});

test('startAutoRotation rotates on every tick, survives errors, never overlaps, and can be stopped', async () => {
  const c = await ServiceClient.create('svc-auto');
  let tick: (() => void) | undefined;
  let cleared = false;
  const timers: Timers = { setInterval: (fn) => { tick = fn; return 1; }, clearInterval: () => void (cleared = true) };

  // Key generation is real async work, so wait for CONDITIONS instead of guessing a delay.
  const until = async (cond: () => boolean, label: string) => {
    const end = Date.now() + 3000;
    while (!cond()) {
      if (Date.now() > end) assert.fail(`timed out waiting for: ${label}`);
      await new Promise((r) => setTimeout(r, 5));
    }
  };

  const rotated: string[] = [];
  const errors: unknown[] = [];
  let fail = false;
  let slow = false;
  let release: (() => void) | undefined;
  const stop = startAutoRotation(c, {
    intervalMs: 1000,
    timers,
    register: async () => {
      if (fail) throw new Error('boom');
      if (slow) await new Promise<void>((r) => (release = r));
    },
    onRotated: (kid) => rotated.push(kid),
    onError: (e) => errors.push(e),
  });

  tick!();
  await until(() => rotated.length === 1, 'first rotation');
  const kidAfterFirst = c.kid;

  fail = true;
  tick!();
  await until(() => errors.length === 1, 'error to be reported');
  assert.equal(c.kid, kidAfterFirst); // failed rotation kept the key

  fail = false;
  slow = true;
  tick!(); // starts a slow rotation...
  await until(() => release !== undefined, 'slow rotation to reach register()');
  tick!(); // ...a second tick while one is in flight must be ignored
  await new Promise((r) => setTimeout(r, 30));
  assert.equal(rotated.length, 1, 'no second rotation may start while one is in flight');
  release!();
  await until(() => rotated.length === 2, 'slow rotation to finish');
  assert.equal(rotated.length, 2);
  assert.notEqual(c.kid, kidAfterFirst);

  stop();
  assert.equal(cleared, true);
});

test('live server with KEY_ROTATION_MS: traffic keeps flowing across many rotations and JWKS reflects the keys', async () => {
  const app = await createApp(loadConfig({ ADMIN_API_KEY: 'k', PORT: '0', KEY_ROTATION_MS: '60' }));
  const base = `http://127.0.0.1:${await app.listen(0)}`;
  try {
    const frontend = app.clients.get('frontend-service')!;
    const firstKid = frontend.kid;
    let ok = 0;
    for (let i = 0; i < 40; i++) {
      const res = await fetch(`${base}/api/proxy/orders/list`, { headers: { authorization: bearer(await frontend.signToken()), 'x-destination-service': 'orders-service' } });
      if (res.status === 200) ok++;
      await new Promise((r) => setTimeout(r, 15));
    }
    assert.equal(ok, 40, 'a rotation must never cause a failed request');
    assert.notEqual(frontend.kid, firstKid, 'rotation did not happen');

    // Rotation keeps running in the background, so snapshot the kid BEFORE fetching: a client only
    // switches to a key after it was registered (and old keys stay for the grace period), so this
    // kid must be listed. Reading frontend.kid AFTER the fetch would race with the next rotation.
    const kidBeforeFetch = frontend.kid;
    const jwks = (await (await fetch(`${base}/.well-known/jwks.json`)).json()) as { keys: Array<{ kid: string; service: string }> };
    assert.ok(jwks.keys.some((k) => k.kid === kidBeforeFetch && k.service === 'frontend-service'));
    assert.ok(jwks.keys.every((k) => !('d' in k)));
  } finally {
    await app.close();
  }
});

test('admin can revoke a key over HTTP; JWKS needs the admin key in private mode', async () => {
  const app = await createApp(loadConfig({ ADMIN_API_KEY: 'k', PORT: '0', PUBLIC_DASHBOARD: 'false' }));
  const base = `http://127.0.0.1:${await app.listen(0)}`;
  try {
    assert.equal((await fetch(`${base}/.well-known/jwks.json`)).status, 401);
    assert.equal((await fetch(`${base}/.well-known/jwks.json`, { headers: { 'x-admin-key': 'k' } })).status, 200);

    const c = app.clients.get('frontend-service')!;
    const token = await c.signToken();
    assert.equal((await fetch(`${base}/admin/services/frontend-service/keys/${c.kid}/revoke`, { method: 'POST' })).status, 401);
    const rev = await fetch(`${base}/admin/services/frontend-service/keys/${c.kid}/revoke`, { method: 'POST', headers: { 'x-admin-key': 'k' } });
    assert.equal(rev.status, 200);
    const res = await fetch(`${base}/api/proxy/orders/list`, { headers: { authorization: bearer(token), 'x-destination-service': 'orders-service' } });
    assert.equal(res.headers.get('x-zt-reason'), 'UNKNOWN_KEY');
    assert.equal((await fetch(`${base}/admin/services/frontend-service/keys/nope/revoke`, { method: 'POST', headers: { 'x-admin-key': 'k' } })).status, 404);
  } finally {
    await app.close();
  }
});
