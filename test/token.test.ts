import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ServiceClient } from '../src/identity/serviceClient.js';
import { setup } from './helpers.js';

const bearer = (t: string) => `Bearer ${t}`;

test('a valid token authenticates as the right service', async () => {
  const { mesh, clients, nowSec } = await setup();
  const token = await clients.get('frontend-service')!.signToken({ nowSec: nowSec() });
  const r = await mesh.verifier.verify(bearer(token));
  assert.equal(r.ok, true);
  if (r.ok) assert.equal(r.serviceId, 'frontend-service');
});

test('missing / malformed Authorization headers are rejected', async () => {
  const { mesh } = await setup();
  assert.deepEqual((await mesh.verifier.verify(undefined)).ok, false);
  const bad = await mesh.verifier.verify('Basic abc');
  assert.equal(!bad.ok && bad.code, 'MALFORMED_TOKEN');
  const junk = await mesh.verifier.verify('Bearer not.a.jwt');
  assert.equal(!junk.ok && junk.code, 'MALFORMED_TOKEN');
});

test('replaying a token is detected', async () => {
  const { mesh, clients, nowSec } = await setup();
  const token = await clients.get('orders-service')!.signToken({ nowSec: nowSec() });
  assert.equal((await mesh.verifier.verify(bearer(token))).ok, true);
  const second = await mesh.verifier.verify(bearer(token));
  assert.equal(!second.ok && second.code, 'TOKEN_REPLAY');
});

test('expired tokens are rejected, and clock tolerance is honoured', async () => {
  const { mesh, clients, nowSec } = await setup();
  const c = clients.get('frontend-service')!;
  const expired = await c.signToken({ nowSec: nowSec(), lifetimeSec: 60, issuedAtOffsetSec: -3600 });
  const r = await mesh.verifier.verify(bearer(expired));
  assert.equal(!r.ok && r.code, 'TOKEN_EXPIRED');

  // Expired 2 seconds ago is still inside the 5 s tolerance.
  const barely = await c.signToken({ nowSec: nowSec(), lifetimeSec: 60, issuedAtOffsetSec: -62 });
  assert.equal((await mesh.verifier.verify(bearer(barely))).ok, true);
});

test('time moving forward expires a previously valid token', async () => {
  const { mesh, clients, clock, nowSec } = await setup();
  const token = await clients.get('frontend-service')!.signToken({ nowSec: nowSec(), lifetimeSec: 30 });
  clock.advance(60_000);
  const r = await mesh.verifier.verify(bearer(token));
  assert.equal(!r.ok && r.code, 'TOKEN_EXPIRED');
});

test('editing the payload breaks the signature', async () => {
  const { mesh, clients, nowSec } = await setup();
  const [h, p, s] = (await clients.get('frontend-service')!.signToken({ nowSec: nowSec() })).split('.');
  const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
  payload.exp += 86_400;
  const forged = `${h}.${Buffer.from(JSON.stringify(payload)).toString('base64url')}.${s}`;
  const r = await mesh.verifier.verify(bearer(forged));
  assert.equal(!r.ok && r.code, 'INVALID_SIGNATURE');
});

test('alg=none and HS256 tokens are refused before any key is used', async () => {
  const { mesh } = await setup();
  const enc = (o: unknown) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const claims = { sub: 'frontend-service', iss: 'frontend-service', aud: 'zero-trust-mesh' };
  const none = `${enc({ alg: 'none', kid: 'x' })}.${enc(claims)}.`;
  const hs = `${enc({ alg: 'HS256', kid: 'x' })}.${enc(claims)}.c2ln`;
  for (const t of [none, hs]) {
    const r = await mesh.verifier.verify(bearer(t));
    assert.equal(!r.ok && r.code, 'ALG_NOT_ALLOWED');
  }
});

test('a token signed by a different key but claiming to be the service is rejected', async () => {
  const { mesh, clients, nowSec } = await setup();
  const real = clients.get('frontend-service')!;
  const impostor = await ServiceClient.create('frontend-service', { kid: real.kid }); // same kid, different key
  const token = await impostor.signToken({ nowSec: nowSec() });
  const r = await mesh.verifier.verify(bearer(token));
  assert.equal(!r.ok && r.code, 'INVALID_SIGNATURE');
});

test('wrong audience, unknown service, unknown kid, disabled service', async () => {
  const { mesh, clients, nowSec } = await setup();
  const c = clients.get('frontend-service')!;

  const aud = await mesh.verifier.verify(bearer(await c.signToken({ nowSec: nowSec(), audience: 'other' })));
  assert.equal(!aud.ok && aud.code, 'INVALID_CLAIMS');

  const stranger = await ServiceClient.create('ghost-service');
  const unknown = await mesh.verifier.verify(bearer(await stranger.signToken({ nowSec: nowSec() })));
  assert.equal(!unknown.ok && unknown.code, 'UNKNOWN_SERVICE');

  const wrongKid = await ServiceClient.create('frontend-service', { kid: 'not-registered' });
  const k = await mesh.verifier.verify(bearer(await wrongKid.signToken({ nowSec: nowSec() })));
  assert.equal(!k.ok && k.code, 'UNKNOWN_KEY');

  mesh.registry.setStatus('frontend-service', 'DISABLED');
  const d = await mesh.verifier.verify(bearer(await c.signToken({ nowSec: nowSec() })));
  assert.equal(!d.ok && d.code, 'SERVICE_NOT_ACTIVE');
});

test('tokens with an over-long lifetime are refused', async () => {
  const { mesh, clients, nowSec } = await setup();
  const token = await clients.get('frontend-service')!.signToken({ nowSec: nowSec(), lifetimeSec: 3600 });
  const r = await mesh.verifier.verify(bearer(token));
  assert.equal(!r.ok && r.code, 'LIFETIME_TOO_LONG');
});

test('revoked tokens are refused', async () => {
  const { mesh, clients, nowSec } = await setup();
  const token = await clients.get('frontend-service')!.signToken({ nowSec: nowSec(), jti: 'leaked-1' });
  await mesh.jtiStore.revoke('leaked-1', nowSec() + 600);
  const r = await mesh.verifier.verify(bearer(token));
  assert.equal(!r.ok && r.code, 'TOKEN_REVOKED');
});

test('an attacker cannot burn a victim jti with a forged token (replay check runs after the signature)', async () => {
  const { mesh, clients, nowSec } = await setup();
  const impostor = await ServiceClient.create('frontend-service', { kid: clients.get('frontend-service')!.kid });
  await mesh.verifier.verify(bearer(await impostor.signToken({ nowSec: nowSec(), jti: 'victim-jti' })));
  const genuine = await clients.get('frontend-service')!.signToken({ nowSec: nowSec(), jti: 'victim-jti' });
  assert.equal((await mesh.verifier.verify(bearer(genuine))).ok, true);
});

test('key rotation: old key works during the grace period, then stops', async () => {
  const { mesh, clients, clock, nowSec } = await setup();
  const oldClient = clients.get('orders-service')!;
  const newClient = await ServiceClient.create('orders-service');
  await mesh.registry.rotateKey('orders-service', newClient.publicJwk, newClient.kid, 5 * 60_000);

  assert.equal((await mesh.verifier.verify(bearer(await oldClient.signToken({ nowSec: nowSec() })))).ok, true);
  assert.equal((await mesh.verifier.verify(bearer(await newClient.signToken({ nowSec: nowSec() })))).ok, true);

  clock.advance(6 * 60_000);
  const late = await mesh.verifier.verify(bearer(await oldClient.signToken({ nowSec: nowSec() })));
  assert.equal(!late.ok && late.code, 'UNKNOWN_KEY');
  assert.equal((await mesh.verifier.verify(bearer(await newClient.signToken({ nowSec: nowSec() })))).ok, true);
});

test('registry refuses private JWKs and non-Ed25519 keys', async () => {
  const { mesh } = await setup();
  await assert.rejects(mesh.registry.register({ serviceId: 'bad-one', displayName: 'x', kid: 'k', publicJwk: { kty: 'OKP', crv: 'Ed25519', x: 'AAAA', d: 'BBBB' } }), /private/i);
  await assert.rejects(mesh.registry.register({ serviceId: 'bad-two', displayName: 'x', kid: 'k', publicJwk: { kty: 'RSA', n: 'a', e: 'AQAB' } }), /Ed25519/);
});
