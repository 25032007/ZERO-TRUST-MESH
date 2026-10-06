/**
 * Path-safety regression tests (P0 traversal/prefix-confusion fix).
 *
 * The policy engine authorizes a path string while the HTTP client normalizes
 * dot-segments and encoding on forward. These tests prove: (1) ambiguous
 * paths are rejected before authorization, (2) prefix matching is
 * segment-aware, and (3) the pipeline fails closed with INVALID_PATH.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { canonicalizePath, isSafePath, pathMatchesPrefix } from '../src/policy/paths.js';
import { PolicyEngine, type Policy } from '../src/policy/policyEngine.js';
import { input, setup } from './helpers.js';

test('isSafePath accepts normal paths', () => {
  for (const p of ['/', '/orders', '/orders/list', '/orders/123', '/database', '/database/rows', '/database/admin', '/orders/', '/a-b_c~d']) {
    assert.equal(isSafePath(p), true, p);
  }
});

test('isSafePath rejects dot-segment traversal', () => {
  for (const p of ['/../secret', '/../../secret', '/orders/../database', '/orders/../../database', '/database/./admin', '/./database', '/database/../admin', '/a/b/../../c', '/.']) {
    assert.equal(isSafePath(p), false, p);
  }
});

test('isSafePath rejects encoded dot segments', () => {
  for (const p of ['/%2e%2e/secret', '/%2E%2E/secret', '/%2e/admin', '/database/%2e%2e/admin', '/database/%2E/admin', '/.%2e/secret', '/%2e./secret']) {
    assert.equal(isSafePath(p), false, p);
  }
});

test('isSafePath rejects encoded separators and backslashes', () => {
  for (const p of ['/orders%2flist', '/orders%2Flist', '/orders%5clist', '/orders%5Clist', '..\\secret', '/..\\secret', '/orders\\list', '/%c0%af/secret', '/orders/%', '']) {
    assert.equal(isSafePath(p), false, p);
  }
});

test('isSafePath rejects non-strings and non-absolute paths', () => {
  assert.equal(isSafePath(undefined), false);
  assert.equal(isSafePath(null), false);
  assert.equal(isSafePath(42), false);
  assert.equal(isSafePath('orders/list'), false);
});

test('pathMatchesPrefix is segment-aware', () => {
  assert.equal(pathMatchesPrefix('/orders', '/orders'), true);
  assert.equal(pathMatchesPrefix('/orders/', '/orders'), true);
  assert.equal(pathMatchesPrefix('/orders/list', '/orders'), true);
  assert.equal(pathMatchesPrefix('/orders/123', '/orders'), true);
  assert.equal(pathMatchesPrefix('/orders-admin', '/orders'), false);
  assert.equal(pathMatchesPrefix('/orders-secret', '/orders'), false);
  assert.equal(pathMatchesPrefix('/orders2', '/orders'), false);
  assert.equal(pathMatchesPrefix('/ordersomething', '/orders'), false);
  assert.equal(pathMatchesPrefix('/anything', '/'), true);
  assert.equal(pathMatchesPrefix('/database/admin/users', '/database/admin'), true);
  assert.equal(pathMatchesPrefix('/database-admin', '/database'), false);
});

test('policy allowPaths enforces segment boundaries', () => {
  const allow = (over: Partial<Policy> = {}): Policy => ({ id: 'p', source: 'a', destination: 'b', methods: ['GET'], description: '', ...over });
  const p = new PolicyEngine([allow({ allowPaths: ['/orders'] })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/orders').allowed, true);
  assert.equal(p.evaluate('a', 'b', 'GET', '/orders/list').allowed, true);
  assert.equal(p.evaluate('a', 'b', 'GET', '/orders/123').allowed, true);
  for (const bad of ['/orders-admin', '/orders-secret', '/orders2']) {
    const d = p.evaluate('a', 'b', 'GET', bad);
    assert.equal(d.allowed, false, bad);
    assert.equal(d.reason, 'PATH_NOT_ALLOWED', bad);
  }
});

test('policy denyPaths enforces segment boundaries', () => {
  const allow = (over: Partial<Policy> = {}): Policy => ({ id: 'p', source: 'a', destination: 'b', methods: ['GET'], description: '', ...over });
  const p = new PolicyEngine([allow({ allowPaths: ['/database'], denyPaths: ['/database/admin'] })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/database/rows').allowed, true);
  assert.equal(p.evaluate('a', 'b', 'GET', '/database/admin').reason, 'PATH_DENIED');
  assert.equal(p.evaluate('a', 'b', 'GET', '/database/admin/users').reason, 'PATH_DENIED');
  // A sibling segment must not be mistaken for the denied subtree.
  assert.equal(p.evaluate('a', 'b', 'GET', '/database-admin').reason, 'PATH_NOT_ALLOWED');
});

test('explicit deny policies match paths segment-wise', () => {
  const allow = (over: Partial<Policy> = {}): Policy => ({ id: 'p', source: 'a', destination: 'b', methods: ['GET'], description: '', ...over });
  const p = new PolicyEngine([allow({ id: 'open' }), allow({ id: 'no-admin', effect: 'deny', priority: 5, allowPaths: ['/admin'] })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/admin/x').reason, 'EXPLICIT_DENY');
  assert.equal(p.evaluate('a', 'b', 'GET', '/orders').allowed, true);
  assert.equal(p.evaluate('a', 'b', 'GET', '/administrator').allowed, true);
});

test('pipeline rejects traversal paths with INVALID_PATH before authentication', async () => {
  const ctx = await setup();
  // No token at all: path safety runs before auth, so the verdict names the path.
  const r = await ctx.mesh.pipeline.evaluate(input({ destination: 'orders-service', path: '/orders/../../database-service/database/rows' }));
  assert.equal(r.decision, 'BLOCK');
  assert.equal(r.reason, 'INVALID_PATH');
  assert.equal(r.httpStatus, 400);
});

test('pipeline rejects encoded traversal with INVALID_PATH even with a valid token', async () => {
  const ctx = await setup();
  for (const path of ['/database/./admin/users', '/%2e%2e/database/admin', '/database/%2e%2e/admin/x', '/orders%2flist']) {
    const token = await ctx.clients.get('payments-service')!.signToken({ nowSec: ctx.nowSec() });
    const r = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, destination: 'database-service', path }));
    assert.equal(r.decision, 'BLOCK', path);
    assert.equal(r.reason, 'INVALID_PATH', path);
    assert.equal(r.httpStatus, 400, path);
  }
});

test('pipeline still allows a normal request after the path gate', async () => {
  const ctx = await setup();
  const token = await ctx.clients.get('frontend-service')!.signToken({ nowSec: ctx.nowSec() });
  const r = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}` }));
  assert.equal(r.decision, 'ALLOW');
  assert.equal(r.reason, 'OK');
});

test('canonicalizePath leaves legitimate paths byte-identical', () => {
  for (const p of ['/', '/orders', '/orders/', '/orders/list', '/orders/123', '/database', '/database/rows', '/database/admin', '/a-b_c~d']) {
    assert.equal(canonicalizePath(p), p, p);
  }
});

test('canonicalizePath collapses duplicate slashes', () => {
  assert.equal(canonicalizePath('/foo//bar'), '/foo/bar');
  assert.equal(canonicalizePath('/foo///bar//baz'), '/foo/bar/baz');
  assert.equal(canonicalizePath('/orders//list'), '/orders/list');
  assert.equal(canonicalizePath('//orders//list//'), '/orders/list/');
});

test('canonicalizePath decodes percent-encoding exactly once', () => {
  assert.equal(canonicalizePath('/foo/%61dmin'), '/foo/admin');
  assert.equal(canonicalizePath('/orders/%6cist'), '/orders/list');
  // Re-encoded on the wire form: decode then re-serialize, byte-stable.
  assert.equal(canonicalizePath('/files/my%20file'), '/files/my%20file');
  // Encoded + duplicate slash combined.
  assert.equal(canonicalizePath('/foo//%61dmin/'), '/foo/admin/');
});

test('canonicalizePath preserves case (no case folding anywhere)', () => {
  assert.equal(canonicalizePath('/Admin'), '/Admin');
  assert.equal(canonicalizePath('/ADMIN/x'), '/ADMIN/x');
  assert.equal(canonicalizePath('/orders/%41dmin'), '/orders/Admin');
});

test('canonicalizePath rejects double-encoding (decode-order guard)', () => {
  // Each would decode to something the forwarder interprets differently
  // than a single decode: fail closed instead of decoding twice.
  for (const p of ['/foo/%2561dmin', '/foo/%252e%252e/bar', '/foo/%252fbar', '/files/100%25off']) {
    assert.equal(canonicalizePath(p), null, p);
  }
});

test('canonicalizePath rejects URL-restructuring characters', () => {
  for (const p of ['/orders%3flist', '/foo/%23bar', '/orders/%', '/%c0%af/secret', '']) {
    assert.equal(canonicalizePath(p), null, p);
  }
});

test('canonicalizePath still rejects every previously-blocked traversal shape', () => {
  for (const p of ['/../secret', '/orders/../database', '/database/./admin', '/%2e%2e/database/admin', '/orders%2flist', '/..\\secret', '/orders\\list']) {
    assert.equal(canonicalizePath(p), null, p);
  }
});

test('duplicate slash cannot escape the authorized prefix (authorization path)', async () => {
  const ctx = await setup();
  const token = await ctx.clients.get('frontend-service')!.signToken({ nowSec: ctx.nowSec() });
  // Legitimate unusual form: same decision as canonical, forwarded form canonical.
  const r = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, path: '/orders//list' }));
  assert.equal(r.decision, 'ALLOW');
  assert.equal(r.reason, 'OK');
  assert.equal(r.path, '/orders/list');
});

test('duplicate slash cannot dodge a deny prefix (authorization path)', async () => {
  const ctx = await setup();
  const freshToken = () => ctx.clients.get('payments-service')!.signToken({ nowSec: ctx.nowSec() });
  const sneaky = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${await freshToken()}`, destination: 'database-service', path: '/database//admin/users' }));
  const canonical = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${await freshToken()}`, destination: 'database-service', path: '/database/admin/users' }));
  // Both representations resolve to the identical denial.
  assert.equal(sneaky.decision, 'BLOCK');
  assert.equal(sneaky.reason, 'PATH_DENIED');
  assert.equal(sneaky.decision, canonical.decision);
  assert.equal(sneaky.reason, canonical.reason);
});

test('percent-encoded path cannot dodge a deny prefix (authorization path)', async () => {
  const ctx = await setup();
  const token = await ctx.clients.get('payments-service')!.signToken({ nowSec: ctx.nowSec() });
  const sneaky = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, destination: 'database-service', path: '/database/%61dmin/users' }));
  assert.equal(sneaky.decision, 'BLOCK', 'encoded deny-path bypass must fail closed');
  assert.equal(sneaky.reason, 'PATH_DENIED');
});

test('encoded legitimate path authorizes identically to its canonical form', async () => {
  const ctx = await setup();
  const token = await ctx.clients.get('frontend-service')!.signToken({ nowSec: ctx.nowSec() });
  const r = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, path: '/orders/%6cist' }));
  assert.equal(r.decision, 'ALLOW');
  assert.equal(r.reason, 'OK');
  assert.equal(r.path, '/orders/list');
});

test('path case is preserved and fails closed against lowercase policies', async () => {
  const ctx = await setup();
  const freshToken = () => ctx.clients.get('frontend-service')!.signToken({ nowSec: ctx.nowSec() });
  // Control first: the canonical lowercase path is allowed.
  const ok = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${await freshToken()}`, path: '/orders/list' }));
  assert.equal(ok.decision, 'ALLOW');
  // Case variant must NOT become equivalent: no case folding anywhere.
  const r = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${await freshToken()}`, path: '/ORDERS/list' }));
  assert.equal(r.decision, 'BLOCK');
  assert.equal(r.reason, 'PATH_NOT_ALLOWED');
});

test('double-encoded and URL-restructuring paths fail closed in the pipeline', async () => {
  const ctx = await setup();
  for (const path of ['/database/%2561dmin', '/orders%3flist', '/foo/%252e%252e/bar']) {
    const token = await ctx.clients.get('payments-service')!.signToken({ nowSec: ctx.nowSec() });
    const r = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, destination: 'database-service', path }));
    assert.equal(r.decision, 'BLOCK', path);
    assert.equal(r.reason, 'INVALID_PATH', path);
    assert.equal(r.httpStatus, 400, path);
  }
});
