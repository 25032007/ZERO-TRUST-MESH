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
import { isSafePath, pathMatchesPrefix } from '../src/policy/paths.js';
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
