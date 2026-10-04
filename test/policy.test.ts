import assert from 'node:assert/strict';
import { test } from 'node:test';
import { PolicyEngine, type Policy } from '../src/policy/policyEngine.js';

const allow = (over: Partial<Policy> = {}): Policy => ({ id: 'a1', source: 'a', destination: 'b', methods: ['GET'], description: '', ...over });

test('explicit deny at higher priority beats an allow', () => {
  const p = new PolicyEngine([allow({ id: 'allow-all' }), allow({ id: 'block-it', effect: 'deny', priority: 10 })]);
  const d = p.evaluate('a', 'b', 'GET', '/x');
  assert.equal(d.allowed, false);
  assert.equal(d.reason, 'EXPLICIT_DENY');
  assert.equal(d.policyId, 'block-it');
});

test('a higher-priority allow beats a lower-priority deny', () => {
  const p = new PolicyEngine([allow({ id: 'exception', priority: 10 }), allow({ id: 'block-it', effect: 'deny', priority: 1 })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/x').allowed, true);
});

test('at equal priority deny is evaluated before allow (ties fail safe)', () => {
  const p = new PolicyEngine([allow({ id: 'a-allow' }), allow({ id: 'z-deny', effect: 'deny' })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/x').reason, 'EXPLICIT_DENY');
});

test('explicit deny only applies to the methods, paths and hours it describes', () => {
  const p = new PolicyEngine([allow({ id: 'ok' }), allow({ id: 'no-admin', effect: 'deny', priority: 5, methods: ['GET'], allowPaths: ['/admin'] })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/orders').allowed, true);
  assert.equal(p.evaluate('a', 'b', 'GET', '/admin/x').reason, 'EXPLICIT_DENY');
});

test('per-policy dry-run flags the denial but does not change the verdict reason', () => {
  const p = new PolicyEngine([allow({ id: 'strict', allowPaths: ['/orders'], mode: 'dry-run' })]);
  const d = p.evaluate('a', 'b', 'GET', '/other');
  assert.equal(d.allowed, false);
  assert.equal(d.reason, 'PATH_NOT_ALLOWED');
  assert.equal(d.dryRun, true);
});

test('enforce mode (default) never sets the dry-run flag', () => {
  const p = new PolicyEngine([allow({ allowPaths: ['/orders'] })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/other').dryRun, false);
});

test('global dry-run covers NO_POLICY too, and can be switched off again', () => {
  const p = new PolicyEngine([]);
  p.setDryRun(true);
  assert.equal(p.evaluate('x', 'y', 'GET', '/').dryRun, true);
  p.setDryRun(false);
  assert.equal(p.evaluate('x', 'y', 'GET', '/').dryRun, false);
});

test('replaceAll swaps the whole set atomically and drops removed policies', () => {
  const p = new PolicyEngine([allow({ id: 'old' })]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/').allowed, true);
  p.replaceAll([{ id: 'new', source: 'c', destination: 'd', methods: ['GET'], description: '' }]);
  assert.equal(p.evaluate('a', 'b', 'GET', '/').reason, 'NO_POLICY');
  assert.equal(p.evaluate('c', 'd', 'GET', '/').allowed, true);
  assert.deepEqual(p.list().map((x) => x.id), ['new']);
});
