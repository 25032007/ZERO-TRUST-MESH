import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Policy } from '../src/policy/policyEngine.js';
import { recommend, type RecommendOptions } from '../src/policy/recommend.js';
import { UsageTracker } from '../src/policy/usage.js';

const MIN = 60_000;
const opts: RecommendOptions = { minObservationMs: 10 * MIN, minHits: 20, minDenied: 5 };

const policies: Policy[] = [
  { id: 'fe-orders', source: 'fe', destination: 'orders', methods: ['GET', 'POST'], allowPaths: ['/orders', '/reports'], description: '' },
  { id: 'orders-pay', source: 'orders', destination: 'pay', methods: ['POST'], allowPaths: ['/pay'], description: '' },
  { id: 'dead', source: 'fe', destination: 'legacy', methods: ['GET'], description: '' },
  { id: 'ban', source: 'fe', destination: 'secrets', methods: ['GET'], effect: 'deny', description: '' },
];

function traffic(t: UsageTracker, id: string, method: string, path: string, allowPaths: string[] | undefined, n: number, now = 5 * MIN) {
  for (let i = 0; i < n; i++) t.recordAllowed(id, method, path, allowPaths, now);
}

test('too little observation time: withhold advice and propose NO change', () => {
  const t = new UsageTracker(() => 0);
  traffic(t, 'fe-orders', 'GET', '/orders/list', ['/orders', '/reports'], 500);
  const r = recommend(policies, t.snapshot(), 3 * MIN, opts);
  assert.equal(r.confident, false);
  assert.deepEqual(r.recommendations.map((x) => x.type), ['INSUFFICIENT_DATA']);
  assert.equal(r.proposedPolicies.length, policies.length); // nothing dropped
  assert.deepEqual(r.proposedPolicies.find((p) => p.id === 'fe-orders')!.methods, ['GET', 'POST']);
});

test('after enough time: narrows methods and paths, drops unused policies, never touches explicit denies', () => {
  const t = new UsageTracker(() => 0);
  traffic(t, 'fe-orders', 'GET', '/orders/list', ['/orders', '/reports'], 300); // POST and /reports never used
  traffic(t, 'orders-pay', 'POST', '/pay/charge', ['/pay'], 100);
  const r = recommend(policies, t.snapshot(), 30 * MIN, opts);
  assert.equal(r.confident, true);

  const types = r.recommendations.map((x) => `${x.type}:${x.policyId}`);
  assert.ok(types.includes('NARROW_METHODS:fe-orders'));
  assert.ok(types.includes('NARROW_PATHS:fe-orders'));
  assert.ok(types.includes('REMOVE_UNUSED_POLICY:dead'));
  assert.ok(!types.some((x) => x.endsWith(':orders-pay')), 'a fully used policy needs no change');
  assert.ok(!types.some((x) => x.endsWith(':ban')));

  const proposed = Object.fromEntries(r.proposedPolicies.map((p) => [p.id, p]));
  assert.deepEqual(proposed['fe-orders'].methods, ['GET']);
  assert.deepEqual(proposed['fe-orders'].allowPaths, ['/orders']);
  assert.deepEqual(proposed['orders-pay'].methods, ['POST']);
  assert.equal(proposed['dead'], undefined);
  assert.equal(proposed['ban'].effect, 'deny');
});

test('summary counts granted vs used permissions (the least-privilege reduction)', () => {
  const t = new UsageTracker(() => 0);
  traffic(t, 'fe-orders', 'GET', '/orders/list', ['/orders', '/reports'], 300);
  traffic(t, 'orders-pay', 'POST', '/pay/x', ['/pay'], 100);
  const r = recommend(policies, t.snapshot(), 30 * MIN, opts);
  // fe-orders: 2 methods x 2 prefixes = 4 grants, 1 used. orders-pay: 1 grant, 1 used. dead: 1 grant, 0 used.
  assert.equal(r.summary.permissionsGranted, 6);
  assert.equal(r.summary.permissionsUsed, 2);
  assert.equal(r.summary.permissionsUnused, 4);
  assert.equal(r.summary.unusedPercent, 67);
});

test('a lightly-used policy is NOT narrowed (a rare monthly job must not be cut on thin evidence)', () => {
  const t = new UsageTracker(() => 0);
  traffic(t, 'fe-orders', 'GET', '/orders/list', ['/orders', '/reports'], 5); // only 5 hits < minHits
  const r = recommend(policies, t.snapshot(), 30 * MIN, opts);
  assert.ok(!r.recommendations.some((x) => x.policyId === 'fe-orders'));
  assert.deepEqual(r.proposedPolicies.find((p) => p.id === 'fe-orders')!.methods, ['GET', 'POST']);
});

test('usage is attributed to the most specific matching prefix', () => {
  const t = new UsageTracker(() => 0);
  t.recordAllowed('p', 'GET', '/api/v2/users', ['/api', '/api/v2'], 1);
  assert.deepEqual(Object.keys(t.snapshot().perPolicy.p.combos), ['GET /api/v2']);
});

test('policies without allowPaths use the "*" prefix', () => {
  const t = new UsageTracker(() => 0);
  t.recordAllowed('dead', 'GET', '/anything', undefined, 1);
  assert.deepEqual(Object.keys(t.snapshot().perPolicy.dead.combos), ['GET *']);
});

test('denied edges are surfaced for HUMAN REVIEW only and never become allow policies', () => {
  const t = new UsageTracker(() => 0);
  for (let i = 0; i < 12; i++) t.recordDenied('frontend', 'database', 'NO_POLICY', i);
  t.recordDenied('frontend', 'auth', 'NO_POLICY', 1);
  const r = recommend(policies, t.snapshot(), 30 * MIN, opts);
  const review = r.recommendations.filter((x) => x.type === 'REVIEW_DENIED_EDGE');
  assert.equal(review.length, 1); // the edge with 1 denial is below the threshold
  assert.equal(review[0].edge, 'frontend->database');
  assert.match(review[0].message, /attack/i);
  assert.ok(!r.proposedPolicies.some((p) => p.destination === 'database'));
});

test('the proposed document is a valid, loadable policy document', async () => {
  const { validatePolicyDocument } = await import('../src/policy/policyFile.js');
  const t = new UsageTracker(() => 0);
  traffic(t, 'fe-orders', 'GET', '/orders/list', ['/orders', '/reports'], 300);
  const r = recommend(
    [
      { id: 'fe-orders', source: 'fe-service', destination: 'orders-service', methods: ['GET', 'POST'], allowPaths: ['/orders', '/reports'], description: '' },
    ],
    t.snapshot(),
    30 * MIN,
    opts,
  );
  const v = validatePolicyDocument(JSON.parse(JSON.stringify(r.proposedDocument)));
  assert.equal(v.ok, true, v.ok ? '' : v.errors.join('; '));
});
