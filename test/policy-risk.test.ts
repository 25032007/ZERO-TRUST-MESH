import assert from 'node:assert/strict';
import { test } from 'node:test';
import { jsonDepth } from '../src/risk/anomaly.js';
import { SlidingCounter } from '../src/util/slidingCounter.js';
import { AuditLog } from '../src/audit/auditLog.js';
import { LateralMovementDetector } from '../src/detection/lateralMovement.js';
import { PolicyEngine, DEFAULT_POLICIES } from '../src/policy/policyEngine.js';
import { loadConfig } from '../src/config.js';
import { fakeClock } from './helpers.js';

test('policy: default deny, method, path allow-list and deny-list', () => {
  const p = new PolicyEngine(DEFAULT_POLICIES);
  assert.equal(p.evaluate('frontend-service', 'orders-service', 'GET', '/orders/list').allowed, true);
  assert.equal(p.evaluate('frontend-service', 'database-service', 'GET', '/database/x').reason, 'NO_POLICY');
  assert.equal(p.evaluate('frontend-service', 'orders-service', 'DELETE', '/orders/1').reason, 'METHOD_NOT_ALLOWED');
  assert.equal(p.evaluate('frontend-service', 'orders-service', 'GET', '/secrets').reason, 'PATH_NOT_ALLOWED');
  assert.equal(p.evaluate('payments-service', 'database-service', 'GET', '/database/admin/x').reason, 'PATH_DENIED');
  assert.equal(p.evaluate('payments-service', 'database-service', 'GET', '/database/rows').allowed, true);
});

test('policy: time windows use the injected clock', () => {
  const clock = fakeClock(Date.UTC(2026, 0, 1, 3, 0, 0)); // 03:00 UTC
  const p = new PolicyEngine([{ id: 'x', source: 'a', destination: 'b', methods: ['GET'], hoursUtc: { start: 9, end: 17 }, description: '' }], clock);
  assert.equal(p.evaluate('a', 'b', 'GET', '/').reason, 'OUTSIDE_TIME_WINDOW');
  clock.set(Date.UTC(2026, 0, 1, 10, 0, 0));
  assert.equal(p.evaluate('a', 'b', 'GET', '/').allowed, true);
});

test('jsonDepth is iterative and handles very deep input without a stack overflow', () => {
  let deep: unknown = 1;
  for (let i = 0; i < 50_000; i++) deep = { n: deep };
  assert.equal(jsonDepth(deep), 50_000);
  assert.equal(jsonDepth('x'), 0);
  assert.equal(jsonDepth({ a: [1, { b: 2 }] }), 3);
});

test('SlidingCounter expires old events', () => {
  const c = new SlidingCounter();
  c.hit(0, 1000);
  c.hit(500, 1000);
  assert.equal(c.count(900, 1000), 2);
  assert.equal(c.count(1200, 1000), 1);
  assert.equal(c.count(5000, 1000), 0);
});

test('lateral movement: needs distinct hops inside the window, within ONE trace', () => {
  const d = new LateralMovementDetector({ windowMs: 1000, minHops: 3 });
  assert.equal(d.observe('t1', 'a', 'b', 0).detected, false);
  assert.equal(d.observe('t1', 'b', 'c', 100).detected, false);
  const hit = d.observe('t1', 'c', 'd', 200);
  assert.equal(hit.detected, true);
  assert.deepEqual(hit.path, ['a', 'b', 'c', 'd']);

  // Hammering the same edge is not traversal; a different trace is unrelated; a slow chain expires.
  for (let i = 0; i < 20; i++) assert.equal(d.observe('t2', 'a', 'b', i).detected, false);
  assert.equal(d.observe('t3', 'a', 'b', 0).detected, false);
  assert.equal(d.observe('t3', 'b', 'c', 2000).detected, false);
  assert.equal(d.observe('t3', 'c', 'd', 4000).detected, false);
});

test('audit log: chain verifies, and editing or deleting history is detected', () => {
  const log = new AuditLog(100);
  const add = (n: number) => log.append({ requestId: `r${n}`, traceId: 't', decision: 'ALLOW', reason: 'OK', riskScore: n, method: 'GET', path: '/', factors: [] });
  for (let i = 0; i < 10; i++) add(i);
  assert.equal(log.verify().valid, true);

  const records = log._unsafeRecordsForTest();
  records[4].riskScore = 0; // attacker rewrites an entry
  const edited = log.verify();
  assert.equal(edited.valid, false);
  assert.equal(edited.brokenAtSeq, records[4].seq);

  const log2 = new AuditLog(100);
  for (let i = 0; i < 10; i++) log2.append({ requestId: `r${i}`, traceId: 't', decision: 'ALLOW', reason: 'OK', riskScore: i, method: 'GET', path: '/', factors: [] });
  log2._unsafeRecordsForTest().splice(3, 1); // attacker deletes an entry
  assert.equal(log2.verify().valid, false);
});

test('audit log ring buffer keeps verifying after old entries are evicted', () => {
  const log = new AuditLog(5);
  for (let i = 0; i < 20; i++) log.append({ requestId: `r${i}`, traceId: 't', decision: 'ALLOW', reason: 'OK', riskScore: 0, method: 'GET', path: '/', factors: [] });
  assert.equal(log.recent(100).length, 5);
  assert.equal(log.verify().valid, true);
});

test('config: environment overrides and sane defaults', () => {
  const cfg = loadConfig({ RISK_BLOCK_AT: '90', ADMIN_API_KEY: 'k' });
  assert.equal(cfg.thresholds.block, 90);
  assert.equal(cfg.adminKeyGenerated, false);
  assert.equal(loadConfig({}).adminKeyGenerated, true);
  assert.equal(loadConfig({ PUBLIC_DASHBOARD: 'false' }).publicDashboard, false);
});

test('lateral movement: a declared workflow is not flagged, but a different chain still is', () => {
  const known = (p: string[]) => ['a', 'b', 'c', 'd'].slice(0, p.length).join() === p.join();
  const d = new LateralMovementDetector({ windowMs: 1000, minHops: 3 }, known);

  d.observe('legit', 'a', 'b', 0);
  d.observe('legit', 'b', 'c', 100);
  const legit = d.observe('legit', 'c', 'd', 200);
  assert.equal(legit.detected, false);
  assert.equal(legit.knownWorkflow, true);

  d.observe('evil', 'a', 'x', 0);
  d.observe('evil', 'a', 'y', 100);
  const evil = d.observe('evil', 'x', 'z', 200);
  assert.equal(evil.detected, true);
  assert.equal(evil.knownWorkflow, false);
});
