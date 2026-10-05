import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { PipelineResult } from '../src/types.js';
import { ThreatCorrelator, type ThreatCorrelationConfig } from '../src/threat/correlator.js';
import { normalizePipelineResult } from '../src/threat/normalizer.js';

const cfg = (over: Partial<ThreatCorrelationConfig> = {}): ThreatCorrelationConfig => ({
  windowMs: 60_000,
  traceWindowMs: 1_000,
  maxActiveFindings: 10,
  maxEvidencePerFinding: 3,
  ...over,
});

const verdict = (over: Partial<PipelineResult> = {}): PipelineResult => ({
  requestId: 'request-1', traceId: 'trace-1', decision: 'MONITOR', httpStatus: 200, reason: 'ELEVATED_RISK', riskScore: 30, riskLevel: 'MEDIUM',
  source: 'frontend-service', destination: 'orders-service', method: 'GET', path: '/orders/list', factors: [], stages: [], mfaSatisfied: false, durationMs: 1, timestamp: 1,
  ...over,
});

function correlate(c: ThreatCorrelator, result: PipelineResult, lateral?: { path: string[]; hops: number; detected: boolean; knownWorkflow: boolean }) {
  return c.correlate(normalizePipelineResult(result, lateral ? { lateral } : undefined));
}

test('request context shares evidence while category identity remains isolated', () => {
  const c = new ThreatCorrelator(cfg());
  const findings = correlate(c, verdict({
    factors: [
      { code: 'OFF_HOURS', points: 5, detail: 'outside business hours' },
      { code: 'PAYLOAD_ANOMALY', points: 25, detail: 'payload exceeds limit' },
      { code: 'SENSITIVE_ENDPOINT', points: 10, detail: 'sensitive target' },
    ],
    riskScore: 40,
  }));
  assert.equal(findings.length, 2);
  assert.deepEqual(findings.map((f) => f.category).sort(), ['BEHAVIORAL_ANOMALY', 'REQUEST_PAYLOAD_ABUSE']);
  assert.ok(findings.every((f) => f.evidenceIds.length === 3));
});

test('different request and category do not merge', () => {
  const c = new ThreatCorrelator(cfg());
  correlate(c, verdict({ requestId: 'one', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'outside' }] }));
  correlate(c, verdict({ requestId: 'two', factors: [{ code: 'PAYLOAD_ANOMALY', points: 25, detail: 'large' }] }));
  assert.equal(c.recent().length, 2);
});

test('trace correlation preserves only the observed lateral path', () => {
  const c = new ThreatCorrelator(cfg());
  const findings = correlate(
    c,
    verdict({ requestId: 'lateral-request', traceId: 'trace-chain', decision: 'BLOCK', reason: 'LATERAL_MOVEMENT', riskScore: 90, riskLevel: 'CRITICAL', factors: [{ code: 'LATERAL_MOVEMENT', points: 50, detail: '3 hops' }] }),
    { path: ['frontend-service', 'orders-service', 'payments-service', 'database-service'], hops: 3, detected: true, knownWorkflow: false },
  );
  assert.equal(findings.length, 1);
  assert.equal(findings[0].correlationKey, 'trace:trace-chain');
  assert.deepEqual(findings[0].attackPath?.services, ['frontend-service', 'orders-service', 'payments-service', 'database-service']);
  assert.equal(findings[0].attackPath?.traceId, 'trace-chain');
  assert.deepEqual(findings[0].attackPath?.observedAt, [1]);
});

test('recurrence updates one finding, preserves first seen, bounds evidence, and keeps maximum finalized risk', () => {
  const c = new ThreatCorrelator(cfg({ maxEvidencePerFinding: 2 }));
  const first = correlate(c, verdict({ requestId: 'one', timestamp: 10, riskScore: 30, factors: [{ code: 'RATE_SPIKE', points: 10, detail: 'first' }] }))[0];
  const second = correlate(c, verdict({ requestId: 'two', timestamp: 20, riskScore: 60, riskLevel: 'HIGH', factors: [{ code: 'RATE_SPIKE', points: 20, detail: 'second' }] }))[0];
  const third = correlate(c, verdict({ requestId: 'three', timestamp: 30, riskScore: 40, factors: [{ code: 'RATE_SPIKE', points: 10, detail: 'third' }] }))[0];
  assert.equal(first.findingId, second.findingId);
  assert.equal(second.findingId, third.findingId);
  assert.equal(third.recurrence?.count, 3);
  assert.equal(third.recurrence?.firstSeenAt, 10);
  assert.equal(third.recurrence?.lastSeenAt, 30);
  assert.equal(third.risk.score, 60);
  assert.ok(third.evidenceIds.length <= 2);
  assert.ok(third.risk.contributionIds.length <= 2);
});

test('events outside the configured window create a new active finding', () => {
  const c = new ThreatCorrelator(cfg({ windowMs: 10 }));
  const a = correlate(c, verdict({ requestId: 'one', timestamp: 1, factors: [{ code: 'OFF_HOURS', points: 5, detail: 'outside' }] }))[0];
  const b = correlate(c, verdict({ requestId: 'two', timestamp: 12, factors: [{ code: 'OFF_HOURS', points: 5, detail: 'outside' }] }))[0];
  assert.notEqual(a.findingId, b.findingId);
  assert.equal(c.recent().length, 1, 'expired correlation state is evicted rather than resolved');
});

test('active finding capacity evicts the oldest state without changing finding status', () => {
  const c = new ThreatCorrelator(cfg({ maxActiveFindings: 2 }));
  for (const [requestId, source] of [['one', 'a-service'], ['two', 'b-service'], ['three', 'c-service']] as const) {
    correlate(c, verdict({ requestId, source, destination: 'orders-service', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'outside' }] }));
  }
  const active = c.recent();
  assert.equal(active.length, 2);
  assert.ok(active.every((finding) => finding.status === 'active'));
  assert.ok(!active.some((finding) => finding.source === 'a-service'));
});

test('correlation reads finalized risk and never changes finalized decision fields', () => {
  const c = new ThreatCorrelator(cfg());
  const inputs: PipelineResult[] = [
    verdict({ requestId: 'allow', decision: 'ALLOW', reason: 'OK', riskScore: 5, factors: [{ code: 'OFF_HOURS', points: 5, detail: 'outside' }] }),
    verdict({ requestId: 'monitor', decision: 'MONITOR', reason: 'ELEVATED_RISK', riskScore: 30, factors: [{ code: 'RATE_SPIKE', points: 10, detail: 'spike' }] }),
    verdict({ requestId: 'step-up', decision: 'STEP_UP_AUTH', reason: 'STEP_UP_REQUIRED', riskScore: 65, riskLevel: 'HIGH', factors: [{ code: 'PAYLOAD_ANOMALY', points: 50, detail: 'deep payload' }] }),
    verdict({ requestId: 'block', decision: 'BLOCK', reason: 'LATERAL_MOVEMENT', riskScore: 90, riskLevel: 'CRITICAL', factors: [{ code: 'LATERAL_MOVEMENT', points: 50, detail: 'path' }] }),
  ];
  for (const input of inputs) {
    const before = structuredClone(input);
    const finding = correlate(c, input)[0];
    assert.deepEqual(input, before);
    assert.equal(finding.risk.score, before.riskScore);
    assert.equal(finding.decisionContext.decision, before.decision);
  }
});
