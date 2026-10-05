import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { PipelineResult } from '../src/types.js';
import type { Evidence, NormalizedSignal, Recommendation, ThreatFinding } from '../src/threat/contracts.js';
import { normalizePipelineResult } from '../src/threat/normalizer.js';
import { input, setup } from './helpers.js';

async function call(ctx: Awaited<ReturnType<typeof setup>>, from: string, over: Parameters<typeof input>[0] = {}, signOpts = {}) {
  const token = await ctx.clients.get(from)!.signToken({ nowSec: ctx.nowSec(), ...signOpts });
  return ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, ...over }));
}

const result = (over: Partial<PipelineResult> = {}): PipelineResult => ({
  requestId: 'request-1', traceId: 'trace-1', decision: 'ALLOW', httpStatus: 200, reason: 'OK', riskScore: 10, riskLevel: 'LOW',
  source: 'frontend-service', destination: 'orders-service', method: 'GET', path: '/orders/list', factors: [], stages: [], mfaSatisfied: false, durationMs: 1, timestamp: 1,
  ...over,
});

test('Phase 1 contracts carry their required fields', () => {
  const signal: NormalizedSignal = {
    signalId: 's', occurredAt: 1, type: 'NEW_SERVICE_PAIR', detector: { name: 'test', version: '1' }, disposition: 'observed', role: 'threat_signal', primaryCategory: 'SERVICE_GRAPH_ANOMALY', evidenceRefs: [],
  };
  const evidence: Evidence = {
    evidenceId: 'e', kind: 'graph', observedAt: 1, detector: { name: 'test', version: '1' }, facts: {}, reliability: 'contextual', completeness: 'complete',
  };
  const finding: ThreatFinding = {
    findingId: 'f', openedAt: 1, lastSeenAt: 1, category: 'SERVICE_GRAPH_ANOMALY', severity: 'LOW',
    risk: { score: 0, riskModelVersion: 'test', contributionIds: [] }, confidence: { score: 0, criteria: [] }, status: 'active', evidenceIds: [], detectorSummary: [], affectedServices: [], decisionContext: { decision: 'ALLOW', reason: 'OK' },
  };
  const recommendation: Recommendation = {
    recommendationId: 'r', createdAt: 1, category: 'MONITOR', priority: 'LOW', status: 'open', title: 'Observe', rationale: 'test', affectedEntities: [], suggestedAction: 'observe', expectedImpact: 'none', confidence: 0, sourceFindingIds: [], evidenceIds: [], rule: { id: 'test', version: '1' },
  };
  assert.equal(signal.type, 'NEW_SERVICE_PAIR');
  assert.equal(evidence.kind, 'graph');
  assert.equal(finding.category, 'SERVICE_GRAPH_ANOMALY');
  assert.equal(recommendation.category, 'MONITOR');
});

test('sensitive endpoints are contextual evidence, not threat classification', () => {
  const observation = normalizePipelineResult(result({
    factors: [{ code: 'SENSITIVE_ENDPOINT', points: 10, detail: 'GET database-service/database/rows is a sensitive target' }],
    riskScore: 10,
  }));
  const signal = observation.signals[0];
  assert.equal(signal.role, 'contextual_evidence');
  assert.equal(signal.primaryCategory, undefined);
  assert.deepEqual(signal.contextualCategories, ['SERVICE_GRAPH_ANOMALY', 'RECONNAISSANCE_PROBING', 'REQUEST_PAYLOAD_ABUSE']);
  assert.equal(signal.riskContribution?.points, 10);
  assert.equal(observation.findings.length, 0);
});

test('rate limiting and quarantine remain non-threat enforcement semantics', () => {
  const limited = normalizePipelineResult(result({ decision: 'BLOCK', httpStatus: 429, reason: 'RATE_LIMITED', riskScore: 50 }));
  assert.equal(limited.signals[0].role, 'control_outcome');
  assert.equal(limited.signals[0].primaryCategory, undefined);
  assert.equal(limited.findings.length, 0);

  const quarantined = normalizePipelineResult(result({ decision: 'BLOCK', httpStatus: 403, reason: 'SERVICE_QUARANTINED', riskScore: 100 }));
  assert.equal(quarantined.signals[0].type, 'QUARANTINE');
  assert.equal(quarantined.signals[0].role, 'decision_context');
  assert.equal(quarantined.signals[0].primaryCategory, undefined);
  assert.equal(quarantined.findings.length, 0);
});

test('mapping assigns one owner category and secondary categories are contextual', () => {
  const observation = normalizePipelineResult(result({
    factors: [
      { code: 'NEW_SERVICE_PAIR', points: 10, detail: 'First request on frontend-service->orders-service' },
      { code: 'PAYLOAD_ANOMALY', points: 25, detail: 'payload exceeds limit' },
    ],
    riskScore: 35,
  }));
  const graph = observation.signals[0];
  const payload = observation.signals[1];
  assert.equal(graph.primaryCategory, 'SERVICE_GRAPH_ANOMALY');
  assert.deepEqual(graph.secondaryCategories, ['BEHAVIORAL_ANOMALY']);
  assert.equal(payload.primaryCategory, 'REQUEST_PAYLOAD_ABUSE');
  assert.deepEqual(payload.secondaryCategories, ['BEHAVIORAL_ANOMALY']);
  assert.equal(observation.signals.reduce((sum, s) => sum + (s.riskContribution?.points ?? 0), 0), 35);
});

test('hard failures and dry-run policy violations map without becoming soft contributions', () => {
  const replay = normalizePipelineResult(result({ decision: 'BLOCK', httpStatus: 401, reason: 'TOKEN_REPLAY', riskScore: 90 }));
  assert.equal(replay.signals[0].type, 'TOKEN_REPLAY');
  assert.equal(replay.signals[0].primaryCategory, 'AUTHENTICATION_TOKEN_ABUSE');
  assert.equal(replay.signals[0].riskContribution, undefined);

  const dryRun = normalizePipelineResult(result({ dryRunViolation: { reason: 'NO_POLICY', policyId: 'trial' } }));
  assert.equal(dryRun.signals[0].type, 'DRY_RUN_POLICY_VIOLATION');
  assert.equal(dryRun.signals[0].disposition, 'dry_run');
  assert.equal(dryRun.signals[0].riskContribution, undefined);
});

test('observing actual pipeline results leaves representative scores and decisions unchanged', async () => {
  const ctx = await setup({ RISK_MODE: 'fixed', BURST_WARN_AT: '2', BURST_HIGH_AT: '4', RATE_LIMIT_MAX_REQUESTS: '100000' });
  ctx.clock.set(Date.UTC(2026, 0, 15, 3, 0, 0));

  const first = await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { a: 1 }, payloadBytes: 10 });
  assert.equal(first.decision, 'ALLOW');
  assert.ok(first.factors.some((f) => f.code === 'NEW_SERVICE_PAIR'));
  assert.ok(first.factors.some((f) => f.code === 'OFF_HOURS'));

  const sensitive = await call(ctx, 'payments-service', { destination: 'database-service', path: '/database/rows' });
  assert.ok(sensitive.factors.some((f) => f.code === 'SENSITIVE_ENDPOINT'));

  let rate = first;
  for (let i = 0; i < 5; i++) rate = await call(ctx, 'frontend-service');
  assert.ok(rate.factors.some((f) => f.code === 'ELEVATED_FREQUENCY' || f.code === 'ABNORMAL_FREQUENCY'));

  for (let i = 0; i < 3; i++) await ctx.mesh.pipeline.evaluate(input({ authorization: 'Bearer invalid', ip: '6.6.6.6' }));
  const authHistory = await call(ctx, 'frontend-service', { ip: '6.6.6.6' });
  assert.ok(authHistory.factors.some((f) => f.code === 'RECENT_AUTH_FAILURES'));

  const payload = await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { x: 'x'.repeat(120_000) }, payloadBytes: 120_000 });
  assert.ok(payload.factors.some((f) => f.code === 'PAYLOAD_ANOMALY'));

  const denied = await call(ctx, 'frontend-service', { destination: 'database-service', path: '/database/query' });
  assert.equal(denied.reason, 'NO_POLICY');

  const token = await ctx.clients.get('frontend-service')!.signToken({ nowSec: ctx.nowSec() });
  await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}` }));
  const replay = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}` }));
  assert.equal(replay.reason, 'TOKEN_REPLAY');

  for (const verdict of [first, sensitive, rate, authHistory, payload, denied, replay]) {
    const observation = ctx.mesh.threats.recent().find((o) => o.signals.some((s) => s.evidenceRefs.some((id) => id.startsWith(`${verdict.requestId}:`))));
    assert.ok(observation);
    assert.equal(verdict.riskScore, Math.min(100, verdict.factors.reduce((sum, factor) => sum + factor.points, 0)) || verdict.riskScore);
  }
});

test('lateral movement remains a hard override and emits one owned contribution', async () => {
  const ctx = await setup();
  const traceId = 'threat-contract-lateral';
  await call(ctx, 'frontend-service', { traceId });
  await call(ctx, 'orders-service', { traceId, destination: 'payments-service', method: 'POST', path: '/payments/charge' });
  const verdict = await call(ctx, 'payments-service', { traceId, destination: 'database-service', path: '/database/rows' });
  assert.equal(verdict.reason, 'LATERAL_MOVEMENT');
  const observation = ctx.mesh.threats.recent().find((o) => o.signals.some((s) => s.signalId.startsWith(`${verdict.requestId}:`)))!;
  const signal = observation.signals.find((s) => s.type === 'LATERAL_MOVEMENT')!;
  assert.equal(signal.primaryCategory, 'LATERAL_MOVEMENT');
  assert.deepEqual(signal.secondaryCategories, ['SERVICE_GRAPH_ANOMALY']);
  assert.equal(signal.riskContribution?.points, verdict.factors.find((f) => f.code === 'LATERAL_MOVEMENT')?.points);
  assert.equal(observation.findings.find((f) => f.category === 'LATERAL_MOVEMENT')?.decisionContext.hardOverride, true);
});
