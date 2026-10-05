import assert from 'node:assert/strict';
import { test } from 'node:test';
import type { Evidence, NormalizedSignal, ThreatFinding } from '../src/threat/contracts.js';
import { assessFinding } from '../src/threat/assessment.js';
import { categoryExposure } from '../src/threat/exposure.js';

const finding = (over: Partial<ThreatFinding> = {}): ThreatFinding => ({
  findingId: 'finding', openedAt: 1, lastSeenAt: 1, category: 'BEHAVIORAL_ANOMALY', severity: 'LOW',
  risk: { score: 30, riskModelVersion: 'existing-factor-ledger-v1', contributionIds: ['c1'] },
  confidence: { score: 0, criteria: [] }, status: 'active', evidenceIds: ['e1'], detectorSummary: [{ name: 'test', version: '1' }],
  affectedServices: ['frontend-service'], correlationKey: 'edge:frontend-service->orders-service', decisionContext: { decision: 'MONITOR', reason: 'ELEVATED_RISK' }, recurrence: { count: 1, firstSeenAt: 1, lastSeenAt: 1 },
  ...over,
});

const signal = (over: Partial<NormalizedSignal> = {}): NormalizedSignal => ({
  signalId: 's1', occurredAt: 1, type: 'RATE_SPIKE', source: 'frontend-service', destination: 'orders-service', correlationId: 'trace-1', detector: { name: 'test', version: '1' }, disposition: 'observed', role: 'threat_signal', primaryCategory: 'BEHAVIORAL_ANOMALY', evidenceRefs: ['e1'], riskContribution: { id: 'c1', points: 10, factorCode: 'RATE_SPIKE' },
  ...over,
});

const evidence = (over: Partial<Evidence> = {}): Evidence => ({
  evidenceId: 'e1', kind: 'rate', observedAt: 1, source: 'frontend-service', destination: 'orders-service', requestId: 'request-1', traceId: 'trace-1', detector: { name: 'test', version: '1' }, facts: { warm: true, z: 3.2 }, reliability: 'statistical', completeness: 'complete',
  ...over,
});

test('category exposure deduplicates by contribution id and never credits secondary categories', () => {
  const contributions = [
    { id: 'same', points: 10, primaryCategory: 'BEHAVIORAL_ANOMALY' as const },
    { id: 'same', points: 10, primaryCategory: 'BEHAVIORAL_ANOMALY' as const },
    { id: 'lateral', points: 50, primaryCategory: 'LATERAL_MOVEMENT' as const },
  ];
  assert.deepEqual(categoryExposure('BEHAVIORAL_ANOMALY', contributions), { category: 'BEHAVIORAL_ANOMALY', score: 10, contributionIds: ['same'] });
  assert.deepEqual(categoryExposure('SERVICE_GRAPH_ANOMALY', contributions), { category: 'SERVICE_GRAPH_ANOMALY', score: 0, contributionIds: [] });
  assert.equal(categoryExposure('LATERAL_MOVEMENT', contributions).score, 50);
});

test('contextual evidence contributes no category exposure', () => {
  const contextual = signal({ type: 'SENSITIVE_ENDPOINT', role: 'contextual_evidence', primaryCategory: undefined, riskContribution: { id: 'sensitive', points: 10, factorCode: 'SENSITIVE_ENDPOINT' } });
  const assessed = assessFinding(finding(), [contextual], [evidence()], []);
  assert.equal(assessed.assessment?.categoryExposure.score, 0);
});

test('confidence exposes all four deterministic criteria and cold baselines cannot validate', () => {
  const warm = assessFinding(finding(), [signal()], [evidence()], [{ id: 'c1', points: 10, primaryCategory: 'BEHAVIORAL_ANOMALY' }]);
  assert.equal(warm.confidence.score, 75);
  assert.equal(warm.confidence.criteria.find((item) => item.name === 'detectorValidity')?.satisfied, true);

  const cold = assessFinding(finding(), [signal()], [evidence({ facts: { warm: false, z: 3.2 } })], [{ id: 'c1', points: 10, primaryCategory: 'BEHAVIORAL_ANOMALY' }]);
  assert.equal(cold.confidence.criteria.find((item) => item.name === 'detectorValidity')?.satisfied, false);
  assert.ok(cold.confidence.score <= 50);
});

test('token replay is high severity and can reach complete confidence from deterministic proof', () => {
  const replay = signal({ type: 'TOKEN_REPLAY', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', riskContribution: undefined });
  const assessed = assessFinding(
    finding({ category: 'AUTHENTICATION_TOKEN_ABUSE', risk: { score: 90, riskModelVersion: 'existing-factor-ledger-v1', contributionIds: [] } }),
    [replay], [evidence({ kind: 'token', reliability: 'deterministic', facts: { jti: 'redacted-id', firstUseKnown: true } })], [],
  );
  assert.equal(assessed.severity, 'HIGH');
  assert.equal(assessed.confidence.score, 100);
  assert.equal(assessed.risk.score, 90);
});

test('lateral movement is critical and secondary graph context never changes risk', () => {
  const lateral = signal({ type: 'LATERAL_MOVEMENT', primaryCategory: 'LATERAL_MOVEMENT', secondaryCategories: ['SERVICE_GRAPH_ANOMALY'], riskContribution: { id: 'lateral', points: 50, factorCode: 'LATERAL_MOVEMENT' } });
  const assessed = assessFinding(finding({ category: 'LATERAL_MOVEMENT', risk: { score: 90, riskModelVersion: 'existing-factor-ledger-v1', contributionIds: ['lateral'] } }), [lateral], [evidence({ kind: 'trace', reliability: 'deterministic', facts: { path: ['a', 'b', 'c'], distinctHops: 3 } })], [{ id: 'lateral', points: 50, primaryCategory: 'LATERAL_MOVEMENT' }]);
  assert.equal(assessed.severity, 'CRITICAL');
  assert.equal(assessed.assessment?.categoryExposure.score, 50);
  assert.equal(assessed.risk.score, 90);
});

test('context-dependent severity uses recurrence rather than finalized risk', () => {
  const lowRiskRepeated = assessFinding(finding({ recurrence: { count: 3, firstSeenAt: 1, lastSeenAt: 3 }, risk: { score: 5, riskModelVersion: 'existing-factor-ledger-v1', contributionIds: ['c1'] } }), [signal()], [evidence()], [{ id: 'c1', points: 10, primaryCategory: 'BEHAVIORAL_ANOMALY' }]);
  assert.equal(lowRiskRepeated.severity, 'HIGH');
  assert.equal(lowRiskRepeated.risk.score, 5);
});
