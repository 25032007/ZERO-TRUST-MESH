/**
 * Pure unit tests for the read-only threat presenter.
 *
 * Findings come from the REAL correlator (normalize + correlate), so these
 * prove the presenter shapes existing backend state without recalculating,
 * reclassifying, or inventing anything.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { ThreatCorrelator, type ThreatCorrelationConfig } from '../src/threat/correlator.js';
import { normalizePipelineResult } from '../src/threat/normalizer.js';
import { attackPathView, categoryBreakdown, investigationView, listFindings } from '../src/threat/presenter.js';
import type { Evidence, ThreatFinding } from '../src/threat/contracts.js';
import type { PipelineResult } from '../src/types.js';

const cfg: ThreatCorrelationConfig = { windowMs: 60_000, traceWindowMs: 1_000, maxActiveFindings: 50, maxEvidencePerFinding: 100 };

const verdict = (over: Partial<PipelineResult> = {}): PipelineResult => ({
  requestId: 'request-1', traceId: 'trace-1', decision: 'MONITOR', httpStatus: 200, reason: 'ELEVATED_RISK', riskScore: 30, riskLevel: 'MEDIUM',
  source: 'frontend-service', destination: 'orders-service', method: 'GET', path: '/orders/list', factors: [], stages: [], mfaSatisfied: false, durationMs: 1, timestamp: 1,
  ...over,
});

/** Correlate verdicts and return the stored findings (newest first). */
function found(verdicts: PipelineResult[]): ThreatFinding[] {
  const c = new ThreatCorrelator(cfg);
  for (const v of verdicts) {
    const lateral = v.reason === 'LATERAL_MOVEMENT'
      ? { lateral: { path: ['a', 'b', 'c'], hops: 3, detected: true, knownWorkflow: false } }
      : undefined;
    c.correlate(normalizePipelineResult(v, lateral));
  }
  return c.recent(50);
}

test('listFindings clamps runaway and degenerate limits server-side', () => {
  const all = found([verdict({ requestId: 'a', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }] })]);
  assert.equal(listFindings(all, { limit: 100000 }).findings.length <= 200, true);
  assert.equal(listFindings(all, { limit: -5 }).findings.length, 1);
  assert.equal(listFindings(all, {}).findings.length, 1);
});

test('listFindings cursor walks the full list without overlap', () => {
  const all = found([
    verdict({ requestId: 'a', source: 's1', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }] }),
    verdict({ requestId: 'b', source: 's2', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }] }),
    verdict({ requestId: 'c', source: 's3', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }] }),
  ]);
  assert.equal(all.length, 3);
  const first = listFindings(all, { limit: 2 });
  assert.equal(first.findings.length, 2);
  assert.ok(first.nextCursor !== null);
  const second = listFindings(all, { limit: 2, cursor: first.nextCursor });
  assert.equal(second.findings.length, 1);
  assert.equal(second.nextCursor, null);
  const ids = [...first.findings, ...second.findings].map((f) => f.findingId);
  assert.equal(new Set(ids).size, 3);
  // Garbage cursors fall back to the start instead of failing.
  assert.equal(listFindings(all, { limit: 2, cursor: 'bogus' }).findings.length, 2);
});

test('listFindings combines filters and ignores overlong values', () => {
  const all = found([
    verdict({ requestId: 'a', source: 'frontend-service', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }] }),
    verdict({ requestId: 'b', source: 'orders-service', destination: 'users-service', path: '/users/me', factors: [{ code: 'PAYLOAD_ANOMALY', points: 25, detail: 'big' }] }),
  ]);
  const both = listFindings(all, { category: 'BEHAVIORAL_ANOMALY', source: 'frontend-service' });
  assert.equal(both.total, 1);
  assert.equal(both.findings[0].source, 'frontend-service');
  const none = listFindings(all, { category: 'BEHAVIORAL_ANOMALY', source: 'no-such-service' });
  assert.deepEqual(none, { findings: [], nextCursor: null, total: 0 });
  // A 500-char filter cannot become a memory-heavy query; it is ignored.
  const ignored = listFindings(all, { source: 'x'.repeat(500) });
  assert.equal(ignored.total, all.length);
});

test('categoryBreakdown exposure is an explanatory sum with severity ranking', () => {
  const all = found([
    verdict({ requestId: 'replay', traceId: 't1', decision: 'BLOCK', reason: 'TOKEN_REPLAY', riskScore: 90, riskLevel: 'CRITICAL', factors: [], timestamp: 10 }),
    verdict({ requestId: 'late', traceId: 't2', source: 'svc-a', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }], timestamp: 20 }),
  ]);
  const { categories, totalActiveFindings } = categoryBreakdown(all);
  assert.equal(totalActiveFindings, all.length);
  for (const row of categories) {
    // Exposure equals the stored per-finding assessment scores added up —
    // presented for comparison, never fed back into pipeline risk.
    const expected = all.filter((f) => f.category === row.category).reduce((s, f) => s + (f.assessment?.categoryExposure.score ?? 0), 0);
    assert.equal(row.exposureScore, expected);
    assert.ok(row.findingIds.length <= 20 && row.findingIds.length >= 1);
  }
  const tokenAbuse = categories.find((c) => c.category === 'AUTHENTICATION_TOKEN_ABUSE')!;
  assert.equal(tokenAbuse.maxSeverity, 'HIGH');
  const behavioral = categories.find((c) => c.category === 'BEHAVIORAL_ANOMALY')!;
  assert.equal(behavioral.maxSeverity, 'LOW');
});

test('investigationView returns null when nothing is active and caps evidence at 200', () => {
  assert.equal(investigationView('edge:a->b', []), null);
  const all = found([verdict({ requestId: 'a', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }] })]);
  const key = all[0].correlationKey!;
  const mkEvidence = (n: number): Evidence[] =>
    Array.from({ length: n }, (_, i) => ({
      evidenceId: `ev-${i}`, kind: 'baseline' as const, observedAt: i, detector: { name: 'd', version: '1' },
      facts: { i }, reliability: 'contextual' as const, completeness: 'partial' as const,
    }));
  const view = investigationView(key, [{ finding: all[0], evidence: mkEvidence(250) }])!;
  assert.equal(view.correlationKey, key);
  assert.equal(view.evidence.length, 200);
  assert.equal(new Set(view.evidence.map((e) => e.evidenceId)).size, 200);
  assert.ok(view.firstSeenAt <= view.lastSeenAt);
  assert.ok(view.affectedServices.length >= 1 && view.decisions.length >= 1);
});

test('attackPathView distinguishes no data from a valid empty', () => {
  assert.deepEqual(attackPathView([]), { paths: [], totalActiveFindings: 0 });
  const all = found([verdict({ requestId: 'a', factors: [{ code: 'OFF_HOURS', points: 5, detail: 'x' }] })]);
  assert.deepEqual(attackPathView(all), { paths: [], totalActiveFindings: 1 });
  const lateral = found([verdict({
    requestId: 'l', traceId: 'chain', decision: 'BLOCK', reason: 'LATERAL_MOVEMENT', riskScore: 90, riskLevel: 'CRITICAL',
    factors: [{ code: 'LATERAL_MOVEMENT', points: 50, detail: '3 hops' }],
  })]);
  const view = attackPathView(lateral);
  assert.equal(view.paths.length, 1);
  assert.deepEqual(view.paths[0].services, ['a', 'b', 'c']);
});
