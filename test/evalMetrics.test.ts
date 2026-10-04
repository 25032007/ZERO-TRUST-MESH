import assert from 'node:assert/strict';
import { test } from 'node:test';
import { computeMetrics, meanStd, type Outcome } from '../src/eval/metrics.js';
import type { AttackClass, Episode, EvalEvent } from '../src/eval/trafficGenerator.js';
import type { Decision } from '../src/types.js';

let id = 0;
const ev = (label: EvalEvent['label'], t: number, episode?: number): EvalEvent => ({
  id: id++, t, source: 'a', destination: 'b', method: 'GET', path: '/', payloadBytes: 0, ip: '1.1.1.1', traceId: 't', label, episode, tokenKind: 'valid',
});
const out = (event: EvalEvent, decision: Decision, reason = 'X'): Outcome => ({ event, decision, reason, riskScore: 0 });
const ep = (idn: number, cls: AttackClass, startT: number): Episode => ({ id: idn, cls, startT, endT: startT + 1000 });

test('confusion matrix, precision, recall, FPR and F1 are computed correctly (hand-checked)', () => {
  const outcomes = [
    // 10 normal: 2 flagged (FP), 8 clean (TN)
    ...Array.from({ length: 8 }, (_, i) => out(ev('normal', i), 'ALLOW')),
    out(ev('normal', 9), 'MONITOR'),
    out(ev('normal', 10), 'BLOCK'),
    // 4 behavioural attack events: 3 flagged (TP), 1 missed (FN)
    out(ev('rate-flood', 20, 0), 'MONITOR'),
    out(ev('rate-flood', 21, 0), 'BLOCK'),
    out(ev('rate-flood', 22, 0), 'STEP_UP_AUTH'),
    out(ev('rate-flood', 23, 0), 'ALLOW'),
  ];
  const m = computeMetrics(outcomes, [ep(0, 'rate-flood', 20)]);
  assert.deepEqual([m.behavioral.tp, m.behavioral.fp, m.behavioral.tn, m.behavioral.fn], [3, 2, 8, 1]);
  assert.equal(m.behavioral.precision, 3 / 5);
  assert.equal(m.behavioral.recall, 3 / 4);
  assert.equal(m.behavioral.fpr, 2 / 10);
  assert.ok(Math.abs(m.behavioral.f1 - (2 * 0.6 * 0.75) / (0.6 + 0.75)) < 1e-12);
  assert.equal(m.fpr, 0.2);
  assert.equal(m.falsePositives, 2);
});

test('episode recall counts an attack as detected if ANY request was flagged, and reports time-to-detect', () => {
  const outcomes = [
    out(ev('lateral-chain', 100, 0), 'ALLOW'),
    out(ev('lateral-chain', 350, 0), 'ALLOW'),
    out(ev('lateral-chain', 600, 0), 'BLOCK'), // flagged at t=600, episode started at 100
    out(ev('lateral-chain', 5000, 1), 'ALLOW'), // second episode: never detected
    out(ev('lateral-chain', 5300, 1), 'ALLOW'),
  ];
  const m = computeMetrics(outcomes, [ep(0, 'lateral-chain', 100), ep(1, 'lateral-chain', 5000)]);
  const c = m.perClass['lateral-chain'];
  assert.equal(c.episodes, 2);
  assert.equal(c.episodesDetected, 1);
  assert.equal(c.episodeRecall, 0.5);
  assert.equal(c.medianTimeToDetectMs, 500);
  assert.equal(c.eventRecall, 1 / 5);
});

test('normal requests refused only because a service was quarantined are COLLATERAL, not false positives', () => {
  const outcomes = [
    out(ev('normal', 1), 'ALLOW'),
    out(ev('normal', 2), 'BLOCK', 'SERVICE_QUARANTINED'),
    out(ev('normal', 3), 'BLOCK', 'LATERAL_MOVEMENT'), // a genuine false positive
  ];
  const m = computeMetrics(outcomes, []);
  assert.equal(m.collateralBlocks, 1);
  assert.equal(m.falsePositives, 1);
  assert.equal(m.normalEvents, 2);
  assert.equal(m.fpr, 0.5);
});

test('behavioural and hard-fail attacks are scored separately against the same normal traffic', () => {
  const outcomes = [
    out(ev('normal', 1), 'ALLOW'),
    out(ev('rate-flood', 2, 0), 'ALLOW'), // behavioural miss
    out(ev('token-replay', 3, 1), 'BLOCK', 'TOKEN_REPLAY'), // hard-fail hit
  ];
  const m = computeMetrics(outcomes, [ep(0, 'rate-flood', 2), ep(1, 'token-replay', 3)]);
  assert.equal(m.behavioral.recall, 0);
  assert.equal(m.hardFail.recall, 1);
});

test('empty and degenerate inputs never divide by zero', () => {
  const m = computeMetrics([], []);
  assert.equal(m.fpr, 0);
  assert.equal(m.behavioral.f1, 0);
  assert.equal(m.perClass['rate-flood'].episodeRecall, 0);
  assert.equal(m.perClass['rate-flood'].medianTimeToDetectMs, undefined);
});

test('meanStd matches a hand computation', () => {
  const r = meanStd([2, 4, 4, 4, 5, 5, 7, 9]);
  assert.equal(r.mean, 5);
  assert.ok(Math.abs(r.std - 2.138089935) < 1e-6); // sample std-dev
  assert.deepEqual(meanStd([3]), { mean: 3, std: 0 });
});
