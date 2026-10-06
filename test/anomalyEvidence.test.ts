/**
 * Anomaly evidence integrity: every `warm`/`z` value consumed downstream must
 * come from the detector that computed it — never defaulted, recomputed, or
 * relabeled. Producer writes it, the factor carries it, the normalizer copies
 * it verbatim, and pure rule hits carry no statistics at all.
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { AnomalyEngine } from '../src/risk/anomaly.js';
import { normalizePipelineResult } from '../src/threat/normalizer.js';
import { input, setup } from './helpers.js';

async function call(ctx: Awaited<ReturnType<typeof setup>>, from: string, over: Parameters<typeof input>[0] = {}) {
  const token = await ctx.clients.get(from)!.signToken({ nowSec: ctx.nowSec() });
  return ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, ...over }));
}

test('anomaly engine exposes the actual z-score and explicit warmth when the statistical check fires', async () => {
  const ctx = await setup();
  const engine = new AnomalyEngine(ctx.config.payload);
  for (let i = 0; i < 30; i++) engine.analyze('a->b', { n: i }, 200);
  const outlier = engine.analyze('a->b', { n: 1 }, 50_000);
  assert.ok(outlier.points > 0);
  // Exact computed value, not a rounded category: (50000-200)/max(std,1), std is 0.
  assert.equal(outlier.zScore?.value, 49800);
  // Warm is the gate condition itself, written by the producer — never defaulted.
  assert.equal(outlier.zScore?.warm, true);
  assert.ok(outlier.findings.some((f) => f.includes('z-score 49800.0')));
});

test('anomaly engine writes no z-evidence for pure deterministic rule hits', async () => {
  const ctx = await setup();
  const engine = new AnomalyEngine(ctx.config.payload);
  let bomb: unknown = 'x'.repeat(150_000);
  for (let i = 0; i < 25; i++) bomb = { n: bomb };
  const first = engine.analyze('a->b', bomb, 150_000);
  assert.ok(first.points > 0, 'size + depth rules must still fire without history');
  assert.equal(first.zScore, undefined);
});

test('payload z-score travels pipeline factor -> evidence facts verbatim and is labeled statistical', async () => {
  const ctx = await setup();
  for (let i = 0; i < 40; i++) await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: i }, payloadBytes: 200 + (i % 5) });
  const big = await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: 1 }, payloadBytes: 50_000 });
  const factor = big.factors.find((f) => f.code === 'PAYLOAD_ANOMALY')!;
  assert.ok(factor, 'expected a PAYLOAD_ANOMALY factor');
  assert.equal(typeof factor.meta?.z, 'number');
  assert.equal(factor.meta?.warm, true);
  // The machine value and the human string describe the same computation.
  const fromDetail = parseFloat(/z-score ([0-9.]+)/.exec(factor.detail)![1]);
  assert.ok(Math.abs(factor.meta!.z! - fromDetail) < 0.05);
  // Scoring is untouched by metadata: the invariant still holds exactly.
  assert.equal(big.riskScore, big.factors.reduce((s, f) => s + f.points, 0));

  const observation = normalizePipelineResult(big);
  const item = observation.evidence.find((e) => e.kind === 'payload')!;
  assert.ok(item, 'expected payload evidence');
  assert.equal(item.reliability, 'statistical');
  assert.equal(item.facts.z, factor.meta!.z);
  assert.equal(item.facts.warm, true);
});

test('size/depth-only payload evidence stays deterministic with no z or warm keys', async () => {
  const ctx = await setup();
  let bomb: unknown = 'x'.repeat(150_000);
  for (let i = 0; i < 25; i++) bomb = { n: bomb };
  const r = await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: bomb, payloadBytes: 150_000 });
  const factor = r.factors.find((f) => f.code === 'PAYLOAD_ANOMALY')!;
  assert.ok(factor, 'expected a PAYLOAD_ANOMALY factor from size+depth rules');
  assert.equal(factor.meta, undefined);
  const observation = normalizePipelineResult(r);
  const item = observation.evidence.find((e) => e.kind === 'payload')!;
  assert.equal(item.reliability, 'deterministic');
  assert.ok(!('z' in item.facts) && !('warm' in item.facts));
});

test('baseline rate spikes carry the computed z and warmth into statistical evidence', async () => {
  const ctx = await setup({ RATE_LIMIT_MAX_REQUESTS: '100000' });
  const W = ctx.config.baseline.windowMs;
  for (let w = 0; w < 10; w++) {
    for (let i = 0; i < 20; i++) {
      await call(ctx, 'frontend-service');
      ctx.clock.advance(W / 20);
    }
  }
  let spiked = null;
  for (let i = 0; i < 150; i++) {
    const r = await call(ctx, 'frontend-service');
    if (!spiked && r.factors.some((f) => f.code === 'RATE_SPIKE')) spiked = r;
    ctx.clock.advance(5);
  }
  assert.ok(spiked, 'expected a RATE_SPIKE factor after warming the baseline');
  const factor = spiked!.factors.find((f) => f.code === 'RATE_SPIKE')!;
  assert.equal(typeof factor.meta?.z, 'number');
  assert.equal(factor.meta?.warm, true);
  const observation = normalizePipelineResult(spiked!);
  const item = observation.evidence.find((e) => e.kind === 'rate')!;
  assert.equal(item.reliability, 'statistical');
  assert.equal(item.facts.z, factor.meta!.z);
  assert.equal(item.facts.warm, true);
  assert.equal(spiked!.riskScore, spiked!.factors.reduce((s, f) => s + f.points, 0));
});

test('correlated finding assessment explains the real recorded deviation', async () => {
  const ctx = await setup();
  for (let i = 0; i < 40; i++) await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: i }, payloadBytes: 200 + (i % 5) });
  await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: 1 }, payloadBytes: 50_000 });
  const finding = ctx.mesh.threats.findings().find((f) => f.category === 'REQUEST_PAYLOAD_ABUSE');
  assert.ok(finding, 'expected a correlated REQUEST_PAYLOAD_ABUSE finding');
  const explanation = finding!.assessment?.explanation ?? '';
  assert.ok(explanation.includes('deviation of'), `unexpected explanation: ${explanation}`);
});
