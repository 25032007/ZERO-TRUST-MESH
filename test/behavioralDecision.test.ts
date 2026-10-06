/**
 * Behavioral detection must REACH a decision.
 *
 * A high-confidence rate spike (z >= zHigh on a warm baseline) carries 30
 * points, so it reaches MONITOR on its own instead of vanishing into ALLOW.
 * Measured on the synthetic eval harness before shipping (recall
 * 0.002 -> 0.142 with 2/1543 batch-edge flags); these tests lock the
 * mechanism deterministically with the fake clock (12:00 UTC, business
 * hours — no wall-clock dependence).
 */
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { input, setup } from './helpers.js';

async function call(ctx: Awaited<ReturnType<typeof setup>>, from: string, over: Parameters<typeof input>[0] = {}) {
  const token = await ctx.clients.get(from)!.signToken({ nowSec: ctx.nowSec() });
  return ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, ...over }));
}

test('a high-confidence rate spike reaches MONITOR on its own (decision-capable)', async () => {
  const ctx = await setup();
  const W = ctx.config.baseline.windowMs;
  for (let w = 0; w < 10; w++) {
    for (let i = 0; i < 20; i++) {
      await call(ctx, 'frontend-service');
      ctx.clock.advance(W / 20);
    }
  }
  const seen: Awaited<ReturnType<typeof call>>[] = [];
  for (let i = 0; i < 150; i++) {
    seen.push(await call(ctx, 'frontend-service'));
    ctx.clock.advance(5);
  }
  const flagged = seen.find((r) => r.decision === 'MONITOR' && r.factors.some((f) => f.code === 'RATE_SPIKE'));
  assert.ok(flagged, 'warmed baseline must drive the flood to MONITOR');
  assert.equal(flagged!.reason, 'ELEVATED_RISK');
  assert.ok(flagged!.riskScore >= 30);
  // Exact-sum invariant holds with the new weight.
  assert.equal(flagged!.riskScore, flagged!.factors.reduce((s, f) => s + f.points, 0));
  // MONITOR observes and forwards: no quarantine for a non-critical score.
  assert.equal(ctx.mesh.quarantine.isQuarantined('frontend-service'), undefined);
});

test('steady normal traffic stays ALLOW after warm-up (no hair-trigger)', async () => {
  const ctx = await setup();
  const W = ctx.config.baseline.windowMs;
  for (let w = 0; w < 8; w++) {
    for (let i = 0; i < 10; i++) {
      await call(ctx, 'frontend-service');
      ctx.clock.advance(W / 10);
    }
  }
  for (let i = 0; i < 10; i++) {
    const r = await call(ctx, 'frontend-service');
    assert.equal(r.decision, 'ALLOW');
    ctx.clock.advance(W / 10);
  }
});

test('a legitimate 4x batch burst is never blocked or quarantined', async () => {
  const ctx = await setup();
  const W = ctx.config.baseline.windowMs;
  const edge = { destination: 'users-service', path: '/users/me' };
  // Quiet edge learns its normal rhythm (~4 requests per window).
  for (let w = 0; w < 8; w++) {
    for (let i = 0; i < 4; i++) {
      await call(ctx, 'orders-service', edge);
      ctx.clock.advance(W / 4);
    }
  }
  // Batch job: 4x the normal rate, ramped and held like a real batch window.
  const seen: string[] = [];
  for (let w = 0; w < 4; w++) {
    for (let i = 0; i < 16; i++) {
      seen.push((await call(ctx, 'orders-service', edge)).decision);
      ctx.clock.advance(W / 16);
    }
  }
  assert.ok(!seen.includes('BLOCK'), `batch traffic must never be blocked, got: ${seen.join(',')}`);
  assert.equal(ctx.mesh.quarantine.isQuarantined('orders-service'), undefined);
});

test('a lone payload z-score below the boundary stays ALLOW on an established edge', async () => {
  // Honest scope lock: with zScorePoints at 15, one moderately anomalous
  // payload is visible in factors but needs corroborating signals to flag.
  // (Measured: raising it to 30 caught the class but pushed legit heavy-tail
  // payloads into MONITOR at 5% FPR — rejected.)
  const ctx = await setup();
  for (let i = 0; i < 35; i++) {
    await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: i }, payloadBytes: 450 });
  }
  const r = await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: 1 }, payloadBytes: 12_000 });
  assert.ok(r.factors.some((f) => f.code === 'PAYLOAD_ANOMALY'));
  assert.equal(r.decision, 'ALLOW');
});

test('default deny is intact alongside behavioral scoring', async () => {
  const ctx = await setup();
  const token = await ctx.clients.get('frontend-service')!.signToken({ nowSec: ctx.nowSec() });
  const r = await ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, destination: 'database-service', path: '/database/rows' }));
  assert.equal(r.decision, 'BLOCK');
  assert.equal(r.reason, 'NO_POLICY');
});
