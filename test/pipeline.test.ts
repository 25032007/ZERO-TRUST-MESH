import assert from 'node:assert/strict';
import { test } from 'node:test';
import { generateTotp } from '../src/crypto/totp.js';
import { input, setup } from './helpers.js';

async function call(ctx: Awaited<ReturnType<typeof setup>>, from: string, over: Parameters<typeof input>[0] = {}, signOpts = {}) {
  const token = await ctx.clients.get(from)!.signToken({ nowSec: ctx.nowSec(), ...signOpts });
  return ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, ...over }));
}

test('a normal request is allowed with a low score and a full stage trace', async () => {
  const ctx = await setup();
  const r = await call(ctx, 'frontend-service');
  assert.equal(r.decision, 'ALLOW');
  assert.ok(r.riskScore < 30);
  assert.deepEqual(r.stages.map((s) => s.stage), ['rate_limit', 'authentication', 'quarantine', 'authorization', 'payload_anomaly', 'lateral_movement', 'risk_scoring', 'decision']);
});

test('risk score is exactly the sum of its factors (explainability)', async () => {
  const ctx = await setup();
  const r = await call(ctx, 'payments-service', { destination: 'database-service', path: '/database/rows' });
  assert.equal(r.riskScore, r.factors.reduce((s, f) => s + f.points, 0));
  assert.ok(r.factors.some((f) => f.code === 'SENSITIVE_ENDPOINT'));
  assert.ok(r.factors.some((f) => f.code === 'NEW_SERVICE_PAIR'));
});

test('NEW_SERVICE_PAIR only fires the first time an edge is seen', async () => {
  const ctx = await setup();
  const a = await call(ctx, 'frontend-service');
  const b = await call(ctx, 'frontend-service');
  assert.ok(a.factors.some((f) => f.code === 'NEW_SERVICE_PAIR'));
  assert.ok(!b.factors.some((f) => f.code === 'NEW_SERVICE_PAIR'));
});

test('off-hours requests get an OFF_HOURS factor', async () => {
  const ctx = await setup();
  ctx.clock.set(Date.UTC(2026, 0, 15, 3, 0, 0)); // 03:00 UTC, outside 6-22
  const r = await call(ctx, 'frontend-service');
  assert.ok(r.factors.some((f) => f.code === 'OFF_HOURS'));
});

test('default deny, and denied requests never reach scoring', async () => {
  const ctx = await setup();
  const r = await call(ctx, 'frontend-service', { destination: 'database-service', path: '/database/q' });
  assert.equal(r.decision, 'BLOCK');
  assert.equal(r.reason, 'NO_POLICY');
  assert.equal(r.stages.at(-1)!.stage, 'authorization');
});

test('spoofed X-Service-ID is caught even though the token is valid', async () => {
  const ctx = await setup();
  const r = await call(ctx, 'frontend-service', { claimedService: 'payments-service' });
  assert.equal(r.reason, 'IDENTITY_MISMATCH');
});

test('missing destination is a 400', async () => {
  const ctx = await setup();
  const r = await call(ctx, 'frontend-service', { destination: undefined });
  assert.equal(r.reason, 'MISSING_DESTINATION');
  assert.equal(r.httpStatus, 400);
});

test('repeated auth failures from one IP raise the risk of that IP\'s later valid requests', async () => {
  const ctx = await setup();
  for (let i = 0; i < 3; i++) await ctx.mesh.pipeline.evaluate(input({ authorization: 'Bearer junk', ip: '6.6.6.6' }));
  const attacker = await call(ctx, 'frontend-service', { ip: '6.6.6.6' });
  const innocent = await call(ctx, 'frontend-service', { ip: '10.9.9.9' });
  assert.ok(attacker.factors.some((f) => f.code === 'RECENT_AUTH_FAILURES' && f.points === 15));
  assert.ok(!innocent.factors.some((f) => f.code === 'RECENT_AUTH_FAILURES'));
});

test('framing: forged tokens in a victim\'s name do not raise the VICTIM\'s risk or quarantine it', async () => {
  const ctx = await setup();
  for (let i = 0; i < 20; i++) await ctx.mesh.pipeline.evaluate(input({ authorization: 'Bearer junk', ip: '6.6.6.6' }));
  assert.equal(ctx.mesh.quarantine.isQuarantined('frontend-service'), undefined);
  const real = await call(ctx, 'frontend-service', { ip: '10.1.1.1' });
  assert.equal(real.decision, 'ALLOW');
});

test('fixed-threshold mode: burst of requests raises ELEVATED then ABNORMAL frequency', async () => {
  const ctx = await setup({ RISK_MODE: 'fixed', BURST_WARN_AT: '5', BURST_HIGH_AT: '10', RATE_LIMIT_MAX_REQUESTS: '100000' });
  const codes: string[][] = [];
  for (let i = 0; i < 12; i++) codes.push((await call(ctx, 'frontend-service')).factors.map((f) => f.code));
  assert.ok(codes[5].includes('ELEVATED_FREQUENCY'));
  assert.ok(codes[11].includes('ABNORMAL_FREQUENCY'));
  assert.ok(!codes[0].includes('ELEVATED_FREQUENCY'));
});

test('rate limiting kicks in per service', async () => {
  const ctx = await setup({ RATE_LIMIT_MAX_REQUESTS: '3' });
  const results = [];
  for (let i = 0; i < 5; i++) results.push((await call(ctx, 'frontend-service')).reason);
  assert.equal(results[3], 'RATE_LIMITED');
});

test('lateral movement blocks the 3rd hop and quarantines the pivot until release or expiry', async () => {
  const ctx = await setup();
  const trace = 'trace-1';
  await call(ctx, 'frontend-service', { traceId: trace });
  await call(ctx, 'orders-service', { traceId: trace, destination: 'payments-service', method: 'POST', path: '/payments/charge' });
  const third = await call(ctx, 'payments-service', { traceId: trace, destination: 'database-service', path: '/database/rows' });
  assert.equal(third.reason, 'LATERAL_MOVEMENT');

  const follow = await call(ctx, 'payments-service', { destination: 'database-service', path: '/database/rows' });
  assert.equal(follow.reason, 'SERVICE_QUARANTINED');

  ctx.clock.advance(ctx.config.quarantineMs + 1);
  const after = await call(ctx, 'payments-service', { destination: 'database-service', path: '/database/rows' });
  assert.equal(after.decision === 'BLOCK', false);
});

test('critical risk score blocks and quarantines', async () => {
  const ctx = await setup({ RISK_MODE: 'fixed', BURST_WARN_AT: '2', BURST_HIGH_AT: '3', RATE_LIMIT_MAX_REQUESTS: '100000' });
  ctx.clock.set(Date.UTC(2026, 0, 15, 3, 0, 0)); // off hours +5
  // big AND deeply nested -> 25 + 25 anomaly points; plus sensitive target, off-hours and a request burst
  let bomb: unknown = 'x'.repeat(150_000);
  for (let i = 0; i < 25; i++) bomb = { n: bomb };
  let last = await call(ctx, 'payments-service', { destination: 'database-service', path: '/database/q', method: 'POST', body: bomb, payloadBytes: 150_000 });
  for (let i = 0; i < 4 && last.decision !== 'BLOCK'; i++) last = await call(ctx, 'payments-service', { destination: 'database-service', path: '/database/q', method: 'POST', body: bomb, payloadBytes: 150_000 });
  assert.equal(last.decision, 'BLOCK');
  assert.equal(last.reason, 'RISK_CRITICAL');
  assert.ok(ctx.mesh.quarantine.isQuarantined('payments-service'));
});

test('step-up: a risky request needs TOTP; a code works once and replaying it fails', async () => {
  const ctx = await setup();
  const deep = (() => { let n: unknown = 'x'; for (let i = 0; i < 25; i++) n = { n }; return n; })();
  const base = { destination: 'database-service', path: '/database/q', method: 'POST', body: deep, payloadBytes: 120_000 };

  const first = await call(ctx, 'payments-service', base);
  assert.equal(first.decision, 'STEP_UP_AUTH');
  assert.equal(first.reason, 'STEP_UP_REQUIRED');

  const secret = ctx.mesh.registry.getTotpSecret('payments-service')!;
  const code = generateTotp(secret, ctx.clock());

  const wrong = await call(ctx, 'payments-service', { ...base, totp: code === '000000' ? '111111' : '000000' });
  assert.equal(wrong.reason, 'STEP_UP_FAILED');

  const ok = await call(ctx, 'payments-service', { ...base, totp: code });
  assert.equal(ok.decision, 'ALLOW');
  assert.equal(ok.mfaSatisfied, true);

  const reused = await call(ctx, 'payments-service', { ...base, totp: code });
  assert.equal(reused.reason, 'STEP_UP_FAILED'); // same code cannot be used twice
});

test('statistical size anomaly needs history, then flags outliers without learning from them', async () => {
  const ctx = await setup();
  for (let i = 0; i < 40; i++) await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: i }, payloadBytes: 200 + (i % 5) });
  const big = await call(ctx, 'frontend-service', { method: 'POST', path: '/orders/create', body: { n: 1 }, payloadBytes: 50_000 });
  assert.ok(big.factors.some((f) => f.code === 'PAYLOAD_ANOMALY' && /z-score/.test(f.detail)));
});

test('every decision is written to the audit log and counted in metrics', async () => {
  const ctx = await setup();
  await call(ctx, 'frontend-service');
  await call(ctx, 'frontend-service', { destination: 'database-service', path: '/database/q' });
  const snap = ctx.mesh.metrics.snapshot();
  assert.equal(snap.total, 2);
  assert.equal(snap.byDecision.ALLOW, 1);
  assert.equal(snap.byDecision.BLOCK, 1);
  assert.equal(ctx.mesh.audit.recent(10).length, 2);
  assert.equal(ctx.mesh.audit.verify().valid, true);
});

test('a DECLARED workflow is allowed end-to-end, while an undeclared 3-hop chain is still blocked and quarantined', async () => {
  const ctx = await setup();
  ctx.mesh.policies.setAllowedWorkflows([['frontend-service', 'orders-service', 'payments-service', 'database-service']]);

  const t1 = 'legit-trace';
  await call(ctx, 'frontend-service', { traceId: t1 });
  await call(ctx, 'orders-service', { traceId: t1, destination: 'payments-service', method: 'POST', path: '/payments/charge' });
  const third = await call(ctx, 'payments-service', { traceId: t1, destination: 'database-service', path: '/database/rows' });
  assert.notEqual(third.decision, 'BLOCK');
  assert.ok(third.stages.find((s) => s.stage === 'lateral_movement')!.detail.startsWith('declared workflow'));

  // Same edges, different shape (frontend also talks to auth, orders to users) -> not declared.
  const t2 = 'odd-trace';
  await call(ctx, 'frontend-service', { traceId: t2 });
  await call(ctx, 'frontend-service', { traceId: t2, destination: 'auth-service', method: 'POST', path: '/auth/login' });
  const odd = await call(ctx, 'orders-service', { traceId: t2, destination: 'users-service', path: '/users/me' });
  assert.equal(odd.reason, 'LATERAL_MOVEMENT');
});

test('baseline mode: steady traffic is never flagged, a spike on the SAME edge is (no fixed thresholds involved)', async () => {
  const ctx = await setup({ RATE_LIMIT_MAX_REQUESTS: '100000' });
  const W = ctx.config.baseline.windowMs;
  const spikeCodes = (r: { factors: { code: string }[] }) => r.factors.filter((f) => f.code === 'RATE_SPIKE');

  // 10 windows of steady traffic (20 requests per window): the edge learns what "normal" is.
  let falseAlarms = 0;
  for (let w = 0; w < 10; w++) {
    for (let i = 0; i < 20; i++) {
      falseAlarms += spikeCodes(await call(ctx, 'frontend-service')).length;
      ctx.clock.advance(W / 20);
    }
  }
  assert.equal(falseAlarms, 0);

  // Sudden burst: 150 requests inside one window.
  let flagged = 0;
  for (let i = 0; i < 150; i++) {
    const r = await call(ctx, 'frontend-service');
    if (spikeCodes(r).length > 0) flagged++;
    ctx.clock.advance(5);
  }
  assert.ok(flagged > 100, `expected most of the burst to be flagged, got ${flagged}`);
});

test('baseline mode: the same request count is normal on a busy edge but a spike on a quiet one', async () => {
  const ctx = await setup({ RATE_LIMIT_MAX_REQUESTS: '100000' });
  const W = ctx.config.baseline.windowMs;
  const hasSpike = (r: { factors: { code: string }[] }) => r.factors.some((f) => f.code === 'RATE_SPIKE');

  // frontend->orders is busy (60/window), frontend->auth is quiet (4/window).
  for (let w = 0; w < 10; w++) {
    for (let i = 0; i < 60; i++) { await call(ctx, 'frontend-service'); ctx.clock.advance(W / 60); }
    for (let i = 0; i < 4; i++) await call(ctx, 'frontend-service', { destination: 'auth-service', method: 'POST', path: '/auth/login' });
  }
  let busySpike = false;
  for (let i = 0; i < 80; i++) { busySpike ||= hasSpike(await call(ctx, 'frontend-service')); ctx.clock.advance(5); }
  let quietSpike = false;
  for (let i = 0; i < 80; i++) { quietSpike ||= hasSpike(await call(ctx, 'frontend-service', { destination: 'auth-service', method: 'POST', path: '/auth/login' })); ctx.clock.advance(5); }
  assert.equal(busySpike, false, '80 requests is only ~1.3x the busy edge\'s normal rate');
  assert.equal(quietSpike, true, '80 requests is 20x the quiet edge\'s normal rate');
});
