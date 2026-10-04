import assert from 'node:assert/strict';
import { test } from 'node:test';
import { input, setup } from './helpers.js';

async function call(ctx: Awaited<ReturnType<typeof setup>>, from: string, over: Parameters<typeof input>[0] = {}) {
  const token = await ctx.clients.get(from)!.signToken({ nowSec: ctx.nowSec() });
  return ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, ...over }));
}

test('enforce mode (default): a denied request is blocked and no violation is recorded', async () => {
  const ctx = await setup();
  const r = await call(ctx, 'frontend-service', { destination: 'database-service', path: '/database/q' });
  assert.equal(r.decision, 'BLOCK');
  assert.equal(r.dryRunViolation, undefined);
  assert.equal(ctx.mesh.metrics.snapshot().dryRunViolations, 0);
});

test('global DRY_RUN: policy denial is logged as "would block" and the request is allowed through', async () => {
  const ctx = await setup({ DRY_RUN: 'true' });
  const r = await call(ctx, 'frontend-service', { destination: 'database-service', path: '/database/q' });
  assert.notEqual(r.decision, 'BLOCK');
  assert.equal(r.dryRunViolation?.reason, 'NO_POLICY');
  const authz = r.stages.find((s) => s.stage === 'authorization')!;
  assert.equal(authz.outcome, 'flag');
  assert.match(authz.detail, /DRY-RUN/);
  // The rest of the pipeline still ran on this realistic traffic.
  assert.ok(r.stages.some((s) => s.stage === 'risk_scoring'));
  assert.equal(ctx.mesh.metrics.snapshot().dryRunViolations, 1);
  assert.equal(ctx.mesh.audit.recent(1)[0].dryRunViolation, 'NO_POLICY');
  assert.equal(ctx.mesh.audit.verify().valid, true);
});

test('per-policy dry-run only relaxes THAT policy; other denials still block', async () => {
  const ctx = await setup();
  ctx.mesh.policies.replaceAll([
    { id: 'trial-rule', source: 'frontend-service', destination: 'orders-service', methods: ['GET'], allowPaths: ['/orders'], mode: 'dry-run', description: '' },
  ]);
  const trial = await call(ctx, 'frontend-service', { path: '/inventory/list' }); // PATH_NOT_ALLOWED by the dry-run policy
  assert.notEqual(trial.decision, 'BLOCK');
  assert.equal(trial.dryRunViolation?.policyId, 'trial-rule');

  const other = await call(ctx, 'payments-service', { destination: 'database-service', path: '/database/x' }); // NO_POLICY, enforced
  assert.equal(other.decision, 'BLOCK');
  assert.equal(other.dryRunViolation, undefined);
});

test('dry-run never relaxes authentication: a forged token is still blocked', async () => {
  const ctx = await setup({ DRY_RUN: 'true' });
  const r = await ctx.mesh.pipeline.evaluate(input({ authorization: 'Bearer junk.token.here' }));
  assert.equal(r.decision, 'BLOCK');
  assert.equal(r.reason, 'MALFORMED_TOKEN');
});

test('explicit deny in dry-run mode is reported with its policy id', async () => {
  const ctx = await setup();
  ctx.mesh.policies.replaceAll([
    { id: 'allow-all', source: 'frontend-service', destination: 'orders-service', methods: ['GET'], description: '' },
    { id: 'ban-reports', source: 'frontend-service', destination: 'orders-service', methods: ['GET'], allowPaths: ['/reports'], effect: 'deny', priority: 5, mode: 'dry-run', description: '' },
  ]);
  const r = await call(ctx, 'frontend-service', { path: '/reports/q3' });
  assert.notEqual(r.decision, 'BLOCK');
  assert.deepEqual(r.dryRunViolation, { reason: 'EXPLICIT_DENY', policyId: 'ban-reports' });
});
