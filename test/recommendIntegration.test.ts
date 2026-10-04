import assert from 'node:assert/strict';
import { test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { recommend } from '../src/policy/recommend.js';
import { createApp } from '../src/server.js';
import { input, setup } from './helpers.js';

async function call(ctx: Awaited<ReturnType<typeof setup>>, from: string, over: Parameters<typeof input>[0] = {}) {
  const token = await ctx.clients.get(from)!.signToken({ nowSec: ctx.nowSec() });
  return ctx.mesh.pipeline.evaluate(input({ authorization: `Bearer ${token}`, ...over }));
}

test('real pipeline traffic feeds the recommender: unused permissions are found, used ones are kept', async () => {
  const ctx = await setup({ RATE_LIMIT_MAX_REQUESTS: '100000' });

  // 30 minutes of simulated traffic: frontend only ever GETs orders; nothing ever calls auth/users.
  for (let i = 0; i < 60; i++) {
    await call(ctx, 'frontend-service', { path: '/orders/list' });
    await call(ctx, 'orders-service', { destination: 'payments-service', method: 'POST', path: '/payments/charge' });
    ctx.clock.advance(30_000);
  }
  // Someone probes the database from the frontend, repeatedly.
  for (let i = 0; i < 8; i++) await call(ctx, 'frontend-service', { destination: 'database-service', path: '/database/q' });

  const report = recommend(ctx.mesh.policies.list(), ctx.mesh.usage.snapshot(), ctx.clock());
  assert.equal(report.confident, true);

  const ids = (type: string) => report.recommendations.filter((r) => r.type === type).map((r) => r.policyId);
  assert.deepEqual(ids('NARROW_METHODS'), ['frontend-to-orders']); // POST was never used
  assert.ok(ids('REMOVE_UNUSED_POLICY').includes('frontend-to-auth'));
  assert.ok(ids('REMOVE_UNUSED_POLICY').includes('orders-to-users'));
  assert.ok(ids('REMOVE_UNUSED_POLICY').includes('payments-to-database'));
  assert.ok(!ids('REMOVE_UNUSED_POLICY').includes('orders-to-payments'), 'a used policy must be kept');

  const review = report.recommendations.find((r) => r.type === 'REVIEW_DENIED_EDGE')!;
  assert.equal(review.edge, 'frontend-service->database-service');
  assert.equal(report.proposedPolicies.some((p) => p.destination === 'database-service' && p.source === 'frontend-service'), false);

  assert.ok(report.summary.unusedPercent > 50);
});

test('GET /api/policies/recommendations returns the report and honours query overrides', async () => {
  const app = await createApp(loadConfig({ ADMIN_API_KEY: 'k', PORT: '0' }));
  const base = `http://127.0.0.1:${await app.listen(0)}`;
  try {
    const frontend = app.clients.get('frontend-service')!;
    for (let i = 0; i < 25; i++) {
      await (await fetch(`${base}/api/proxy/orders/list`, { headers: { authorization: `Bearer ${await frontend.signToken()}`, 'x-destination-service': 'orders-service' } })).arrayBuffer();
    }
    const early = (await (await fetch(`${base}/api/policies/recommendations`)).json()) as { confident: boolean; recommendations: Array<{ type: string }> };
    assert.equal(early.confident, false); // the server just started
    assert.equal(early.recommendations[0].type, 'INSUFFICIENT_DATA');

    const now = (await (await fetch(`${base}/api/policies/recommendations?minObservationSec=0&minHits=10`)).json()) as { confident: boolean; recommendations: Array<{ type: string; policyId?: string }>; proposedDocument: { policies: unknown[] } };
    assert.equal(now.confident, true);
    assert.ok(now.recommendations.some((r) => r.type === 'NARROW_METHODS' && r.policyId === 'frontend-to-orders'));
    assert.ok(Array.isArray(now.proposedDocument.policies));
  } finally {
    await app.close();
  }
});
