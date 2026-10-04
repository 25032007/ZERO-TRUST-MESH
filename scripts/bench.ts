/**
 * `npm run bench` — honest load test.
 *
 * What it measures: the FULL path of a legitimate request over real HTTP on
 * localhost — Express parsing, the 8-stage security pipeline (including Ed25519
 * signature verification), a real HTTP hop to the mock downstream service, and
 * the response. Every request carries a DIFFERENT pre-signed token, because
 * tokens are single-use (re-using one would just measure the replay rejection).
 *
 * What it does NOT measure: network latency between machines, TLS, or a real
 * database. Treat the numbers as "overhead of the mesh itself", not capacity planning.
 */
import autocannon from 'autocannon';
import { loadConfig } from '../src/config.js';
import { createApp } from '../src/server.js';

const DURATION_SEC = Number(process.env.BENCH_SECONDS ?? 10);
const CONNECTIONS = Number(process.env.BENCH_CONNECTIONS ?? 20);
const TOKENS = Number(process.env.BENCH_TOKENS ?? 60_000);

// Raise the guard-rails that would (correctly) throttle a single noisy client.
const app = await createApp(
  loadConfig({ ...process.env, PORT: '0', RATE_LIMIT_MAX_REQUESTS: '10000000', BURST_WARN_AT: '100000000', BURST_HIGH_AT: '100000000' }),
);
const port = await app.listen(0);

console.log(`Pre-signing ${TOKENS} single-use Ed25519 tokens…`);
const frontend = app.clients.get('frontend-service')!;
const tokens: string[] = [];
for (let i = 0; i < TOKENS; i++) tokens.push(await frontend.signToken({ lifetimeSec: 600 }));

let i = 0;
console.log(`Running ${CONNECTIONS} connections for ${DURATION_SEC}s…`);
const result = await autocannon({
  url: `http://127.0.0.1:${port}`,
  connections: CONNECTIONS,
  duration: DURATION_SEC,
  requests: [
    {
      method: 'GET',
      path: '/api/proxy/orders/list',
      headers: { 'x-destination-service': 'orders-service' },
      setupRequest: (req) => {
        req.headers = { ...req.headers, authorization: `Bearer ${tokens[i++ % tokens.length]}` };
        return req;
      },
    },
  ],
});

const metrics = app.mesh.metrics.snapshot();
const reuse = i > tokens.length ? ' (WARNING: tokens were reused, raise BENCH_TOKENS — replay rejections skew results)' : '';
console.log('\n── End-to-end over HTTP (client view) ─────────────────────────');
console.log(`requests/sec (avg) : ${Math.round(result.requests.average)}`);
console.log(`latency p50        : ${result.latency.p50} ms`);
console.log(`latency p97.5      : ${result.latency.p97_5} ms`);
console.log(`latency p99        : ${result.latency.p99} ms`);
console.log(`2xx responses      : ${result['2xx']}   non-2xx: ${result.non2xx}   errors: ${result.errors}${reuse}`);
console.log('\n── Security pipeline only (server-side timer) ─────────────────');
console.log(`samples            : ${metrics.pipelineLatency.samples} (last 10 000)`);
console.log(`p50 / p95 / p99    : ${metrics.pipelineLatency.p50Ms} / ${metrics.pipelineLatency.p95Ms} / ${metrics.pipelineLatency.p99Ms} ms`);
console.log(`decisions          : ${JSON.stringify(metrics.byDecision)}`);
console.log(`audit chain valid  : ${app.mesh.audit.verify().valid}`);

await app.close();
process.exit(0);
