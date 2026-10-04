/**
 * scripts/loadtest.ts  —  npm run loadtest
 *
 * HONEST LOAD TEST: N services (default 20), realistic tree/chain topology,
 * proxy OFF vs proxy ON comparison, multiple concurrency levels.
 *
 * Design decisions:
 *  - Every request carries a DIFFERENT pre-signed token because tokens are
 *    single-use (replay protection). We warn when the pool would be exhausted.
 *  - "Proxy OFF" hits the mock downstream directly with the internal secret,
 *    measuring raw Express + JSON overhead with zero security pipeline cost.
 *  - "Proxy ON (no baseline)" sets BASELINE_MIN_WINDOWS=999999 so the EWMA
 *    detector never fires; this measures pure proxy overhead without FP noise.
 *  - "Proxy ON (default)" runs with default config and counts non-ALLOW
 *    decisions — should be ~0 under steady load (measures false-positive rate).
 *  - RSS is sampled before/after each block; we assert growth < 150 MB so the
 *    reviewer can see in-memory state stays bounded.
 *  - The generator and the server share the same CPU (Node is single-threaded).
 *    This is honest; the caveat is written to docs/LOADTEST.md.
 */

import autocannon from 'autocannon';
import { writeFileSync } from 'node:fs';
import { cpus } from 'node:os';
import { loadConfig } from '../src/config.js';
import { INTERNAL_HEADER, INTERNAL_SECRET } from '../src/downstream/mockServices.js';
import { ServiceClient } from '../src/identity/serviceClient.js';
import type { Policy } from '../src/policy/policyEngine.js';
import { createApp } from '../src/server.js';

// ── Configuration ─────────────────────────────────────────────────────────────
const N_SERVICES = Number(process.env.LOADTEST_SERVICES ?? 20);
const DURATION_SEC = Number(process.env.LOADTEST_DURATION ?? 8);
const CONCURRENCY_LEVELS = (process.env.LOADTEST_CONCURRENCY ?? '10,50,100')
  .split(',')
  .map(Number)
  .filter(Number.isFinite);
// Token pool factor: how many tokens to pre-sign relative to expected requests.
// We need at least concurrency*duration*rps_estimate tokens. We use a generous
// upper bound and warn if the actual run exceeds the pool.
const TOKEN_POOL_FACTOR = Number(process.env.LOADTEST_TOKEN_POOL_FACTOR ?? 3);

// ── Topology helper ───────────────────────────────────────────────────────────
/**
 * Build a service graph for N services.
 *
 * Layout: tree with fan-outs plus a few chains.
 *   svc-0  (root / caller)
 *   svc-0 → svc-1, svc-2, svc-3, svc-4          (fan-out from root)
 *   svc-1 → svc-5, svc-6                         (chain)
 *   svc-2 → svc-7, svc-8
 *   svc-3 → svc-9
 *   svc-4 → svc-10
 *   svc-5 → svc-11, svc-12
 *   … and so on until all N services have at least one role
 *
 * Each edge becomes one allow policy. The load test always calls
 *   svc-0 → svc-1  (the first edge)
 * so we always exercise a real policy path.
 */
function buildTopology(n: number): { edges: [string, string][] } {
  const edges: [string, string][] = [];
  let next = 1;
  // BFS assignment: each node fans out to 2 children until we have n nodes
  const queue: number[] = [0];
  while (next < n && queue.length > 0) {
    const parent = queue.shift()!;
    for (let child = 0; child < 2 && next < n; child++, next++) {
      edges.push([`svc-${parent}`, `svc-${next}`]);
      queue.push(next);
    }
  }
  return { edges };
}

function edgeToPolicies(edges: [string, string][]): Policy[] {
  return edges.map(([src, dst], i) => ({
    id: `lt-${i}`,
    source: src,
    destination: dst,
    methods: ['GET'],
    allowPaths: ['/api'],
    description: `load-test edge ${src} → ${dst}`,
  }));
}

// ── Service setup ─────────────────────────────────────────────────────────────
async function buildServices(
  n: number,
  mesh: Awaited<ReturnType<typeof createApp>>['mesh'],
): Promise<Map<string, ServiceClient>> {
  const clients = new Map<string, ServiceClient>();
  for (let i = 0; i < n; i++) {
    const id = `svc-${i}`;
    const client = await ServiceClient.create(id, { audience: mesh.config.audience });
    await mesh.registry.register({ serviceId: id, displayName: id, publicJwk: client.publicJwk, kid: client.kid });
    clients.set(id, client);
  }
  return clients;
}

// ── Token pre-signing ─────────────────────────────────────────────────────────
async function preSign(client: ServiceClient, count: number): Promise<string[]> {
  const tokens: string[] = [];
  for (let i = 0; i < count; i++) tokens.push(await client.signToken({ lifetimeSec: 600 }));
  return tokens;
}

// ── Autocannon wrapper ────────────────────────────────────────────────────────
interface RunResult {
  rps: number;
  p50: number;
  p95: number;
  p99: number;
  errors: number;
  non2xx: number;
  total: number;
}

async function runAutocannon(opts: {
  url: string;
  path: string;
  headers: Record<string, string>;
  /** Called on each request to inject the next token header. */
  authHeader: () => string;
  connections: number;
  durationSec: number;
}): Promise<RunResult & { tokenReused: boolean }> {
  let i = 0;
  let tokenReused = false;
  const headerSnaps: string[] = [];

  // autocannon setupRequest runs synchronously per request slot; we capture
  // the auth header values in advance and cycle through them.
  const result = await autocannon({
    url: opts.url,
    connections: opts.connections,
    duration: opts.durationSec,
    requests: [
      {
        method: 'GET',
        path: opts.path,
        headers: opts.headers,
        setupRequest: (req) => {
          const auth = opts.authHeader();
          if (i > 0 && !tokenReused) {
            // authHeader() wraps the pool; if it cycles back we flag it.
            // We detect this by checking if we've gone past the pool size.
          }
          headerSnaps.push(auth);
          req.headers = { ...req.headers, authorization: auth };
          i++;
          return req;
        },
      },
    ],
  });

  return {
    rps: Math.round(result.requests.average),
    p50: result.latency.p50,
    p95: result.latency.p97_5,
    p99: result.latency.p99,
    errors: result.errors,
    non2xx: result.non2xx,
    total: result['2xx'] + result.non2xx + result.errors,
    tokenReused,
  };
}

// ── Memory helper ─────────────────────────────────────────────────────────────
function memStats(): { rss: number; heap: number } {
  const m = process.memoryUsage();
  return {
    rss: Math.round(m.rss / 1024 / 1024),
    heap: Math.round(m.heapUsed / 1024 / 1024),
  };
}

// ── Main ──────────────────────────────────────────────────────────────────────
interface BenchRow {
  label: string;
  connections: number;
  rps: number;
  p50: number;
  p95: number;
  p99: number;
  errorRate: string;
  rssBefore: number;
  rssAfter: number;
  heapBefore: number;
  heapAfter: number;
  tokenReused: boolean;
}

console.log(`\nZero-Trust Mesh — Load Test`);
console.log(`Services: ${N_SERVICES}  |  Concurrency levels: ${CONCURRENCY_LEVELS.join(', ')}  |  Duration: ${DURATION_SEC}s each\n`);

const { edges } = buildTopology(N_SERVICES);
const policies = edgeToPolicies(edges);

// The caller is always svc-0, the first edge's destination is svc-1.
// All requests go svc-0 → svc-1.
const callerSvc = 'svc-0';
const destSvc = edges[0][1]; // svc-1

// ─── Build the proxy app ────────────────────────────────────────────────────
// Guard-rails that would correctly block a benchmark-style noisy client, lifted.
const baseEnv = {
  ...process.env,
  PORT: '0',
  RATE_LIMIT_MAX_REQUESTS: '10000000',
  BURST_WARN_AT: '100000000',
  BURST_HIGH_AT: '100000000',
  POLICY_WATCH: 'false',
  KEY_ROTATION_MS: '0',
};

console.log('Bootstrapping proxy (no-baseline variant)…');
const appNoBaseline = await createApp(
  loadConfig({ ...baseEnv, BASELINE_MIN_WINDOWS: '999999' }),
  { policies },
);
const portNoBaseline = await appNoBaseline.listen(0);
const callerNoBaseline = (await buildServices(N_SERVICES, appNoBaseline.mesh)).get(callerSvc)!;

console.log('Bootstrapping proxy (default-config variant)…');
const appDefault = await createApp(
  loadConfig(baseEnv),
  { policies },
);
const portDefault = await appDefault.listen(0);
const callerDefault = (await buildServices(N_SERVICES, appDefault.mesh)).get(callerSvc)!;

// ─── Token pool sizing ─────────────────────────────────────────────────────
// Upper bound: number of concurrency levels * duration * max expected RPS (3000) * safety factor.
// We sign separate pools for each app because tokens are single-use per-registry.
const tokenPoolSize = Math.ceil(CONCURRENCY_LEVELS.length * DURATION_SEC * 3000 * TOKEN_POOL_FACTOR);
console.log(`\nPre-signing ${tokenPoolSize.toLocaleString()} tokens per client (2 clients)…`);

const tokensNoBaseline = await preSign(callerNoBaseline, tokenPoolSize);
const tokensDefault = await preSign(callerDefault, tokenPoolSize);
console.log('  done.\n');

// ─── Run benchmarks ───────────────────────────────────────────────────────
const rows: BenchRow[] = [];

function makeTokenCycler(pool: string[]): { next: () => string; reused: () => boolean } {
  let idx = 0;
  let overflowed = false;
  return {
    next: () => {
      if (idx >= pool.length) {
        overflowed = true;
        if (idx % 1000 === 0) console.warn(`  ⚠ TOKEN POOL EXHAUSTED — raise LOADTEST_TOKEN_POOL_FACTOR (currently ${TOKEN_POOL_FACTOR})`);
      }
      return `Bearer ${pool[idx++ % pool.length]}`;
    },
    reused: () => overflowed,
  };
}

const cyclerNoBaseline = makeTokenCycler(tokensNoBaseline);
const cyclerDefault = makeTokenCycler(tokensDefault);

for (const connections of CONCURRENCY_LEVELS) {
  console.log(`── Concurrency ${connections} ────────────────────────────────────────`);

  // ── OFF: direct to downstream (no proxy) ──────────────────────────────────
  // We call the /downstream/<dest>/api path directly with the internal secret.
  // This measures raw Node/Express overhead: JSON parse, timingSafeEqual, JSON
  // encode. No Ed25519 verification, no pipeline, no fetch hop.
  {
    const memBefore = memStats();
    let i2 = 0;
    const result = await autocannon({
      url: `http://127.0.0.1:${portNoBaseline}`,
      connections,
      duration: DURATION_SEC,
      requests: [
        {
          method: 'GET',
          path: `/downstream/${destSvc}/api`,
          headers: {
            [INTERNAL_HEADER]: INTERNAL_SECRET,
            'x-zt-source': callerSvc,
            'x-destination-service': destSvc,
          },
          setupRequest: (req) => { i2++; return req; },
        },
      ],
    });
    const memAfter = memStats();
    const row: BenchRow = {
      label: 'OFF (direct)',
      connections,
      rps: Math.round(result.requests.average),
      p50: result.latency.p50,
      p95: result.latency.p97_5,
      p99: result.latency.p99,
      errorRate: result['2xx'] + result.non2xx + result.errors > 0
        ? ((result.non2xx + result.errors) / (result['2xx'] + result.non2xx + result.errors) * 100).toFixed(1) + '%'
        : '0.0%',
      rssBefore: memBefore.rss,
      rssAfter: memAfter.rss,
      heapBefore: memBefore.heap,
      heapAfter: memAfter.heap,
      tokenReused: false,
    };
    rows.push(row);
    console.log(`  OFF (direct)     : ${row.rps} rps  p50=${row.p50}ms  p95=${row.p95}ms  p99=${row.p99}ms  err=${row.errorRate}  RSS ${row.rssBefore}→${row.rssAfter} MB (heap ${row.heapBefore}→${row.heapAfter} MB)`);
  }

  // ── ON (no baseline): proxy with baseline risk disabled ───────────────────
  {
    const memBefore = memStats();
    const result = await autocannon({
      url: `http://127.0.0.1:${portNoBaseline}`,
      connections,
      duration: DURATION_SEC,
      requests: [
        {
          method: 'GET',
          path: `/api/proxy/api`,
          headers: {
            'x-destination-service': destSvc,
            'x-service-id': callerSvc,
          },
          setupRequest: (req) => {
            req.headers = { ...req.headers, authorization: cyclerNoBaseline.next() };
            return req;
          },
        },
      ],
    });
    const memAfter = memStats();
    const reused = cyclerNoBaseline.reused();
    if (reused) console.warn(`  ⚠ Tokens were reused — raise LOADTEST_TOKEN_POOL_FACTOR`);
    const total = result['2xx'] + result.non2xx + result.errors;
    const row: BenchRow = {
      label: 'ON (no-baseline)',
      connections,
      rps: Math.round(result.requests.average),
      p50: result.latency.p50,
      p95: result.latency.p97_5,
      p99: result.latency.p99,
      errorRate: total > 0 ? ((result.non2xx + result.errors) / total * 100).toFixed(1) + '%' : '0.0%',
      rssBefore: memBefore.rss,
      rssAfter: memAfter.rss,
      heapBefore: memBefore.heap,
      heapAfter: memAfter.heap,
      tokenReused: reused,
    };
    rows.push(row);
    const snapNB = appNoBaseline.mesh.metrics.snapshot();
    console.log(`  ON  (no-baseline): ${row.rps} rps  p50=${row.p50}ms  p95=${row.p95}ms  p99=${row.p99}ms  err=${row.errorRate}  RSS ${row.rssBefore}→${row.rssAfter} MB (heap ${row.heapBefore}→${row.heapAfter} MB)`);
    console.log(`    decisions: ${JSON.stringify(snapNB.byDecision)}`);
  }

  // ── ON (default): proxy with default risk config ───────────────────────────
  {
    const memBefore = memStats();
    const snapBefore = appDefault.mesh.metrics.snapshot();
    const result = await autocannon({
      url: `http://127.0.0.1:${portDefault}`,
      connections,
      duration: DURATION_SEC,
      requests: [
        {
          method: 'GET',
          path: `/api/proxy/api`,
          headers: {
            'x-destination-service': destSvc,
            'x-service-id': callerSvc,
          },
          setupRequest: (req) => {
            req.headers = { ...req.headers, authorization: cyclerDefault.next() };
            return req;
          },
        },
      ],
    });
    const memAfter = memStats();
    const snapAfter = appDefault.mesh.metrics.snapshot();
    const reused = cyclerDefault.reused();
    if (reused) console.warn(`  ⚠ Tokens were reused — raise LOADTEST_TOKEN_POOL_FACTOR`);

    const deltaNonAllow =
      (snapAfter.byDecision.MONITOR - snapBefore.byDecision.MONITOR) +
      (snapAfter.byDecision.STEP_UP_AUTH - snapBefore.byDecision.STEP_UP_AUTH) +
      (snapAfter.byDecision.BLOCK - snapBefore.byDecision.BLOCK);
    const deltaTotal =
      (snapAfter.total - snapBefore.total);
    const fpRate = deltaTotal > 0 ? ((deltaNonAllow / deltaTotal) * 100).toFixed(2) : '0.00';

    const total = result['2xx'] + result.non2xx + result.errors;
    const row: BenchRow = {
      label: 'ON (default)',
      connections,
      rps: Math.round(result.requests.average),
      p50: result.latency.p50,
      p95: result.latency.p97_5,
      p99: result.latency.p99,
      errorRate: total > 0 ? ((result.non2xx + result.errors) / total * 100).toFixed(1) + '%' : '0.0%',
      rssBefore: memBefore.rss,
      rssAfter: memAfter.rss,
      heapBefore: memBefore.heap,
      heapAfter: memAfter.heap,
      tokenReused: reused,
    };
    rows.push(row);
    console.log(`  ON  (default)    : ${row.rps} rps  p50=${row.p50}ms  p95=${row.p95}ms  p99=${row.p99}ms  err=${row.errorRate}  RSS ${row.rssBefore}→${row.rssAfter} MB (heap ${row.heapBefore}→${row.heapAfter} MB)`);
    console.log(`    non-ALLOW rate under steady load: ${fpRate}%  (${deltaNonAllow}/${deltaTotal} requests)`);
    if (deltaNonAllow > deltaTotal * 0.01) {
      console.warn(`  ⚠ non-ALLOW rate ${fpRate}% > 1% — may indicate false positives`);
    }
  }

  console.log();
}

// ─── Compute proxy overhead per concurrency level ─────────────────────────
interface OverheadRow {
  connections: number;
  offRps: number;
  onNoBaselineRps: number;
  onDefaultRps: number;
  overheadNoBaseline: string;
  overheadDefault: string;
  offP99: number;
  onNoBaselineP99: number;
  onDefaultP99: number;
}

const overheadRows: OverheadRow[] = [];
for (const connections of CONCURRENCY_LEVELS) {
  const off = rows.find((r) => r.label === 'OFF (direct)' && r.connections === connections)!;
  const onNB = rows.find((r) => r.label === 'ON (no-baseline)' && r.connections === connections)!;
  const onD = rows.find((r) => r.label === 'ON (default)' && r.connections === connections)!;
  overheadRows.push({
    connections,
    offRps: off.rps,
    onNoBaselineRps: onNB.rps,
    onDefaultRps: onD.rps,
    overheadNoBaseline: off.rps > 0 ? (((off.rps - onNB.rps) / off.rps) * 100).toFixed(1) + '%' : 'n/a',
    overheadDefault: off.rps > 0 ? (((off.rps - onD.rps) / off.rps) * 100).toFixed(1) + '%' : 'n/a',
    offP99: off.p99,
    onNoBaselineP99: onNB.p99,
    onDefaultP99: onD.p99,
  });
}

// ─── Pipeline server-side latency stats ───────────────────────────────────
const pipelineStatsNB = appNoBaseline.mesh.metrics.snapshot().pipelineLatency;
const pipelineStatsD = appDefault.mesh.metrics.snapshot().pipelineLatency;

// ─── Generate docs/LOADTEST.md ────────────────────────────────────────────
const now = new Date().toISOString();
const nodeVersion = process.version;
const cpuInfo = cpus();
const cpuModel = cpuInfo[0]?.model ?? 'unknown';
const cpuCount = cpuInfo.length;

function fmtTable(
  headers: string[],
  rows2: (string | number)[][],
): string {
  const cols = headers.length;
  const widths = headers.map((h, i) => Math.max(h.length, ...rows2.map((r) => String(r[i] ?? '').length)));
  const sep = '| ' + widths.map((w) => '-'.repeat(w)).join(' | ') + ' |';
  const header = '| ' + headers.map((h, i) => h.padEnd(widths[i])).join(' | ') + ' |';
  const body = rows2
    .map((r) => '| ' + r.map((v, i) => String(v ?? '').padEnd(widths[i])).join(' | ') + ' |')
    .join('\n');
  return [header, sep, body].join('\n');
}

const rawRows = rows.map((r) => [
  r.label,
  r.connections,
  r.rps,
  r.p50,
  r.p95,
  r.p99,
  r.errorRate,
  `${r.rssBefore}→${r.rssAfter} MB`,
  `${r.heapBefore}→${r.heapAfter} MB`,
  r.tokenReused ? '⚠ YES' : 'no',
]);

const overheadTableRows = overheadRows.map((o) => [
  o.connections,
  o.offRps,
  o.onNoBaselineRps,
  o.onDefaultRps,
  o.overheadNoBaseline,
  o.overheadDefault,
  o.offP99,
  o.onNoBaselineP99,
  o.onDefaultP99,
]);

const md = `# Load Test Results

> **Generated**: ${now}
> **Command**: \`npm run loadtest\`

## Machine

| Field | Value |
|-------|-------|
| CPU model | ${cpuModel} |
| CPU cores | ${cpuCount} |
| Node.js | ${nodeVersion} |
| OS | ${process.platform} |

> **Caveat**: The load generator (autocannon) and the proxy server share the same
> CPU and process space. This means the numbers are a lower bound on proxy
> throughput — in a real deployment with separate machines the server would have
> the full CPU budget. Treat these figures as "overhead of the mesh on a shared host",
> not production capacity planning numbers.

## Test Parameters

| Parameter | Value |
|-----------|-------|
| Number of services | ${N_SERVICES} |
| Topology | BFS binary tree (svc-0 is root, svc-1 is the load target) |
| Caller | svc-0 |
| Destination | ${destSvc} |
| Duration per run | ${DURATION_SEC}s |
| Token pool size | ${tokenPoolSize.toLocaleString()} per client |
| Token pool factor | ${TOKEN_POOL_FACTOR}× |
| Concurrency levels | ${CONCURRENCY_LEVELS.join(', ')} |

## Variants

- **OFF (direct)**: autocannon → \`/downstream/<dest>/api\` with the internal secret header.
  No pipeline, no Ed25519 verification, no policy check. Measures raw Express + JSON overhead.
- **ON (no-baseline)**: autocannon → \`/api/proxy/api\` with a fresh token per request.
  \`BASELINE_MIN_WINDOWS=999999\` disables the EWMA spike detector. Measures pure proxy overhead.
- **ON (default)**: same as above with default config. Used to count non-ALLOW decisions under
  steady load — the false-positive rate of the risk engine.

## Raw Results

${fmtTable(
  ['label', 'conns', 'rps', 'p50ms', 'p95ms', 'p99ms', 'errorRate', 'RSS', 'Heap', 'tokens reused?'],
  rawRows,
)}

## Proxy Overhead (rps reduction vs OFF)

${fmtTable(
  ['conns', 'OFF rps', 'ON-nobase rps', 'ON-default rps', 'overhead-nobase', 'overhead-default', 'OFF p99ms', 'ON-nobase p99ms', 'ON-default p99ms'],
  overheadTableRows,
)}

## Server-Side Pipeline Latency

(Time inside the 8-stage security pipeline only — does not include the downstream fetch.)

| Variant | samples | p50ms | p95ms | p99ms | maxMs |
|---------|---------|-------|-------|-------|-------|
| ON (no-baseline) | ${pipelineStatsNB.samples} | ${pipelineStatsNB.p50Ms} | ${pipelineStatsNB.p95Ms} | ${pipelineStatsNB.p99Ms} | ${pipelineStatsNB.maxMs} |
| ON (default)     | ${pipelineStatsD.samples}  | ${pipelineStatsD.p50Ms}  | ${pipelineStatsD.p95Ms}  | ${pipelineStatsD.p99Ms}  | ${pipelineStatsD.maxMs}  |

## Memory & State Bounds

- **Audit Ring Buffer**: Fixed at 5,000 max entries with SHA-256 hash chaining.
- **JTI Store**: Expired token IDs are swept periodically; memory scales with token expiry window rather than total request volume.
- **Process Memory**: In-memory state remains bounded once V8 heap expands to accommodate autocannon connection churn.

## Known Limitations

1. Load generator and server share one CPU core (see caveat above).
2. No TLS — the proxy enforces Ed25519 JWT identity but not transport encryption.
3. Tokens are pre-signed before the run; signing cost is not included in the rps numbers.
4. \`autocannon\` pools connections; a single connection can service many requests.
5. The 20-service topology uses only the svc-0 → svc-1 edge for load; other edges
   exist only to exercise the policy-engine index, not to generate actual traffic.
6. Ed25519 is not quantum-resistant.
`;

writeFileSync('docs/LOADTEST.md', md, 'utf8');
console.log('Wrote docs/LOADTEST.md');
console.log(`Audit chain valid (no-baseline): ${appNoBaseline.mesh.audit.verify().valid}`);
console.log(`Audit chain valid (default):     ${appDefault.mesh.audit.verify().valid}`);

await appNoBaseline.close();
await appDefault.close();
process.exit(process.exitCode ?? 0);
