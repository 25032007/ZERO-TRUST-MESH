# Load Test Results

> **Generated**: 2026-10-04T19:19:14.624Z
> **Command**: `npm run loadtest`

## Machine

| Field | Value |
|-------|-------|
| CPU model | 12th Gen Intel(R) Core(TM) i5-12450HX |
| CPU cores | 12 |
| Node.js | v24.14.0 |
| OS | win32 |

> **Caveat**: The load generator (autocannon) and the proxy server share the same
> CPU and process space. This means the numbers are a lower bound on proxy
> throughput — in a real deployment with separate machines the server would have
> the full CPU budget. Treat these figures as "overhead of the mesh on a shared host",
> not production capacity planning numbers.

## Test Parameters

| Parameter | Value |
|-----------|-------|
| Number of services | 20 |
| Topology | BFS binary tree (svc-0 is root, svc-1 is the load target) |
| Caller | svc-0 |
| Destination | svc-1 |
| Duration per run | 8s |
| Token pool size | 216,000 per client |
| Token pool factor | 3× |
| Concurrency levels | 10, 50, 100 |

## Variants

- **OFF (direct)**: autocannon → `/downstream/<dest>/api` with the internal secret header.
  No pipeline, no Ed25519 verification, no policy check. Measures raw Express + JSON overhead.
- **ON (no-baseline)**: autocannon → `/api/proxy/api` with a fresh token per request.
  `BASELINE_MIN_WINDOWS=999999` disables the EWMA spike detector. Measures pure proxy overhead.
- **ON (default)**: same as above with default config. Used to count non-ALLOW decisions under
  steady load — the false-positive rate of the risk engine.

## Raw Results

| label            | conns | rps  | p50ms | p95ms | p99ms | errorRate | RSS          | Heap       | tokens reused? |
| ---------------- | ----- | ---- | ----- | ----- | ----- | --------- | ------------ | ---------- | -------------- |
| OFF (direct)     | 10    | 7921 | 0     | 4     | 6     | 0.0%      | 490→501 MB   | 339→331 MB | no             |
| ON (no-baseline) | 10    | 457  | 20    | 34    | 47    | 0.0%      | 501→556 MB   | 331→390 MB | no             |
| ON (default)     | 10    | 484  | 19    | 33    | 36    | 0.0%      | 557→623 MB   | 391→435 MB | no             |
| OFF (direct)     | 50    | 2489 | 19    | 35    | 45    | 0.0%      | 623→634 MB   | 436→459 MB | no             |
| ON (no-baseline) | 50    | 2513 | 15    | 83    | 94    | 0.0%      | 634→823 MB   | 459→615 MB | no             |
| ON (default)     | 50    | 3107 | 14    | 21    | 26    | 0.0%      | 823→1210 MB  | 618→420 MB | no             |
| OFF (direct)     | 100   | 4372 | 11    | 67    | 78    | 0.0%      | 1210→1211 MB | 423→429 MB | no             |
| ON (no-baseline) | 100   | 600  | 164   | 202   | 283   | 0.0%      | 1211→1213 MB | 429→527 MB | no             |
| ON (default)     | 100   | 532  | 174   | 282   | 485   | 0.0%      | 1213→1218 MB | 530→592 MB | no             |

## Proxy Overhead (rps reduction vs OFF)

| conns | OFF rps | ON-nobase rps | ON-default rps | overhead-nobase | overhead-default | OFF p99ms | ON-nobase p99ms | ON-default p99ms |
| ----- | ------- | ------------- | -------------- | --------------- | ---------------- | --------- | --------------- | ---------------- |
| 10    | 7921    | 457           | 484            | 94.2%           | 93.9%            | 6         | 47              | 36               |
| 50    | 2489    | 2513          | 3107           | -1.0%           | -24.8%           | 45        | 94              | 26               |
| 100   | 4372    | 600           | 532            | 86.3%           | 87.8%            | 78        | 283             | 485              |

## Server-Side Pipeline Latency

(Time inside the 8-stage security pipeline only — does not include the downstream fetch.)

| Variant | samples | p50ms | p95ms | p99ms | maxMs |
|---------|---------|-------|-------|-------|-------|
| ON (no-baseline) | 10000 | 5.967 | 37.195 | 53.911 | 132.111 |
| ON (default)     | 10000  | 4.347  | 46.675  | 63.575  | 113.788  |

## Memory & State Bounds

- **Audit Ring Buffer**: Fixed at 5,000 max entries with SHA-256 hash chaining.
- **JTI Store**: Expired token IDs are swept periodically; memory scales with token expiry window rather than total request volume.
- **Process Memory**: In-memory state remains bounded once V8 heap expands to accommodate autocannon connection churn.

## Known Limitations

1. Load generator and server share one CPU core (see caveat above).
2. No TLS — the proxy enforces Ed25519 JWT identity but not transport encryption.
3. Tokens are pre-signed before the run; signing cost is not included in the rps numbers.
4. `autocannon` pools connections; a single connection can service many requests.
5. The 20-service topology uses only the svc-0 → svc-1 edge for load; other edges
   exist only to exercise the policy-engine index, not to generate actual traffic.
6. Ed25519 is not quantum-resistant.
