# Zero-Trust Mesh

A **zero-trust policy-enforcement proxy for service-to-service traffic**. Every request between microservices is authenticated with a signed identity, checked against a default-deny policy, scored for risk, and recorded in a tamper-evident audit log. Nothing is trusted because it is "inside the network".

> Built as a learning/portfolio project. It is a working reference implementation, **not** a hardened production product — see [Known limitations](#known-limitations).

```
 frontend ──► orders ──► payments ──► database          (the demo topology)
     │            └──────► users ◄────── auth
     └──────► auth
                 every arrow goes through ▼
 ┌───────────────────────────────────────────────────────────────────┐
 │  1 rate limit → 2 authenticate → 3 quarantine → 4 authorise       │
 │  → 5 payload anomaly → 6 lateral movement → 7 risk score → 8 verdict│
 └───────────────────────────────────────────────────────────────────┘
        ALLOW · MONITOR · STEP_UP_AUTH (TOTP) · BLOCK (+ quarantine)
```

## Quick start

```bash
npm install
npm test            # 139 tests
npm run demo        # runs 13 real attack scenarios, prints PASS/FAIL table
npm run dev         # http://localhost:4000  (live dashboard + simulator)
npm run evaluate    # grid-search tuning + multi-seed eval → docs/EVALUATION.md
```

Docker: `docker build -t zero-trust-mesh . && docker run -p 4000:4000 -e ADMIN_API_KEY=change-me -e PUBLIC_DASHBOARD=false zero-trust-mesh`

## What it does

| Capability | How it works |
|---|---|
| **Workload identity** | Each service owns an Ed25519 private key and signs its own 60 s tokens. The proxy stores **public keys only**, so there are no private keys to steal from it and no "mint a token" endpoint. |
| **Algorithm pinning** | Only `EdDSA` is accepted regardless of the token header → defeats `alg=none` and HS256-key-confusion attacks. |
| **Single-use tokens** | Every `jti` is accepted once → replay attacks are rejected. Replay check runs *after* signature verification. |
| **Anti-spoofing** | `X-Service-ID` is untrusted; if it contradicts the cryptographic identity the request is blocked. |
| **Default-deny policy** | Per (source → destination): methods, allowed paths, denied sub-paths, optional UTC time window. |
| **Explainable risk score** | `score = Σ factors` (list below). The response and audit log show each factor. |
| **Lateral-movement detection** | ≥ 3 distinct hops inside one `X-Trace-Id` within 1 s → block + quarantine the pivot service. |
| **Step-up auth** | High-risk requests need a one-time TOTP (RFC 6238, implemented in `src/crypto/totp.ts`, verified against RFC test vectors). |
| **Containment** | Automatic, time-limited quarantine; manual release via admin API. |
| **Tamper-evident audit log** | SHA-256 hash chain; `GET /api/audit/verify` detects edited or deleted entries. |
| **Key rotation** | New key goes live immediately, old key verifies for a configurable grace period (`KEY_ROTATION_MS`). Automatic rotation scheduler included. |
| **JWKS endpoint** | `GET /.well-known/jwks.json` — public keys in standard format, expired/disabled keys excluded. Admin can revoke a key immediately. |
| **Least-privilege recommender** | `GET /api/policies/recommendations` — tracks actual permission usage and suggests narrowing methods/paths, dropping unused policies, and flagging denied edges for human review. |
| **Detector evaluation** | Labeled traffic generator (normal + 8 attack classes) + evaluation harness: precision/recall/FPR at event and episode level, grid-search tuning, ablation study, load-scaling report. |
| **Backend isolation** | Mock backends only answer requests carrying a secret header known to the proxy, so the proxy cannot be bypassed. |

### Risk factors (`src/config.ts` → `points`)

| Factor | Points | Trigger |
|---|---|---|
| `NEW_SERVICE_PAIR` | +10 | first time an edge is seen |
| `SENSITIVE_ENDPOINT` | +10 | destination `database-service` or path under `/admin`, `/secrets`, `/internal` |
| `OFF_HOURS` | +5 | outside 06:00–22:00 UTC |
| `ELEVATED_FREQUENCY` / `ABNORMAL_FREQUENCY` | +10 / +20 | ≥ 50 / ≥ 100 requests from one service in 5 s |
| `PAYLOAD_ANOMALY` | up to +50 | body > 100 KB (+25), JSON depth > 20 (+25), size z-score > 4 (+15) |
| `RECENT_AUTH_FAILURES` | +5 each, max +25 | failed auth from the same **IP** in the last minute |
| `LATERAL_MOVEMENT` | +50 | plus an unconditional block rule |

Verdicts: **< 30** ALLOW · **30–59** MONITOR · **60–79** STEP_UP_AUTH · **≥ 80** BLOCK + quarantine. Hard failures (bad signature, replay, no policy, …) are rejected immediately with a fixed severity.

## Attack simulator (real, not scripted)

`npm run demo` or the dashboard forge genuinely bad requests and send them through the running proxy. Each scenario states what it expects, so it doubles as an end-to-end test (CI fails if a defence stops working).

| Scenario | Observed result |
|---|---|
| Normal request | ALLOW (risk 10) |
| Unauthorised path (frontend → database) | BLOCK `NO_POLICY` |
| Forbidden sub-path (`/database/admin`) | BLOCK `PATH_DENIED` |
| Expired token | BLOCK `TOKEN_EXPIRED` |
| Tampered token (exp edited) | BLOCK `INVALID_SIGNATURE` |
| Replay | 1st ALLOW, 2nd BLOCK `TOKEN_REPLAY` |
| `alg=none` / HS256 confusion | BLOCK `ALG_NOT_ALLOWED` |
| Wrong audience | BLOCK `INVALID_CLAIMS` |
| Header spoofing | BLOCK `IDENTITY_MISMATCH` |
| Lateral movement (3 hops) | hop 3 BLOCK `LATERAL_MOVEMENT`, then `SERVICE_QUARANTINED` |
| Payload bomb | MONITOR (risk 50) |
| Step-up | `STEP_UP_REQUIRED` (60) → retry with TOTP → ALLOW |

## Benchmark (measured, reproducible)

`npm run bench` — full HTTP path (Express → 8-stage pipeline incl. Ed25519 verify → real HTTP hop to a mock backend), 20 connections, 10 s, a **different** pre-signed token per request (tokens are single-use).

Measured in a **1-vCPU sandbox where the load generator, proxy and backend shared one core**:

| | result |
|---|---|
| Throughput | ~830 req/s (~49,800 req/min), 0 errors |
| End-to-end latency p50 / p99 | 20 ms / 92 ms |
| Security pipeline only p50 / p99 | 3.9 ms / 20.8 ms |

These are *overhead numbers on one shared core over loopback*, not capacity planning. Run `npm run bench` on your machine and replace this table with your own figures.

## Project layout

```
src/
  identity/      registry (public keys, rotation, TOTP) · serviceClient (what a service runs)
  token/         tokenVerifier (6-step verification) · jtiStore (replay/revocation)
  policy/        default-deny policy engine + demo topology
  risk/          riskEngine (additive factors) · anomaly (size/depth/z-score)
  detection/     lateralMovement
  security/      rateLimiter · quarantine
  audit/         hash-chained audit log
  observability/ metrics (percentiles) · events (WebSocket stream)
  pipeline/      the 8-stage SecurityPipeline
  simulator/     real attack scenarios
  server.ts      Express adapter · index.ts entry point
public/index.html   live dashboard
  eval/          labeled traffic generator · runner · metrics (precision/recall/FPR/F1)
demoMesh.ts        bootstrap 6 demo services with key registration
test/               139 tests (unit, pipeline, end-to-end over HTTP, eval harness)
scripts/evaluate.ts grid-search tuning + multi-seed evaluation → docs/EVALUATION.md
docs/DESIGN_DECISIONS.md   12 interview Q&As
docs/EVALUATION.md         detector evaluation report (generated by npm run evaluate)
```

## API

| Route | Auth | Purpose |
|---|---|---|
| `ANY /api/proxy/<path>` | Bearer token + `X-Destination-Service` (+ optional `X-Trace-Id`, `X-Service-TOTP`) | enforced entry point |
| `GET /api/metrics`, `/api/audit`, `/api/audit/verify`, `/api/audit/summary`, `/api/policies`, `/api/services`, `/api/quarantine` | none if `PUBLIC_DASHBOARD=true`, else admin key | dashboard data |
| `GET /api/policies/recommendations` | same as dashboard | least-privilege suggestions (min observation window enforced) |
| `POST /api/simulator/:id`, `/api/simulator/run-all` | same as above | run attack scenarios |
| `GET /.well-known/jwks.json` | none (public keys only) | JWKS for external verifiers |
| `POST /admin/services` · `/admin/services/:id/rotate-key` · `/admin/services/:id/status` · `/admin/tokens/revoke` · `/admin/keys/revoke` · `/admin/quarantine/:id/release` | `x-admin-key` always | operations |
| `WS /ws` | same as dashboard | live decision stream |

Response headers on every proxied call: `X-ZT-Decision`, `X-ZT-Reason`, `X-ZT-Risk`, `X-ZT-Request-Id`.

## Configuration

See [`.env.example`](.env.example). All thresholds and point values live in `src/config.ts`.

## Known limitations

- **State is in-memory** (used jtis, rate limits, risk history, quarantine, audit log). Fine for one process; multiple replicas need shared state (Redis). `JtiStore` is an interface for that swap.
- The demo registers services and holds their private keys **in-process** so the simulator/benchmark work out of the box. In a real deployment each service keeps its own key.
- Traffic between proxy and backends is plain HTTP on loopback in the demo; production needs mTLS.
- The audit hash chain detects tampering inside the retained window; it cannot prove the newest entries were not truncated.
- Fixed-window rate limiting allows a 2× burst across a window boundary.
- Lateral-movement detection is heuristic; a legitimately deep, very fast call chain can trigger it (tunable).
- Ed25519 is **not** quantum-resistant.
- The benchmark above is from a single shared core over loopback.
- **Evaluation uses synthetic data** generated by the same author who wrote the detector; scenarios and parameters are co-designed, so numbers in `docs/EVALUATION.md` likely over-estimate real-world performance. Results are labelled "synthetic" throughout.

## License

MIT
