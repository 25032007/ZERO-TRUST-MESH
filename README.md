# Zero-Trust Mesh

**An explainable, real-time zero-trust enforcement and threat-intelligence platform for service-to-service communication.**

Every request between services is authenticated by workload identity, authorized against default-deny policy-as-code, scored with an explainable risk model, recorded in a tamper-evident audit log — and then normalized into threat signals that are correlated into findings, investigations, and reconstructed attack paths for a live security-operations console. All enforcement is policy-driven and deterministic; behavioral analysis uses statistical techniques (per-pair EWMA baselines, z-scores). There is no ML/AI detection in this system.

## Overview

In a microservice environment the network perimeter is meaningless: services call each other constantly, and a compromised service is already "inside." Perimeter security cannot answer the questions that matter — *which workload is calling, is it allowed to, and does this particular request look wrong?*

Zero-Trust Mesh answers them on every request by applying zero-trust principles directly at the service-to-service layer:

- **Never trust, always verify** — every request carries an Ed25519-signed JWT proving workload identity; the proxy holds public keys only.
- **Explicit authorization** — default-deny JSON policies decide each `source → destination` edge; anything unlisted is blocked.
- **Continuous monitoring** — payload shape, per-pair request rates, and multi-hop traversal are observed on every request and folded into an explainable risk score.
- **Assume breach** — lateral-movement detection and quarantine isolate a pivoting service within the same request path.
- **From signals to intelligence** — each completed pipeline verdict is normalized into typed signals and evidence, correlated across requests/traces/edges, and assessed into categorized threat findings with severity and confidence — an additive analytical layer that never overrides enforcement.

## Key Capabilities

All items below are implemented and covered by tests (`npm test`: 173 passing, 23 test files):

- **Workload identity** — Ed25519 JWTs, algorithm pinned to EdDSA (never read from the token), audience and lifetime enforced.
- **Anti-spoofing** — the attacker-controlled `X-Service-ID` header is cross-checked against the cryptographic identity (`IDENTITY_MISMATCH`).
- **Replay protection** — single-use `jti` enforced server-side; the replay check runs *after* signature verification so attackers cannot burn a victim's token id.
- **Revocation** — per-key revocation (immediate, no grace) and per-token (`jti`) revocation over the admin API.
- **Default-deny authorization** — priority-ordered JSON policies with allow/deny effects, method/path allow- and deny-lists, time windows, and declared workflows.
- **Policy-as-code operations** — strict schema validation (typos are errors), atomic hot reload, invalid edits rejected with the old policies kept, fail-fast startup, per-policy and global dry-run.
- **Rate limiting** — per-IP quota (5× service quota, checked before crypto) plus per-authenticated-service quota.
- **Payload anomaly detection** — size/depth limits plus per-pair statistical (z-score) size checks that need history before they trust themselves.
- **Behavioral baselines** — per-service-pair rolling EWMA rate baselines with warm-up, winsorised learning, and silence-aware decay (baseline mode); fixed thresholds retained for comparison.
- **Lateral-movement detection** — ≥3 distinct service hops inside 1 s within one trace → block + quarantine; declared workflows exempt.
- **Quarantine** — automatic isolation on lateral movement or critical risk (60 s default, auto-release), with admin release.
- **Step-up authentication** — high-risk requests get `STEP_UP_AUTH` (401 + `WWW-Authenticate` challenge) and must retry with a single-use TOTP code.
- **Explainable risk scoring** — `score = min(100, Σ factor points)`; every point carries a named factor code and human-readable detail; hard failures get fixed severities instead.
- **Threat taxonomy, correlation, assessment** — 8 categories, bounded in-memory correlation with recurrence tracking and contribution deduplication, plus separate severity (category/recurrence rules) and confidence (4 × 25-point criteria) models.
- **Attack-path reconstruction** — trace-correlated findings chain into ordered service paths from observed evidence only.
- **Least-privilege recommender** — advisory-only; proposes narrowing/removal plus a trial policy document for dry-run, never auto-applies.
- **Tamper-evident audit log** — hash-chained, ring-buffered, with a verify endpoint.
- **Real-time operations** — REST dashboard APIs, one WebSocket carrying versioned `decision` and `threat.finding.v1` events, metrics snapshots.
- **SOC console** — 14-view frontend (overview through attack simulator) that renders authoritative backend data and computes no verdicts itself.

## Architecture

```
                        ┌─ SecurityPipeline (authoritative enforcement) ────────┐
                        │                                                        │
Client request ──► rate_limit (IP) ──► authentication (+anti-spoof, svc quota) ─►│
                        │ quarantine ──► authorization (default-deny policy) ────►│
                        │ payload_anomaly ──► lateral_movement ──► risk_scoring ─►│
                        │ decision: ALLOW / MONITOR / STEP_UP_AUTH / BLOCK ─────►│
                        └──────────────┬───────────────────────┬─────────────────┘
                                       │ audit + metrics       │ decision event (WS)
                                       ▼                       ▼
                                  AuditLog (hash chain)   EventBus ──► /ws ──► SOC console
                                  MetricsCollector             │
                                                               ▼ threat fan-out (additive)
                        ┌─ ThreatIntelligence (analytical, never enforces) ──────┐
                        │ normalize verdict ──► signals + evidence ──► correlate │
                        │ ──► assess (exposure/confidence/severity) ──► findings │
                        └──────────────┬───────────────────────┬─────────────────┘
                                       │ read-only REST        │ threat.finding.v1 (WS)
                                       ▼                       ▼
                                  SOC console: findings, investigations,
                                  categories, attack paths
```

**Authoritative components:** `SecurityPipeline` (verdicts), `RiskEngine` (scores), `PolicyEngine` (authorization), `ThreatCorrelator` (findings), `AuditLog` (record). The frontend, the recommender, and the threat layer are consumers — none of them can change a verdict. Threat Intelligence observes *finalized* results inside a `try/catch` that cannot interrupt the proxy.

## Security Pipeline

Each request to `/api/proxy/*` passes eight stages in order (cheap checks first, identity before anything that trusts a name):

1. **Rate limit (IP)** — socket-address quota; protects the proxy before crypto is spent.
2. **Authentication** — Ed25519 verification, expiry, audience, lifetime cap, single-use `jti`; then anti-spoofing (`X-Service-ID` vs. token identity); then the per-service quota. Failures are recorded per IP (never per claimed service, so victims cannot be framed).
3. **Quarantine** — isolated services are rejected immediately.
4. **Authorization** — default-deny policy evaluation; denials are recorded for the recommender; dry-run violations are flagged and let through for observation.
5. **Payload anomaly** — size/depth/statistical checks, learned per service pair.
6. **Lateral movement** — trace observation; detection quarantines the pivot service.
7. **Risk scoring** — explainable sum of soft-signal factors (0–100).
8. **Decision** — lateral movement overrides to `BLOCK`; otherwise the score maps to a verdict.

Then: audit record appended, metrics recorded, decision event published, threat observation recorded. **Hard failures** (bad signature, replay, no policy, …) reject immediately with a fixed severity from `src/config.ts` (e.g. `INVALID_SIGNATURE: 95`, `TOKEN_REPLAY: 90`, `NO_POLICY: 70`) and never reach scoring.

## Risk Model

```
score = min(100, Σ points of every triggered factor)
```

Default factor points (`src/config.ts`): new service pair 10, sensitive endpoint 10, off-hours 5, elevated/abnormal frequency 10/20 (fixed mode), rate-spike elevated/high 10/20 (baseline mode), per recent auth failure 5 (max 25), lateral movement 50; payload anomaly up to 50 (size 25, depth 25, z-score 15). Default decision thresholds: **≥30 MONITOR** (forwarded, flagged), **≥60 STEP_UP_AUTH** (held, TOTP required), **≥80 BLOCK + quarantine**. Risk levels: `LOW <30`, `MEDIUM 30+`, `HIGH 60+`, `CRITICAL 80+`. All thresholds and points are environment-overridable (see `.env.example`).

Risk, severity, and confidence are deliberately separate models:

| Concept | Meaning | Decided by |
|---|---|---|
| **Risk** (0–100) | Assessed danger of the observed request/behavior | `RiskEngine` (or fixed severity for hard failures); drives enforcement |
| **Severity** (`LOW…CRITICAL`) | Inherent impact of a threat *finding* | Category/recurrence rules (e.g. lateral movement is always `CRITICAL`, replay is `HIGH`) — never a proxy for the score |
| **Confidence** (0–100) | Strength/completeness of supporting evidence | Four fixed 25-point criteria: detector validity, evidence completeness, corroboration, correlation quality |

Severity and confidence never replace or recompute the enforcement risk score.

## Threat Intelligence

```
PipelineResult ──► normalize ──► NormalizedSignals + Evidence ──► correlate
    ──► assess (category exposure, confidence, severity) ──► ThreatFinding
    ──► read-only API + WS events ──► investigation / attack path / console
```

- **Normalization** maps pipeline reasons and risk factors to typed signals (`TOKEN_REPLAY`, `POLICY_DENIED`, `RATE_SPIKE`, …) with roles (`threat_signal` vs. `contextual_evidence` vs. `control_outcome` vs. `decision_context`), plus primitive-only evidence (no payloads, tokens, or secrets by construction).
- **Taxonomy** (8 categories, from `src/threat/contracts.ts`): `IDENTITY_COMPROMISE`, `AUTHENTICATION_TOKEN_ABUSE`, `AUTHORIZATION_POLICY_VIOLATION`, `BEHAVIORAL_ANOMALY`, `LATERAL_MOVEMENT`, `RECONNAISSANCE_PROBING`, `REQUEST_PAYLOAD_ABUSE`, `SERVICE_GRAPH_ANOMALY`.
- **Category exposure** sums *unique* factor-contribution points per category (capped at 100). It is explanatory — where correlated exposure concentrates — and is never added to enforcement risk.

## Threat Findings / Correlation

- **Lifecycle** — findings open on first correlated signal and update on recurrence (count, first/last seen, latest decision context, max risk); entries expire outside the correlation window (60 s; 1 s for traces) and capacity evicts oldest-first (max 5,000 active findings, 100 evidence refs each; observations ring-capped at 5,000).
- **Correlation keys** — `trace:<id>` (lateral movement), `edge:<src>-><dst>`, `service:<id>`, or `request:<id>` fallback.
- **Deduplication** — risk contribution ids and evidence ids are appended uniquely and bounded, so recurrence can never inflate or duplicate proof.
- **Attack paths** — reconstructed only from stored trace evidence (ordered service chain + trace id + timestamps). The API returns `{paths, totalActiveFindings}` so clients can distinguish *no data yet* from a *valid empty* result. Nothing is inferred beyond observed evidence.
- **Limitation (honest)** — threat history is bounded and in-memory: a restart clears findings, and there is no persistent historical analytics store. The API is read-only; there are no analyst write/disposition actions yet.

## Recommendation System

The least-privilege engine (`GET /api/policies/recommendations`) is a pure function over current policies plus observed usage. It emits `REMOVE_UNUSED_POLICY`, `NARROW_METHODS`, `NARROW_PATHS`, `REVIEW_DENIED_EDGE`, or `INSUFFICIENT_DATA`. Safety rules: no advice before 10 minutes of observation or 20 hits per policy; denied edges are surfaced for *human* review only (an attack and a missing permission look identical); output includes a tightened policy document meant to be trialed with `DRY_RUN=true`. Recommendations never block, quarantine, or modify policy. Not AI-generated.

## Real-Time Operations

- **REST** — metrics snapshot (`byDecision`, throughput, pipeline latency percentiles, dry-run count), audit records + verify + summary, services, policies + status + recommendations, quarantine list, JWKS, simulator controls, and the `/api/threats/*` family (see table below).
- **WebSocket** (`/ws`, same connection for everything) — `{type: "decision", data: PipelineResult}` on every verdict; `{type: "threat.finding.v1", data: FindingSummary}` per correlated finding. Threat events upsert console state; they never enter the decision feed.
- **Simulator** — 13 scenarios (normal traffic + unauthorized access, forbidden sub-path, expired/tampered/replayed tokens, `alg:none`, HS256 confusion, wrong audience, spoofing, lateral movement, payload bomb, TOTP step-up) executed as real forged traffic through the live pipeline via `POST /api/simulator/run-all` or `npm run demo` (exits 1 on any failure).

## Frontend / Security Operations Console

`public/index.html` (no framework, no extra dependencies) consumes REST + the single WebSocket and computes no security values. Views: **Overview** (posture, decision distribution, attention queue), **Live Operations** (filterable decision stream + event-investigation workspace with identity/why/timeline/decision-context), **Threat Findings** (severity/risk/confidence list + finding detail with signals and evidence), **Investigations** (per-correlation-key evidence/timeline/decisions), **Threat Categories** (exposure vs. severity vs. confidence vs. risk), **Attack Paths** (observed hop chains), **Service Map** (policy-derived relationships, default-deny statement), **Service Activity**, **Behavioral Anomalies**, **Policies**, **Containment** (quarantine + audit-chain status), **Audit**, **Recommendations**, **Attack Simulator**. Light/dark themes, responsive down to mobile, keyboard-accessible with visible focus and text-plus-color status.

## API Overview

| Endpoint | Purpose |
|---|---|
| `ANY /api/proxy/*` | Enforced entry point (Bearer token + `X-Destination-Service`) |
| `GET /healthz` | Liveness |
| `GET /api/metrics` | Decision counts, throughput, pipeline latency, dry-run violations |
| `GET /api/services` | Registered services (public halves only) |
| `GET /api/policies`, `GET /api/policies/status` | Active policies + file version info |
| `GET /api/policies/recommendations` | Least-privilege report + trial policy document |
| `GET /api/quarantine` | Currently isolated services |
| `GET /api/audit`, `GET /api/audit/verify`, `GET /api/audit/summary` | Records (filterable), hash-chain verification, counts |
| `GET /.well-known/jwks.json` | Valid public keys (RFC 7517) |
| `GET /api/threats/findings` | Active findings — bounded, filterable, paginated (`limit`, `cursor`) |
| `GET /api/threats/findings/:findingId` | One finding with signals, evidence, assessment (404 if expired) |
| `GET /api/threats/categories` | Per-category exposure aggregates |
| `GET /api/threats/investigations/:correlationKey` | Grouped findings + evidence + timeline (404 if none active) |
| `GET /api/threats/attack-paths` | Reconstructed multi-hop paths (honest empty when none) |
| `GET /api/threats/summary` | Compact counts for badges |
| `GET /api/simulator/scenarios`, `POST /api/simulator/run-all`, `POST /api/simulator/:id` | Attack-scenario controls |
| `POST /admin/services`, `/admin/services/:id/rotate-key`, `/admin/services/:id/status`, `/admin/services/:id/keys/:kid/revoke`, `/admin/tokens/revoke`, `/admin/policies/reload`, `/admin/quarantine/:id/release` | Mutating operations — always require `x-admin-key` |
| `WS /ws` | Live `decision` and `threat.finding.v1` events |

Read-only dashboard routes are open when `PUBLIC_DASHBOARD=true` (demo default) and key-protected otherwise; the proxy never mints tokens and there is no unauthenticated token endpoint.

## Running the Project

Requires Node ≥ 20. Copy `.env.example` to `.env` as needed (all settings optional; unset `ADMIN_API_KEY` generates a random one per run, printed at startup).

```bash
npm ci              # install dependencies
npm run dev         # start with live reload (dashboard: http://localhost:4000)
npm run build       # compile to dist/
npm start           # run the compiled build
npm run typecheck   # tsc --noEmit (must be clean before committing)
npm test            # full suite: node:test over test/*.test.ts via tsx
npm run demo        # 13 attack scenarios through the real pipeline (exit 1 on failure)
npm run bench       # autocannon benchmark of the proxy path
npm run evaluate    # detector evaluation harness -> docs/EVALUATION.md
npm run loadtest    # multi-service concurrency sweep -> docs/LOADTEST.md
```

## Testing / Validation

- **173/173 tests passing** across 23 test files (verified with `npm test`): pipeline verdicts, token security (incl. `alg=none`/confusion/replay-after-signature), policy engine + hot reload, risk/baseline math, lateral movement, quarantine framing, audit-chain tamper detection, threat contracts/correlation/assessment, recommender, eval harness, end-to-end HTTP, and the threat-API/WS contract suite.
- `npm run typecheck` and `npm run build` clean; CI runs typecheck, test, build, and demo on Node 20 and 22.
- Simulator regression: 13/13 scenarios behave as expected against the live server; audit chain verifies and metrics reconcile after the run.
- Live-validated: dashboard serves (200), single WebSocket delivers both decision and versioned threat events, all four decisions observed in metrics, attack path reconstructed end-to-end from a real 3-hop trace.

## Evaluation Results

*From `docs/EVALUATION.md` (synthetic data)*

**Tuning Results:** Best parameters found maximizing F1 (subject to FPR <= 1%):
`alpha: 0.1`, `zWarn: 2`, `spikeHighPoints: 15`, `zScorePoints: 10`

**Variant Comparison (1x Load):**
| Variant | Behavioral F1 | FPR |
|---------|---------------|-----|
| Fixed Thresholds | 0.003 ± 0.000 | 0.093 ± 0.059% |
| Baseline Tuned | 0.002 ± 0.000 | 0.000 ± 0.000% |

**Ablation Study (1x Load, Tuned Params):**
- Removing Workflows degrades FPR to `1.332 ± 0.119%`.
- Reverting to Fixed Thresholds increases FPR to `0.093 ± 0.059%`.

**Load Scaling (Baseline Tuned):**
- 1x Load: F1 `0.002 ± 0.000`, FPR `0.000 ± 0.000%`
- 2x Load: F1 `0.001 ± 0.000`, FPR `0.004 ± 0.006%`
- 4x Load: F1 `0.001 ± 0.000`, FPR `0.000 ± 0.000%`

## Load-Test Results

*From `docs/LOADTEST.md` (Node.js v24.14.0 on 12th Gen i5, 20 services)*

**Raw Results (ON - default):**
- 10 connections: 484 rps (p50: 19ms, p99: 36ms)
- 50 connections: 3107 rps (p50: 14ms, p99: 26ms)
- 100 connections: 532 rps (p50: 174ms, p99: 485ms)

**Server-Side Pipeline Latency (ON - default):**
- p50: 4.347 ms
- p95: 46.675 ms
- p99: 63.575 ms

*(Note: Load generator and proxy shared the same CPU, so throughput is a lower bound).*

## Security Design Principles

- **Default deny** — unlisted service pairs are blocked; equal-priority ties fail safe.
- **Least privilege** — usage-tracked policies plus an advisory tightener that proposes before enforcing.
- **Workload identity** — cryptographic service identity with pinned algorithms, anti-spoof binding, and single-use tokens.
- **Defense in depth** — eight ordered gates from IP quota to risk decision; a bypass in one layer still faces the rest.
- **Explicit authorization** — policy-as-code with strict validation, atomic reloads, and dry-run rollout.
- **Explainability** — risk is a named-factor sum; findings carry signals, evidence, and assessment rationale.
- **Evidence-based assessment** — severity and confidence derive from stored proof under fixed rules, never from gut feel or from the risk score.
- **Deterministic enforcement** — same inputs, same verdict; statistical methods are confined to observation and scoring inputs.
- **Bounded state** — capped maps, ring buffers, and capacity-evicted correlation so memory cannot grow unboundedly.
- **Auditability** — every decision hash-chained; tampering is detectable via `/api/audit/verify`.
- **Separation of analysis and enforcement** — threat intelligence observes finalized verdicts and can never change one.

## Known Limitations

- **In-memory state**: JTI store, rate limits, audit log, and threat findings live in memory (a `JtiStore` interface exists for a future Redis backend); restarts clear them.
- **No mTLS**: traffic between proxy and backends is plain HTTP on loopback.
- **Lateral-slow miss**: the `lateral-slow` attack class spreads traversal over 8 s and bypasses the 1 s correlation window by design.
- **Synthetic evaluation**: the evaluation uses synthetic data generated by the same author who wrote the detector, so real-world performance is likely lower.
- **Ed25519 is not quantum-resistant**: cryptographic identity relies on standard Ed25519.
- **Read-only intelligence API**: findings, investigations, and paths are observable but there are no analyst write/disposition actions yet.

## Project Highlights

- Built an 8-stage zero-trust enforcement pipeline (Ed25519 workload identity, anti-spoofing, single-use tokens, default-deny policy-as-code, rate limiting, quarantine, TOTP step-up) with every verdict explained and audit-chained.
- Implemented statistical behavioral detection — per-pair EWMA rate baselines with warm-up and winsorised learning, plus payload z-score analysis — feeding an explainable `min(100, Σ factors)` risk model with fixed-severity hard failures.
- Designed a threat-intelligence layer that normalizes verdicts into typed signals/evidence, correlates them into findings with recurrence and contribution deduplication, and assesses them under three strictly separated models (risk, severity, confidence).
- Exposed findings through a bounded, filterable, versioned read-only API plus additive WebSocket events, and built a 14-view SOC console on top that renders authoritative data and computes no security values itself.
- Validated with 173 passing tests, a 13-scenario live attack simulator, a labeled-traffic evaluation harness with grid-searched tuning, and a 20-service load test — all reproducible via npm scripts.
