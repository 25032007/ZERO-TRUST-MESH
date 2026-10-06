# Zero-Trust Mesh

> An explainable, real-time zero-trust enforcement and threat-intelligence platform for service-to-service communication.

Every request between services carries a cryptographic workload identity. The mesh verifies that identity, authorizes the call against default-deny policy, scores how suspicious it looks, and records the verdict in a tamper-evident log. Finalized verdicts then flow into an additive intelligence layer that normalizes them into signals, correlates them into findings, and serves them to a live security-operations console. Enforcement stays authoritative; intelligence stays analytical — the two never trade jobs.

## Why this project exists

Authentication alone does not secure service-to-service traffic. A valid token says *who is calling*, but not whether the call is allowed, normal, or part of an attack chain. This project closes that gap:

- workload identity must be **verified**, not trusted from a header;
- authorization must be **explicit** — unlisted service pairs are blocked;
- abnormal behavior (payload shape, request-rate spikes, odd hours) must be **detected** per service pair, not against global magic numbers;
- lateral movement across services must be **constrained** inside a single trace;
- every security decision should be **explainable** down to named, point-valued factors;
- related security events should be **correlated into investigations**, not left as isolated log lines.

## What the system does

### Zero-Trust Enforcement

- Ed25519 JWT workload verification with pinned algorithm, audience, lifetime, and single-use token ids
- Anti-spoofing: the caller header is cross-checked against the cryptographic identity
- Token replay protection (checked after signature verification) and revocation (per-key and per-token)
- Default-deny policy enforcement with priority, allow/deny effects, method/path rules, time windows, dry-run, hot reload, and declared workflows
- Service-aware rate limiting (per-IP quota before crypto, per-service quota after authentication)
- Quarantine enforcement with automatic release
- Payload anomaly detection (size/depth limits plus per-pair statistical checks)
- Lateral-movement detection (3+ distinct hops in 1 s within one trace → block and quarantine)
- Explainable risk scoring: `min(100, Σ factor points)`, every point attributed

### Threat Intelligence

- Signal normalization from finalized pipeline verdicts into typed, role-tagged signals
- Primitive-only evidence generation (no tokens, secrets, or raw payloads by construction)
- Bounded in-memory correlation into findings with recurrence tracking and contribution deduplication
- Category exposure scoring (explanatory — never fed back into enforcement risk)
- Severity assessed from category/recurrence rules; confidence from four fixed 25-point criteria
- Investigations grouped by correlation key; attack paths reconstructed from observed trace evidence
- Deterministic, advisory recommendations with human approval required

### Security Operations

- REST APIs for metrics, audit, policies, quarantine, services, keys, simulator, and threat intelligence
- A single WebSocket streaming live decisions plus versioned `threat.finding.v1` events
- Live operational visibility: decision stream, posture, attention queue, service activity
- Tamper-evident audit trail with one-click chain verification
- Investigation views, threat findings, service map, and a 13-scenario attack simulator firing real forged traffic

## Architecture

Three planes. Enforcement decides; intelligence analyzes; operations presents.

### Enforcement Plane

```text
Client Request
      │
      ▼
IP Rate Limit
      │
      ▼
Workload Authentication
      │
      ├── JWT verification
      ├── anti-spoofing
      └── service quota
      │
      ▼
Quarantine Check
      │
      ▼
Default-Deny Authorization
      │
      ▼
Payload / Behavioral Analysis
      │
      ▼
Lateral Movement Detection
      │
      ▼
Risk Engine
      │
      ▼
Decision
ALLOW / MONITOR / STEP_UP_AUTH / BLOCK
```

Hard security failures (bad signature, replay, no policy, quarantine hit) terminate the request at the failing stage with a fixed severity — later stages do not run for that request. Surviving requests accumulate soft-signal factors into a 0–100 score that maps to a verdict.

### Intelligence Plane

```text
Finalized Pipeline Result
          │
          ▼
Signal Normalization
          │
          ▼
Evidence
          │
          ▼
Correlation
          │
          ▼
Threat Assessment
 ┌────────┼────────┐
 ▼        ▼        ▼
Risk   Severity  Confidence
          │
          ▼
Threat Findings
          │
     ┌────┼─────┐
     ▼    ▼     ▼
Investigations
Attack Paths
Recommendations
```

> Threat Intelligence is analytical and additive. It does not override the finalized enforcement verdict.

Risk here is the pipeline score, copied — not recomputed. Severity and confidence are assessed from stored proof under fixed rules. Category exposure is explanatory context, never an enforcement input.

### Operations Plane

```text
Security Events
      │
      ├── REST API
      └── WebSocket
             │
             ▼
       SOC Console
             │
   ┌─────────┼─────────┐
   ▼         ▼         ▼
Findings  Investigations  Attack Paths
```

One socket, two event types (`decision`, `threat.finding.v1`). The console renders authoritative backend state and computes no verdicts, scores, or correlations itself.

## Security Decision Flow

1. Identify the workload from its signed token — never from its self-declared header.
2. Authenticate the request (signature, expiry, audience, lifetime, single-use id).
3. Apply rate limits (IP, then service) and quarantine controls.
4. Evaluate default-deny authorization policy.
5. Analyze payload and behavioral signals against per-pair baselines.
6. Detect lateral movement within the request trace.
7. Calculate explainable pipeline risk from the triggered factor ledger.
8. Produce an enforcement decision.
9. Record audit, metrics, and live events.
10. Fan the finalized result into the additive threat-intelligence layer.

Three jobs, three owners:

| Layer | Role | Owner |
|---|---|---|
| **Enforcement** | Authoritative: verdicts, scores, blocks, quarantine | `SecurityPipeline`, `RiskEngine`, `PolicyEngine` |
| **Threat Intelligence** | Analytical: signals, findings, severity, confidence | `ThreatIntelligence`, `ThreatCorrelator` |
| **SOC Console** | Presentation and investigation | `public/index.html` (no security logic) |

## Risk Model

```text
finalRisk = min(100, sum(unique risk-factor contributions))
```

The factor ledger is authoritative: each contribution has a stable id, so recurrence can never double-count. Category exposure is computed from the same ledger but kept separate — category scores are **not** summed into enforcement risk.

| Concept | Meaning |
|---|---|
| Risk | Danger associated with the observed request/incident |
| Severity | Impact if the threat is real |
| Confidence | Strength of supporting evidence |

| Risk | Decision |
|---|---|
| `< 30` | ALLOW |
| `30–59` | MONITOR |
| `60–79` | STEP_UP_AUTH |
| `≥ 80` | BLOCK |

Hard failures bypass the numeric score entirely and block with a fixed severity (e.g. forged signature 95, replay 90, no policy 70). High-risk requests are held for a single-use TOTP code rather than blocked outright, so legitimate-but-unusual traffic has a path forward.

## Threat Intelligence

Findings are classified into the implemented taxonomy (`src/threat/contracts.ts`):

- `IDENTITY_COMPROMISE` — forged, unknown, or spoofed workload identity
- `AUTHENTICATION_TOKEN_ABUSE` — expired, replayed, revoked, over-long-lived, or malformed-claim tokens
- `AUTHORIZATION_POLICY_VIOLATION` — default-deny denials: missing policy, explicit deny, method/path denials, time windows
- `BEHAVIORAL_ANOMALY` — off-hours activity, per-pair rate spikes, frequency bursts
- `LATERAL_MOVEMENT` — multi-hop traversal inside one trace; always critical, always a hard override
- `RECONNAISSANCE_PROBING` — taxonomy slot fed today by contextual evidence such as sensitive-endpoint hits (no standalone probing detector is claimed)
- `REQUEST_PAYLOAD_ABUSE` — anomalous body size, depth, or statistical size deviation
- `SERVICE_GRAPH_ANOMALY` — first-seen service edges and graph-context deviations

A finding does not independently block traffic. Findings describe what correlated evidence shows; the pipeline alone decides what gets blocked.

## Findings, Correlation & Investigations

```text
Signals → Evidence → Correlation → Threat Finding → Investigation
```

- **Request correlation** ties signals and evidence to the originating request id.
- **Trace correlation** links hops of one call chain (`trace:<id>`), the basis for attack paths.
- **Service-edge correlation** (`edge:<src>-><dst>`, `service:<id>`) groups repeat behavior on one relationship.
- **Category-aware correlation** keeps each finding owned by exactly one primary category; secondary categories stay contextual.
- **Bounded state**: at most 5,000 active findings and 100 evidence references per finding; expiry windows (60 s; 1 s for traces) retire stale correlations and capacity evicts oldest-first.
- **Recurrence**: repeat observations update the existing finding (count, first/last seen, latest decision context, maximum risk) instead of duplicating it.
- **Provenance**: every finding carries detector name/version, evidence ids, signal dispositions, and an assessment explanation.
- **Attack paths** are reconstructed strictly from stored trace evidence — ordered service chains with timestamps — never inferred from policy or topology.

## Recommendation System

```text
Threat Finding
      +
Evidence
      +
Policy / Usage Context
      ↓
Deterministic Recommendation Rules
      ↓
Recommendation
```

Two advisory outputs, both deterministic and neither autonomous:

- **Least-privilege recommender** (live via API): `REMOVE_UNUSED_POLICY`, `NARROW_METHODS`, `NARROW_PATHS`, `REVIEW_DENIED_EDGE`, or `INSUFFICIENT_DATA` when observation is thin. Denied edges are surfaced for human judgment only, and the proposed tightened policy set is meant to be trialed in dry-run first.
- **Finding-level recommendation contract** with categories `CONTAIN`, `HARDEN`, `INVESTIGATE`, `MONITOR`, `OPTIMIZE` for classifying what a finding calls for.

> Recommendations are advisory. The recommendation engine does not directly ALLOW, BLOCK, quarantine, revoke credentials, or mutate policy.

Human approval is required before any recommendation becomes action.

## Real-Time Operations

- **REST API** — metrics snapshots, audit records/verification/summary, services, policies and their status, recommendations, quarantine, JWKS, simulator controls, and the full `/api/threats/*` family.
- **WebSocket event stream** (`/ws`) — `{type: "decision"}` on every verdict plus the versioned `{type: "threat.finding.v1"}` per correlated finding, over the same connection the console already holds.
- **Live decisions** populate the operations feed, posture metrics, and attention queue within milliseconds of the pipeline verdict.
- **Threat finding events** upsert console state without polling or page reloads, preserving filters and the open investigation.
- **Metrics** track decision distribution, throughput, pipeline latency percentiles, and dry-run violations.
- **Audit events** are hash-chained per decision and verifiable on demand from the Containment view.
- **SOC console** ties it together: monitor, investigate, understand, control, and respond from one surface.

## SOC Console / Frontend

A dependency-free single-page console (`public/index.html`) organized as **Monitor → Investigate → Understand → Control → Respond**:

- **Overview** — posture, decision distribution, live attention queue, analyst advisory
- **Live Operations** — filterable decision stream with timestamp, route, verdict, risk, and factor counts
- **Threat Findings** — severity/risk/confidence list with full finding detail (signals, evidence, assessment)
- **Investigations** — per-correlation-key evidence, timeline, and decision history
- **Threat Categories** — exposure vs. severity vs. confidence vs. risk, kept visually distinct
- **Attack Paths** — observed multi-hop service chains
- **Service Map / Service Activity / Behavioral Anomalies** — policy-derived relationships and live pair behavior
- **Policies / Containment / Audit** — enforcement controls, quarantine state, chain verification
- **Recommendations / Attack Simulator** — advisory output and the 13-scenario live-fire panel

## API Overview

### Core Operations

| Endpoint | Purpose |
|---|---|
| `ANY /api/proxy/*` | Enforced entry point (Bearer token + `X-Destination-Service`) |
| `GET /healthz` | Liveness |
| `GET /api/simulator/scenarios`, `POST /api/simulator/run-all`, `POST /api/simulator/:id` | Attack-scenario controls |

### Threat Intelligence

| Endpoint | Purpose |
|---|---|
| `GET /api/threats/findings` | Active findings — bounded, filterable, paginated |
| `GET /api/threats/findings/:findingId` | One finding with signals, evidence, assessment (404 when expired) |
| `GET /api/threats/categories` | Per-category exposure aggregates |
| `GET /api/threats/investigations/:correlationKey` | Grouped findings, evidence, timeline (404 when none active) |
| `GET /api/threats/attack-paths` | Reconstructed paths; honest empty when none observed |
| `GET /api/threats/summary` | Compact counts for console badges |

### Observability

| Endpoint | Purpose |
|---|---|
| `GET /api/metrics` | Decision counts, throughput, pipeline latency |
| `GET /api/audit`, `GET /api/audit/verify`, `GET /api/audit/summary` | Records, chain verification, counts |
| `GET /api/services` | Registered services (public keys only) |

### Security Controls

| Endpoint | Purpose |
|---|---|
| `GET /api/policies`, `GET /api/policies/status`, `GET /api/policies/recommendations` | Policy set, file version, least-privilege report |
| `GET /api/quarantine` | Currently isolated services |
| `GET /.well-known/jwks.json` | Valid public keys |
| `POST /admin/services`, `…/rotate-key`, `…/status`, `…/keys/:kid/revoke`, `/admin/tokens/revoke`, `/admin/policies/reload`, `/admin/quarantine/:id/release` | Mutating operations — always require `x-admin-key` |

## Demo / Evaluation Flow

```text
Normal Request
      ↓
Security Pipeline
      ↓
Risk / Decision
      ↓
Security Event
      ↓
Threat Correlation
      ↓
Threat Finding
      ↓
Investigation / Attack Path
```

The fastest way to walk this flow: start the server, open the console, run all simulator scenarios, then watch findings, the lateral-movement attack path, and category exposure appear from real pipeline verdicts. Synthetic-detector evaluation (`npm run evaluate` → `docs/EVALUATION.md`) and the 20-service load test (`npm run loadtest` → `docs/LOADTEST.md`) extend the story with measured numbers — see below. No hosted demo exists; everything runs locally.

## Testing & Validation

- **Suite: 173 tests across 23 files** (`npm test`). Last full run in this environment: **171/173** — the 2 failures are both in `e2e.test.ts` and time-of-day dependent: at 02:40 UTC the off-hours factor (+5) pushed the step-up probe to exactly 80, flipping it from `STEP_UP_AUTH` to `BLOCK` (which quarantined the service and cascaded into the simulator's forbidden-path scenario). Daytime runs are green; no code was changed for this README.
- **Typecheck and build clean** (`tsc --noEmit`, `tsc -p tsconfig.build.json`); CI enforces typecheck, test, build, and demo on Node 20 and 22.
- **Simulator: 13 scenarios** (1 normal + 12 attacks: unauthorized access, forbidden sub-path, expired/tampered/replayed tokens, `alg:none`, HS256 confusion, wrong audience, spoofing, lateral movement, payload bomb, TOTP step-up) — all passing when the suite is green; `npm run demo` exits 1 on any failure.
- **Synthetic detector evaluation** (`docs/EVALUATION.md`, explicitly synthetic — not production accuracy): baseline-tuned variant holds FPR at `0.000 ± 0.000%` at 1x load vs `0.093 ± 0.059%` for fixed thresholds; removing declared workflows degrades FPR to `1.332 ± 0.119%`.
- **Load test** (`docs/LOADTEST.md`, 20 services, shared-CPU lower bound): 3,107 rps at 50 connections; server-side pipeline latency p50 4.347 ms, p99 63.575 ms.
- **Live-validated**: dashboard 200, single WebSocket carrying both decision and `threat.finding.v1` events, all four decisions observed in metrics, audit chain verifying after attack traffic.

## Run Locally

Prerequisites: Node ≥ 20.

```bash
npm ci              # install dependencies
npm run dev         # start with reload (console: http://localhost:4000)
npm test            # full suite (node:test via tsx)
npm run demo        # 13 live attack scenarios (exit 1 on any failure)
npm run typecheck   # must be clean before committing
npm run build       # compile to dist/, then npm start to serve it
```

Optional: copy `.env.example` to `.env`. Everything has defaults; leaving `ADMIN_API_KEY` empty generates a random one per run (printed at startup). Key tunables: `PORT`, `PUBLIC_DASHBOARD`, `RISK_MONITOR_AT` / `RISK_STEP_UP_AT` / `RISK_BLOCK_AT`, `POLICY_FILE`, `DRY_RUN`, `RISK_MODE`, threat-correlation windows and caps, `KEY_ROTATION_MS`. Never commit real secrets.

## Security Design Principles

- Default deny with fail-closed ties and explicit authorization
- Cryptographic workload identity (Ed25519, pinned algorithm, single-use ids)
- Fail-closed controls: hard failures reject immediately with fixed severities
- Explainable risk: named factors, exact-sum scores, surfaced evidence
- Bounded state: capped maps, ring buffers, capacity-evicted correlation
- Immutable, auditable security events via a hash-chained log
- Separation of enforcement and intelligence — analysis can never override a verdict
- No raw secrets in threat findings: evidence is primitive-only by construction
- Deterministic enforcement: same inputs, same verdict; statistics stay in observation

## Known Limitations

Engineering boundaries, not gaps in the story:

- **In-memory state** — token ids, rate limits, audit log, and threat findings live in process (a `JtiStore` interface exists for a future Redis backend); restarts clear them.
- **No persistent finding history** — correlations expire by window and capacity; there is no long-term analytics store yet.
- **No ML/LLM detection** — assessment is rules, EWMA/z-score statistics, and fixed criteria. This is deliberate and stated as such.
- **Advisory recommendations** — nothing auto-remediates; human approval is required before action.
- **Bounded correlation windows** — a slow traversal spread past the trace window (see the `lateral-slow` evaluation class) evades trace correlation by design.
- **Synthetic evaluation** — the harness generates its own traffic with the same author's detector, so real-world performance is likely lower.
- **No mTLS** — proxy-to-backend traffic is plain HTTP on loopback; Ed25519 is not quantum-resistant.

## Screenshots

> Screenshots can be added here for the SOC console, live operations,
> threat investigations, and attack-path analysis.

## Project Highlights

- Zero-trust service-to-service enforcement: 8-stage pipeline with cryptographic workload identity and default-deny authorization.
- Explainable risk engine: exact-sum factor ledger, fixed-severity hard failures, and TOTP step-up instead of blunt blocking.
- Lateral-movement detection with automatic quarantine, plus per-pair EWMA behavioral baselines that keep false positives near zero in synthetic evaluation.
- Threat-intelligence correlation turning verdicts into categorized findings, investigations, and reconstructed attack paths — analytical, never overriding enforcement.
- Real-time SOC operations over REST plus one WebSocket (`decision`, `threat.finding.v1`), with a 14-view console that computes no security values itself.
- Deterministic recommendation engine (least-privilege rules + finding-action taxonomy), strictly advisory with human approval.
- Comprehensive automated testing: 173 tests, live 13-scenario attack simulator, evaluation harness, and load-test sweep — all reproducible via npm scripts.