# AGENTS.md — Zero-Trust Mesh

Zero-trust proxy for service-to-service traffic (TypeScript, Node >= 20, Express 5, jose, ws).
Portfolio project for SDE placements: every claim in this repo must be true and demonstrable.

## Commands (repo root)
- `npm test`  all tests (node:test via tsx). One file: `node --import tsx --test test/<name>.test.ts`
- `npm run typecheck`  tsc --noEmit (must be clean)
- `npm run demo`  13 real attack scenarios through the real pipeline (exit 1 if any fails)
- `npm run dev` / `npm run build` / `npm start`;  `npm run bench`  autocannon benchmark
Before every commit: typecheck + tests pass. CI runs typecheck, test, build, demo on Node 20 and 22.

## Map
- `src/pipeline/pipeline.ts`  8-stage SecurityPipeline: rate_limit, authentication, quarantine, authorization, payload_anomaly, lateral_movement, risk_scoring, decision
- `src/mesh.ts`  composition root (everything built from config + an injectable clock)
- `src/config.ts`  ALL tunables and env vars. No magic numbers elsewhere.
- `src/identity/`  registry (public keys, rotation, JWKS, TOTP), serviceClient (private-key side), rotation
- `src/token/`  tokenVerifier (alg pinning, single-use jti), jtiStore (interface + in-memory impl)
- `src/policy/`  policyEngine (priority, deny, dry-run), policyFile (strict JSON validation), policyStore (atomic hot reload), usage + recommend (least privilege)
- `src/risk/`  riskEngine (score = sum of named factors), baseline (per-pair EWMA), anomaly (payload size/depth/z-score)
- `src/detection/`, `src/security/`, `src/audit/`, `src/observability/`  lateral movement, rate limiter, quarantine, hash-chained audit log, metrics, websocket events
- `src/simulator/attacks.ts`  real forged attacks (used by demo, dashboard, e2e tests)
- `src/eval/`  rng, trafficGenerator, metrics (labeled-traffic evaluation harness)
- `src/server.ts` Express adapter + admin routes; `public/index.html` dashboard; `policies/default.json`
- `test/` mirrors src; `test/helpers.ts` has fakeClock() and setup() (isolated mesh per test)

## Security invariants — never break these
1. The proxy stores PUBLIC keys only. No endpoint may mint tokens.
2. Algorithm is pinned to EdDSA (never read from the token). Replay check runs AFTER signature verification.
3. Default deny. Dry-run may relax policy denials only, never authentication.
4. Risk score is the exact sum of named factors. Hard failures use fixed severities from config.
5. Auth failures are tracked per IP, never per claimed service id (prevents framing a victim).
6. The audit hash chain must still verify (GET /api/audit/verify) after any change to record fields.
7. Invalid policy file: reject on reload and keep the old policies; fail fast on startup.
8. Admin routes always require x-admin-key. Never return stack traces.

## Coding rules
- No `Date.now()` inside engines: take a clock from deps (tests use fakeClock).
- Keep memory bounded (capMap / ring buffers). No new runtime dependency without a strong reason.
- Comment the WHY (design reason, trade-off, limitation) in plain English. Public functions get a doc comment.
- Every feature ships with tests, including an abuse/failure case. Timing tests wait on conditions, never fixed sleeps.
- New env var: add to config.ts AND .env.example.
- Must work on Windows and Linux: no shell-specific npm scripts (no `set X=1 &&`).

## Honesty rules (most important here)
- Never invent a number. Every number in README/docs must come from a command you actually ran; show the command next to it.
- Label synthetic-data results as synthetic. Keep "Known limitations" truthful.
- Do not call rule-based logic "AI/ML". Ed25519 is not quantum-resistant.
- If a test fails, find the root cause. Never weaken or delete a test just to go green.

## Workflow
- One task per session. Read only the files named in the task and their tests. Never scan node_modules or dist.
- Plan first (files to touch, tests to add, 5 lines), then implement.
- Small commits, conventional messages (feat(scope):, test:, docs:, fix:), tests in the same commit as the code. Do NOT push; the owner pushes.
- Final report: what changed, commands run with their results, known gaps.

## Status
Done: Ed25519 identity, single-use tokens, policy-as-code (JSON, priority, dry-run, hot reload, declared workflows), per-pair baseline risk, JWKS + auto key rotation, least-privilege recommender, labeled traffic generator + metrics, evaluation runner (runner.ts + evalRunner.test.ts), grid-search tuning + multi-seed report (scripts/evaluate.ts → docs/EVALUATION.md), README + AGENTS.md docs update.
Not done: 20-service load test, dashboard polish (never checked in a real browser), optional Redis JtiStore and mTLS. 