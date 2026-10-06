/**
 * SecurityPipeline — the heart of the project.
 *
 * Every request to /api/proxy/* is pushed through eight stages, in this order.
 * The order is deliberate: cheap checks first, expensive/stateful checks later,
 * and identity BEFORE anything that trusts the caller's name.
 *
 *   1. rate_limit        per-IP quota                      (protect the proxy itself)
 *   2. authentication    Ed25519 token, single-use, pinned alg, anti-spoofing
 *   3. quarantine        is this service currently isolated?
 *   4. authorization     default-deny policy for (source → destination)
 *   5. payload_anomaly   size / depth / statistical outlier
 *   6. lateral_movement  multi-hop traversal inside one trace
 *   7. risk_scoring      sum of explainable factors -> 0-100
 *   8. decision          ALLOW / MONITOR / STEP_UP_AUTH / BLOCK (+ quarantine)
 *
 * Stages 1-4 are "hard" gates: failing one rejects the request immediately with a
 * fixed severity. Stages 5-7 produce "soft" signals that feed the risk score, and
 * stage 8 maps the score to a verdict.
 *
 * The pipeline is a pure-ish class with injected dependencies (no Express, no
 * globals), which is why it can be unit-tested in microseconds.
 */
import { performance } from 'node:perf_hooks';
import type { MeshConfig } from '../config.js';
import type { AuditLog } from '../audit/auditLog.js';
import type { LateralMovementDetector } from '../detection/lateralMovement.js';
import type { ServiceRegistry } from '../identity/registry.js';
import type { EventBus } from '../observability/events.js';
import type { MetricsCollector } from '../observability/metrics.js';
import type { PolicyEngine } from '../policy/policyEngine.js';
import type { UsageTracker } from '../policy/usage.js';
import type { AnomalyEngine } from '../risk/anomaly.js';
import { levelFor, type RiskEngine } from '../risk/riskEngine.js';
import type { QuarantineService } from '../security/quarantine.js';
import type { RateLimiter } from '../security/rateLimiter.js';
import type { TokenVerifier } from '../token/tokenVerifier.js';
import type { ThreatIntelligence } from '../threat/threatIntelligence.js';
import type { ThreatObservationContext } from '../threat/normalizer.js';
import { isSafePath } from '../policy/paths.js';
import { toSummary as toThreatSummary } from '../threat/presenter.js';
import type { Decision, PipelineInput, PipelineResult, RiskFactor, StageTrace } from '../types.js';

export interface PipelineDeps {
  config: MeshConfig;
  clock: () => number;
  registry: ServiceRegistry;
  verifier: TokenVerifier;
  /** Quota per source IP (checked before we know who the caller is). */
  ipLimiter: RateLimiter;
  /** Quota per authenticated service. */
  serviceLimiter: RateLimiter;
  quarantine: QuarantineService;
  policies: PolicyEngine;
  /** Records which permissions are really used (feeds the least-privilege recommender). */
  usage: UsageTracker;
  anomaly: AnomalyEngine;
  lateral: LateralMovementDetector;
  risk: RiskEngine;
  audit: AuditLog;
  metrics: MetricsCollector;
  bus: EventBus;
  /** Additive observer of completed results; never participates in enforcement. */
  threats: ThreatIntelligence;
}

/** Shape of a verdict before bookkeeping (timing, audit, metrics) is attached. */
interface Verdict {
  decision: Decision;
  httpStatus: number;
  reason: string;
  riskScore: number;
  source?: string;
  factors?: RiskFactor[];
  mfaSatisfied?: boolean;
}

export class SecurityPipeline {
  constructor(private readonly d: PipelineDeps) {}

  async evaluate(input: PipelineInput): Promise<PipelineResult> {
    const startedAt = performance.now();
    const now = this.d.clock();
    const cfg = this.d.config;
    const stages: StageTrace[] = [];
    /** Filled in by stage 4 when dry-run mode lets a policy denial through. */
    let dryRunViolation: PipelineResult['dryRunViolation'];
    let threatContext: ThreatObservationContext | undefined;

    /** Attach timing, write the audit record, update metrics, notify the dashboard. */
    const finish = (v: Verdict): PipelineResult => {
      const result: PipelineResult = {
        requestId: input.requestId,
        traceId: input.traceId,
        decision: v.decision,
        httpStatus: v.httpStatus,
        reason: v.reason,
        riskScore: v.riskScore,
        riskLevel: levelFor(v.riskScore),
        source: v.source,
        destination: input.destination,
        method: input.method,
        path: input.path,
        factors: v.factors ?? [],
        stages,
        mfaSatisfied: v.mfaSatisfied ?? false,
        dryRunViolation,
        durationMs: performance.now() - startedAt,
        timestamp: now,
      };
      this.d.audit.append({
        requestId: result.requestId,
        traceId: result.traceId,
        decision: result.decision,
        reason: result.reason,
        riskScore: result.riskScore,
        source: result.source,
        destination: result.destination,
        method: result.method,
        path: result.path,
        factors: result.factors,
        dryRunViolation: dryRunViolation?.reason,
        timestamp: now,
      });
      if (dryRunViolation) this.d.metrics.recordDryRunViolation();
      this.d.metrics.record(result.decision, result.durationMs);
      this.d.bus.publishDecision(result);
      // Threat contracts are observational. A future enrichment bug must never
      // change the already-finalised security verdict or interrupt the proxy.
      try {
        const observation = this.d.threats.observe(result, threatContext);
        // Additive fan-out: one versioned event per correlated finding so the
        // dashboard can upsert without polling. Summaries only (no recalculation).
        for (const finding of observation.findings) this.d.bus.publishThreatFinding(toThreatSummary(finding));
      } catch {
        // No-op by design: audit, metrics, and the decision event were recorded first.
      }
      return result;
    };

    /** Reject immediately (stages 1-4). Severity comes from config, see MeshConfig.hardFailSeverity. */
    const hardFail = (stage: string, reason: string, httpStatus: number, detail: string, source?: string): PipelineResult => {
      stages.push({ stage, outcome: 'fail', detail });
      return finish({ decision: 'BLOCK', httpStatus, reason, riskScore: cfg.hardFailSeverity[reason] ?? 70, source });
    };

    // ── 0. PATH SAFETY (before anything else, including rate limiting) ────
    // The policy engine authorizes a path string while the HTTP client
    // normalizes dot-segments/encoding when forwarding. Any path whose meaning
    // could change under that normalization is rejected here, so the exact
    // string that passes authorization is also the exact string forwarded.
    if (!isSafePath(input.path)) {
      return hardFail('path_validation', 'INVALID_PATH', 400, `Unsafe request path rejected before authorization`);
    }

    // ── 1. RATE LIMIT (per IP, before we spend CPU on crypto) ──────────────
    if (!this.d.ipLimiter.hit(`ip:${input.ip}`)) {
      return hardFail('rate_limit', 'RATE_LIMITED', 429, `IP ${input.ip} exceeded its request quota`);
    }
    stages.push({ stage: 'rate_limit', outcome: 'pass', detail: 'within IP quota' });

    // ── 2. AUTHENTICATION ──────────────────────────────────────────────────
    const auth = await this.d.verifier.verify(input.authorization);
    if (!auth.ok) {
      // Remember the failure against the IP so repeated probing raises risk.
      this.d.risk.recordAuthFailure(input.ip, now);
      return hardFail('authentication', auth.code, 401, auth.detail);
    }
    const source = auth.serviceId;

    // Anti-spoofing: the X-Service-ID header is attacker-controlled. If it says
    // something different from what the cryptographic identity says, someone is lying.
    if (input.claimedService && input.claimedService !== source) {
      this.d.risk.recordAuthFailure(input.ip, now);
      return hardFail('authentication', 'IDENTITY_MISMATCH', 403, `Header claims "${input.claimedService}" but token proves "${source}"`, source);
    }
    stages.push({ stage: 'authentication', outcome: 'pass', detail: `verified as ${source} (kid ${auth.kid})` });

    // Per-service quota, now that we know who it is.
    if (!this.d.serviceLimiter.hit(`svc:${source}`)) {
      return hardFail('rate_limit', 'RATE_LIMITED', 429, `${source} exceeded its request quota`, source);
    }

    // ── 3. QUARANTINE ──────────────────────────────────────────────────────
    const q = this.d.quarantine.isQuarantined(source);
    if (q) {
      return hardFail('quarantine', 'SERVICE_QUARANTINED', 403, `Quarantined: ${q.reason}`, source);
    }
    stages.push({ stage: 'quarantine', outcome: 'pass', detail: 'service not quarantined' });

    // ── 4. AUTHORIZATION (default deny) ────────────────────────────────────
    if (!input.destination) {
      return hardFail('authorization', 'MISSING_DESTINATION', 400, 'X-Destination-Service header is required', source);
    }
    const policy = this.d.policies.evaluate(source, input.destination, input.method, input.path);
    if (!policy.allowed) this.d.usage.recordDenied(source, input.destination, policy.reason, now);
    if (!policy.allowed && !policy.dryRun) {
      return hardFail('authorization', policy.reason, 403, `${source} → ${input.destination} ${input.method} ${input.path}: ${policy.reason}`, source);
    }
    if (!policy.allowed) {
      // DRY-RUN: the policy says "deny", but we are only observing. Record what
      // WOULD have happened and keep going so the rest of the pipeline (risk,
      // anomaly, lateral movement) still sees realistic traffic.
      dryRunViolation = { reason: policy.reason, policyId: policy.policyId };
      stages.push({ stage: 'authorization', outcome: 'flag', detail: `DRY-RUN: would block (${policy.reason}${policy.policyId ? ` by ${policy.policyId}` : ''}) — allowed through` });
    } else {
      stages.push({ stage: 'authorization', outcome: 'pass', detail: `allowed by policy ${policy.policyId}` });
      this.d.usage.recordAllowed(policy.policyId!, input.method, input.path, this.d.policies.get(policy.policyId!)?.allowPaths, now);
    }

    // ── 5. PAYLOAD ANOMALY ─────────────────────────────────────────────────
    // Payload sizes are learned PER PAIR: what is normal for orders → payments is not normal for frontend → auth.
    const anomaly = this.d.anomaly.analyze(`${source}->${input.destination}`, input.body, input.payloadBytes);
    stages.push({
      stage: 'payload_anomaly',
      outcome: anomaly.points > 0 ? 'flag' : 'pass',
      detail: anomaly.findings.join('; ') || 'payload looks normal',
    });

    // ── 6. LATERAL MOVEMENT ────────────────────────────────────────────────
    const lateral = this.d.lateral.observe(input.traceId, source, input.destination, now);
    threatContext = { lateral };
    stages.push({
      stage: 'lateral_movement',
      outcome: lateral.detected ? 'flag' : 'pass',
      detail: lateral.detected
        ? `${lateral.hops} hops: ${lateral.path.join(' → ')}`
        : lateral.knownWorkflow
          ? `declared workflow: ${lateral.path.join(' → ')}`
          : `${lateral.hops} hop(s) in this trace`,
    });

    // ── 7. RISK SCORING ────────────────────────────────────────────────────
    const risk = this.d.risk.assess({
      source,
      destination: input.destination,
      method: input.method,
      path: input.path,
      ip: input.ip,
      now,
      anomaly,
      lateral,
    });
    stages.push({
      stage: 'risk_scoring',
      outcome: risk.score >= cfg.thresholds.monitor ? 'flag' : 'pass',
      detail: `score ${risk.score} (${risk.level})`,
    });

    // ── 8. DECISION ────────────────────────────────────────────────────────
    // Lateral movement is a rule of its own: it blocks regardless of the sum,
    // because a pivoting attacker should not be able to stay under the threshold.
    if (lateral.detected) {
      this.d.quarantine.quarantine(source, `lateral movement: ${lateral.path.join(' → ')}`);
      stages.push({ stage: 'decision', outcome: 'fail', detail: 'lateral movement -> block + quarantine' });
      return finish({
        decision: 'BLOCK',
        httpStatus: 403,
        reason: 'LATERAL_MOVEMENT',
        riskScore: Math.max(risk.score, cfg.hardFailSeverity.LATERAL_MOVEMENT),
        source,
        factors: risk.factors,
      });
    }

    if (risk.score >= cfg.thresholds.block) {
      this.d.quarantine.quarantine(source, `critical risk score ${risk.score}`);
      stages.push({ stage: 'decision', outcome: 'fail', detail: `score ${risk.score} >= ${cfg.thresholds.block} -> block + quarantine` });
      return finish({ decision: 'BLOCK', httpStatus: 403, reason: 'RISK_CRITICAL', riskScore: risk.score, source, factors: risk.factors });
    }

    if (risk.score >= cfg.thresholds.stepUp) {
      // High risk: ask the caller to prove possession of the second factor.
      if (input.totp && this.d.registry.consumeTotp(source, input.totp)) {
        stages.push({ stage: 'decision', outcome: 'pass', detail: `score ${risk.score}: step-up satisfied with valid TOTP` });
        return finish({ decision: 'ALLOW', httpStatus: 200, reason: 'STEP_UP_SATISFIED', riskScore: risk.score, source, factors: risk.factors, mfaSatisfied: true });
      }
      const reason = input.totp ? 'STEP_UP_FAILED' : 'STEP_UP_REQUIRED';
      stages.push({ stage: 'decision', outcome: 'fail', detail: `score ${risk.score}: ${reason}` });
      return finish({ decision: 'STEP_UP_AUTH', httpStatus: 401, reason, riskScore: risk.score, source, factors: risk.factors });
    }

    if (risk.score >= cfg.thresholds.monitor) {
      stages.push({ stage: 'decision', outcome: 'flag', detail: `score ${risk.score}: allowed with enhanced monitoring` });
      return finish({ decision: 'MONITOR', httpStatus: 200, reason: 'ELEVATED_RISK', riskScore: risk.score, source, factors: risk.factors });
    }

    stages.push({ stage: 'decision', outcome: 'pass', detail: `score ${risk.score}: allowed` });
    return finish({ decision: 'ALLOW', httpStatus: 200, reason: 'OK', riskScore: risk.score, source, factors: risk.factors });
  }
}
