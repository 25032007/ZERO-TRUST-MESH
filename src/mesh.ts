/**
 * Composition root — the ONE place where all components are created and wired.
 *
 * Everything is built from a config and an injectable clock, so tests can create
 * an isolated mesh with a fake clock, while production uses the real one.
 * (Dependency injection without a framework: just a function that returns objects.)
 */
import { AuditLog } from './audit/auditLog.js';
import type { MeshConfig } from './config.js';
import { LateralMovementDetector } from './detection/lateralMovement.js';
import { ServiceRegistry } from './identity/registry.js';
import { EventBus } from './observability/events.js';
import { MetricsCollector } from './observability/metrics.js';
import { SecurityPipeline } from './pipeline/pipeline.js';
import { DEFAULT_POLICIES, PolicyEngine, type Policy } from './policy/policyEngine.js';
import { AnomalyEngine } from './risk/anomaly.js';
import { RiskEngine } from './risk/riskEngine.js';
import { QuarantineService } from './security/quarantine.js';
import { RateLimiter } from './security/rateLimiter.js';
import { MemoryJtiStore, type JtiStore } from './token/jtiStore.js';
import { TokenVerifier } from './token/tokenVerifier.js';

export interface MeshOptions {
  clock?: () => number;
  policies?: Policy[];
  jtiStore?: JtiStore;
}

/** Quota per IP is this many times the per-service quota (IPs can host many services). */
const IP_QUOTA_MULTIPLIER = 5;

export function createMesh(config: MeshConfig, opts: MeshOptions = {}) {
  const clock = opts.clock ?? Date.now;

  const registry = new ServiceRegistry(clock);
  const jtiStore = opts.jtiStore ?? new MemoryJtiStore(clock);
  const verifier = new TokenVerifier(
    registry,
    jtiStore,
    { audience: config.audience, maxLifetimeSec: config.maxTokenLifetimeSec, clockToleranceSec: config.clockToleranceSec },
    clock,
  );
  const policies = new PolicyEngine(opts.policies ?? DEFAULT_POLICIES, clock);
  const quarantine = new QuarantineService(config.quarantineMs, clock);
  const audit = new AuditLog(5000, clock);
  const metrics = new MetricsCollector(clock);
  const bus = new EventBus();
  const risk = new RiskEngine(config);

  const pipeline = new SecurityPipeline({
    config,
    clock,
    registry,
    verifier,
    ipLimiter: new RateLimiter(config.rateLimit.windowMs, config.rateLimit.maxRequests * IP_QUOTA_MULTIPLIER, clock),
    serviceLimiter: new RateLimiter(config.rateLimit.windowMs, config.rateLimit.maxRequests, clock),
    quarantine,
    policies,
    anomaly: new AnomalyEngine(config.payload),
    lateral: new LateralMovementDetector(config.lateral),
    risk,
    audit,
    metrics,
    bus,
  });

  return { config, clock, registry, jtiStore, verifier, policies, quarantine, risk, audit, metrics, bus, pipeline };
}

export type Mesh = ReturnType<typeof createMesh>;
