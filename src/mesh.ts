/**
 * Composition root — the ONE place where all components are created and wired.
 *
 * Everything is built from a config and an injectable clock, so tests can create
 * an isolated mesh with a fake clock, while production uses the real one.
 * (Dependency injection without a framework: just a function that returns objects.)
 */
import { existsSync } from 'node:fs';
import path from 'node:path';
import { AuditLog } from './audit/auditLog.js';
import type { MeshConfig } from './config.js';
import { LateralMovementDetector } from './detection/lateralMovement.js';
import { ServiceRegistry } from './identity/registry.js';
import { EventBus } from './observability/events.js';
import { MetricsCollector } from './observability/metrics.js';
import { SecurityPipeline } from './pipeline/pipeline.js';
import { DEFAULT_POLICIES, PolicyEngine, type Policy } from './policy/policyEngine.js';
import { PolicyStore } from './policy/policyStore.js';
import { UsageTracker } from './policy/usage.js';
import { AnomalyEngine } from './risk/anomaly.js';
import { RiskEngine } from './risk/riskEngine.js';
import { QuarantineService } from './security/quarantine.js';
import { RateLimiter } from './security/rateLimiter.js';
import { MemoryJtiStore, type JtiStore } from './token/jtiStore.js';
import { TokenVerifier } from './token/tokenVerifier.js';
import { ThreatIntelligence } from './threat/threatIntelligence.js';

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
  const policies = new PolicyEngine([], clock);

  // Where do policies come from? Priority: explicit list (tests) > JSON file > built-in defaults.
  const policyFile = path.resolve(config.policyFile);
  const useFile = opts.policies === undefined && existsSync(policyFile);
  const policyStore = new PolicyStore(policies, useFile ? policyFile : undefined, config.dryRun, clock);
  if (useFile) policyStore.loadInitial(); // throws on an invalid file: never start unprotected
  else policyStore.useInline(opts.policies ?? DEFAULT_POLICIES);
  const quarantine = new QuarantineService(config.quarantineMs, clock);
  const audit = new AuditLog(5000, clock);
  const metrics = new MetricsCollector(clock);
  const bus = new EventBus();
  const risk = new RiskEngine(config);
  const usage = new UsageTracker(clock);
  const threats = new ThreatIntelligence(config.threatCorrelation, clock);

  const pipeline = new SecurityPipeline({
    config,
    clock,
    registry,
    verifier,
    ipLimiter: new RateLimiter(config.rateLimit.windowMs, config.rateLimit.maxRequests * IP_QUOTA_MULTIPLIER, clock),
    serviceLimiter: new RateLimiter(config.rateLimit.windowMs, config.rateLimit.maxRequests, clock),
    quarantine,
    policies,
    usage,
    anomaly: new AnomalyEngine(config.payload),
    lateral: new LateralMovementDetector(config.lateral, (p) => policies.isKnownWorkflow(p)),
    risk,
    audit,
    metrics,
    bus,
    threats,
  });

  return { config, clock, registry, jtiStore, verifier, policies, policyStore, usage, quarantine, risk, audit, metrics, bus, threats, pipeline };
}

export type Mesh = ReturnType<typeof createMesh>;
