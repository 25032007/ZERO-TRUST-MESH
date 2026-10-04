/**
 * Central configuration.
 *
 * Every tunable number in the system lives here — no "magic numbers" are buried in
 * the engines. Values can be overridden through environment variables so the same
 * code runs in dev, tests, benchmarks and production.
 */
import { randomBytes } from 'node:crypto';

export interface MeshConfig {
  port: number;

  // ── Admin / dashboard access ─────────────────────────────────────────────
  adminApiKey: string;
  /** True when we had to invent the admin key (no ADMIN_API_KEY env var). */
  adminKeyGenerated: boolean;
  /** When true, read-only dashboard routes and the simulator need no key. */
  publicDashboard: boolean;

  // ── Token rules ──────────────────────────────────────────────────────────
  /** Every token must be addressed to this audience (the mesh itself). */
  audience: string;
  /** Tokens living longer than this are rejected even if the signature is fine. */
  maxTokenLifetimeSec: number;
  /** Allowed clock drift between a service and the proxy. */
  clockToleranceSec: number;

  // ── Rate limiting ────────────────────────────────────────────────────────
  rateLimit: { windowMs: number; maxRequests: number };

  // ── Containment ──────────────────────────────────────────────────────────
  /** How long a quarantined service stays isolated (auto-release afterwards). */
  quarantineMs: number;

  // ── Risk scoring ─────────────────────────────────────────────────────────
  thresholds: {
    /** score >= this  -> MONITOR (allowed, but flagged) */
    monitor: number;
    /** score >= this  -> STEP_UP_AUTH (needs a TOTP code) */
    stepUp: number;
    /** score >= this  -> BLOCK + quarantine the calling service */
    block: number;
  };
  /** Points per soft risk signal (see src/risk/riskEngine.ts). */
  points: {
    newServicePair: number;
    sensitiveEndpoint: number;
    offHours: number;
    burstWarn: number;
    burstHigh: number;
    perRecentAuthFailure: number;
    maxAuthFailurePoints: number;
    lateralMovement: number;
  };
  /** Request-frequency thresholds (requests by one service inside burstWindowMs). */
  burst: { windowMs: number; warnAt: number; highAt: number };
  /** Auth failures from one IP are remembered for this long. */
  authFailureWindowMs: number;
  /** UTC hours considered "business hours" (start inclusive, end exclusive). */
  businessHours: { startHour: number; endHour: number };
  /** Calls to these services are treated as sensitive. */
  sensitiveServices: string[];
  /** Any path starting with one of these is sensitive regardless of service. */
  sensitivePathPrefixes: string[];

  // ── Lateral movement ─────────────────────────────────────────────────────
  /** >= minHops distinct service-to-service hops inside windowMs in ONE trace. */
  lateral: { windowMs: number; minHops: number };

  // ── Payload anomaly detection ────────────────────────────────────────────
  payload: {
    maxBytes: number;
    maxDepth: number;
    /** z-score above which a payload size is "unusual" for that destination. */
    zScoreLimit: number;
    /** Samples needed before the statistical check is trusted. */
    minSamples: number;
    sizePoints: number;
    depthPoints: number;
    zScorePoints: number;
    /** Upper bound for the whole anomaly contribution. */
    maxPoints: number;
  };

  /**
   * Severity (0-100) reported for HARD failures — requests that are rejected
   * outright before/without soft risk scoring (bad signature, replay, no policy…).
   * These are fixed on purpose: a forged signature is not "a bit risky", it is
   * simply invalid. The number only drives dashboard colouring and sorting.
   */
  hardFailSeverity: Record<string, number>;
}

/** Read a number from the environment, falling back to a default. */
function num(env: NodeJS.ProcessEnv, key: string, fallback: number): number {
  const raw = env[key];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): MeshConfig {
  const suppliedKey = env.ADMIN_API_KEY && env.ADMIN_API_KEY.length > 0 ? env.ADMIN_API_KEY : undefined;

  return {
    port: num(env, 'PORT', 4000),

    adminApiKey: suppliedKey ?? randomBytes(16).toString('hex'),
    adminKeyGenerated: suppliedKey === undefined,
    publicDashboard: (env.PUBLIC_DASHBOARD ?? 'true') !== 'false',

    audience: 'zero-trust-mesh',
    maxTokenLifetimeSec: num(env, 'TOKEN_MAX_LIFETIME_SEC', 900),
    clockToleranceSec: num(env, 'CLOCK_TOLERANCE_SEC', 5),

    rateLimit: {
      windowMs: num(env, 'RATE_LIMIT_WINDOW_MS', 60_000),
      maxRequests: num(env, 'RATE_LIMIT_MAX_REQUESTS', 1000),
    },

    quarantineMs: num(env, 'QUARANTINE_MS', 60_000),

    thresholds: {
      monitor: num(env, 'RISK_MONITOR_AT', 30),
      stepUp: num(env, 'RISK_STEP_UP_AT', 60),
      block: num(env, 'RISK_BLOCK_AT', 80),
    },
    points: {
      newServicePair: 10,
      sensitiveEndpoint: 10,
      offHours: 5,
      burstWarn: 10,
      burstHigh: 20,
      perRecentAuthFailure: 5,
      maxAuthFailurePoints: 25,
      lateralMovement: 50,
    },
    burst: {
      windowMs: 5_000,
      warnAt: num(env, 'BURST_WARN_AT', 50),
      highAt: num(env, 'BURST_HIGH_AT', 100),
    },
    authFailureWindowMs: 60_000,
    businessHours: {
      startHour: num(env, 'BUSINESS_HOURS_START', 6),
      endHour: num(env, 'BUSINESS_HOURS_END', 22),
    },
    sensitiveServices: ['database-service'],
    sensitivePathPrefixes: ['/admin', '/secrets', '/internal'],

    lateral: { windowMs: 1_000, minHops: 3 },

    payload: {
      maxBytes: 100_000,
      maxDepth: 20,
      zScoreLimit: 4,
      minSamples: 30,
      sizePoints: 25,
      depthPoints: 25,
      zScorePoints: 15,
      maxPoints: 50,
    },

    hardFailSeverity: {
      RATE_LIMITED: 50,
      MISSING_TOKEN: 85,
      MALFORMED_TOKEN: 80,
      ALG_NOT_ALLOWED: 95,
      UNKNOWN_SERVICE: 70,
      SERVICE_NOT_ACTIVE: 65,
      UNKNOWN_KEY: 75,
      INVALID_SIGNATURE: 95,
      TOKEN_EXPIRED: 40,
      INVALID_CLAIMS: 75,
      LIFETIME_TOO_LONG: 60,
      TOKEN_REVOKED: 75,
      TOKEN_REPLAY: 90,
      IDENTITY_MISMATCH: 90,
      SERVICE_QUARANTINED: 100,
      MISSING_DESTINATION: 40,
      NO_POLICY: 70,
      METHOD_NOT_ALLOWED: 65,
      PATH_DENIED: 75,
      PATH_NOT_ALLOWED: 65,
      OUTSIDE_TIME_WINDOW: 55,
      LATERAL_MOVEMENT: 90,
      RISK_CRITICAL: 80,
    },
  };
}
