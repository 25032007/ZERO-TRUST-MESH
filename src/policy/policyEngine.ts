/**
 * PolicyEngine — authorization: "is service A even ALLOWED to talk to service B?"
 *
 * Principle: DEFAULT DENY. If no policy explicitly allows the (source → destination)
 * pair, the request is refused. Nothing is implicitly trusted just because it is
 * "inside" the network — that is the core idea of zero trust.
 *
 * A policy can narrow things further by HTTP method, path prefix, explicit
 * deny-paths and time window.
 *
 * Policy model (v2)
 *   effect   'allow' (default) | 'deny'   — an explicit deny wins over allows of equal
 *                                            or lower priority ("never let X talk to Y").
 *   priority integer, higher is evaluated first (default 0). At equal priority a
 *            deny is evaluated before an allow, so ties fail safe.
 *   mode     'enforce' (default) | 'dry-run' — in dry-run the engine still computes
 *            the verdict but flags it so the pipeline can LOG "would have blocked"
 *            instead of blocking. This is how you roll out a new rule safely.
 */

import { pathMatchesPrefix } from './paths.js';

export type PolicyEffect = 'allow' | 'deny';
export type PolicyMode = 'enforce' | 'dry-run';

export interface Policy {
  id: string;
  source: string;
  destination: string;
  /** Allowed (or, for effect=deny, matched) HTTP methods (upper-case). */
  methods: string[];
  /** Path prefixes that are allowed/matched. Empty = every path (except denied ones). */
  allowPaths?: string[];
  /** Path prefixes that are ALWAYS refused, even if allowPaths matches. */
  denyPaths?: string[];
  /** If set, the policy only applies inside these UTC hours [start, end). */
  hoursUtc?: { start: number; end: number };
  effect?: PolicyEffect;
  priority?: number;
  mode?: PolicyMode;
  description: string;
}

export type PolicyReason =
  | 'ALLOWED'
  | 'NO_POLICY'
  | 'EXPLICIT_DENY'
  | 'METHOD_NOT_ALLOWED'
  | 'PATH_DENIED'
  | 'PATH_NOT_ALLOWED'
  | 'OUTSIDE_TIME_WINDOW';

export interface PolicyDecision {
  allowed: boolean;
  reason: PolicyReason;
  policyId?: string;
  /**
   * True when the request was DENIED but the responsible policy (or the whole
   * engine) is in dry-run mode: the pipeline should log it and let it through.
   */
  dryRun?: boolean;
}

export class PolicyEngine {
  private policies = new Map<string, Policy>();
  /** Index by "source->destination", pre-sorted, so evaluation is one Map lookup. */
  private byPair = new Map<string, Policy[]>();
  private globalDryRun = false;
  /** Declared legitimate multi-hop chains (see isKnownWorkflow). */
  private workflows: string[][] = [];

  constructor(
    initial: Policy[] = [],
    private readonly clock: () => number = Date.now,
  ) {
    this.replaceAll(initial);
  }

  /** Add one policy (used by tests and the admin API). */
  add(policy: Policy): void {
    this.replaceAll([...this.policies.values(), policy]);
  }

  /**
   * Atomically swap the whole policy set. The new index is built completely
   * BEFORE it replaces the old one, so a concurrent evaluate() never sees a
   * half-loaded state (JS is single-threaded, but evaluate() is called between
   * awaits — this keeps the swap a single synchronous assignment).
   */
  replaceAll(policies: Policy[]): void {
    const nextPolicies = new Map<string, Policy>();
    const nextByPair = new Map<string, Policy[]>();
    for (const p of policies) {
      nextPolicies.set(p.id, p);
      const key = `${p.source}->${p.destination}`;
      const list = nextByPair.get(key) ?? [];
      list.push(p);
      nextByPair.set(key, list);
    }
    for (const list of nextByPair.values()) list.sort(compareForEvaluation);
    this.policies = nextPolicies;
    this.byPair = nextByPair;
  }

  /** Global dry-run: every denial becomes "would block" (safe rollout of the whole policy set). */
  setDryRun(enabled: boolean): void {
    this.globalDryRun = enabled;
  }

  get dryRun(): boolean {
    return this.globalDryRun;
  }

  list(): Policy[] {
    return [...this.policies.values()];
  }

  get(id: string): Policy | undefined {
    return this.policies.get(id);
  }

  /** Replace the declared workflows (chains of services that legitimately call each other in sequence). */
  setAllowedWorkflows(workflows: string[][]): void {
    this.workflows = workflows.map((w) => [...w]);
  }

  allowedWorkflows(): string[][] {
    return this.workflows.map((w) => [...w]);
  }

  /**
   * Is `path` (e.g. [frontend, orders, payments, database]) a declared workflow
   * or the START of one? Prefix matching matters because the lateral-movement
   * detector fires as soon as the third hop appears, i.e. mid-workflow.
   */
  isKnownWorkflow(path: string[]): boolean {
    return this.workflows.some((wf) => path.length <= wf.length && path.every((svc, i) => wf[i] === svc));
  }

  evaluate(source: string, destination: string, method: string, path: string): PolicyDecision {
    const candidates = this.byPair.get(`${source}->${destination}`);
    if (!candidates || candidates.length === 0) {
      return { allowed: false, reason: 'NO_POLICY', dryRun: this.globalDryRun };
    }

    const isDry = (p: Policy) => this.globalDryRun || p.mode === 'dry-run';
    const upperMethod = method.toUpperCase();

    // Remember the "closest" failure so the error message is as specific as possible.
    let best: PolicyDecision = { allowed: false, reason: 'METHOD_NOT_ALLOWED', dryRun: isDry(candidates[0]) };

    for (const p of candidates) {
      if (!p.methods.includes(upperMethod)) continue;

      const inWindow = this.inTimeWindow(p);
      const pathMatches = !p.allowPaths || p.allowPaths.length === 0 || p.allowPaths.some((prefix) => pathMatchesPrefix(path, prefix));

      if (p.effect === 'deny') {
        // An explicit deny applies only when everything it describes matches.
        if (pathMatches && inWindow) return { allowed: false, reason: 'EXPLICIT_DENY', policyId: p.id, dryRun: isDry(p) };
        continue;
      }

      if (p.denyPaths?.some((prefix) => pathMatchesPrefix(path, prefix))) {
        best = { allowed: false, reason: 'PATH_DENIED', policyId: p.id, dryRun: isDry(p) };
        continue;
      }
      if (!pathMatches) {
        best = { allowed: false, reason: 'PATH_NOT_ALLOWED', policyId: p.id, dryRun: isDry(p) };
        continue;
      }
      if (!inWindow) {
        best = { allowed: false, reason: 'OUTSIDE_TIME_WINDOW', policyId: p.id, dryRun: isDry(p) };
        continue;
      }
      return { allowed: true, reason: 'ALLOWED', policyId: p.id };
    }
    return best;
  }

  private inTimeWindow(p: Policy): boolean {
    if (!p.hoursUtc) return true;
    const hour = new Date(this.clock()).getUTCHours();
    return hour >= p.hoursUtc.start && hour < p.hoursUtc.end;
  }
}

/** Higher priority first; at equal priority deny before allow; then by id for determinism. */
function compareForEvaluation(a: Policy, b: Policy): number {
  const byPriority = (b.priority ?? 0) - (a.priority ?? 0);
  if (byPriority !== 0) return byPriority;
  const aDeny = a.effect === 'deny' ? 0 : 1;
  const bDeny = b.effect === 'deny' ? 0 : 1;
  if (aDeny !== bDeny) return aDeny - bDeny;
  return a.id.localeCompare(b.id);
}

/**
 * The demo mesh topology. Note what is NOT here: frontend → database,
 * orders → database, anything → auth except frontend. Absence = denied.
 *
 *   frontend ──► orders ──► payments ──► database
 *       │           └──────► users ◄────── auth
 *       └──────► auth
 *
 * The same policies ship as `policies/default.json`; a test keeps the two in sync.
 */
export const DEFAULT_POLICIES: Policy[] = [
  { id: 'frontend-to-orders', source: 'frontend-service', destination: 'orders-service', methods: ['GET', 'POST'], allowPaths: ['/orders'], description: 'UI may list and create orders' },
  { id: 'frontend-to-auth', source: 'frontend-service', destination: 'auth-service', methods: ['POST'], allowPaths: ['/auth'], description: 'UI may log users in' },
  { id: 'orders-to-payments', source: 'orders-service', destination: 'payments-service', methods: ['POST'], allowPaths: ['/payments'], description: 'Orders may request a charge' },
  { id: 'orders-to-users', source: 'orders-service', destination: 'users-service', methods: ['GET'], allowPaths: ['/users'], description: 'Orders may read user profiles' },
  { id: 'payments-to-database', source: 'payments-service', destination: 'database-service', methods: ['GET', 'POST'], allowPaths: ['/database'], denyPaths: ['/database/admin'], description: 'Only payments may reach the database (never its /admin path)' },
  { id: 'auth-to-users', source: 'auth-service', destination: 'users-service', methods: ['GET'], allowPaths: ['/users'], description: 'Auth looks up user records' },
];
