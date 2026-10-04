/**
 * PolicyEngine — authorization: "is service A even ALLOWED to talk to service B?"
 *
 * Principle: DEFAULT DENY. If no policy explicitly allows the (source → destination)
 * pair, the request is refused. Nothing is implicitly trusted just because it is
 * "inside" the network — that is the core idea of zero trust.
 *
 * A policy can narrow things further by HTTP method, path prefix, explicit
 * deny-paths and time window.
 */

export interface Policy {
  id: string;
  source: string;
  destination: string;
  /** Allowed HTTP methods (upper-case). */
  methods: string[];
  /** Path prefixes that are allowed. Empty = every path (except denied ones). */
  allowPaths?: string[];
  /** Path prefixes that are ALWAYS refused, even if allowPaths matches. */
  denyPaths?: string[];
  /** If set, the call is only allowed inside these UTC hours [start, end). */
  hoursUtc?: { start: number; end: number };
  description: string;
}

export type PolicyReason =
  | 'ALLOWED'
  | 'NO_POLICY'
  | 'METHOD_NOT_ALLOWED'
  | 'PATH_DENIED'
  | 'PATH_NOT_ALLOWED'
  | 'OUTSIDE_TIME_WINDOW';

export interface PolicyDecision {
  allowed: boolean;
  reason: PolicyReason;
  policyId?: string;
}

export class PolicyEngine {
  private policies = new Map<string, Policy>();
  /** Index by "source->destination" so evaluation is a single Map lookup. */
  private byPair = new Map<string, Policy[]>();

  constructor(
    initial: Policy[] = [],
    private readonly clock: () => number = Date.now,
  ) {
    initial.forEach((p) => this.add(p));
  }

  add(policy: Policy): void {
    this.policies.set(policy.id, policy);
    const key = `${policy.source}->${policy.destination}`;
    const list = this.byPair.get(key) ?? [];
    list.push(policy);
    this.byPair.set(key, list);
  }

  list(): Policy[] {
    return [...this.policies.values()];
  }

  evaluate(source: string, destination: string, method: string, path: string): PolicyDecision {
    const candidates = this.byPair.get(`${source}->${destination}`);
    if (!candidates || candidates.length === 0) return { allowed: false, reason: 'NO_POLICY' };

    // Remember the "closest" failure so the error message is as specific as possible.
    let best: PolicyDecision = { allowed: false, reason: 'METHOD_NOT_ALLOWED' };

    for (const p of candidates) {
      if (!p.methods.includes(method.toUpperCase())) continue;

      if (p.denyPaths?.some((prefix) => path.startsWith(prefix))) {
        best = { allowed: false, reason: 'PATH_DENIED', policyId: p.id };
        continue;
      }
      if (p.allowPaths && p.allowPaths.length > 0 && !p.allowPaths.some((prefix) => path.startsWith(prefix))) {
        best = { allowed: false, reason: 'PATH_NOT_ALLOWED', policyId: p.id };
        continue;
      }
      if (p.hoursUtc) {
        const hour = new Date(this.clock()).getUTCHours();
        if (hour < p.hoursUtc.start || hour >= p.hoursUtc.end) {
          best = { allowed: false, reason: 'OUTSIDE_TIME_WINDOW', policyId: p.id };
          continue;
        }
      }
      return { allowed: true, reason: 'ALLOWED', policyId: p.id };
    }
    return best;
  }
}

/**
 * The demo mesh topology. Note what is NOT here: frontend → database,
 * orders → database, anything → auth except frontend. Absence = denied.
 *
 *   frontend ──► orders ──► payments ──► database
 *       │           └──────► users ◄────── auth
 *       └──────► auth
 */
export const DEFAULT_POLICIES: Policy[] = [
  { id: 'frontend-to-orders', source: 'frontend-service', destination: 'orders-service', methods: ['GET', 'POST'], allowPaths: ['/orders'], description: 'UI may list and create orders' },
  { id: 'frontend-to-auth', source: 'frontend-service', destination: 'auth-service', methods: ['POST'], allowPaths: ['/auth'], description: 'UI may log users in' },
  { id: 'orders-to-payments', source: 'orders-service', destination: 'payments-service', methods: ['POST'], allowPaths: ['/payments'], description: 'Orders may request a charge' },
  { id: 'orders-to-users', source: 'orders-service', destination: 'users-service', methods: ['GET'], allowPaths: ['/users'], description: 'Orders may read user profiles' },
  { id: 'payments-to-database', source: 'payments-service', destination: 'database-service', methods: ['GET', 'POST'], allowPaths: ['/database'], denyPaths: ['/database/admin'], description: 'Only payments may reach the database (never its /admin path)' },
  { id: 'auth-to-users', source: 'auth-service', destination: 'users-service', methods: ['GET'], allowPaths: ['/users'], description: 'Auth looks up user records' },
];
