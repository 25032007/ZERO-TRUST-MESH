/**
 * UsageTracker — remembers which permissions are ACTUALLY exercised.
 *
 * A policy that grants "GET and POST on /orders" but only ever sees GET /orders/list
 * is carrying a standing permission nobody needs: if that service is compromised,
 * the attacker inherits POST for free. Recording real usage lets us recommend the
 * least-privilege version (see recommend.ts).
 *
 * We track two things:
 *   • ALLOWED requests per policy, broken down by (method, matched path prefix)
 *   • DENIED attempts per edge, with reasons — kept apart on purpose, because a
 *     denial is just as likely an attack as a missing permission, so denials are
 *     only ever surfaced for HUMAN REVIEW, never auto-converted into allows.
 *
 * Memory is bounded: usage keys are limited by the policy file's size, and the
 * denied-edge map is capped.
 */
import { capMap } from '../util/slidingCounter.js';

export interface PolicyUsage {
  hits: number;
  firstUsed: number;
  lastUsed: number;
  /** "METHOD prefix" -> count, e.g. "GET /orders" -> 412. Prefix is "*" when the policy has no allowPaths. */
  combos: Record<string, number>;
}

export interface DeniedEdge {
  edge: string;
  count: number;
  lastSeen: number;
  reasons: Record<string, number>;
}

export interface UsageSnapshot {
  startedAt: number;
  perPolicy: Record<string, PolicyUsage>;
  denied: DeniedEdge[];
}

const MAX_DENIED_EDGES = 5_000;

export class UsageTracker {
  readonly startedAt: number;
  private perPolicy = new Map<string, PolicyUsage>();
  private denied = new Map<string, DeniedEdge>();

  constructor(clock: () => number = Date.now) {
    this.startedAt = clock();
  }

  /** An ALLOWED request that matched `policyId`. `allowPaths` are that policy's prefixes (for attribution). */
  recordAllowed(policyId: string, method: string, path: string, allowPaths: string[] | undefined, now: number): void {
    let u = this.perPolicy.get(policyId);
    if (!u) {
      u = { hits: 0, firstUsed: now, lastUsed: now, combos: {} };
      this.perPolicy.set(policyId, u);
    }
    // Attribute to the MOST SPECIFIC (longest) matching prefix.
    let prefix = '*';
    if (allowPaths && allowPaths.length > 0) {
      const matches = allowPaths.filter((p) => path.startsWith(p));
      prefix = matches.length > 0 ? matches.reduce((a, b) => (b.length > a.length ? b : a)) : '*';
    }
    const key = `${method.toUpperCase()} ${prefix}`;
    u.hits++;
    u.lastUsed = now;
    u.combos[key] = (u.combos[key] ?? 0) + 1;
  }

  /** A request on `source->destination` that a policy refused (or would refuse, in dry-run). */
  recordDenied(source: string, destination: string, reason: string, now: number): void {
    const edge = `${source}->${destination}`;
    let d = this.denied.get(edge);
    if (!d) {
      d = { edge, count: 0, lastSeen: now, reasons: {} };
      this.denied.set(edge, d);
      capMap(this.denied, MAX_DENIED_EDGES);
    }
    d.count++;
    d.lastSeen = now;
    d.reasons[reason] = (d.reasons[reason] ?? 0) + 1;
  }

  snapshot(): UsageSnapshot {
    return {
      startedAt: this.startedAt,
      perPolicy: Object.fromEntries([...this.perPolicy].map(([id, u]) => [id, { ...u, combos: { ...u.combos } }])),
      denied: [...this.denied.values()].map((d) => ({ ...d, reasons: { ...d.reasons } })),
    };
  }
}
