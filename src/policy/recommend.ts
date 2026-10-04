/**
 * Policy recommendations — "what permissions can you safely take away?"
 *
 * Pure function: (current policies, observed usage, now) -> advice. No side effects,
 * so it is trivially testable and can run offline on exported usage too.
 *
 * What it recommends
 *   REMOVE_UNUSED_POLICY  a policy that matched no traffic during the observation period
 *   NARROW_METHODS        methods granted but never used (e.g. POST granted, only GET seen)
 *   NARROW_PATHS          allowed path prefixes that never matched
 *   REVIEW_DENIED_EDGE    repeated denials on an edge — for a HUMAN to judge (it may be
 *                         an attack, a bug, or a missing permission; we never auto-allow)
 *
 * Safety rules baked in (so the advice cannot cause an outage on thin evidence)
 *   • Nothing is recommended until `minObservationMs` of traffic has been seen.
 *   • A policy is only narrowed when it has at least `minHits` observed requests.
 *   • Rarely-used-but-legitimate paths (monthly batch jobs!) are the classic trap:
 *     that is why the output is a PROPOSED policy set meant to be tried in dry-run
 *     mode first (see `proposedDocument`), not something that is applied automatically.
 */
import type { Policy } from './policyEngine.js';
import type { UsageSnapshot } from './usage.js';

export type RecommendationType = 'INSUFFICIENT_DATA' | 'REMOVE_UNUSED_POLICY' | 'NARROW_METHODS' | 'NARROW_PATHS' | 'REVIEW_DENIED_EDGE';

export interface Recommendation {
  type: RecommendationType;
  policyId?: string;
  edge?: string;
  message: string;
  evidence: Record<string, unknown>;
}

export interface RecommendOptions {
  /** Minimum observation period before any advice is given. */
  minObservationMs: number;
  /** Minimum requests a policy must have seen before it may be narrowed. */
  minHits: number;
  /** Denials on an edge before it is surfaced for review. */
  minDenied: number;
}

export const DEFAULT_RECOMMEND_OPTIONS: RecommendOptions = { minObservationMs: 10 * 60_000, minHits: 20, minDenied: 5 };

export interface RecommendationReport {
  observationMs: number;
  /** False while there is too little data; recommendations are then withheld. */
  confident: boolean;
  recommendations: Recommendation[];
  summary: {
    /** Distinct (policy, method, path-prefix) grants in allow policies. */
    permissionsGranted: number;
    permissionsUsed: number;
    permissionsUnused: number;
    /** Share of granted permissions that were never used. */
    unusedPercent: number;
  };
  /** The tightened policy set. Equal to the current set when not confident. */
  proposedPolicies: Policy[];
  /** Ready to save as a policy file and try with DRY_RUN=true. */
  proposedDocument: { version: 1; dryRun: boolean; policies: Policy[] };
}

export function recommend(policies: Policy[], usage: UsageSnapshot, now: number, opts: RecommendOptions = DEFAULT_RECOMMEND_OPTIONS): RecommendationReport {
  const observationMs = now - usage.startedAt;
  const confident = observationMs >= opts.minObservationMs;
  const recommendations: Recommendation[] = [];
  const proposed: Policy[] = [];

  let granted = 0;
  let used = 0;

  for (const p of policies) {
    if (p.effect === 'deny') {
      proposed.push(p); // explicit denies are protective: never touch them
      continue;
    }
    const u = usage.perPolicy[p.id];
    const prefixes = p.allowPaths && p.allowPaths.length > 0 ? p.allowPaths : ['*'];
    const grants = p.methods.flatMap((m) => prefixes.map((prefix) => `${m} ${prefix}`));
    const usedGrants = grants.filter((g) => (u?.combos[g] ?? 0) > 0);
    granted += grants.length;
    used += usedGrants.length;

    if (!confident) {
      proposed.push(p);
      continue;
    }

    if (!u || u.hits === 0) {
      recommendations.push({
        type: 'REMOVE_UNUSED_POLICY',
        policyId: p.id,
        message: `Policy "${p.id}" (${p.source} → ${p.destination}) matched no traffic in ${fmtDuration(observationMs)}. Consider removing it.`,
        evidence: { hits: 0, observationMs, grants: grants.length },
      });
      continue; // dropped from the proposal
    }

    if (u.hits < opts.minHits) {
      proposed.push(p); // too little traffic to narrow safely
      continue;
    }

    const usedMethods = p.methods.filter((m) => prefixes.some((prefix) => (u.combos[`${m} ${prefix}`] ?? 0) > 0));
    const unusedMethods = p.methods.filter((m) => !usedMethods.includes(m));
    const usedPrefixes = prefixes.filter((prefix) => p.methods.some((m) => (u.combos[`${m} ${prefix}`] ?? 0) > 0));
    const unusedPrefixes = prefixes.filter((prefix) => !usedPrefixes.includes(prefix));
    const narrowPaths = prefixes[0] !== '*' && unusedPrefixes.length > 0;

    if (unusedMethods.length > 0) {
      recommendations.push({
        type: 'NARROW_METHODS',
        policyId: p.id,
        message: `Policy "${p.id}" grants ${p.methods.join('/')} but only ${usedMethods.join('/')} was used in ${u.hits} requests. Remove ${unusedMethods.join('/')}.`,
        evidence: { hits: u.hits, usedMethods, unusedMethods },
      });
    }
    if (narrowPaths) {
      recommendations.push({
        type: 'NARROW_PATHS',
        policyId: p.id,
        message: `Policy "${p.id}" allows path prefix(es) ${unusedPrefixes.join(', ')} that never matched in ${u.hits} requests. Remove them.`,
        evidence: { hits: u.hits, usedPrefixes, unusedPrefixes },
      });
    }

    proposed.push({
      ...p,
      methods: usedMethods,
      ...(narrowPaths ? { allowPaths: usedPrefixes } : {}),
    });
  }

  if (!confident) {
    recommendations.push({
      type: 'INSUFFICIENT_DATA',
      message: `Only ${fmtDuration(observationMs)} of traffic observed; need at least ${fmtDuration(opts.minObservationMs)} before recommending any change.`,
      evidence: { observationMs, required: opts.minObservationMs },
    });
  } else {
    for (const d of usage.denied) {
      if (d.count < opts.minDenied) continue;
      recommendations.push({
        type: 'REVIEW_DENIED_EDGE',
        edge: d.edge,
        message: `${d.count} requests on ${d.edge} were denied. Review before changing anything: this is what an attack probe looks like, but it can also be a missing permission.`,
        evidence: { count: d.count, reasons: d.reasons, lastSeen: d.lastSeen },
      });
    }
  }

  return {
    observationMs,
    confident,
    recommendations,
    summary: {
      permissionsGranted: granted,
      permissionsUsed: used,
      permissionsUnused: granted - used,
      unusedPercent: granted === 0 ? 0 : Math.round(((granted - used) / granted) * 100),
    },
    proposedPolicies: proposed,
    proposedDocument: { version: 1, dryRun: false, policies: proposed },
  };
}

function fmtDuration(ms: number): string {
  const s = Math.round(ms / 1000);
  if (s < 90) return `${s}s`;
  if (s < 5400) return `${Math.round(s / 60)} min`;
  return `${(s / 3600).toFixed(1)} h`;
}
