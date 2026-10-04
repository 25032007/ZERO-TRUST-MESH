/**
 * LateralMovementDetector — spots an attacker "pivoting" through the mesh.
 *
 * Scenario: an attacker compromises the frontend, then uses it to reach orders,
 * then payments, then the database. Each single hop may look legitimate on its
 * own (every one has an allow-policy), but a chain of several hops in under a
 * second inside ONE trace is how automated pivoting looks.
 *
 * How it works
 *   Services forward a shared `X-Trace-Id` header when they call each other. For
 *   every authorised hop we remember (from → to, time) under that trace id. If
 *   `minHops` distinct hops land inside `windowMs`, we raise an alert.
 *
 * Honest limitation (also in the README): a legitimately deep call chain that is
 * very fast would trigger this too. `minHops` / `windowMs` are tunable, and the
 * detector only feeds a risk signal + containment — it is not proof of malice.
 */
import type { MeshConfig } from '../config.js';
import { capMap } from '../util/slidingCounter.js';

interface Hop {
  from: string;
  to: string;
  at: number;
}

export interface LateralResult {
  detected: boolean;
  /** Ordered service path of the chain, e.g. [frontend, orders, payments, database]. */
  path: string[];
  hops: number;
  /** True when the chain looked like traversal but matches a DECLARED workflow, so it was not flagged. */
  knownWorkflow: boolean;
}

const MAX_TRACKED_TRACES = 10_000;

export class LateralMovementDetector {
  private traces = new Map<string, Hop[]>();

  constructor(
    private readonly cfg: MeshConfig['lateral'],
    /**
     * Optional allow-list of declared workflows (policy-as-code). A chain that
     * matches one is normal business logic, not an attacker pivoting. This is
     * how legitimate deep call chains stop causing false positives.
     */
    private readonly isKnownWorkflow: (path: string[]) => boolean = () => false,
  ) {}

  observe(traceId: string, from: string, to: string, now: number): LateralResult {
    // Keep only hops that are still inside the sliding window.
    const hops = (this.traces.get(traceId) ?? []).filter((h) => now - h.at <= this.cfg.windowMs);
    hops.push({ from, to, at: now });

    // Re-insert so this trace becomes the "newest" entry in the Map (see capMap).
    this.traces.delete(traceId);
    this.traces.set(traceId, hops);
    capMap(this.traces, MAX_TRACKED_TRACES);

    // Count DISTINCT edges: hammering the same hop 100 times is a frequency
    // problem (handled elsewhere), not a traversal across the mesh.
    const distinct = new Set(hops.map((h) => `${h.from}->${h.to}`));
    const looksLikeTraversal = distinct.size >= this.cfg.minHops;

    // Rebuild the node path in the order the hops happened.
    const path: string[] = [];
    for (const h of hops) {
      if (path.length === 0) path.push(h.from);
      if (path[path.length - 1] !== h.to) path.push(h.to);
    }
    const knownWorkflow = looksLikeTraversal && this.isKnownWorkflow(path);
    return { detected: looksLikeTraversal && !knownWorkflow, path, hops: distinct.size, knownWorkflow };
  }
}
