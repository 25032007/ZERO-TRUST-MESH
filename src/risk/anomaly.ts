/**
 * AnomalyEngine — "does this request body look unusual?"
 *
 * Three cheap, explainable checks (no ML, on purpose — every flag can be justified):
 *   1. SIZE   : body larger than a hard limit
 *   2. DEPTH  : JSON nested deeper than a limit (classic parser-DoS / smuggling shape)
 *   3. Z-SCORE: size is a statistical outlier compared with that destination's history
 *
 * The statistical baseline uses Welford's online algorithm, which updates the mean
 * and variance in O(1) per sample without storing the samples.
 */
import type { MeshConfig } from '../config.js';

export interface AnomalyResult {
  points: number;
  findings: string[];
}

/** Running mean/variance (Welford). */
class Welford {
  n = 0;
  mean = 0;
  private m2 = 0;

  add(x: number): void {
    this.n++;
    const delta = x - this.mean;
    this.mean += delta / this.n;
    this.m2 += delta * (x - this.mean);
  }

  get std(): number {
    return this.n > 1 ? Math.sqrt(this.m2 / (this.n - 1)) : 0;
  }
}

/**
 * Maximum nesting depth of a JSON value, computed ITERATIVELY.
 * (A recursive version could itself overflow the stack on a malicious payload —
 * the detector must not be the thing that crashes.)
 */
export function jsonDepth(value: unknown): number {
  if (value === null || typeof value !== 'object') return 0;
  let maxDepth = 0;
  const stack: Array<{ v: unknown; d: number }> = [{ v: value, d: 1 }];
  while (stack.length > 0) {
    const { v, d } = stack.pop()!;
    if (d > maxDepth) maxDepth = d;
    if (v !== null && typeof v === 'object') {
      for (const child of Object.values(v as Record<string, unknown>)) {
        if (child !== null && typeof child === 'object') stack.push({ v: child, d: d + 1 });
      }
    }
  }
  return maxDepth;
}

export class AnomalyEngine {
  /** One size baseline per key (the pipeline uses "source->destination"). */
  private baselines = new Map<string, Welford>();

  constructor(private readonly cfg: MeshConfig['payload']) {}

  analyze(key: string, body: unknown, bytes: number): AnomalyResult {
    const findings: string[] = [];
    let points = 0;

    if (bytes > this.cfg.maxBytes) {
      points += this.cfg.sizePoints;
      findings.push(`payload ${bytes} bytes exceeds limit ${this.cfg.maxBytes}`);
    }

    const depth = jsonDepth(body);
    if (depth > this.cfg.maxDepth) {
      points += this.cfg.depthPoints;
      findings.push(`JSON nesting depth ${depth} exceeds limit ${this.cfg.maxDepth}`);
    }

    // Statistical check — only once we have enough history to trust it.
    let base = this.baselines.get(key);
    if (!base) {
      base = new Welford();
      this.baselines.set(key, base);
    }
    if (base.n >= this.cfg.minSamples) {
      // Floor the std-dev at 1 byte so a perfectly constant history doesn't divide by ~0.
      const z = (bytes - base.mean) / Math.max(base.std, 1);
      if (z > this.cfg.zScoreLimit) {
        points += this.cfg.zScorePoints;
        findings.push(`payload size z-score ${z.toFixed(1)} (typical ≈ ${Math.round(base.mean)} bytes)`);
      }
    }

    // Only learn from payloads that were NOT flagged — otherwise an attacker could
    // slowly "teach" the baseline that huge payloads are normal (baseline poisoning).
    if (findings.length === 0) base.add(bytes);

    return { points: Math.min(points, this.cfg.maxPoints), findings };
  }
}
