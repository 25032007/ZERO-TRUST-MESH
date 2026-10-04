/**
 * MetricsCollector — latency percentiles, throughput and decision counts.
 *
 * Latency samples go into a fixed-size circular buffer (last 10 000 requests) so
 * memory is constant. Percentiles are computed only when someone asks (the
 * dashboard polls every few seconds), never on the hot request path.
 */
import type { Decision } from '../types.js';

const SAMPLE_CAPACITY = 10_000;

export interface LatencyStats {
  samples: number;
  avgMs: number;
  p50Ms: number;
  p95Ms: number;
  p99Ms: number;
  maxMs: number;
}

export class MetricsCollector {
  private pipelineSamples = new Float64Array(SAMPLE_CAPACITY);
  private sampleCount = 0;
  private total = 0;
  private dryRunViolations = 0;
  private byDecision: Record<Decision, number> = { ALLOW: 0, MONITOR: 0, STEP_UP_AUTH: 0, BLOCK: 0 };
  /** requests per wall-clock second, last 120 s. */
  private perSecond = new Map<number, number>();

  constructor(private readonly clock: () => number = Date.now) {}

  /** A policy denial that dry-run mode let through ("would have blocked"). */
  recordDryRunViolation(): void {
    this.dryRunViolations++;
  }

  /** `pipelineMs` is time inside the security pipeline only (not the downstream call). */
  record(decision: Decision, pipelineMs: number): void {
    this.total++;
    this.byDecision[decision]++;
    this.pipelineSamples[this.sampleCount % SAMPLE_CAPACITY] = pipelineMs;
    this.sampleCount++;

    const sec = Math.floor(this.clock() / 1000);
    this.perSecond.set(sec, (this.perSecond.get(sec) ?? 0) + 1);
    if (this.perSecond.size > 130) {
      for (const k of this.perSecond.keys()) if (k < sec - 120) this.perSecond.delete(k);
    }
  }

  snapshot(): {
    total: number;
    byDecision: Record<Decision, number>;
    blockRate: number;
    dryRunViolations: number;
    requestsPerMinute: number;
    pipelineLatency: LatencyStats;
  } {
    const nowSec = Math.floor(this.clock() / 1000);
    let lastMinute = 0;
    for (const [sec, n] of this.perSecond) if (sec > nowSec - 60) lastMinute += n;

    return {
      total: this.total,
      byDecision: { ...this.byDecision },
      blockRate: this.total === 0 ? 0 : this.byDecision.BLOCK / this.total,
      dryRunViolations: this.dryRunViolations,
      requestsPerMinute: lastMinute,
      pipelineLatency: this.latency(),
    };
  }

  private latency(): LatencyStats {
    const n = Math.min(this.sampleCount, SAMPLE_CAPACITY);
    if (n === 0) return { samples: 0, avgMs: 0, p50Ms: 0, p95Ms: 0, p99Ms: 0, maxMs: 0 };

    const sorted = Array.from(this.pipelineSamples.subarray(0, n)).sort((a, b) => a - b);
    const pct = (p: number) => sorted[Math.min(n - 1, Math.floor((p / 100) * n))];
    const avg = sorted.reduce((s, x) => s + x, 0) / n;
    const round = (x: number) => Math.round(x * 1000) / 1000;
    return { samples: n, avgMs: round(avg), p50Ms: round(pct(50)), p95Ms: round(pct(95)), p99Ms: round(pct(99)), maxMs: round(sorted[n - 1]) };
  }
}
