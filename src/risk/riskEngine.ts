/**
 * RiskEngine — turns "soft" signals into an explainable 0-100 score.
 *
 * Remember: hard failures (bad signature, replay, no policy…) never get here —
 * they are rejected earlier with a fixed severity. The risk engine answers a
 * different question about requests that ARE authentic and ARE permitted:
 * "does this particular request look suspicious?"
 *
 *   score = min(100, Σ points of every triggered factor)
 *
 * Because the score is a plain sum of named factors, the dashboard can show
 * "NEW_SERVICE_PAIR +10, SENSITIVE_ENDPOINT +10, PAYLOAD_ANOMALY +50 = 70".
 *
 * NOTE: assess() has side effects — it records this request into the frequency
 * counter and the "pairs seen" set, so call it exactly once per request.
 */
import type { MeshConfig } from '../config.js';
import { pathMatchesPrefix } from '../policy/paths.js';
import type { RiskFactor, RiskLevel } from '../types.js';
import type { AnomalyResult } from './anomaly.js';
import type { LateralResult } from '../detection/lateralMovement.js';
import { SlidingCounter, capMap } from '../util/slidingCounter.js';
import { PairBaseline } from './baseline.js';

export interface RiskInput {
  source: string;
  destination: string;
  method: string;
  path: string;
  ip: string;
  now: number;
  anomaly: AnomalyResult;
  lateral: LateralResult;
}

export interface RiskAssessment {
  score: number;
  level: RiskLevel;
  factors: RiskFactor[];
}

const MAX_TRACKED_KEYS = 10_000;

export function levelFor(score: number): RiskLevel {
  if (score >= 80) return 'CRITICAL';
  if (score >= 60) return 'HIGH';
  if (score >= 30) return 'MEDIUM';
  return 'LOW';
}

export class RiskEngine {
  /** "source->destination" pairs that have been seen before (the mesh's "normal"). */
  private seenPairs = new Set<string>();
  /** Requests per calling service (fixed-threshold mode only). */
  private frequency = new Map<string, SlidingCounter>();
  /** Rolling per-pair rate baseline (baseline mode). */
  private readonly baseline: PairBaseline;
  /** Failed authentications per IP address. */
  private authFailures = new Map<string, SlidingCounter>();

  constructor(private readonly cfg: MeshConfig) {
    this.baseline = new PairBaseline(cfg.baseline);
  }

  /** What the rate baseline currently considers normal for a pair (dashboard / recommender). */
  baselineFor(pair: string) {
    return this.baseline.peek(pair);
  }

  /** Called by the pipeline whenever authentication fails for a request from `ip`. */
  recordAuthFailure(ip: string, now: number): void {
    let counter = this.authFailures.get(ip);
    if (!counter) {
      counter = new SlidingCounter();
      this.authFailures.set(ip, counter);
      capMap(this.authFailures, MAX_TRACKED_KEYS);
    }
    counter.hit(now, this.cfg.authFailureWindowMs);
  }

  /** Forget all remembered auth failures (used by the simulator between scenarios). */
  clearAuthFailures(): void {
    this.authFailures.clear();
  }

  assess(input: RiskInput): RiskAssessment {
    const { points: pts } = this.cfg;
    const factors: RiskFactor[] = [];

    // 1. Has this exact service-to-service edge ever been used before?
    //    First sight of an edge is mildly suspicious; it stops counting afterwards.
    const pair = `${input.source}->${input.destination}`;
    if (!this.seenPairs.has(pair)) {
      this.seenPairs.add(pair);
      factors.push({ code: 'NEW_SERVICE_PAIR', points: pts.newServicePair, detail: `First request on ${pair}` });
    }

    // 2. Is the target something we consider sensitive (database, /admin …)?
    const sensitiveService = this.cfg.sensitiveServices.includes(input.destination);
    const sensitivePath = this.cfg.sensitivePathPrefixes.some((p) => pathMatchesPrefix(input.path, p));
    if (sensitiveService || sensitivePath) {
      factors.push({
        code: 'SENSITIVE_ENDPOINT',
        points: pts.sensitiveEndpoint,
        detail: `${input.method} ${input.destination}${input.path} is a sensitive target`,
      });
    }

    // 3. Outside normal business hours (UTC)?
    const hour = new Date(input.now).getUTCHours();
    const { startHour, endHour } = this.cfg.businessHours;
    if (hour < startHour || hour >= endHour) {
      factors.push({ code: 'OFF_HOURS', points: pts.offHours, detail: `Request at ${hour}:00 UTC, outside ${startHour}-${endHour}` });
    }

    // 4. Is this edge suddenly much busier than IT is normally?
    if (this.cfg.riskMode === 'baseline') {
      const r = this.baseline.observe(pair, input.now);
      if (r.level !== 'none') {
        factors.push({
          code: 'RATE_SPIKE',
          points: r.level === 'high' ? pts.rateSpikeHigh : pts.rateSpikeElevated,
          detail: `${r.count} requests in ${this.cfg.baseline.windowMs / 1000}s vs normal ${r.mean.toFixed(1)}±${r.std.toFixed(1)} on ${pair} (z=${r.z.toFixed(1)})`,
        });
      }
    } else {
      // Fixed thresholds: one global "N per window" rule per calling service.
      let freq = this.frequency.get(input.source);
      if (!freq) {
        freq = new SlidingCounter();
        this.frequency.set(input.source, freq);
      }
      const recent = freq.hit(input.now, this.cfg.burst.windowMs);
      if (recent >= this.cfg.burst.highAt) {
        factors.push({ code: 'ABNORMAL_FREQUENCY', points: pts.burstHigh, detail: `${recent} requests in ${this.cfg.burst.windowMs / 1000}s` });
      } else if (recent >= this.cfg.burst.warnAt) {
        factors.push({ code: 'ELEVATED_FREQUENCY', points: pts.burstWarn, detail: `${recent} requests in ${this.cfg.burst.windowMs / 1000}s` });
      }
    }

    // 5. Odd-looking body?
    if (input.anomaly.points > 0) {
      factors.push({ code: 'PAYLOAD_ANOMALY', points: input.anomaly.points, detail: input.anomaly.findings.join('; ') });
    }

    // 6. Has this IP recently failed authentication? (keyed by IP, NOT by the
    //    claimed service id — otherwise anyone could frame a victim service by
    //    sending forged tokens in its name and push it into quarantine.)
    const fails = this.authFailures.get(input.ip)?.count(input.now, this.cfg.authFailureWindowMs) ?? 0;
    if (fails > 0) {
      factors.push({
        code: 'RECENT_AUTH_FAILURES',
        points: Math.min(pts.maxAuthFailurePoints, fails * pts.perRecentAuthFailure),
        detail: `${fails} failed authentication(s) from this IP in the last minute`,
      });
    }

    // 7. Multi-hop traversal inside one trace.
    if (input.lateral.detected) {
      factors.push({
        code: 'LATERAL_MOVEMENT',
        points: pts.lateralMovement,
        detail: `${input.lateral.hops} hops in one trace: ${input.lateral.path.join(' → ')}`,
      });
    }

    const score = Math.min(100, factors.reduce((sum, f) => sum + f.points, 0));
    return { score, level: levelFor(score), factors };
  }
}
