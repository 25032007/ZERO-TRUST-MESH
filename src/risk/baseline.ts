/**
 * PairBaseline — a rolling "what is normal?" model for request rate, per
 * service pair (e.g. orders → payments).
 *
 * Why this replaces fixed thresholds
 *   "50 requests in 5 s is suspicious" is wrong for BOTH a quiet edge (3 req/5 s
 *   normally — 20 would already be an attack) and a busy one (40 req/5 s
 *   normally — 50 is just Tuesday). The baseline learns each edge's own rhythm
 *   and flags a deviation from IT.
 *
 * How it works
 *   1. Time is cut into fixed windows (default 5 s). Requests are counted per window.
 *   2. When a window completes, its count updates an EWMA (exponentially weighted
 *      moving average) of the mean AND of the variance:
 *          mean'  = mean + α·(x − mean)
 *          var'   = (1 − α)·(var + α·(x − mean)²)
 *   3. The in-progress window is compared with that history as a z-score:
 *          z = (count − mean) / max(std, minRelativeStd·mean, 1)
 *      The floor on the denominator stops a perfectly steady edge (std ≈ 0) from
 *      turning a tiny wobble into a huge z.
 *
 * False-positive guards (the mentor's main concern)
 *   • WARM-UP: nothing is scored until `minWindows` full windows have been seen,
 *     so a brand-new edge is never flagged for "spiking from zero".
 *   • MIN SPIKE SIZE: even with a big z, a window must hold at least
 *     `minSpikeCount` requests, so low-traffic edges don't alarm on 3 vs 0.
 *   • WINSORISED LEARNING: a window's count is clamped to mean + clampZ·scale
 *     before it updates the baseline. An attacker ramping traffic up slowly
 *     ("boiling the frog") can therefore only drag the baseline a bounded amount
 *     per window instead of teaching it that the attack is normal.
 *
 * Honest limitation: EWMA adapts, so a ramp slower than the clamp allows can still
 * be absorbed over a long time. The evaluation harness measures exactly that.
 */
import { capMap } from '../util/slidingCounter.js';

export interface BaselineParams {
  windowMs: number;
  /** EWMA smoothing factor in (0,1]. Higher = adapts faster (and is easier to poison). */
  alpha: number;
  /** Full windows required before scoring starts. */
  minWindows: number;
  /** Smallest request count (in one window) that may be called a spike. */
  minSpikeCount: number;
  /** Floor for the std-dev used in z, as a fraction of the mean. */
  minRelativeStd: number;
  /** Learning clamp: a window counts for at most mean + clampZ·scale. */
  clampZ: number;
  /** z >= this -> "elevated". */
  zWarn: number;
  /** z >= this -> "high". */
  zHigh: number;
}

export interface BaselineReading {
  /** Requests so far in the current window (including this one). */
  count: number;
  mean: number;
  std: number;
  z: number;
  /** False while still learning (no scoring). */
  warm: boolean;
  level: 'none' | 'elevated' | 'high';
}

interface PairState {
  windowIndex: number;
  count: number;
  mean: number;
  variance: number;
  /** Completed windows seen so far (capped, only needed for warm-up). */
  completed: number;
}

const MAX_PAIRS = 10_000;
/** If a pair was silent for longer than this many windows we only replay this many empty ones. */
const MAX_GAP_WINDOWS = 120;

export class PairBaseline {
  private pairs = new Map<string, PairState>();

  constructor(private readonly p: BaselineParams) {}

  /** Record one request for `pair` at time `now` and return how it compares with normal. */
  observe(pair: string, now: number): BaselineReading {
    const idx = Math.floor(now / this.p.windowMs);
    let st = this.pairs.get(pair);
    if (!st) {
      st = { windowIndex: idx, count: 0, mean: 0, variance: 0, completed: 0 };
      this.pairs.set(pair, st);
      capMap(this.pairs, MAX_PAIRS);
    }

    if (idx > st.windowIndex) this.rollForward(st, idx);
    st.count++;
    return this.reading(st);
  }

  /** Read-only view (used by tests, the dashboard and the policy recommender). */
  peek(pair: string): { mean: number; std: number; completed: number } | undefined {
    const st = this.pairs.get(pair);
    return st ? { mean: st.mean, std: Math.sqrt(st.variance), completed: st.completed } : undefined;
  }

  /** Close the finished window(s) and fold them into the EWMA. */
  private rollForward(st: PairState, targetIdx: number): void {
    // First, the window that just ended, with its real count.
    this.learn(st, st.count);
    // Then any completely silent windows in between (count 0): silence is data too.
    const gap = Math.min(targetIdx - st.windowIndex - 1, MAX_GAP_WINDOWS);
    for (let i = 0; i < gap; i++) this.learn(st, 0);
    st.windowIndex = targetIdx;
    st.count = 0;
  }

  private learn(st: PairState, observed: number): void {
    const { alpha, minRelativeStd, clampZ } = this.p;
    let x = observed;

    // Winsorise: once we have a baseline, a window cannot pull it up by more than clampZ·scale.
    if (st.completed >= 1) {
      const scale = Math.max(Math.sqrt(st.variance), minRelativeStd * st.mean, 1);
      x = Math.min(x, st.mean + clampZ * scale);
    }

    if (st.completed === 0) {
      st.mean = x; // seed with the first real window instead of decaying up from 0
      st.variance = 0;
    } else {
      const diff = x - st.mean;
      st.mean += alpha * diff;
      st.variance = (1 - alpha) * (st.variance + alpha * diff * diff);
    }
    st.completed = Math.min(st.completed + 1, 1_000_000);
  }

  private reading(st: PairState): BaselineReading {
    const std = Math.sqrt(st.variance);
    const warm = st.completed >= this.p.minWindows;
    const scale = Math.max(std, this.p.minRelativeStd * st.mean, 1);
    const z = (st.count - st.mean) / scale;

    let level: BaselineReading['level'] = 'none';
    if (warm && st.count >= this.p.minSpikeCount) {
      if (z >= this.p.zHigh) level = 'high';
      else if (z >= this.p.zWarn) level = 'elevated';
    }
    return { count: st.count, mean: st.mean, std, z, warm, level };
  }
}
