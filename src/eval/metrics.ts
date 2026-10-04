/**
 * Evaluation metrics: precision, recall, false-positive rate — at two levels.
 *
 *  EVENT level    every request is one sample ("was this request flagged?").
 *  EPISODE level  one attack (a flood, a pivot chain…) counts as detected if ANY of
 *                 its requests was flagged; we also report how long that took.
 *                 Event recall alone under-sells a detector that catches a flood
 *                 after 3 seconds and over-sells one that flags a single request.
 *
 * "Flagged" = the pipeline answered MONITOR, STEP_UP_AUTH or BLOCK (an analyst would
 * see it). "Actioned" = STEP_UP_AUTH or BLOCK (traffic was actually interrupted).
 *
 * Collateral: a NORMAL request refused only because its service was quarantined
 * (usually as a result of an attack) is reported separately as `collateralBlocks`
 * and kept out of the false-positive rate, so FPR measures the detector's
 * judgement on benign traffic and not the side-effect of containing an attack.
 */
import type { Decision } from '../types.js';
import { BEHAVIORAL_ATTACKS, HARD_FAIL_ATTACKS, type AttackClass, type Episode, type EvalEvent } from './trafficGenerator.js';

export interface Outcome {
  event: EvalEvent;
  decision: Decision;
  reason: string;
  riskScore: number;
}

export interface ClassMetrics {
  events: number;
  flagged: number;
  eventRecall: number;
  episodes: number;
  episodesDetected: number;
  episodeRecall: number;
  /** Median time from episode start to its first flagged request (undefined if never detected). */
  medianTimeToDetectMs?: number;
}

export interface Confusion {
  tp: number;
  fp: number;
  tn: number;
  fn: number;
  precision: number;
  recall: number;
  fpr: number;
  f1: number;
}

export interface EvalMetrics {
  normalEvents: number;
  falsePositives: number;
  collateralBlocks: number;
  fpr: number;
  /** Behavioural attacks vs normal (the meaningful comparison). */
  behavioral: Confusion;
  /** Identity/policy attacks vs normal. */
  hardFail: Confusion;
  perClass: Record<AttackClass, ClassMetrics>;
}

export const isFlagged = (d: Decision) => d !== 'ALLOW';

const ratio = (a: number, b: number) => (b === 0 ? 0 : a / b);

function confusion(outcomes: Outcome[], attackClasses: AttackClass[]): Confusion {
  let tp = 0, fp = 0, tn = 0, fn = 0;
  for (const o of outcomes) {
    const flagged = isFlagged(o.decision);
    if (o.event.label === 'normal') {
      if (o.reason === 'SERVICE_QUARANTINED') continue; // collateral, reported separately
      if (flagged) fp++;
      else tn++;
    } else if (attackClasses.includes(o.event.label)) {
      if (flagged) tp++;
      else fn++;
    }
  }
  const precision = ratio(tp, tp + fp);
  const recall = ratio(tp, tp + fn);
  return { tp, fp, tn, fn, precision, recall, fpr: ratio(fp, fp + tn), f1: precision + recall === 0 ? 0 : (2 * precision * recall) / (precision + recall) };
}

function median(xs: number[]): number | undefined {
  if (xs.length === 0) return undefined;
  const s = [...xs].sort((a, b) => a - b);
  const mid = Math.floor(s.length / 2);
  return s.length % 2 ? s[mid] : (s[mid - 1] + s[mid]) / 2;
}

export function computeMetrics(outcomes: Outcome[], episodes: Episode[]): EvalMetrics {
  const normals = outcomes.filter((o) => o.event.label === 'normal');
  const collateralBlocks = normals.filter((o) => o.reason === 'SERVICE_QUARANTINED').length;
  const judged = normals.filter((o) => o.reason !== 'SERVICE_QUARANTINED');
  const falsePositives = judged.filter((o) => isFlagged(o.decision)).length;

  const perClass = {} as Record<AttackClass, ClassMetrics>;
  for (const cls of [...BEHAVIORAL_ATTACKS, ...HARD_FAIL_ATTACKS]) {
    const ev = outcomes.filter((o) => o.event.label === cls);
    const eps = episodes.filter((e) => e.cls === cls);
    const detectTimes: number[] = [];
    let detected = 0;
    for (const ep of eps) {
      const flagged = ev.filter((o) => o.event.episode === ep.id && isFlagged(o.decision)).sort((a, b) => a.event.t - b.event.t);
      if (flagged.length > 0) {
        detected++;
        detectTimes.push(flagged[0].event.t - ep.startT);
      }
    }
    perClass[cls] = {
      events: ev.length,
      flagged: ev.filter((o) => isFlagged(o.decision)).length,
      eventRecall: ratio(ev.filter((o) => isFlagged(o.decision)).length, ev.length),
      episodes: eps.length,
      episodesDetected: detected,
      episodeRecall: ratio(detected, eps.length),
      medianTimeToDetectMs: median(detectTimes),
    };
  }

  return {
    normalEvents: judged.length,
    falsePositives,
    collateralBlocks,
    fpr: ratio(falsePositives, judged.length),
    behavioral: confusion(outcomes, BEHAVIORAL_ATTACKS),
    hardFail: confusion(outcomes, HARD_FAIL_ATTACKS),
    perClass,
  };
}

/** Mean and sample standard deviation (for reporting results across several seeds). */
export function meanStd(xs: number[]): { mean: number; std: number } {
  const mean = xs.reduce((a, b) => a + b, 0) / (xs.length || 1);
  const variance = xs.length > 1 ? xs.reduce((a, b) => a + (b - mean) ** 2, 0) / (xs.length - 1) : 0;
  return { mean, std: Math.sqrt(variance) };
}
