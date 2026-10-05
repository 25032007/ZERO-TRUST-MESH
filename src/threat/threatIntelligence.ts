import type { PipelineResult } from '../types.js';
import type { ThreatObservation } from './contracts.js';
import { normalizePipelineResult, type ThreatObservationContext } from './normalizer.js';
import { ThreatCorrelator, type ThreatCorrelationConfig } from './correlator.js';

const CAPACITY = 5_000;

/**
 * Bounded, in-process observation sink. It deliberately does not influence a
 * verdict: Phase 1 only records normalized representations of completed results.
 */
export class ThreatIntelligence {
  private observations: ThreatObservation[] = [];
  private readonly correlator: ThreatCorrelator;

  constructor(cfg: ThreatCorrelationConfig, clock: () => number = Date.now) {
    this.correlator = new ThreatCorrelator(cfg, clock);
  }

  observe(result: PipelineResult, context?: ThreatObservationContext): ThreatObservation {
    const observation = normalizePipelineResult(result, context);
    observation.findings = this.correlator.correlate(observation);
    this.observations.push(observation);
    if (this.observations.length > CAPACITY) this.observations.shift();
    return observation;
  }

  /** Newest first; intended for in-process tests and future additive consumers. */
  recent(limit = 100): ThreatObservation[] {
    return this.observations.slice(Math.max(0, this.observations.length - limit)).reverse();
  }

  /** Active correlated findings, newest first. Internal-only until the threat API phase. */
  findings(limit = 100) {
    return this.correlator.recent(limit);
  }
}
