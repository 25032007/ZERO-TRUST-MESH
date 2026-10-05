import type { PipelineResult } from '../types.js';
import type { ThreatObservation } from './contracts.js';
import { normalizePipelineResult } from './normalizer.js';

const CAPACITY = 5_000;

/**
 * Bounded, in-process observation sink. It deliberately does not influence a
 * verdict: Phase 1 only records normalized representations of completed results.
 */
export class ThreatIntelligence {
  private observations: ThreatObservation[] = [];

  observe(result: PipelineResult): ThreatObservation {
    const observation = normalizePipelineResult(result);
    this.observations.push(observation);
    if (this.observations.length > CAPACITY) this.observations.shift();
    return observation;
  }

  /** Newest first; intended for in-process tests and future additive consumers. */
  recent(limit = 100): ThreatObservation[] {
    return this.observations.slice(Math.max(0, this.observations.length - limit)).reverse();
  }
}
