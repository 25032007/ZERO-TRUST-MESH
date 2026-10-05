import type { Evidence, NormalizedSignal, ThreatFinding } from './contracts.js';
import type { ContributionRecord } from './exposure.js';
import { categoryExposure } from './exposure.js';
import { assessConfidence } from './confidence.js';
import { assessSeverity } from './severity.js';

/** Enrich one finding using only finalized evidence and contribution records. */
export function assessFinding(finding: ThreatFinding, signals: Iterable<NormalizedSignal>, evidence: Iterable<Evidence>, contributions: Iterable<ContributionRecord>): ThreatFinding {
  const signalList = [...signals];
  const evidenceList = [...evidence];
  const exposure = categoryExposure(finding.category, contributions);
  const confidence = assessConfidence(finding, signalList, evidenceList);
  const severity = assessSeverity(finding, signalList, evidenceList);
  const explanation = explanationFor(finding, exposure.score, signalList, evidenceList);
  return {
    ...finding,
    severity,
    confidence,
    assessment: {
      categoryExposure: exposure,
      severity,
      risk: { ...finding.risk, contributionIds: [...finding.risk.contributionIds] },
      confidence,
      explanation,
    },
  };
}

function explanationFor(finding: ThreatFinding, exposure: number, signals: NormalizedSignal[], evidence: Evidence[]): string {
  const signal = signals.find((item) => item.primaryCategory === finding.category);
  const item = signal ? evidence.find((candidate) => signal.evidenceRefs.includes(candidate.evidenceId)) : undefined;
  if (item?.facts.z !== undefined) return `${signal!.type} recorded a deviation of ${item.facts.z} standard deviations.`;
  if (item?.facts.distinctHops !== undefined) return `Observed ${item.facts.distinctHops} distinct service hops in the correlated trace.`;
  if (exposure > 0) return `${finding.category} has ${exposure} points of unique existing factor exposure.`;
  return `${finding.category} is supported by finalized detector evidence.`;
}
