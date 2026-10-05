import type { Evidence, NormalizedSignal, ThreatConfidence, ThreatFinding } from './contracts.js';

/** Four fixed criteria keep confidence separate from risk and reproducible. */
export function assessConfidence(finding: ThreatFinding, signals: Iterable<NormalizedSignal>, evidence: Iterable<Evidence>): ThreatConfidence {
  const primarySignals = [...signals].filter((signal) => signal.primaryCategory === finding.category);
  const records = [...evidence];
  const hasWarmStatisticalSignal = primarySignals.some((signal) => {
    const item = records.find((candidate) => signal.evidenceRefs.includes(candidate.evidenceId));
    return item?.reliability === 'statistical' && item.facts.warm === true;
  });
  const hasColdStatisticalSignal = primarySignals.some((signal) => {
    const item = records.find((candidate) => signal.evidenceRefs.includes(candidate.evidenceId));
    return item?.reliability === 'statistical' && item.facts.warm !== true;
  });
  const deterministic = primarySignals.some((signal) => {
    const item = records.find((candidate) => signal.evidenceRefs.includes(candidate.evidenceId));
    return item?.reliability === 'deterministic';
  });
  const detectorValidity = (deterministic || hasWarmStatisticalSignal || primarySignals.some((signal) => {
    const item = records.find((candidate) => signal.evidenceRefs.includes(candidate.evidenceId));
    return item?.reliability === 'contextual';
  })) && !hasColdStatisticalSignal;
  const evidenceCompleteness = primarySignals.some((signal) => records.some((item) =>
    signal.evidenceRefs.includes(item.evidenceId)
      && item.completeness === 'complete'
      && item.observedAt !== undefined
      && item.detector.name.length > 0
      && item.detector.version.length > 0
      && Object.keys(item.facts).length > 0,
  ));
  const distinctTypes = new Set(primarySignals.map((signal) => signal.type));
  const corroboration = primarySignals.some((signal) => signal.type === 'TOKEN_REPLAY')
    || distinctTypes.size >= 2
    || (finding.recurrence?.count ?? 1) >= 2;
  const correlationQuality = finding.attackPath?.traceId !== undefined
    || finding.correlationKey?.startsWith('trace:') === true
    || finding.correlationKey?.startsWith('edge:') === true
    || finding.correlationKey?.startsWith('service:') === true
    || records.some((item) => item.requestId !== undefined);
  const criteria = [
    criterion('detectorValidity', detectorValidity, detectorValidity ? 'Detector inputs satisfied its deterministic or warm-baseline condition.' : 'Statistical baseline is not warm or detector evidence is unavailable.'),
    criterion('evidenceCompleteness', evidenceCompleteness, evidenceCompleteness ? 'Required detector, timestamp, entity, and facts are present.' : 'Required detector facts or entity context are incomplete.'),
    criterion('corroboration', corroboration, corroboration ? 'Cryptographic proof, independent signal type, or distinct recurrence supports the finding.' : 'Only one uncorroborated signal supports the finding.'),
    criterion('correlationQuality', correlationQuality, correlationQuality ? 'A request, trace, edge, or service correlation identity is available.' : 'No usable correlation identity is available.'),
  ];
  return { score: criteria.reduce((sum, item) => sum + item.points, 0), criteria };
}

function criterion(name: ThreatConfidence['criteria'][number]['name'], satisfied: boolean, reason: string): ThreatConfidence['criteria'][number] {
  return { name, satisfied, points: satisfied ? 25 : 0, reason };
}
