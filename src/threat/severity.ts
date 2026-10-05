import type { Evidence, NormalizedSignal, ThreatFinding, ThreatSeverity } from './contracts.js';

/** Explicit category rules prevent finalized risk from silently becoming severity. */
export function assessSeverity(finding: ThreatFinding, signals: Iterable<NormalizedSignal>, _evidence: Iterable<Evidence>): ThreatSeverity {
  const primary = [...signals].filter((signal) => signal.primaryCategory === finding.category);
  if (finding.category === 'LATERAL_MOVEMENT') return 'CRITICAL';
  if (primary.some((signal) => signal.type === 'TOKEN_REPLAY')) return 'HIGH';
  if (finding.category === 'IDENTITY_COMPROMISE' && primary.some((signal) => ['INVALID_SIGNATURE', 'UNKNOWN_KEY', 'IDENTITY_MISMATCH'].includes(signal.type))) return 'HIGH';

  const recurrence = finding.recurrence?.count ?? 1;
  const hasSensitiveContext = [...signals].some((signal) => signal.type === 'SENSITIVE_ENDPOINT');
  switch (finding.category) {
    case 'AUTHORIZATION_POLICY_VIOLATION':
      return recurrence >= 2 && hasSensitiveContext ? 'HIGH' : recurrence >= 2 || hasSensitiveContext ? 'MEDIUM' : 'LOW';
    case 'BEHAVIORAL_ANOMALY':
    case 'REQUEST_PAYLOAD_ABUSE':
      return recurrence >= 3 ? 'HIGH' : recurrence >= 2 ? 'MEDIUM' : 'LOW';
    case 'SERVICE_GRAPH_ANOMALY':
    case 'RECONNAISSANCE_PROBING':
    case 'AUTHENTICATION_TOKEN_ABUSE':
      return recurrence >= 2 ? 'MEDIUM' : 'LOW';
    default:
      return 'LOW';
  }
}
