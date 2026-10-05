import type { PipelineResult, RiskFactor } from '../types.js';
import type { Evidence, EvidenceFacts, EvidenceKind, EvidenceReliability, NormalizedSignal, SignalDisposition, SignalType, ThreatCategory, ThreatFinding, ThreatObservation, ThreatSeverity } from './contracts.js';

const DETECTOR = { name: 'security-pipeline', version: '1' } as const;

interface Mapping {
  type: SignalType;
  primaryCategory: ThreatCategory;
  secondaryCategories?: ThreatCategory[];
  kind: EvidenceKind;
  reliability: EvidenceReliability;
}

const FACTOR_MAPPINGS: Record<string, Mapping> = {
  NEW_SERVICE_PAIR: { type: 'NEW_SERVICE_PAIR', primaryCategory: 'SERVICE_GRAPH_ANOMALY', secondaryCategories: ['BEHAVIORAL_ANOMALY'], kind: 'graph', reliability: 'contextual' },
  SENSITIVE_ENDPOINT: { type: 'SENSITIVE_ENDPOINT', primaryCategory: 'SERVICE_GRAPH_ANOMALY', kind: 'graph', reliability: 'contextual' },
  OFF_HOURS: { type: 'OFF_HOURS', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'baseline', reliability: 'contextual' },
  RATE_SPIKE: { type: 'RATE_SPIKE', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'rate', reliability: 'statistical' },
  ELEVATED_FREQUENCY: { type: 'RATE_SPIKE', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'rate', reliability: 'deterministic' },
  ABNORMAL_FREQUENCY: { type: 'RATE_SPIKE', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'rate', reliability: 'deterministic' },
  RECENT_AUTH_FAILURES: { type: 'RECENT_AUTH_FAILURES', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'authentication', reliability: 'contextual' },
  PAYLOAD_ANOMALY: { type: 'PAYLOAD_ANOMALY', primaryCategory: 'REQUEST_PAYLOAD_ABUSE', secondaryCategories: ['BEHAVIORAL_ANOMALY'], kind: 'payload', reliability: 'deterministic' },
  LATERAL_MOVEMENT: { type: 'LATERAL_MOVEMENT', primaryCategory: 'LATERAL_MOVEMENT', secondaryCategories: ['SERVICE_GRAPH_ANOMALY'], kind: 'trace', reliability: 'deterministic' },
};

const HARD_MAPPINGS: Record<string, Mapping> = {
  INVALID_SIGNATURE: { type: 'INVALID_SIGNATURE', primaryCategory: 'IDENTITY_COMPROMISE', secondaryCategories: ['AUTHENTICATION_TOKEN_ABUSE'], kind: 'identity', reliability: 'deterministic' },
  UNKNOWN_KEY: { type: 'UNKNOWN_KEY', primaryCategory: 'IDENTITY_COMPROMISE', kind: 'identity', reliability: 'deterministic' },
  IDENTITY_MISMATCH: { type: 'IDENTITY_MISMATCH', primaryCategory: 'IDENTITY_COMPROMISE', secondaryCategories: ['AUTHENTICATION_TOKEN_ABUSE'], kind: 'identity', reliability: 'deterministic' },
  SERVICE_NOT_ACTIVE: { type: 'DISABLED_IDENTITY', primaryCategory: 'IDENTITY_COMPROMISE', kind: 'identity', reliability: 'deterministic' },
  TOKEN_EXPIRED: { type: 'TOKEN_EXPIRED', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  INVALID_CLAIMS: { type: 'TOKEN_INVALID_CLAIMS', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  LIFETIME_TOO_LONG: { type: 'TOKEN_LIFETIME_VIOLATION', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  TOKEN_REPLAY: { type: 'TOKEN_REPLAY', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', secondaryCategories: ['IDENTITY_COMPROMISE'], kind: 'token', reliability: 'deterministic' },
  TOKEN_REVOKED: { type: 'TOKEN_REVOKED', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  NO_POLICY: { type: 'NO_POLICY', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  EXPLICIT_DENY: { type: 'POLICY_DENIED', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  PATH_DENIED: { type: 'POLICY_DENIED', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  METHOD_NOT_ALLOWED: { type: 'METHOD_NOT_ALLOWED', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  PATH_NOT_ALLOWED: { type: 'PATH_NOT_ALLOWED', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  OUTSIDE_TIME_WINDOW: { type: 'TIME_WINDOW_DENIED', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  SERVICE_QUARANTINED: { type: 'QUARANTINE', primaryCategory: 'LATERAL_MOVEMENT', kind: 'quarantine', reliability: 'deterministic' },
  RATE_LIMITED: { type: 'RATE_LIMITED', primaryCategory: 'RECONNAISSANCE_PROBING', kind: 'rate', reliability: 'contextual' },
};

/** Convert a completed pipeline verdict into additive, bounded threat contracts. */
export function normalizePipelineResult(result: PipelineResult): ThreatObservation {
  const pairs: Array<{ mapping: Mapping; disposition: SignalDisposition; factor?: RiskFactor; dryRun?: boolean }> = [];
  for (const factor of result.factors) {
    const mapping = FACTOR_MAPPINGS[factor.code];
    if (mapping) pairs.push({ mapping, disposition: 'observed', factor });
  }
  const hard = HARD_MAPPINGS[result.reason];
  if (hard) pairs.push({ mapping: hard, disposition: 'hard_failure' });
  if (result.dryRunViolation) {
    pairs.push({
      mapping: { type: 'DRY_RUN_POLICY_VIOLATION', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
      disposition: 'dry_run',
      dryRun: true,
    });
  }

  const evidence: Evidence[] = [];
  const signals: NormalizedSignal[] = [];
  const findings: ThreatFinding[] = [];
  pairs.forEach(({ mapping, disposition, factor, dryRun }, index) => {
    const suffix = `${mapping.type}:${index}`;
    const evidenceId = `${result.requestId}:evidence:${suffix}`;
    const signalId = `${result.requestId}:signal:${suffix}`;
    const facts: EvidenceFacts = factor
      ? { factorCode: factor.code, points: factor.points, detail: factor.detail }
      : { reason: result.reason, method: result.method, path: result.path, dryRun: !!dryRun };
    const item: Evidence = {
      evidenceId,
      kind: mapping.kind,
      observedAt: result.timestamp,
      source: result.source,
      destination: result.destination,
      requestId: result.requestId,
      traceId: result.traceId,
      detector: DETECTOR,
      facts,
      reliability: mapping.reliability,
      completeness: result.source || result.destination ? 'complete' : 'partial',
    };
    const contributionId = factor ? `${result.requestId}:factor:${factor.code}:${index}` : undefined;
    const signal: NormalizedSignal = {
      signalId,
      occurredAt: result.timestamp,
      type: mapping.type,
      source: result.source,
      destination: result.destination,
      correlationId: result.traceId,
      detector: DETECTOR,
      disposition,
      ...(factor ? { riskContribution: { id: contributionId!, points: factor.points, factorCode: factor.code } } : {}),
      primaryCategory: mapping.primaryCategory,
      ...(mapping.secondaryCategories ? { secondaryCategories: mapping.secondaryCategories } : {}),
      evidenceRefs: [evidenceId],
      metadata: factor ? { factorCode: factor.code, points: factor.points } : { reason: result.reason },
    };
    evidence.push(item);
    signals.push(signal);
    findings.push({
      findingId: `${result.requestId}:finding:${suffix}`,
      openedAt: result.timestamp,
      lastSeenAt: result.timestamp,
      category: mapping.primaryCategory,
      severity: severityFor(signal, result),
      risk: { score: result.riskScore, riskModelVersion: 'existing-factor-ledger-v1', contributionIds: contributionId ? [contributionId] : [] },
      confidence: { score: confidenceFor(item), criteria: confidenceCriteria(item) },
      status: 'active',
      evidenceIds: [evidenceId],
      detectorSummary: [DETECTOR],
      source: result.source,
      destination: result.destination,
      affectedServices: [result.source, result.destination].filter((id): id is string => !!id),
      correlationKey: result.traceId ? `trace:${result.traceId}` : undefined,
      decisionContext: { decision: result.decision, reason: result.reason, ...(isHardOverride(signal, result) ? { hardOverride: true } : {}) },
    });
  });
  return { signals, evidence, findings };
}

function severityFor(signal: NormalizedSignal, result: PipelineResult): ThreatSeverity {
  if (signal.type === 'LATERAL_MOVEMENT') return 'CRITICAL';
  if (['TOKEN_REPLAY', 'INVALID_SIGNATURE', 'UNKNOWN_KEY', 'IDENTITY_MISMATCH'].includes(signal.type)) return 'HIGH';
  if (result.riskScore >= 60) return 'HIGH';
  if (result.riskScore >= 30) return 'MEDIUM';
  return 'LOW';
}

function confidenceCriteria(evidence: Evidence): string[] {
  const criteria = ['detector_validity', 'evidence_completeness'];
  if (evidence.reliability === 'deterministic') criteria.push('corroboration');
  if (evidence.traceId || evidence.requestId) criteria.push('correlation_quality');
  return criteria;
}

function confidenceFor(evidence: Evidence): number {
  return confidenceCriteria(evidence).length * 25;
}

function isHardOverride(signal: NormalizedSignal, result: PipelineResult): boolean {
  return signal.disposition === 'hard_failure' || (signal.type === 'LATERAL_MOVEMENT' && result.reason === 'LATERAL_MOVEMENT');
}
