import type { PipelineResult, RiskFactor } from '../types.js';
import type { LateralResult } from '../detection/lateralMovement.js';
import type { Evidence, EvidenceFacts, EvidenceKind, EvidenceReliability, NormalizedSignal, SignalDisposition, SignalRole, SignalType, ThreatCategory, ThreatFinding, ThreatObservation, ThreatSeverity } from './contracts.js';

const DETECTOR = { name: 'security-pipeline', version: '1' } as const;

interface Mapping {
  type: SignalType;
  role: SignalRole;
  primaryCategory?: ThreatCategory;
  secondaryCategories?: ThreatCategory[];
  contextualCategories?: ThreatCategory[];
  kind: EvidenceKind;
  reliability: EvidenceReliability;
}

/** Internal-only context preserves detector facts without changing PipelineResult or its public consumers. */
export interface ThreatObservationContext {
  lateral?: LateralResult;
}

const FACTOR_MAPPINGS: Record<string, Mapping> = {
  NEW_SERVICE_PAIR: { type: 'NEW_SERVICE_PAIR', role: 'threat_signal', primaryCategory: 'SERVICE_GRAPH_ANOMALY', secondaryCategories: ['BEHAVIORAL_ANOMALY'], kind: 'graph', reliability: 'contextual' },
  // A sensitive target changes the impact of another finding; it does not itself prove graph, probing, or payload abuse.
  SENSITIVE_ENDPOINT: { type: 'SENSITIVE_ENDPOINT', role: 'contextual_evidence', contextualCategories: ['SERVICE_GRAPH_ANOMALY', 'RECONNAISSANCE_PROBING', 'REQUEST_PAYLOAD_ABUSE'], kind: 'graph', reliability: 'contextual' },
  OFF_HOURS: { type: 'OFF_HOURS', role: 'threat_signal', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'baseline', reliability: 'contextual' },
  RATE_SPIKE: { type: 'RATE_SPIKE', role: 'threat_signal', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'rate', reliability: 'statistical' },
  ELEVATED_FREQUENCY: { type: 'RATE_SPIKE', role: 'threat_signal', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'rate', reliability: 'deterministic' },
  ABNORMAL_FREQUENCY: { type: 'RATE_SPIKE', role: 'threat_signal', primaryCategory: 'BEHAVIORAL_ANOMALY', kind: 'rate', reliability: 'deterministic' },
  RECENT_AUTH_FAILURES: { type: 'RECENT_AUTH_FAILURES', role: 'threat_signal', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'authentication', reliability: 'contextual' },
  PAYLOAD_ANOMALY: { type: 'PAYLOAD_ANOMALY', role: 'threat_signal', primaryCategory: 'REQUEST_PAYLOAD_ABUSE', secondaryCategories: ['BEHAVIORAL_ANOMALY'], kind: 'payload', reliability: 'deterministic' },
  LATERAL_MOVEMENT: { type: 'LATERAL_MOVEMENT', role: 'threat_signal', primaryCategory: 'LATERAL_MOVEMENT', secondaryCategories: ['SERVICE_GRAPH_ANOMALY'], kind: 'trace', reliability: 'deterministic' },
};

const HARD_MAPPINGS: Record<string, Mapping> = {
  INVALID_SIGNATURE: { type: 'INVALID_SIGNATURE', role: 'threat_signal', primaryCategory: 'IDENTITY_COMPROMISE', secondaryCategories: ['AUTHENTICATION_TOKEN_ABUSE'], kind: 'identity', reliability: 'deterministic' },
  UNKNOWN_KEY: { type: 'UNKNOWN_KEY', role: 'threat_signal', primaryCategory: 'IDENTITY_COMPROMISE', kind: 'identity', reliability: 'deterministic' },
  IDENTITY_MISMATCH: { type: 'IDENTITY_MISMATCH', role: 'threat_signal', primaryCategory: 'IDENTITY_COMPROMISE', secondaryCategories: ['AUTHENTICATION_TOKEN_ABUSE'], kind: 'identity', reliability: 'deterministic' },
  SERVICE_NOT_ACTIVE: { type: 'DISABLED_IDENTITY', role: 'threat_signal', primaryCategory: 'IDENTITY_COMPROMISE', kind: 'identity', reliability: 'deterministic' },
  TOKEN_EXPIRED: { type: 'TOKEN_EXPIRED', role: 'threat_signal', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  INVALID_CLAIMS: { type: 'TOKEN_INVALID_CLAIMS', role: 'threat_signal', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  LIFETIME_TOO_LONG: { type: 'TOKEN_LIFETIME_VIOLATION', role: 'threat_signal', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  TOKEN_REPLAY: { type: 'TOKEN_REPLAY', role: 'threat_signal', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', secondaryCategories: ['IDENTITY_COMPROMISE'], kind: 'token', reliability: 'deterministic' },
  TOKEN_REVOKED: { type: 'TOKEN_REVOKED', role: 'threat_signal', primaryCategory: 'AUTHENTICATION_TOKEN_ABUSE', kind: 'token', reliability: 'deterministic' },
  NO_POLICY: { type: 'NO_POLICY', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  EXPLICIT_DENY: { type: 'POLICY_DENIED', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  PATH_DENIED: { type: 'POLICY_DENIED', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  METHOD_NOT_ALLOWED: { type: 'METHOD_NOT_ALLOWED', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  INVALID_PATH: { type: 'INVALID_PATH', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  PATH_NOT_ALLOWED: { type: 'PATH_NOT_ALLOWED', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  OUTSIDE_TIME_WINDOW: { type: 'TIME_WINDOW_DENIED', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
  SERVICE_QUARANTINED: { type: 'QUARANTINE', role: 'decision_context', kind: 'quarantine', reliability: 'deterministic' },
  RATE_LIMITED: { type: 'RATE_LIMITED', role: 'control_outcome', kind: 'rate', reliability: 'contextual' },
};

/** Convert a completed pipeline verdict into additive, bounded threat contracts. */
export function normalizePipelineResult(result: PipelineResult, context: ThreatObservationContext = {}): ThreatObservation {
  const pairs: Array<{ mapping: Mapping; disposition: SignalDisposition; factor?: RiskFactor; dryRun?: boolean }> = [];
  for (const factor of result.factors) {
    const mapping = FACTOR_MAPPINGS[factor.code];
    if (mapping) pairs.push({ mapping, disposition: 'observed', factor });
  }
  const hard = HARD_MAPPINGS[result.reason];
  if (hard) pairs.push({ mapping: hard, disposition: 'hard_failure' });
  if (result.dryRunViolation) {
    pairs.push({
      mapping: { type: 'DRY_RUN_POLICY_VIOLATION', role: 'threat_signal', primaryCategory: 'AUTHORIZATION_POLICY_VIOLATION', kind: 'policy', reliability: 'deterministic' },
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
      ? factor.code === 'LATERAL_MOVEMENT' && context.lateral
        ? { factorCode: factor.code, points: factor.points, detail: factor.detail, path: context.lateral.path, distinctHops: context.lateral.hops, declaredWorkflow: context.lateral.knownWorkflow }
        : { factorCode: factor.code, points: factor.points, detail: factor.detail }
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
      role: mapping.role,
      ...(factor ? { riskContribution: { id: contributionId!, points: factor.points, factorCode: factor.code } } : {}),
      ...(mapping.primaryCategory ? { primaryCategory: mapping.primaryCategory } : {}),
      ...(mapping.secondaryCategories ? { secondaryCategories: mapping.secondaryCategories } : {}),
      ...(mapping.contextualCategories ? { contextualCategories: mapping.contextualCategories } : {}),
      evidenceRefs: [evidenceId],
      metadata: factor ? { factorCode: factor.code, points: factor.points } : { reason: result.reason },
    };
    evidence.push(item);
    signals.push(signal);
    if (!mapping.primaryCategory) return;
    findings.push({
      findingId: `${result.requestId}:finding:${suffix}`,
      openedAt: result.timestamp,
      lastSeenAt: result.timestamp,
      category: mapping.primaryCategory,
      severity: severityFor(signal, result),
      risk: { score: result.riskScore, riskModelVersion: 'existing-factor-ledger-v1', contributionIds: contributionId ? [contributionId] : [] },
      confidence: confidenceFor(item),
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
  // Context-dependent severity is enriched from evidence/recurrence later; final risk is never a severity proxy.
  void result;
  return 'LOW';
}

function confidenceFor(evidence: Evidence): ThreatFinding['confidence'] {
  const deterministic = evidence.reliability === 'deterministic';
  const correlated = evidence.traceId !== undefined || evidence.requestId !== undefined;
  const criteria = [
    { name: 'detectorValidity' as const, satisfied: true, points: 25 as const, reason: 'The security pipeline emitted this normalized signal.' },
    { name: 'evidenceCompleteness' as const, satisfied: evidence.completeness === 'complete', points: evidence.completeness === 'complete' ? 25 as const : 0 as const, reason: evidence.completeness === 'complete' ? 'Required evidence fields are present.' : 'Required evidence fields are incomplete.' },
    { name: 'corroboration' as const, satisfied: deterministic, points: deterministic ? 25 as const : 0 as const, reason: deterministic ? 'The detector produced deterministic evidence.' : 'No independent corroboration is available yet.' },
    { name: 'correlationQuality' as const, satisfied: correlated, points: correlated ? 25 as const : 0 as const, reason: correlated ? 'Request or trace identity is available.' : 'No request or trace identity is available.' },
  ];
  return { score: criteria.reduce((sum, criterion) => sum + criterion.points, 0), criteria };
}

function isHardOverride(signal: NormalizedSignal, result: PipelineResult): boolean {
  return signal.disposition === 'hard_failure' || (signal.type === 'LATERAL_MOVEMENT' && result.reason === 'LATERAL_MOVEMENT');
}
