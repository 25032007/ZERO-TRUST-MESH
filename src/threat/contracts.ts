import type { Decision, RiskLevel } from '../types.js';

/** Initial, stable taxonomy for the additive threat-intelligence layer. */
export type ThreatCategory =
  | 'IDENTITY_COMPROMISE'
  | 'AUTHENTICATION_TOKEN_ABUSE'
  | 'AUTHORIZATION_POLICY_VIOLATION'
  | 'BEHAVIORAL_ANOMALY'
  | 'LATERAL_MOVEMENT'
  | 'RECONNAISSANCE_PROBING'
  | 'REQUEST_PAYLOAD_ABUSE'
  | 'SERVICE_GRAPH_ANOMALY';

/** Stable codes emitted only for behaviours the current pipeline actually detects. */
export type SignalType =
  | 'INVALID_SIGNATURE'
  | 'UNKNOWN_KEY'
  | 'IDENTITY_MISMATCH'
  | 'DISABLED_IDENTITY'
  | 'REVOKED_IDENTITY'
  | 'TOKEN_EXPIRED'
  | 'TOKEN_INVALID_CLAIMS'
  | 'TOKEN_LIFETIME_VIOLATION'
  | 'TOKEN_REPLAY'
  | 'TOKEN_REVOKED'
  | 'POLICY_DENIED'
  | 'NO_POLICY'
  | 'METHOD_NOT_ALLOWED'
  | 'PATH_NOT_ALLOWED'
  | 'TIME_WINDOW_DENIED'
  | 'DRY_RUN_POLICY_VIOLATION'
  | 'NEW_SERVICE_PAIR'
  | 'SENSITIVE_ENDPOINT'
  | 'OFF_HOURS'
  | 'RATE_SPIKE'
  | 'RECENT_AUTH_FAILURES'
  | 'PAYLOAD_ANOMALY'
  | 'LATERAL_MOVEMENT'
  | 'QUARANTINE'
  | 'RATE_LIMITED';

export type SignalDisposition = 'observed' | 'hard_failure' | 'dry_run';
/** Distinguishes threat classification from supporting context and enforcement outcomes. */
export type SignalRole = 'threat_signal' | 'contextual_evidence' | 'control_outcome' | 'decision_context';
export type EvidenceKind = 'authentication' | 'token' | 'policy' | 'payload' | 'rate' | 'baseline' | 'graph' | 'trace' | 'identity' | 'quarantine';
export type EvidenceReliability = 'deterministic' | 'statistical' | 'contextual';
export type EvidenceCompleteness = 'complete' | 'partial';
export type ThreatSeverity = RiskLevel;

export interface ConfidenceCriterion {
  name: 'detectorValidity' | 'evidenceCompleteness' | 'corroboration' | 'correlationQuality';
  satisfied: boolean;
  points: 0 | 25;
  reason: string;
}

export interface ThreatConfidence {
  score: number;
  criteria: ConfidenceCriterion[];
}

export interface CategoryExposure {
  category: ThreatCategory;
  score: number;
  contributionIds: string[];
}

export interface ThreatAssessment {
  categoryExposure: CategoryExposure;
  severity: ThreatSeverity;
  risk: { score: number; riskModelVersion: string; contributionIds: string[] };
  confidence: ThreatConfidence;
  explanation: string;
}

/** A bounded primitive-only object prevents raw requests, credentials, and secrets from entering threat data. */
export type EvidenceFacts = Record<string, string | number | boolean | string[] | number[]>;

export interface NormalizedSignal {
  signalId: string;
  occurredAt: number;
  type: SignalType;
  source?: string;
  destination?: string;
  subject?: string;
  correlationId?: string;
  detector: { name: string; version: string };
  disposition: SignalDisposition;
  role: SignalRole;
  measurement?: { value?: number; baseline?: number; threshold?: number; deviation?: number };
  riskContribution?: { id: string; points: number; factorCode: string };
  /** Present only when this signal independently classifies a threat. */
  primaryCategory?: ThreatCategory;
  secondaryCategories?: ThreatCategory[];
  /** Categories this evidence may support without independently classifying one. */
  contextualCategories?: ThreatCategory[];
  evidenceRefs: string[];
  metadata?: EvidenceFacts;
}

export interface Evidence {
  evidenceId: string;
  kind: EvidenceKind;
  observedAt: number;
  source?: string;
  destination?: string;
  requestId?: string;
  traceId?: string;
  detector: { name: string; version: string };
  facts: EvidenceFacts;
  reliability: EvidenceReliability;
  completeness: EvidenceCompleteness;
}

export interface ThreatFinding {
  findingId: string;
  openedAt: number;
  lastSeenAt: number;
  category: ThreatCategory;
  severity: ThreatSeverity;
  risk: { score: number; riskModelVersion: string; contributionIds: string[] };
  confidence: ThreatConfidence;
  status: 'active' | 'resolved' | 'suppressed';
  evidenceIds: string[];
  detectorSummary: Array<{ name: string; version: string }>;
  source?: string;
  destination?: string;
  affectedServices: string[];
  correlationKey?: string;
  decisionContext: { decision: Decision; reason: string; hardOverride?: boolean };
  attackPath?: { services: string[]; traceId?: string; observedAt?: number[] };
  policyContext?: { policyId?: string; reason: string; dryRun: boolean };
  recurrence?: { count: number; firstSeenAt: number; lastSeenAt: number };
  assessment?: ThreatAssessment;
}

/** Contract only: Phase 1 deliberately emits no recommendations. */
export interface Recommendation {
  recommendationId: string;
  createdAt: number;
  category: 'CONTAIN' | 'HARDEN' | 'INVESTIGATE' | 'MONITOR' | 'OPTIMIZE';
  priority: 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
  status: 'open' | 'acknowledged' | 'dismissed' | 'completed';
  title: string;
  rationale: string;
  affectedEntities: string[];
  suggestedAction: string;
  expectedImpact: string;
  confidence: number;
  sourceFindingIds: string[];
  evidenceIds: string[];
  rule: { id: string; version: string };
}

export interface ThreatObservation {
  signals: NormalizedSignal[];
  evidence: Evidence[];
  findings: ThreatFinding[];
}
