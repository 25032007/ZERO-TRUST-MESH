/**
 * Threat presenter — the Phase 4 read-only exposure layer.
 *
 * WHY a separate module: the correlator owns detection-adjacent state, while
 * this file only *shapes* already-finalized findings into API/WS contracts.
 * Nothing here calculates risk, severity, confidence, categories, or
 * correlation; every number is copied from the stored finding. The frontend
 * therefore stays presentation-only and can never drift from the backend.
 *
 * Safety: findings, signals, and evidence facts are primitive-only by
 * construction (see contracts.ts EvidenceFacts), so these DTOs contain no
 * tokens, payloads, credentials, or keys.
 */
import type { Evidence, NormalizedSignal, ThreatCategory, ThreatFinding, ThreatSeverity } from './contracts.js';

/** Versioned WebSocket event type for additive threat updates. */
export const THREAT_FINDING_EVENT = 'threat.finding.v1' as const;

/** Compact analyst-facing row. Risk/confidence/severity are copied verbatim. */
export interface FindingSummary {
  findingId: string;
  openedAt: number;
  lastSeenAt: number;
  category: ThreatCategory;
  severity: ThreatSeverity;
  riskScore: number;
  riskModelVersion: string;
  confidenceScore: number;
  status: ThreatFinding['status'];
  source?: string;
  destination?: string;
  affectedServices: string[];
  correlationKey?: string;
  decision: ThreatFinding['decisionContext']['decision'];
  reason: string;
  hardOverride?: boolean;
  evidenceCount: number;
  detectorSummary: ThreatFinding['detectorSummary'];
  contributionIds: string[];
  recurrence?: ThreatFinding['recurrence'];
}

/** Full safe representation of one finding plus the stored proof behind it. */
export interface FindingDetail extends FindingSummary {
  evidenceIds: string[];
  evidence: Evidence[];
  signals: NormalizedSignal[];
  decisionContext: ThreatFinding['decisionContext'];
  attackPath?: ThreatFinding['attackPath'];
  policyContext?: ThreatFinding['policyContext'];
  assessment?: ThreatFinding['assessment'];
}

export interface FindingsQuery {
  limit?: unknown;
  cursor?: unknown;
  category?: unknown;
  severity?: unknown;
  status?: unknown;
  source?: unknown;
  destination?: unknown;
}

const MAX_LIMIT = 200;
const DEFAULT_LIMIT = 50;
const SEVERITY_RANK: Record<ThreatSeverity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/** Shrink one stored finding to its list-safe summary. Copies values, never derives them. */
export function toSummary(f: ThreatFinding): FindingSummary {
  return {
    findingId: f.findingId,
    openedAt: f.openedAt,
    lastSeenAt: f.lastSeenAt,
    category: f.category,
    severity: f.severity,
    riskScore: f.risk.score,
    riskModelVersion: f.risk.riskModelVersion,
    confidenceScore: f.confidence.score,
    status: f.status,
    ...(f.source ? { source: f.source } : {}),
    ...(f.destination ? { destination: f.destination } : {}),
    affectedServices: [...f.affectedServices],
    ...(f.correlationKey ? { correlationKey: f.correlationKey } : {}),
    decision: f.decisionContext.decision,
    reason: f.decisionContext.reason,
    ...(f.decisionContext.hardOverride ? { hardOverride: true } : {}),
    evidenceCount: f.evidenceIds.length,
    detectorSummary: f.detectorSummary.map((d) => ({ ...d })),
    contributionIds: [...f.risk.contributionIds],
    ...(f.recurrence ? { recurrence: { ...f.recurrence } } : {}),
  };
}

/** Expand one stored finding with its signals and evidence (all already bounded upstream). */
export function toDetail(
  f: ThreatFinding,
  signals: NormalizedSignal[],
  evidence: Evidence[],
): FindingDetail {
  return {
    ...toSummary(f),
    evidenceIds: [...f.evidenceIds],
    evidence,
    signals,
    decisionContext: { ...f.decisionContext },
    ...(f.attackPath ? { attackPath: { ...f.attackPath, services: [...f.attackPath.services] } } : {}),
    ...(f.policyContext ? { policyContext: { ...f.policyContext } } : {}),
    ...(f.assessment ? { assessment: { ...f.assessment } } : {}),
  };
}

function saneLimit(raw: unknown): number {
  const n = Number(raw);
  if (!Number.isFinite(n)) return DEFAULT_LIMIT;
  return Math.max(1, Math.min(MAX_LIMIT, Math.floor(n)));
}

function saneCursor(raw: unknown): number {
  const n = Number(raw);
  if (!Number.isFinite(n) || n < 0) return 0;
  return Math.floor(n);
}

function textFilter(raw: unknown): string | undefined {
  return typeof raw === 'string' && raw.length > 0 && raw.length <= 256 ? raw : undefined;
}

/**
 * Bounded, filterable slice over active findings (newest first).
 * The cursor is an opaque offset; only filters over stored fields are supported.
 */
export function listFindings(
  all: ThreatFinding[],
  query: FindingsQuery,
): { findings: FindingSummary[]; nextCursor: string | null; total: number } {
  const category = textFilter(query.category);
  const severity = textFilter(query.severity);
  const status = textFilter(query.status);
  const source = textFilter(query.source);
  const destination = textFilter(query.destination);
  const filtered = all.filter(
    (f) =>
      (!category || f.category === category) &&
      (!severity || f.severity === severity) &&
      (!status || f.status === status) &&
      (!source || f.source === source) &&
      (!destination || f.destination === destination),
  );
  const limit = saneLimit(query.limit);
  const offset = saneCursor(query.cursor);
  const page = filtered.slice(offset, offset + limit);
  return {
    findings: page.map(toSummary),
    nextCursor: offset + limit < filtered.length ? String(offset + limit) : null,
    total: filtered.length,
  };
}

export interface CategoryRow {
  category: ThreatCategory;
  findingCount: number;
  /** Bounded sample of finding ids (newest first) so the response stays small. */
  findingIds: string[];
  /**
   * Explanatory only: sum of per-finding category-exposure scores. This is NOT
   * pipeline risk and must never be added to it; it only says where correlated
   * factor exposure concentrates.
   */
  exposureScore: number;
  maxSeverity: ThreatSeverity;
  maxConfidence: number;
  lastSeenAt: number;
}

/** Aggregate active findings by category. Reads stored assessments; derives nothing new. */
export function categoryBreakdown(all: ThreatFinding[]): { categories: CategoryRow[]; totalActiveFindings: number } {
  const byCategory = new Map<ThreatCategory, CategoryRow>();
  for (const f of all) {
    let row = byCategory.get(f.category);
    if (!row) {
      row = { category: f.category, findingCount: 0, findingIds: [], exposureScore: 0, maxSeverity: f.severity, maxConfidence: f.confidence.score, lastSeenAt: f.lastSeenAt };
      byCategory.set(f.category, row);
    }
    row.findingCount++;
    if (row.findingIds.length < 20) row.findingIds.push(f.findingId);
    row.exposureScore += f.assessment?.categoryExposure.score ?? 0;
    if (SEVERITY_RANK[f.severity] > SEVERITY_RANK[row.maxSeverity]) row.maxSeverity = f.severity;
    if (f.confidence.score > row.maxConfidence) row.maxConfidence = f.confidence.score;
    if (f.lastSeenAt > row.lastSeenAt) row.lastSeenAt = f.lastSeenAt;
  }
  return {
    categories: [...byCategory.values()].sort((a, b) => b.findingCount - a.findingCount || b.lastSeenAt - a.lastSeenAt),
    totalActiveFindings: all.length,
  };
}

export interface InvestigationView {
  correlationKey: string;
  findings: FindingSummary[];
  /** Deduplicated evidence across the grouped findings, bounded for response size. */
  evidence: Evidence[];
  affectedServices: string[];
  firstSeenAt: number;
  lastSeenAt: number;
  decisions: Array<{ decision: FindingSummary['decision']; reason: string; at: number }>;
}

/**
 * Group the stored findings for one correlation key. Returns null when no
 * ACTIVE finding shares the key, so the route can answer 404 honestly.
 */
export function investigationView(
  correlationKey: string,
  entries: Array<{ finding: ThreatFinding; evidence: Evidence[] }>,
): InvestigationView | null {
  if (entries.length === 0) return null;
  const findings = entries.map((e) => e.finding);
  const seen = new Set<string>();
  const evidence: Evidence[] = [];
  for (const e of entries) {
    for (const item of e.evidence) {
      if (seen.has(item.evidenceId) || evidence.length >= 200) continue;
      seen.add(item.evidenceId);
      evidence.push(item);
    }
  }
  const services = new Set<string>();
  for (const f of findings) for (const s of f.affectedServices) services.add(s);
  return {
    correlationKey,
    findings: findings.map(toSummary),
    evidence,
    affectedServices: [...services],
    firstSeenAt: Math.min(...findings.map((f) => f.openedAt)),
    lastSeenAt: Math.max(...findings.map((f) => f.lastSeenAt)),
    decisions: findings.map((f) => ({ decision: f.decisionContext.decision, reason: f.decisionContext.reason, at: f.lastSeenAt })),
  };
}

export interface AttackPathRow {
  findingId: string;
  correlationKey?: string;
  category: ThreatCategory;
  severity: ThreatSeverity;
  services: string[];
  traceId?: string;
  observedAt?: number[];
  lastSeenAt: number;
}

/**
 * Only paths the correlator actually reconstructed (trace-correlated lateral
 * movement). An empty `paths` array with a nonzero `totalActiveFindings` is a
 * valid empty state; zero findings means no data yet. Never invented.
 */
export function attackPathView(all: ThreatFinding[]): { paths: AttackPathRow[]; totalActiveFindings: number } {
  const paths: AttackPathRow[] = [];
  for (const f of all) {
    if (!f.attackPath) continue;
    paths.push({
      findingId: f.findingId,
      ...(f.correlationKey ? { correlationKey: f.correlationKey } : {}),
      category: f.category,
      severity: f.severity,
      services: [...f.attackPath.services],
      ...(f.attackPath.traceId ? { traceId: f.attackPath.traceId } : {}),
      ...(f.attackPath.observedAt ? { observedAt: [...f.attackPath.observedAt] } : {}),
      lastSeenAt: f.lastSeenAt,
    });
  }
  return { paths, totalActiveFindings: all.length };
}
