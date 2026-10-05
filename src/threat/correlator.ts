import type { ThreatCategory, ThreatFinding, ThreatObservation, ThreatSeverity } from './contracts.js';

export interface ThreatCorrelationConfig {
  windowMs: number;
  traceWindowMs: number;
  maxActiveFindings: number;
  maxEvidencePerFinding: number;
}

interface StoredFinding {
  finding: ThreatFinding;
  lastSeenAt: number;
  windowMs: number;
}

const SEVERITY_RANK: Record<ThreatSeverity, number> = { LOW: 0, MEDIUM: 1, HIGH: 2, CRITICAL: 3 };

/**
 * Bounded in-process aggregation of already-finalized observations. It never
 * creates risk or enforcement; it only updates stable finding state.
 */
export class ThreatCorrelator {
  private active = new Map<string, StoredFinding>();

  constructor(
    private readonly cfg: ThreatCorrelationConfig,
    private readonly clock: () => number = Date.now,
  ) {}

  correlate(observation: ThreatObservation): ThreatFinding[] {
    const now = observation.evidence[0]?.observedAt ?? this.clock();
    this.purge(now);
    const evidenceById = new Map(observation.evidence.map((e) => [e.evidenceId, e]));
    const out: ThreatFinding[] = [];

    for (const seed of observation.findings) {
      const signal = observation.signals.find((s) => s.evidenceRefs.some((id) => seed.evidenceIds.includes(id)));
      if (!signal || !signal.primaryCategory) continue;
      const correlationKey = correlationKeyFor(signal, seed);
      const key = `${signal.primaryCategory}|${correlationKey}`;
      const windowMs = signal.type === 'LATERAL_MOVEMENT' && signal.correlationId ? this.cfg.traceWindowMs : this.cfg.windowMs;
      const existing = this.active.get(key);
      const finding = existing && now - existing.lastSeenAt <= existing.windowMs
        ? this.update(existing.finding, seed, observation, evidenceById)
        : this.create(seed, observation, evidenceById, correlationKey);

      this.active.delete(key);
      this.active.set(key, { finding, lastSeenAt: now, windowMs });
      out.push(cloneFinding(finding));
    }
    this.evictToCapacity();
    return out;
  }

  /** Newest first, without exposing mutable internal state. */
  recent(limit = 100): ThreatFinding[] {
    return [...this.active.values()].slice(-limit).reverse().map(({ finding }) => cloneFinding(finding));
  }

  private create(seed: ThreatFinding, observation: ThreatObservation, evidenceById: Map<string, ThreatObservation['evidence'][number]>, correlationKey: string): ThreatFinding {
    // The key is deterministic for active correlation; openedAt distinguishes a later finding after expiry.
    const finding = cloneFinding({ ...seed, findingId: `finding:${seed.category}:${correlationKey}:${seed.openedAt}`, correlationKey, recurrence: { count: 1, firstSeenAt: seed.openedAt, lastSeenAt: seed.lastSeenAt } });
    this.addRequestEvidence(finding, observation);
    this.addAttackPath(finding, observation, evidenceById);
    return finding;
  }

  private update(current: ThreatFinding, seed: ThreatFinding, observation: ThreatObservation, evidenceById: Map<string, ThreatObservation['evidence'][number]>): ThreatFinding {
    const finding = cloneFinding(current);
    finding.lastSeenAt = seed.lastSeenAt;
    finding.recurrence = {
      count: (current.recurrence?.count ?? 1) + 1,
      firstSeenAt: current.recurrence?.firstSeenAt ?? current.openedAt,
      lastSeenAt: seed.lastSeenAt,
    };
    if (seed.risk.score > finding.risk.score) finding.risk.score = seed.risk.score;
    appendUniqueBounded(finding.risk.contributionIds, seed.risk.contributionIds, this.cfg.maxEvidencePerFinding);
    appendUniqueBounded(finding.detectorSummary, seed.detectorSummary, this.cfg.maxEvidencePerFinding, (x) => `${x.name}:${x.version}`);
    appendUniqueBounded(finding.confidence.criteria, seed.confidence.criteria, this.cfg.maxEvidencePerFinding);
    finding.confidence.score = Math.max(finding.confidence.score, seed.confidence.score);
    if (SEVERITY_RANK[seed.severity] > SEVERITY_RANK[finding.severity]) finding.severity = seed.severity;
    this.addRequestEvidence(finding, observation);
    this.addAttackPath(finding, observation, evidenceById);
    return finding;
  }

  /** Request-level evidence is shared for explainability, while category identity remains separate. */
  private addRequestEvidence(finding: ThreatFinding, observation: ThreatObservation): void {
    appendUniqueBounded(finding.evidenceIds, observation.evidence.map((e) => e.evidenceId), this.cfg.maxEvidencePerFinding);
  }

  private addAttackPath(finding: ThreatFinding, observation: ThreatObservation, evidenceById: Map<string, ThreatObservation['evidence'][number]>): void {
    if (!finding.correlationKey?.startsWith('trace:')) return;
    for (const evidence of evidenceById.values()) {
      const path = evidence.facts.path;
      if (!Array.isArray(path) || !path.every((service): service is string => typeof service === 'string')) continue;
      const observedAt = finding.attackPath?.observedAt ?? [];
      finding.attackPath = { services: [...path], traceId: evidence.traceId, observedAt: [...observedAt, evidence.observedAt].slice(-this.cfg.maxEvidencePerFinding) };
    }
  }

  private purge(now: number): void {
    for (const [key, entry] of this.active) {
      if (now - entry.lastSeenAt > entry.windowMs) this.active.delete(key);
    }
  }

  private evictToCapacity(): void {
    while (this.active.size > this.cfg.maxActiveFindings) {
      const oldest = this.active.keys().next();
      if (oldest.done) return;
      this.active.delete(oldest.value);
    }
  }
}

function correlationKeyFor(signal: ThreatObservation['signals'][number], seed: ThreatFinding): string {
  if (signal.type === 'LATERAL_MOVEMENT' && signal.correlationId) return `trace:${signal.correlationId}`;
  if (signal.source && signal.destination) return `edge:${signal.source}->${signal.destination}`;
  if (signal.source) return `service:${signal.source}`;
  if (signal.destination) return `service:${signal.destination}`;
  return `request:${seed.findingId}`;
}

function appendUniqueBounded<T>(target: T[], additions: T[], max: number, key: (value: T) => string = (value) => JSON.stringify(value)): void {
  const seen = new Set(target.map(key));
  for (const value of additions) {
    if (seen.has(key(value))) continue;
    target.push(value);
    seen.add(key(value));
  }
  if (target.length > max) target.splice(0, target.length - max);
}

function cloneFinding(finding: ThreatFinding): ThreatFinding {
  return {
    ...finding,
    risk: { ...finding.risk, contributionIds: [...finding.risk.contributionIds] },
    confidence: { ...finding.confidence, criteria: [...finding.confidence.criteria] },
    evidenceIds: [...finding.evidenceIds],
    detectorSummary: finding.detectorSummary.map((detector) => ({ ...detector })),
    affectedServices: [...finding.affectedServices],
    ...(finding.attackPath ? { attackPath: { ...finding.attackPath, services: [...finding.attackPath.services], ...(finding.attackPath.observedAt ? { observedAt: [...finding.attackPath.observedAt] } : {}) } } : {}),
    ...(finding.recurrence ? { recurrence: { ...finding.recurrence } } : {}),
  };
}
