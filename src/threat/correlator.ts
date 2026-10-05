import type { Evidence, NormalizedSignal, ThreatCategory, ThreatFinding, ThreatObservation, ThreatSeverity } from './contracts.js';
import { assessFinding } from './assessment.js';
import type { ContributionRecord } from './exposure.js';

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
  signals: Map<string, NormalizedSignal>;
  evidence: Map<string, Evidence>;
  contributions: Map<string, ContributionRecord>;
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
    const out: ThreatFinding[] = [];

    for (const seed of observation.findings) {
      const signal = observation.signals.find((s) => s.evidenceRefs.some((id) => seed.evidenceIds.includes(id)));
      if (!signal || !signal.primaryCategory) continue;
      const correlationKey = correlationKeyFor(signal, seed);
      const key = `${signal.primaryCategory}|${correlationKey}`;
      const windowMs = signal.type === 'LATERAL_MOVEMENT' && signal.correlationId ? this.cfg.traceWindowMs : this.cfg.windowMs;
      const existing = this.active.get(key);
      const entry = existing && now - existing.lastSeenAt <= existing.windowMs
        ? this.update(existing, seed, observation, correlationKey)
        : this.create(seed, observation, correlationKey);

      this.active.delete(key);
      entry.lastSeenAt = now;
      entry.windowMs = windowMs;
      this.active.set(key, entry);
      out.push(cloneFinding(entry.finding));
    }
    this.evictToCapacity();
    return out;
  }

  /** Newest first, without exposing mutable internal state. */
  recent(limit = 100): ThreatFinding[] {
    return [...this.active.values()].slice(-limit).reverse().map(({ finding }) => cloneFinding(finding));
  }

  private create(seed: ThreatFinding, observation: ThreatObservation, correlationKey: string): StoredFinding {
    // The key is deterministic for active correlation; openedAt distinguishes a later finding after expiry.
    const entry: StoredFinding = {
      finding: cloneFinding({ ...seed, findingId: `finding:${seed.category}:${correlationKey}:${seed.openedAt}`, correlationKey, recurrence: { count: 1, firstSeenAt: seed.openedAt, lastSeenAt: seed.lastSeenAt } }),
      lastSeenAt: seed.lastSeenAt,
      windowMs: this.cfg.windowMs,
      signals: new Map(), evidence: new Map(), contributions: new Map(),
    };
    this.addObservation(entry, observation);
    return entry;
  }

  private update(current: StoredFinding, seed: ThreatFinding, observation: ThreatObservation, _correlationKey: string): StoredFinding {
    const finding = cloneFinding(current.finding);
    finding.lastSeenAt = seed.lastSeenAt;
    finding.recurrence = {
      count: (finding.recurrence?.count ?? 1) + 1,
      firstSeenAt: finding.recurrence?.firstSeenAt ?? finding.openedAt,
      lastSeenAt: seed.lastSeenAt,
    };
    // A finding summarizes recurrence, but its decision context describes the latest finalized observation.
    finding.decisionContext = { ...seed.decisionContext };
    if (seed.risk.score > finding.risk.score) finding.risk.score = seed.risk.score;
    appendUniqueBounded(finding.risk.contributionIds, seed.risk.contributionIds, this.cfg.maxEvidencePerFinding);
    appendUniqueBounded(finding.detectorSummary, seed.detectorSummary, this.cfg.maxEvidencePerFinding, (x) => `${x.name}:${x.version}`);
    if (SEVERITY_RANK[seed.severity] > SEVERITY_RANK[finding.severity]) finding.severity = seed.severity;
    const entry: StoredFinding = { ...current, finding };
    this.addObservation(entry, observation);
    return entry;
  }

  /** Request-level evidence is shared for explainability, while category identity remains separate. */
  private addObservation(entry: StoredFinding, observation: ThreatObservation): void {
    const finding = entry.finding;
    appendUniqueBounded(finding.evidenceIds, observation.evidence.map((e) => e.evidenceId), this.cfg.maxEvidencePerFinding);
    for (const signal of observation.signals) entry.signals.set(signal.signalId, signal);
    for (const evidence of observation.evidence) entry.evidence.set(evidence.evidenceId, evidence);
    for (const signal of observation.signals) {
      if (!signal.riskContribution || !signal.primaryCategory) continue;
      entry.contributions.set(signal.riskContribution.id, { ...signal.riskContribution, primaryCategory: signal.primaryCategory });
    }
    while (entry.signals.size > this.cfg.maxEvidencePerFinding * 2) entry.signals.delete(entry.signals.keys().next().value!);
    while (entry.evidence.size > this.cfg.maxEvidencePerFinding * 2) entry.evidence.delete(entry.evidence.keys().next().value!);
    while (entry.contributions.size > this.cfg.maxEvidencePerFinding) entry.contributions.delete(entry.contributions.keys().next().value!);
    if (finding.correlationKey?.startsWith('trace:')) for (const evidence of observation.evidence) {
      const path = evidence.facts.path;
      if (!Array.isArray(path) || !path.every((service): service is string => typeof service === 'string')) continue;
      const observedAt = finding.attackPath?.observedAt ?? [];
      finding.attackPath = { services: [...path], traceId: evidence.traceId, observedAt: [...observedAt, evidence.observedAt].slice(-this.cfg.maxEvidencePerFinding) };
    }
    entry.finding = assessFinding(finding, entry.signals.values(), entry.evidence.values(), entry.contributions.values());
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
