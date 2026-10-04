/**
 * AuditLog — a TAMPER-EVIDENT record of every decision.
 *
 * Each entry stores the SHA-256 hash of the previous entry:
 *
 *     entry[n].hash = SHA256( entry[n-1].hash + canonicalJSON(entry[n] without hash) )
 *
 * If anyone edits or deletes an old entry, every later hash stops matching and
 * verify() reports exactly where the chain broke. (This is the same idea as a
 * blockchain or git history — but be precise in interviews: it detects tampering
 * of what is *inside* the retained window; it cannot prove that the newest
 * entries were not truncated, for that you would ship hashes to external storage.)
 *
 * Only the most recent `capacity` entries are kept in memory (ring buffer).
 */
import { createHash } from 'node:crypto';
import type { Decision, RiskFactor } from '../types.js';

export interface AuditRecord {
  /** Monotonically increasing sequence number. */
  seq: number;
  timestamp: number;
  requestId: string;
  traceId: string;
  decision: Decision;
  reason: string;
  riskScore: number;
  source?: string;
  destination?: string;
  method: string;
  path: string;
  factors: RiskFactor[];
  /** Hash of the previous record ("GENESIS" for the first). */
  prevHash: string;
  /** Hash of this record. */
  hash: string;
}

export type AuditInput = Omit<AuditRecord, 'seq' | 'prevHash' | 'hash' | 'timestamp'> & { timestamp?: number };

const GENESIS = 'GENESIS';

export class AuditLog {
  private records: AuditRecord[] = [];
  private seq = 0;
  private lastHash = GENESIS;

  constructor(
    private readonly capacity = 5000,
    private readonly clock: () => number = Date.now,
  ) {}

  append(input: AuditInput): AuditRecord {
    const partial = {
      ...input,
      seq: ++this.seq,
      timestamp: input.timestamp ?? this.clock(),
      prevHash: this.lastHash,
    };
    const hash = hashRecord(partial);
    const record: AuditRecord = { ...partial, hash };

    this.records.push(record);
    this.lastHash = hash;
    if (this.records.length > this.capacity) this.records.shift(); // drop oldest
    return record;
  }

  /** Newest first. */
  recent(limit = 100, filter?: { decision?: Decision }): AuditRecord[] {
    const out: AuditRecord[] = [];
    for (let i = this.records.length - 1; i >= 0 && out.length < limit; i--) {
      const r = this.records[i];
      if (!filter?.decision || r.decision === filter.decision) out.push(r);
    }
    return out;
  }

  /**
   * Re-compute every hash in the retained window.
   * The first retained record is trusted as the anchor (its predecessor may have
   * been evicted from the ring buffer), every later record must chain to it.
   */
  verify(): { valid: boolean; checked: number; brokenAtSeq?: number } {
    for (let i = 0; i < this.records.length; i++) {
      const r = this.records[i];
      const { hash, ...rest } = r;
      if (hashRecord(rest) !== hash) return { valid: false, checked: i, brokenAtSeq: r.seq };
      if (i > 0 && r.prevHash !== this.records[i - 1].hash) return { valid: false, checked: i, brokenAtSeq: r.seq };
    }
    return { valid: true, checked: this.records.length };
  }

  summary(): { total: number; byDecision: Record<string, number>; byReason: Record<string, number>; chainValid: boolean } {
    const byDecision: Record<string, number> = {};
    const byReason: Record<string, number> = {};
    for (const r of this.records) {
      byDecision[r.decision] = (byDecision[r.decision] ?? 0) + 1;
      byReason[r.reason] = (byReason[r.reason] ?? 0) + 1;
    }
    return { total: this.records.length, byDecision, byReason, chainValid: this.verify().valid };
  }

  /** TEST HOOK: lets a unit test simulate an attacker editing history. */
  _unsafeRecordsForTest(): AuditRecord[] {
    return this.records;
  }
}

/** SHA-256 over prevHash + the record's JSON. Key order is fixed by construction. */
function hashRecord(rec: Omit<AuditRecord, 'hash'>): string {
  return createHash('sha256').update(rec.prevHash).update(JSON.stringify(rec)).digest('hex');
}
