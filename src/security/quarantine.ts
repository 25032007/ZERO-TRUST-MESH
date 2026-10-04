/**
 * QuarantineService — containment. A service that triggers a critical alert is
 * isolated: every further request it makes is refused until the quarantine
 * expires (auto-release) or an operator releases it manually.
 *
 * Trade-off worth mentioning in an interview: automatic quarantine limits blast
 * radius fast, but a false positive takes a healthy service offline — hence the
 * short default duration and the manual-release admin endpoint.
 */
export interface QuarantineEntry {
  serviceId: string;
  reason: string;
  since: number;
  until: number;
}

export class QuarantineService {
  private entries = new Map<string, QuarantineEntry>();

  constructor(
    private readonly durationMs: number,
    private readonly clock: () => number = Date.now,
  ) {}

  quarantine(serviceId: string, reason: string): QuarantineEntry {
    const now = this.clock();
    const entry = { serviceId, reason, since: now, until: now + this.durationMs };
    this.entries.set(serviceId, entry);
    return entry;
  }

  /** Returns the active entry, or undefined (expired entries are removed lazily). */
  isQuarantined(serviceId: string): QuarantineEntry | undefined {
    const entry = this.entries.get(serviceId);
    if (!entry) return undefined;
    if (this.clock() >= entry.until) {
      this.entries.delete(serviceId);
      return undefined;
    }
    return entry;
  }

  release(serviceId: string): boolean {
    return this.entries.delete(serviceId);
  }

  list(): QuarantineEntry[] {
    return [...this.entries.keys()].map((id) => this.isQuarantined(id)).filter((e): e is QuarantineEntry => !!e);
  }
}
