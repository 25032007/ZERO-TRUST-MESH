/**
 * SlidingCounter — "how many events happened in the last N milliseconds?"
 *
 * Used for request-frequency spikes and for counting recent auth failures.
 *
 * Implementation notes (worth knowing for interviews):
 *  - Timestamps are appended in time order, so expired ones are always at the
 *    FRONT of the array. We keep a `head` index instead of calling
 *    Array.shift(), because shift() is O(n) and would make a busy counter O(n²).
 *  - When `head` grows large we compact the array once, so memory stays bounded.
 */
export class SlidingCounter {
  private stamps: number[] = [];
  private head = 0;

  /** Record an event at time `now` and return how many events are in the window. */
  hit(now: number, windowMs: number): number {
    this.stamps.push(now);
    return this.count(now, windowMs);
  }

  /** Count events newer than (now - windowMs) without recording a new one. */
  count(now: number, windowMs: number): number {
    const cutoff = now - windowMs;
    while (this.head < this.stamps.length && this.stamps[this.head] <= cutoff) this.head++;

    // Compact occasionally so the backing array does not grow forever.
    if (this.head > 1024 && this.head * 2 > this.stamps.length) {
      this.stamps = this.stamps.slice(this.head);
      this.head = 0;
    }
    return this.stamps.length - this.head;
  }
}

/**
 * Tiny helper: keep a Map from growing without bound.
 * When it passes `max` entries we drop the oldest inserted one (Maps iterate in
 * insertion order). Good enough defence against memory exhaustion by an attacker
 * spraying random IPs / trace ids at us.
 */
export function capMap<K, V>(map: Map<K, V>, max: number): void {
  while (map.size > max) {
    const oldest = map.keys().next();
    if (oldest.done) return;
    map.delete(oldest.value);
  }
}
