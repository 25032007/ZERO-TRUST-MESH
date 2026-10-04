/**
 * RateLimiter — fixed-window request counter per key.
 *
 * Fixed windows are simple and O(1). Their known weakness: a client can send a
 * full quota at the end of one window and another full quota at the start of the
 * next (2× burst across the boundary). A sliding-window or token-bucket removes
 * that; for this project the simplicity is the better trade-off and the
 * limitation is documented.
 */
import { capMap } from '../util/slidingCounter.js';

interface Bucket {
  windowStart: number;
  count: number;
}

export class RateLimiter {
  private buckets = new Map<string, Bucket>();

  constructor(
    private readonly windowMs: number,
    private readonly maxRequests: number,
    private readonly clock: () => number = Date.now,
  ) {}

  /** Register one request for `key`. Returns false when the quota is exhausted. */
  hit(key: string): boolean {
    const now = this.clock();
    let b = this.buckets.get(key);
    if (!b || now - b.windowStart >= this.windowMs) {
      b = { windowStart: now, count: 0 };
      this.buckets.set(key, b);
      capMap(this.buckets, 50_000); // bound memory against key-spraying
    }
    b.count++;
    return b.count <= this.maxRequests;
  }
}
