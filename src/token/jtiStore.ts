/**
 * JtiStore — remembers which token ids (jti) were already used or were revoked.
 *
 * Why it exists
 *   A signed token is a bearer credential: whoever holds it can use it. If an
 *   attacker sniffs one, they could replay it until it expires. We make every
 *   token SINGLE-USE: the first time a jti is seen it is stored, the second time
 *   the request is rejected as a replay.
 *
 * Why it is an interface
 *   The in-memory version below is correct for ONE proxy process. With several
 *   proxy replicas you would need a shared store — in Redis this is a single
 *   atomic command:   SET jti 1 NX EXAT <exp>   (returns nil if it already existed).
 *   Only this file would change; the rest of the system depends on the interface.
 */
export interface JtiStore {
  /**
   * Atomically record `jti`. Returns true when it was NEW (first use) and
   * false when it had been seen before (= replay).
   * `expiresAtSec` is the token's own exp: after that moment the token would be
   * rejected anyway, so the entry can be forgotten (keeps memory bounded).
   */
  checkAndStore(jti: string, expiresAtSec: number): boolean | Promise<boolean>;
  /** Revoke a token id explicitly (e.g. after a suspected leak). */
  revoke(jti: string, expiresAtSec: number): void | Promise<void>;
  isRevoked(jti: string): boolean | Promise<boolean>;
}

export class MemoryJtiStore implements JtiStore {
  private seen = new Map<string, number>(); // jti -> expiry (unix ms)
  private revoked = new Map<string, number>();
  private sinceSweep = 0;

  constructor(private readonly clock: () => number = Date.now) {}

  checkAndStore(jti: string, expiresAtSec: number): boolean {
    this.maybeSweep();
    if (this.seen.has(jti)) return false; // replay!
    this.seen.set(jti, expiresAtSec * 1000);
    return true;
  }

  revoke(jti: string, expiresAtSec: number): void {
    this.revoked.set(jti, expiresAtSec * 1000);
  }

  isRevoked(jti: string): boolean {
    return this.revoked.has(jti);
  }

  /** Number of remembered ids (exposed for metrics/tests). */
  get size(): number {
    return this.seen.size;
  }

  /**
   * Drop expired entries. Done lazily every 1000 inserts so no timer is needed
   * and the cost is amortised across requests.
   */
  private maybeSweep(): void {
    if (++this.sinceSweep < 1000) return;
    this.sinceSweep = 0;
    const now = this.clock();
    for (const [jti, exp] of this.seen) if (exp < now) this.seen.delete(jti);
    for (const [jti, exp] of this.revoked) if (exp < now) this.revoked.delete(jti);
  }
}
