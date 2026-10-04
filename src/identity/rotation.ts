/**
 * Automated key rotation for a service.
 *
 * Why rotate at all? A private key that never changes is a standing liability:
 * the longer it lives, the more chances it has to leak (old backups, ex-employees,
 * a past compromise nobody noticed). Short-lived keys shrink that window and make
 * rotation a boring routine instead of an emergency procedure.
 *
 * Safety design (see ServiceClient.rotate): the new public key is registered with
 * the proxy BEFORE the service starts signing with it, and the proxy keeps
 * verifying the old key for a grace period that covers the longest token lifetime,
 * so no in-flight request fails during a rotation. If registration fails, the
 * service keeps its current key and simply tries again on the next tick.
 */
import type { JWK } from 'jose';
import type { ServiceClient } from './serviceClient.js';

/** Timer functions are injectable so tests can drive rotation deterministically. */
export interface Timers {
  setInterval(fn: () => void, ms: number): unknown;
  clearInterval(handle: unknown): void;
}

const realTimers: Timers = {
  setInterval: (fn, ms) => setInterval(fn, ms),
  clearInterval: (h) => clearInterval(h as NodeJS.Timeout),
};

export interface AutoRotationOptions {
  intervalMs: number;
  /** Registers the new PUBLIC key with the proxy (e.g. HTTP call or registry.rotateKey). */
  register: (publicJwk: JWK, kid: string) => Promise<void>;
  onRotated?: (kid: string) => void;
  onError?: (err: unknown) => void;
  timers?: Timers;
}

/** Start rotating `client`'s key every `intervalMs`. Returns a function that stops it. */
export function startAutoRotation(client: ServiceClient, opts: AutoRotationOptions): () => void {
  const timers = opts.timers ?? realTimers;
  let inFlight = false; // never run two rotations at once, even if one is slow

  const tick = async () => {
    if (inFlight) return;
    inFlight = true;
    try {
      const { kid } = await client.rotate(opts.register);
      opts.onRotated?.(kid);
    } catch (err) {
      opts.onError?.(err); // old key stays active; we retry on the next tick
    } finally {
      inFlight = false;
    }
  };

  const handle = timers.setInterval(() => void tick(), opts.intervalMs);
  (handle as { unref?: () => void } | undefined)?.unref?.(); // do not keep the process alive
  return () => timers.clearInterval(handle);
}
