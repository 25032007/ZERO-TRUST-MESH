/**
 * TOTP (RFC 6238) implemented from scratch with only node:crypto.
 *
 * Why not a library? (1) fewer dependencies in a security project, and (2) it is
 * only ~40 lines, so every step can be explained in an interview:
 *
 *   HOTP(K, C) = Truncate( HMAC-SHA1(K, C) ) mod 10^digits        (RFC 4226)
 *   TOTP(K, T) = HOTP(K, floor(unixTime / 30))                    (RFC 6238)
 *
 * The same algorithm Google Authenticator uses, so the secret can be scanned into
 * a real authenticator app via the otpauth:// URI.
 */
import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/** Encode bytes as Base32 (the format authenticator apps expect for secrets). */
export function base32Encode(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const byte of bytes) {
    value = ((value << 8) | byte) & 0xffff; // push 8 new bits (keep value small)
    bits += 8;
    while (bits >= 5) {
      // pull out 5 bits at a time -> one base32 character
      out += BASE32_ALPHABET[(value >>> (bits - 5)) & 31];
      bits -= 5;
    }
  }
  if (bits > 0) out += BASE32_ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

/** Decode a Base32 string back into bytes. */
export function base32Decode(text: string): Buffer {
  const clean = text.replace(/=+$/g, '').toUpperCase();
  let bits = 0;
  let value = 0;
  const out: number[] = [];
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) throw new Error(`Invalid base32 character: ${ch}`);
    value = ((value << 5) | idx) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      out.push((value >>> (bits - 8)) & 0xff);
      bits -= 8;
    }
  }
  return Buffer.from(out);
}

/** Create a fresh random 160-bit secret (RFC 4226 recommends >= 128 bits). */
export function generateTotpSecret(): string {
  return base32Encode(randomBytes(20));
}

/** HOTP: HMAC-based one-time password for a given counter value. */
export function hotp(secret: Buffer, counter: number, digits = 6): string {
  // The counter is an 8-byte big-endian integer.
  const counterBuf = Buffer.alloc(8);
  counterBuf.writeBigUInt64BE(BigInt(counter));

  const hmac = createHmac('sha1', secret).update(counterBuf).digest(); // 20 bytes

  // "Dynamic truncation": the low 4 bits of the last byte pick an offset, then we
  // take 4 bytes from there and clear the top bit so the number is positive.
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  return String(binary % 10 ** digits).padStart(digits, '0');
}

/** The TOTP time-step counter for a timestamp (30-second steps by default). */
export function timeStep(nowMs: number, stepSec = 30): number {
  return Math.floor(nowMs / 1000 / stepSec);
}

/** Generate the code that is valid at `nowMs`. */
export function generateTotp(secretBase32: string, nowMs: number, digits = 6, stepSec = 30): string {
  return hotp(base32Decode(secretBase32), timeStep(nowMs, stepSec), digits);
}

/**
 * Check a submitted code. We accept the previous, current and next time-step
 * (window = 1) to tolerate clock drift between the service and the proxy.
 *
 * Returns the matched time-step counter (so the caller can reject re-use of the
 * same code — RFC 6238 §5.2 says a code must be accepted only once) or `null`
 * when the code is wrong.
 */
export function verifyTotp(
  secretBase32: string,
  submitted: string,
  nowMs: number,
  window = 1,
  digits = 6,
  stepSec = 30,
): number | null {
  if (!/^\d+$/.test(submitted) || submitted.length !== digits) return null;

  const secret = base32Decode(secretBase32);
  const current = timeStep(nowMs, stepSec);
  const given = Buffer.from(submitted);

  for (let delta = -window; delta <= window; delta++) {
    const expected = Buffer.from(hotp(secret, current + delta, digits));
    // timingSafeEqual avoids leaking "how many digits matched" through timing.
    if (expected.length === given.length && timingSafeEqual(expected, given)) return current + delta;
  }
  return null;
}

/** otpauth:// URI that authenticator apps can import (usually shown as a QR code). */
export function otpauthUri(secretBase32: string, account: string, issuer = 'ZeroTrustMesh'): string {
  const label = encodeURIComponent(`${issuer}:${account}`);
  return `otpauth://totp/${label}?secret=${secretBase32}&issuer=${encodeURIComponent(issuer)}&digits=6&period=30`;
}
