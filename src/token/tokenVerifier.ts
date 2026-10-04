/**
 * TokenVerifier — decides "is this bearer token genuine, fresh and unused?".
 *
 * The checks run in a deliberate order (cheap & safe first, state-changing last):
 *
 *  1. Header parse + ALGORITHM PINNING   → kills alg=none and HS256-confusion attacks
 *  2. Look up the claimed service & key  → unknown / disabled / unknown kid
 *  3. Cryptographic verification         → signature, exp, iss, sub, aud
 *  4. Lifetime cap                       → refuse long-lived tokens
 *  5. Revocation list
 *  6. Replay check (consumes the jti)    → ONLY after the signature is proven valid,
 *                                          so an attacker cannot "burn" someone
 *                                          else's jti by sending forged tokens.
 */
import { decodeJwt, decodeProtectedHeader, errors as joseErrors, jwtVerify } from 'jose';
import type { ServiceRegistry } from '../identity/registry.js';
import type { JtiStore } from './jtiStore.js';

/** The ONLY signature algorithm we accept. Never read this from the token. */
const ALLOWED_ALGORITHMS = ['EdDSA'];

export type AuthErrorCode =
  | 'MISSING_TOKEN'
  | 'MALFORMED_TOKEN'
  | 'ALG_NOT_ALLOWED'
  | 'UNKNOWN_SERVICE'
  | 'SERVICE_NOT_ACTIVE'
  | 'UNKNOWN_KEY'
  | 'INVALID_SIGNATURE'
  | 'TOKEN_EXPIRED'
  | 'INVALID_CLAIMS'
  | 'LIFETIME_TOO_LONG'
  | 'TOKEN_REVOKED'
  | 'TOKEN_REPLAY';

export type AuthResult =
  | { ok: true; serviceId: string; kid: string; jti: string; expiresAtSec: number }
  | { ok: false; code: AuthErrorCode; detail: string };

export interface VerifierOptions {
  audience: string;
  maxLifetimeSec: number;
  clockToleranceSec: number;
}

export class TokenVerifier {
  constructor(
    private readonly registry: ServiceRegistry,
    private readonly jtiStore: JtiStore,
    private readonly opts: VerifierOptions,
    private readonly clock: () => number = Date.now,
  ) {}

  /** Verify an `Authorization` header value ("Bearer <jwt>"). */
  async verify(authorizationHeader: string | undefined): Promise<AuthResult> {
    // ── 0. Extract the bearer token ───────────────────────────────────────
    if (!authorizationHeader) return fail('MISSING_TOKEN', 'No Authorization header');
    const [scheme, token, ...extra] = authorizationHeader.split(' ');
    if (scheme !== 'Bearer' || !token || extra.length > 0) {
      return fail('MALFORMED_TOKEN', 'Authorization header must be "Bearer <token>"');
    }

    // ── 1. Parse the header and PIN the algorithm ─────────────────────────
    // The token header is attacker-controlled. If we let it choose the algorithm
    // we are vulnerable to: alg=none (no signature) and alg=HS256 signed with the
    // *public* key as the HMAC secret. So we compare against our own allow-list.
    let header;
    try {
      header = decodeProtectedHeader(token);
    } catch {
      return fail('MALFORMED_TOKEN', 'Token header is not valid');
    }
    if (!header.alg || !ALLOWED_ALGORITHMS.includes(header.alg)) {
      return fail('ALG_NOT_ALLOWED', `Algorithm "${header.alg ?? 'none'}" is not accepted; only EdDSA`);
    }
    if (!header.kid) return fail('MALFORMED_TOKEN', 'Token header has no kid');

    // ── 2. Who does the token CLAIM to be? (untrusted until step 3) ───────
    let claimedService: string;
    try {
      const unverified = decodeJwt(token);
      if (typeof unverified.sub !== 'string') return fail('INVALID_CLAIMS', 'Token has no sub claim');
      claimedService = unverified.sub;
    } catch {
      return fail('MALFORMED_TOKEN', 'Token payload is not valid');
    }

    const svc = this.registry.get(claimedService);
    if (!svc) return fail('UNKNOWN_SERVICE', `Service "${claimedService}" is not registered`);
    if (svc.status !== 'ACTIVE') return fail('SERVICE_NOT_ACTIVE', `Service is ${svc.status}`);

    const key = this.registry.getVerificationKey(claimedService, header.kid);
    if (!key) return fail('UNKNOWN_KEY', `No valid key "${header.kid}" for ${claimedService}`);

    // ── 3. Cryptographic verification ─────────────────────────────────────
    let payload;
    try {
      ({ payload } = await jwtVerify(token, key, {
        algorithms: ALLOWED_ALGORITHMS,
        issuer: claimedService, // a service may only vouch for itself
        subject: claimedService,
        audience: this.opts.audience, // token must be meant for THIS mesh
        clockTolerance: this.opts.clockToleranceSec,
        currentDate: new Date(this.clock()), // injectable clock => testable
        requiredClaims: ['exp', 'iat', 'jti', 'iss', 'sub', 'aud'],
      }));
    } catch (err) {
      return mapJoseError(err);
    }

    // ── 4. Lifetime cap ───────────────────────────────────────────────────
    const exp = payload.exp as number;
    const iat = payload.iat as number;
    if (exp - iat > this.opts.maxLifetimeSec) {
      return fail('LIFETIME_TOO_LONG', `Token lifetime ${exp - iat}s exceeds max ${this.opts.maxLifetimeSec}s`);
    }

    // ── 5. Revocation ─────────────────────────────────────────────────────
    const jti = payload.jti as string;
    if (await this.jtiStore.isRevoked(jti)) return fail('TOKEN_REVOKED', 'Token was revoked');

    // ── 6. Replay protection (state-changing, so it goes last) ────────────
    if (!(await this.jtiStore.checkAndStore(jti, exp))) {
      return fail('TOKEN_REPLAY', 'Token id was already used');
    }

    return { ok: true, serviceId: claimedService, kid: header.kid, jti, expiresAtSec: exp };
  }
}

function fail(code: AuthErrorCode, detail: string): AuthResult {
  return { ok: false, code, detail };
}

/**
 * Translate jose's error classes into OUR error codes.
 * (The previous version of this project keyed a lookup table on strings that the
 * library never produced, so every real failure fell through to a default score.
 * Matching on `err.code` — a stable identifier — avoids that class of bug.)
 */
function mapJoseError(err: unknown): AuthResult {
  if (err instanceof joseErrors.JWTExpired) return fail('TOKEN_EXPIRED', 'Token has expired');
  if (err instanceof joseErrors.JWSSignatureVerificationFailed) {
    return fail('INVALID_SIGNATURE', 'Signature does not match the registered public key');
  }
  if (err instanceof joseErrors.JOSEAlgNotAllowed) return fail('ALG_NOT_ALLOWED', 'Algorithm not allowed');
  if (err instanceof joseErrors.JWTClaimValidationFailed) {
    return fail('INVALID_CLAIMS', `Claim "${err.claim}" failed validation (${err.reason})`);
  }
  return fail('MALFORMED_TOKEN', 'Token could not be verified');
}
