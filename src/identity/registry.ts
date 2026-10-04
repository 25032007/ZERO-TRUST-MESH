/**
 * ServiceRegistry — the proxy's phone book of known workloads.
 *
 * ───────────────────────────────────────────────────────────────────────────
 * KEY DESIGN DECISION (the "workload identity" model)
 * ───────────────────────────────────────────────────────────────────────────
 * The proxy stores ONLY PUBLIC keys. Each service keeps its own private key and
 * signs its own short-lived tokens (see serviceClient.ts). That means:
 *
 *   • Compromising the proxy does not let an attacker impersonate services
 *     (there are no private keys here to steal).
 *   • There is no "mint a token for service X" endpoint to abuse — the previous
 *     version of this project had one, which defeated the whole point.
 *
 * This is the same trust model SPIFFE/SPIRE and mTLS use: identity = possession
 * of a private key that matches a registered public key.
 */
import { importJWK, type JWK } from 'jose';
import { generateTotpSecret, verifyTotp } from '../crypto/totp.js';

/** The key type jose gives back after importing a public JWK. */
type VerifyKey = Awaited<ReturnType<typeof importJWK>>;

export type ServiceStatus = 'ACTIVE' | 'DISABLED' | 'REVOKED';

interface StoredKey {
  kid: string;
  key: VerifyKey;
  /** Unix ms after which this key no longer verifies (set during rotation). */
  notAfter?: number;
}

export interface ServiceRecord {
  serviceId: string;
  displayName: string;
  status: ServiceStatus;
  /** kid of the key new tokens are expected to use. */
  currentKid: string;
  /** All keys that may still be valid (current + old ones inside the grace period). */
  keys: Map<string, StoredKey>;
  /** Shared TOTP secret used for step-up authentication. */
  totpSecret: string;
  /** Last TOTP time-step accepted — prevents re-using the same code (RFC 6238 §5.2). */
  lastTotpStep: number;
  registeredAt: number;
}

/** Safe-to-expose view of a service (no secrets, no key material). */
export interface ServiceSummary {
  serviceId: string;
  displayName: string;
  status: ServiceStatus;
  currentKid: string;
  keyCount: number;
  registeredAt: number;
}

export class ServiceRegistry {
  private services = new Map<string, ServiceRecord>();

  constructor(private readonly clock: () => number = Date.now) {}

  /**
   * Register a new service with its PUBLIC key.
   * Returns the TOTP secret exactly once so the operator can enrol an authenticator.
   */
  async register(params: {
    serviceId: string;
    displayName: string;
    publicJwk: JWK;
    kid: string;
  }): Promise<{ totpSecret: string }> {
    if (this.services.has(params.serviceId)) throw new Error(`Service already registered: ${params.serviceId}`);
    if (!/^[a-z0-9][a-z0-9-]{1,62}$/.test(params.serviceId)) {
      throw new Error('serviceId must be lowercase letters, digits and dashes (2-63 chars)');
    }

    const key = await importPublicKey(params.publicJwk);
    const totpSecret = generateTotpSecret();

    this.services.set(params.serviceId, {
      serviceId: params.serviceId,
      displayName: params.displayName,
      status: 'ACTIVE',
      currentKid: params.kid,
      keys: new Map([[params.kid, { kid: params.kid, key }]]),
      totpSecret,
      lastTotpStep: -1,
      registeredAt: this.clock(),
    });
    return { totpSecret };
  }

  /**
   * Rotate a service's key without downtime.
   * The old key keeps verifying for `graceMs` so tokens already in flight
   * (max 15 minutes old) do not suddenly fail.
   */
  async rotateKey(serviceId: string, publicJwk: JWK, newKid: string, graceMs: number): Promise<void> {
    const svc = this.mustGet(serviceId);
    if (svc.keys.has(newKid)) throw new Error(`kid already used: ${newKid}`);

    const now = this.clock();
    for (const stored of svc.keys.values()) {
      // Only shorten — never extend — an existing expiry.
      stored.notAfter = Math.min(stored.notAfter ?? Infinity, now + graceMs);
    }
    svc.keys.set(newKid, { kid: newKid, key: await importPublicKey(publicJwk) });
    svc.currentKid = newKid;
  }

  setStatus(serviceId: string, status: ServiceStatus): void {
    this.mustGet(serviceId).status = status;
  }

  get(serviceId: string): ServiceRecord | undefined {
    return this.services.get(serviceId);
  }

  has(serviceId: string): boolean {
    return this.services.has(serviceId);
  }

  /**
   * Find the key that should verify a token, or `undefined` when the kid is
   * unknown or its rotation grace period has ended.
   */
  getVerificationKey(serviceId: string, kid: string): VerifyKey | undefined {
    const stored = this.services.get(serviceId)?.keys.get(kid);
    if (!stored) return undefined;
    if (stored.notAfter !== undefined && this.clock() > stored.notAfter) return undefined;
    return stored.key;
  }

  /**
   * Verify a step-up TOTP code and burn it. Returns true only the first time a
   * valid code from a given time-step is presented.
   */
  consumeTotp(serviceId: string, code: string): boolean {
    const svc = this.services.get(serviceId);
    if (!svc) return false;
    const step = verifyTotp(svc.totpSecret, code, this.clock());
    if (step === null) return false;
    if (step <= svc.lastTotpStep) return false; // same (or older) code used before
    svc.lastTotpStep = step;
    return true;
  }

  /** Secret lookup — used only by the in-process demo mesh / simulator. */
  getTotpSecret(serviceId: string): string | undefined {
    return this.services.get(serviceId)?.totpSecret;
  }

  list(): ServiceSummary[] {
    return [...this.services.values()].map((s) => ({
      serviceId: s.serviceId,
      displayName: s.displayName,
      status: s.status,
      currentKid: s.currentKid,
      keyCount: s.keys.size,
      registeredAt: s.registeredAt,
    }));
  }

  private mustGet(serviceId: string): ServiceRecord {
    const svc = this.services.get(serviceId);
    if (!svc) throw new Error(`Unknown service: ${serviceId}`);
    return svc;
  }
}

/** Import an Ed25519 public JWK, refusing anything that is not Ed25519. */
async function importPublicKey(jwk: JWK): Promise<VerifyKey> {
  if (jwk.kty !== 'OKP' || jwk.crv !== 'Ed25519') {
    throw new Error('Only Ed25519 public keys (kty=OKP, crv=Ed25519) are accepted');
  }
  if ('d' in jwk) {
    // A JWK containing "d" has the PRIVATE part. Refuse it so nobody ever uploads one by mistake.
    throw new Error('Refusing JWK that contains a private component ("d")');
  }
  return importJWK(jwk, 'EdDSA');
}
