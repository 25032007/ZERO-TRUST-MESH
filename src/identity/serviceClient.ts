/**
 * ServiceClient — what a real microservice would run on ITS side.
 *
 * It owns the private key and signs short-lived, single-use tokens. In production
 * this code would live in each service's HTTP client library; here we also use
 * it in tests, the simulator and the benchmark to play the role of "a service".
 *
 * Note the options like `lifetimeSec: -60` or `audience`: they let the simulator
 * forge deliberately BAD tokens (expired, wrong audience…) with a real signature
 * so we can prove the proxy rejects them for the right reason.
 */
import { SignJWT, exportJWK, generateKeyPair, type JWK } from 'jose';
import { randomUUID } from 'node:crypto';

type PrivateKey = Awaited<ReturnType<typeof generateKeyPair>>['privateKey'];

export interface SignOptions {
  /** Token lifetime in seconds (negative = already expired). Default 60. */
  lifetimeSec?: number;
  /** Override the audience (default: the mesh). */
  audience?: string;
  /** Override the unique token id. */
  jti?: string;
  /** Shift the issued-at time (seconds) relative to "now". */
  issuedAtOffsetSec?: number;
  /** Override "now" in unix seconds (used by tests with a fake clock). */
  nowSec?: number;
}

export class ServiceClient {
  private constructor(
    public readonly serviceId: string,
    public readonly kid: string,
    private readonly privateKey: PrivateKey,
    /** The public half — this is what gets registered with the proxy. */
    public readonly publicJwk: JWK,
    private readonly audience: string,
  ) {}

  /** Generate a brand-new Ed25519 identity for a service. */
  static async create(serviceId: string, opts: { kid?: string; audience?: string } = {}): Promise<ServiceClient> {
    // `extractable: true` is needed only so we can export the PUBLIC key as a JWK.
    const { publicKey, privateKey } = await generateKeyPair('EdDSA', { crv: 'Ed25519', extractable: true });
    const kid = opts.kid ?? `${serviceId}-k${Date.now().toString(36)}`;
    const publicJwk = { ...(await exportJWK(publicKey)), kid, alg: 'EdDSA', use: 'sig' };
    return new ServiceClient(serviceId, kid, privateKey, publicJwk, opts.audience ?? 'zero-trust-mesh');
  }

  /** Sign a token proving "I am <serviceId>". Every call produces a fresh jti. */
  async signToken(opts: SignOptions = {}): Promise<string> {
    const nowSec = opts.nowSec ?? Math.floor(Date.now() / 1000);
    const iat = nowSec + (opts.issuedAtOffsetSec ?? 0);
    const exp = iat + (opts.lifetimeSec ?? 60);

    return new SignJWT({})
      .setProtectedHeader({ alg: 'EdDSA', kid: this.kid, typ: 'JWT' })
      .setIssuer(this.serviceId) // who made the token
      .setSubject(this.serviceId) // who it is about (same thing for workload tokens)
      .setAudience(opts.audience ?? this.audience) // who it is meant for (the mesh)
      .setIssuedAt(iat)
      .setExpirationTime(exp)
      .setJti(opts.jti ?? randomUUID()) // unique id -> enables replay protection
      .sign(this.privateKey);
  }
}
