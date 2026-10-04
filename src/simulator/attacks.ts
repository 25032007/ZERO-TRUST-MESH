/**
 * Attack simulator — sends REAL attack traffic through the REAL pipeline.
 *
 * (An earlier version of this project returned hard-coded "blocked, score 86"
 * results without running any security code. This one forges genuinely bad
 * tokens/requests, sends them over HTTP to the running proxy, and reports what
 * the proxy actually decided. If a defence is broken, a scenario FAILS.)
 *
 * Each scenario declares what it EXPECTS, so the simulator doubles as an
 * end-to-end regression test (see test/e2e.test.ts).
 */
import { createHmac, randomUUID } from 'node:crypto';
import { generateTotp } from '../crypto/totp.js';
import type { ServiceClient } from '../identity/serviceClient.js';
import type { Mesh } from '../mesh.js';

export interface SimContext {
  mesh: Mesh;
  clients: Map<string, ServiceClient>;
  /** Base URL of the running proxy, e.g. http://127.0.0.1:4000 */
  baseUrl: () => string;
}

export interface StepResult {
  label: string;
  httpStatus: number;
  decision: string;
  reason: string;
  riskScore: number | null;
}

export interface ScenarioResult {
  id: string;
  title: string;
  description: string;
  expected: string;
  passed: boolean;
  steps: StepResult[];
}

interface SendOptions {
  from: string;
  to: string;
  method?: string;
  path: string;
  body?: unknown;
  /** Use this token instead of signing a fresh valid one. */
  token?: string;
  traceId?: string;
  headers?: Record<string, string>;
}

/** Send one request through the proxy and summarise the outcome. */
async function send(ctx: SimContext, label: string, o: SendOptions): Promise<StepResult> {
  const client = ctx.clients.get(o.from)!;
  const token = o.token ?? (await client.signToken());
  const method = o.method ?? 'GET';

  const res = await fetch(`${ctx.baseUrl()}/api/proxy${o.path}`, {
    method,
    headers: {
      authorization: `Bearer ${token}`,
      'x-destination-service': o.to,
      'x-trace-id': o.traceId ?? randomUUID(),
      ...(o.body !== undefined ? { 'content-type': 'application/json' } : {}),
      ...o.headers,
    },
    body: o.body !== undefined ? JSON.stringify(o.body) : undefined,
  });
  await res.arrayBuffer(); // drain the body so the connection can be reused

  const risk = res.headers.get('x-zt-risk');
  return {
    label,
    httpStatus: res.status,
    decision: res.headers.get('x-zt-decision') ?? 'UNKNOWN',
    reason: res.headers.get('x-zt-reason') ?? 'UNKNOWN',
    riskScore: risk === null ? null : Number(risk),
  };
}

const b64 = (obj: unknown) => Buffer.from(JSON.stringify(obj)).toString('base64url');

/** Build a JSON value nested `depth` levels deep with a big string at the bottom. */
function payloadBomb(depth: number, leafBytes: number): unknown {
  let node: unknown = 'x'.repeat(leafBytes);
  for (let i = 0; i < depth; i++) node = { n: node };
  return node;
}

interface ScenarioDef {
  id: string;
  title: string;
  description: string;
  expected: string;
  run: (ctx: SimContext) => Promise<{ steps: StepResult[]; passed: boolean }>;
}

const blockedWith = (s: StepResult, reason: string) => s.decision === 'BLOCK' && s.reason === reason;

export const SCENARIOS: ScenarioDef[] = [
  {
    id: 'normal-traffic',
    title: 'Normal request',
    description: 'Frontend lists orders — a legitimate, policy-allowed call.',
    expected: 'ALLOW (low risk)',
    run: async (ctx) => {
      const s = await send(ctx, 'frontend → orders GET /orders/list', { from: 'frontend-service', to: 'orders-service', path: '/orders/list' });
      return { steps: [s], passed: s.decision === 'ALLOW' && s.httpStatus === 200 };
    },
  },
  {
    id: 'unauthorized-path',
    title: 'Unauthorized access',
    description: 'A compromised frontend tries to read the database directly. No policy allows this edge.',
    expected: 'BLOCK — NO_POLICY (default deny)',
    run: async (ctx) => {
      const s = await send(ctx, 'frontend → database POST /database/query', { from: 'frontend-service', to: 'database-service', method: 'POST', path: '/database/query', body: { sql: 'SELECT *' } });
      return { steps: [s], passed: blockedWith(s, 'NO_POLICY') };
    },
  },
  {
    id: 'forbidden-subpath',
    title: 'Forbidden sub-path',
    description: 'Payments is allowed to reach the database, but its /database/admin path is explicitly denied.',
    expected: 'BLOCK — PATH_DENIED',
    run: async (ctx) => {
      const s = await send(ctx, 'payments → database GET /database/admin/users', { from: 'payments-service', to: 'database-service', path: '/database/admin/users' });
      return { steps: [s], passed: blockedWith(s, 'PATH_DENIED') };
    },
  },
  {
    id: 'expired-token',
    title: 'Expired token',
    description: 'A genuinely signed token that expired nearly an hour ago (stolen / cached credential).',
    expected: 'BLOCK — TOKEN_EXPIRED',
    run: async (ctx) => {
      const token = await ctx.clients.get('frontend-service')!.signToken({ lifetimeSec: 60, issuedAtOffsetSec: -3600 });
      const s = await send(ctx, 'expired token', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', token });
      return { steps: [s], passed: blockedWith(s, 'TOKEN_EXPIRED') };
    },
  },
  {
    id: 'tampered-token',
    title: 'Tampered token',
    description: 'Attacker edits the signed payload (extends exp by a day) but cannot re-sign it.',
    expected: 'BLOCK — INVALID_SIGNATURE',
    run: async (ctx) => {
      const valid = await ctx.clients.get('frontend-service')!.signToken();
      const [h, p, sig] = valid.split('.');
      const payload = JSON.parse(Buffer.from(p, 'base64url').toString());
      payload.exp += 86_400;
      const tampered = `${h}.${b64(payload)}.${sig}`;
      const s = await send(ctx, 'payload edited, signature kept', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', token: tampered });
      return { steps: [s], passed: blockedWith(s, 'INVALID_SIGNATURE') };
    },
  },
  {
    id: 'replay-attack',
    title: 'Token replay',
    description: 'A valid token is captured on the wire and sent a second time.',
    expected: 'first ALLOW, second BLOCK — TOKEN_REPLAY',
    run: async (ctx) => {
      const token = await ctx.clients.get('frontend-service')!.signToken();
      const first = await send(ctx, '1st use (legitimate)', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', token });
      const second = await send(ctx, '2nd use (replayed)', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', token });
      return { steps: [first, second], passed: first.decision === 'ALLOW' && blockedWith(second, 'TOKEN_REPLAY') };
    },
  },
  {
    id: 'alg-none',
    title: 'Algorithm "none"',
    description: 'Classic JWT attack: header says alg=none so there is no signature to check.',
    expected: 'BLOCK — ALG_NOT_ALLOWED (algorithm pinning)',
    run: async (ctx) => {
      const c = ctx.clients.get('frontend-service')!;
      const now = Math.floor(Date.now() / 1000);
      const forged = `${b64({ alg: 'none', typ: 'JWT', kid: c.kid })}.${b64({ iss: c.serviceId, sub: c.serviceId, aud: ctx.mesh.config.audience, iat: now, exp: now + 60, jti: randomUUID() })}.`;
      const s = await send(ctx, 'unsigned token', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', token: forged });
      return { steps: [s], passed: blockedWith(s, 'ALG_NOT_ALLOWED') };
    },
  },
  {
    id: 'alg-confusion',
    title: 'Algorithm confusion (HS256)',
    description: 'Attacker signs with HMAC-SHA256 using the service\'s PUBLIC key as the secret, hoping the server mixes up key types.',
    expected: 'BLOCK — ALG_NOT_ALLOWED (algorithm pinning)',
    run: async (ctx) => {
      const c = ctx.clients.get('frontend-service')!;
      const now = Math.floor(Date.now() / 1000);
      const head = b64({ alg: 'HS256', typ: 'JWT', kid: c.kid });
      const body = b64({ iss: c.serviceId, sub: c.serviceId, aud: ctx.mesh.config.audience, iat: now, exp: now + 60, jti: randomUUID() });
      const sig = createHmac('sha256', String(c.publicJwk.x)).update(`${head}.${body}`).digest('base64url');
      const s = await send(ctx, 'HS256 token keyed with public key', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', token: `${head}.${body}.${sig}` });
      return { steps: [s], passed: blockedWith(s, 'ALG_NOT_ALLOWED') };
    },
  },
  {
    id: 'wrong-audience',
    title: 'Wrong audience',
    description: 'A token that was issued for a different API is presented to the mesh.',
    expected: 'BLOCK — INVALID_CLAIMS',
    run: async (ctx) => {
      const token = await ctx.clients.get('frontend-service')!.signToken({ audience: 'some-other-api' });
      const s = await send(ctx, 'token for another audience', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', token });
      return { steps: [s], passed: blockedWith(s, 'INVALID_CLAIMS') };
    },
  },
  {
    id: 'identity-spoofing',
    title: 'Identity spoofing',
    description: 'Frontend sends its own valid token but sets X-Service-ID: payments-service to borrow payments\' privileges.',
    expected: 'BLOCK — IDENTITY_MISMATCH',
    run: async (ctx) => {
      const s = await send(ctx, 'header lies about who is calling', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', headers: { 'x-service-id': 'payments-service' } });
      return { steps: [s], passed: blockedWith(s, 'IDENTITY_MISMATCH') };
    },
  },
  {
    id: 'lateral-movement',
    title: 'Lateral movement',
    description: 'One trace pivots frontend → orders → payments → database within a second. Every hop is individually allowed; the chain is not.',
    expected: 'hops 1-2 pass, hop 3 BLOCK — LATERAL_MOVEMENT, then the pivot service is quarantined',
    run: async (ctx) => {
      const trace = randomUUID();
      const h1 = await send(ctx, 'hop 1: frontend → orders', { from: 'frontend-service', to: 'orders-service', path: '/orders/list', traceId: trace });
      const h2 = await send(ctx, 'hop 2: orders → payments', { from: 'orders-service', to: 'payments-service', method: 'POST', path: '/payments/charge', body: { amount: 1 }, traceId: trace });
      const h3 = await send(ctx, 'hop 3: payments → database', { from: 'payments-service', to: 'database-service', method: 'POST', path: '/database/query', body: { q: 1 }, traceId: trace });
      const follow = await send(ctx, 'follow-up from quarantined payments', { from: 'payments-service', to: 'database-service', path: '/database/rows' });
      ctx.mesh.quarantine.release('payments-service'); // reset so later scenarios are independent
      return {
        steps: [h1, h2, h3, follow],
        passed: h1.httpStatus === 200 && h2.httpStatus === 200 && blockedWith(h3, 'LATERAL_MOVEMENT') && blockedWith(follow, 'SERVICE_QUARANTINED'),
      };
    },
  },
  {
    id: 'payload-bomb',
    title: 'Payload bomb',
    description: 'A 120 KB body nested 25 levels deep sent to orders — the shape of a parser-DoS attempt.',
    expected: 'flagged: MONITOR or STEP_UP_AUTH (never plain ALLOW)',
    run: async (ctx) => {
      const s = await send(ctx, 'huge + deeply nested JSON', { from: 'frontend-service', to: 'orders-service', method: 'POST', path: '/orders/create', body: payloadBomb(25, 120_000) });
      return { steps: [s], passed: s.decision === 'MONITOR' || s.decision === 'STEP_UP_AUTH' };
    },
  },
  {
    id: 'step-up-auth',
    title: 'Step-up authentication (TOTP)',
    description: 'A risky-but-permitted call (payload bomb on a sensitive target) is paused until the service proves a second factor.',
    expected: 'first STEP_UP_AUTH, retry with valid TOTP → ALLOW',
    run: async (ctx) => {
      const body = payloadBomb(25, 120_000);
      const first = await send(ctx, 'risky request, no TOTP', { from: 'payments-service', to: 'database-service', method: 'POST', path: '/database/query', body });
      const secret = ctx.mesh.registry.getTotpSecret('payments-service')!;
      const code = generateTotp(secret, ctx.mesh.clock());
      const retry = await send(ctx, 'same request + valid TOTP', { from: 'payments-service', to: 'database-service', method: 'POST', path: '/database/query', body, headers: { 'x-service-totp': code } });
      return { steps: [first, retry], passed: first.decision === 'STEP_UP_AUTH' && retry.decision === 'ALLOW' && retry.reason === 'STEP_UP_SATISFIED' };
    },
  },
];

export function listScenarios() {
  return SCENARIOS.map(({ id, title, description, expected }) => ({ id, title, description, expected }));
}

/**
 * Run one scenario. Before each run we clear the per-IP "recent auth failures"
 * memory: all simulator traffic comes from localhost, so without a reset the
 * failures from earlier attack scenarios would inflate the risk of later,
 * unrelated ones and make results depend on click order.
 */
export async function runScenario(ctx: SimContext, id: string): Promise<ScenarioResult | undefined> {
  const def = SCENARIOS.find((s) => s.id === id);
  if (!def) return undefined;
  ctx.mesh.risk.clearAuthFailures();
  const { steps, passed } = await def.run(ctx);
  return { id: def.id, title: def.title, description: def.description, expected: def.expected, passed, steps };
}

export async function runAll(ctx: SimContext): Promise<ScenarioResult[]> {
  const out: ScenarioResult[] = [];
  for (const s of SCENARIOS) out.push((await runScenario(ctx, s.id))!);
  return out;
}
