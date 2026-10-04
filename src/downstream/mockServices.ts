/**
 * Mock downstream microservices.
 *
 * A zero-trust proxy needs something to protect, so we host five tiny fake
 * services inside the same process under /downstream/<service>/...
 *
 * IMPORTANT security property demonstrated here: the downstream services do NOT
 * trust the network. They only answer requests that carry the secret
 * `x-mesh-internal` header, which only the proxy knows. So you cannot bypass the
 * proxy by calling /downstream/database-service/... directly.
 *
 * GENERIC FALLBACK: the five named handlers cover the demo topology. Any other
 * registered service name (e.g. services dynamically created by the load test)
 * receives a generic `{ok:true, action:'METHOD /path'}` response. The security
 * property is unchanged - the internal-secret check always runs first.
 */
import { randomBytes, timingSafeEqual } from 'node:crypto';
import { Router } from 'express';

/** Random per process; shared only between the proxy and the mock services. */
export const INTERNAL_SECRET = randomBytes(24).toString('hex');
export const INTERNAL_HEADER = 'x-mesh-internal';

/** Canned responses so the demo shows realistic-looking data flowing through. */
const handlers: Record<string, (method: string, path: string, body: unknown) => unknown> = {
  'orders-service': (m, p) => (p.startsWith('/orders/list') ? { orders: [{ id: 'ORD-1001', total: 42.5, status: 'PAID' }, { id: 'ORD-1002', total: 18, status: 'PENDING' }] } : { ok: true, action: `${m} ${p}` }),
  'payments-service': (_m, _p, body) => ({ chargeId: `ch_${randomBytes(4).toString('hex')}`, status: 'succeeded', echo: typeof body === 'object' ? 'body received' : undefined }),
  'users-service': () => ({ user: { id: 'u-7', name: 'Demo User', plan: 'pro' } }),
  'auth-service': () => ({ session: 'demo-session', expiresInSec: 900 }),
  'database-service': () => ({ rows: [{ id: 1, note: 'sensitive row' }], rowCount: 1 }),
};

export function createDownstreamRouter(): Router {
  const router = Router();

  router.use((req, res) => {
    // 1. Refuse anything that did not come through the proxy.
    const supplied = String(req.headers[INTERNAL_HEADER] ?? '');
    const a = Buffer.from(supplied);
    const b = Buffer.from(INTERNAL_SECRET);
    if (a.length !== b.length || !timingSafeEqual(a, b)) {
      res.status(403).json({ error: 'DIRECT_ACCESS_FORBIDDEN', message: 'Downstream services only accept traffic from the proxy' });
      return;
    }

    // 2. /<service>/<rest of path>
    const [, service, ...rest] = req.path.split('/');
    if (!service) {
      // No service segment at all - malformed path.
      res.status(404).json({ error: 'UNKNOWN_DOWNSTREAM', service });
      return;
    }
    const handler = handlers[service];
    const subPath = '/' + rest.join('/');
    // Named demo services get canned responses; any other registered service
    // gets a simple OK so the load-test can register arbitrary names.
    const payload = handler
      ? (handler(req.method, subPath, req.body) as object)
      : { ok: true, action: `${req.method} ${subPath}` };
    res.json({ service, receivedFrom: req.headers['x-zt-source'], ...payload });
  });

  return router;
}
