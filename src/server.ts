/**
 * HTTP layer. Express is only a thin adapter: it turns an HTTP request into a
 * PipelineInput, asks the pipeline for a verdict, and either forwards the request
 * or answers with the refusal. All security logic lives in the pipeline.
 *
 * Route map
 *   ANY  /api/proxy/<path>        the enforced entry point (needs a token)
 *   GET  /healthz                 liveness
 *   GET  /api/metrics|audit|...   read-only dashboard data
 *   POST /api/simulator/:id       run an attack scenario (demo)
 *   POST /admin/...               mutating operations (always need the admin key)
 *   ANY  /downstream/...          mock backends (only reachable via the proxy)
 *   WS   /ws                      live decision stream
 */
import { randomUUID, timingSafeEqual } from 'node:crypto';
import { createServer, type Server } from 'node:http';
import path from 'node:path';
import express, { type NextFunction, type Request, type Response } from 'express';
import type { JWK } from 'jose';
import type { MeshConfig } from './config.js';
import { createDemoMesh } from './demoMesh.js';
import { createDownstreamRouter, INTERNAL_HEADER, INTERNAL_SECRET } from './downstream/mockServices.js';
import type { ServiceClient } from './identity/serviceClient.js';
import { startAutoRotation } from './identity/rotation.js';
import { createMesh, type Mesh, type MeshOptions } from './mesh.js';
import { attachWebSocket } from './observability/events.js';
import { listScenarios, runAll, runScenario, type SimContext } from './simulator/attacks.js';

export interface App {
  server: Server;
  mesh: Mesh;
  clients: Map<string, ServiceClient>;
  /** Start listening; resolves with the actual port (use 0 for a random one). */
  listen(port: number): Promise<number>;
  close(): Promise<void>;
}

/** Constant-time string comparison (no timing side-channel on the admin key). */
function safeEqual(a: string, b: string): boolean {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
}

/** Accept only sane trace ids so attackers cannot inject giant/odd strings into logs. */
function sanitizeTraceId(raw: unknown, fallback: string): string {
  return typeof raw === 'string' && /^[A-Za-z0-9._-]{1,128}$/.test(raw) ? raw : fallback;
}

export async function createApp(config: MeshConfig, meshOptions: MeshOptions = {}): Promise<App> {
  const mesh = createMesh(config, meshOptions);
  const clients = await createDemoMesh(mesh);

  const app = express();
  app.disable('x-powered-by'); // do not advertise the framework
  app.use(express.json({ limit: '2mb' }));

  let selfBase = `http://127.0.0.1:${config.port}`;
  const simCtx: SimContext = { mesh, clients, baseUrl: () => selfBase };

  // ── Access control helpers ────────────────────────────────────────────────
  const hasAdminKey = (req: Request) => safeEqual(String(req.headers['x-admin-key'] ?? ''), config.adminApiKey);

  /** Mutating routes: ALWAYS require the admin key. */
  const requireAdmin = (req: Request, res: Response, next: NextFunction) =>
    hasAdminKey(req) ? next() : void res.status(401).json({ error: 'ADMIN_KEY_REQUIRED' });

  /** Read-only dashboard routes: open in demo mode, key-protected otherwise. */
  const dashboardAccess = (req: Request, res: Response, next: NextFunction) =>
    config.publicDashboard || hasAdminKey(req) ? next() : void res.status(401).json({ error: 'ADMIN_KEY_REQUIRED' });

  // ── Health ────────────────────────────────────────────────────────────────
  app.get('/healthz', (_req, res) => void res.json({ status: 'ok', uptimeSec: Math.round(process.uptime()) }));

  // ── The enforced entry point ──────────────────────────────────────────────
  app.use('/api/proxy', async (req, res, next) => {
    try {
      const requestId = randomUUID();
      const result = await mesh.pipeline.evaluate({
        requestId,
        traceId: sanitizeTraceId(req.headers['x-trace-id'], requestId),
        // NOTE: we use the socket address on purpose. X-Forwarded-For is
        // attacker-controlled unless a trusted proxy sets it; behind a load
        // balancer you would enable Express's `trust proxy` setting deliberately.
        ip: req.socket.remoteAddress ?? 'unknown',
        method: req.method,
        path: req.path,
        destination: req.headers['x-destination-service'] as string | undefined,
        claimedService: req.headers['x-service-id'] as string | undefined,
        authorization: req.headers.authorization,
        totp: req.headers['x-service-totp'] as string | undefined,
        body: req.body,
        payloadBytes: Number(req.headers['content-length'] ?? 0),
      });

      // Decision metadata is returned as headers so it never mixes with the payload.
      res.setHeader('X-ZT-Request-Id', result.requestId);
      res.setHeader('X-ZT-Decision', result.decision);
      res.setHeader('X-ZT-Reason', result.reason);
      res.setHeader('X-ZT-Risk', String(result.riskScore));

      if (result.decision === 'BLOCK' || result.decision === 'STEP_UP_AUTH') {
        if (result.decision === 'STEP_UP_AUTH') res.setHeader('WWW-Authenticate', 'ZT-TOTP realm="zero-trust-mesh"');
        // In private mode we do not reveal internals (stage details, factors) to the caller.
        const detailed = config.publicDashboard ? { stages: result.stages, factors: result.factors } : {};
        res.status(result.httpStatus).json({ error: result.reason, decision: result.decision, riskScore: result.riskScore, requestId, ...detailed });
        return;
      }

      // ALLOW / MONITOR → forward to the downstream service over real HTTP.
      const query = req.url.includes('?') ? req.url.slice(req.url.indexOf('?')) : '';
      const target = `${selfBase}/downstream/${result.destination}${req.path}${query}`;
      const hasBody = !['GET', 'HEAD'].includes(req.method) && req.body !== undefined;
      try {
        const upstream = await fetch(target, {
          method: req.method,
          headers: {
            [INTERNAL_HEADER]: INTERNAL_SECRET, // proves to the backend "this came from the proxy"
            'x-zt-source': result.source ?? '', // authenticated identity, set by us, not by the caller
            'x-zt-request-id': requestId,
            ...(hasBody ? { 'content-type': 'application/json' } : {}),
          },
          body: hasBody ? JSON.stringify(req.body) : undefined,
          signal: AbortSignal.timeout(5000),
        });
        res.status(upstream.status);
        res.setHeader('content-type', upstream.headers.get('content-type') ?? 'application/json');
        res.send(await upstream.text());
      } catch {
        res.status(502).json({ error: 'DOWNSTREAM_UNAVAILABLE', requestId });
      }
    } catch (err) {
      next(err);
    }
  });

  // ── Dashboard data (read-only) ────────────────────────────────────────────
  app.get('/api/metrics', dashboardAccess, (_req, res) => void res.json(mesh.metrics.snapshot()));
  app.get('/api/services', dashboardAccess, (_req, res) => void res.json(mesh.registry.list()));
  app.get('/api/policies', dashboardAccess, (_req, res) => void res.json(mesh.policies.list()));
  app.get('/api/policies/status', dashboardAccess, (_req, res) => void res.json(mesh.policyStore.status()));
  // JWKS (RFC 7517): every currently valid PUBLIC key. Contains no secrets by construction.
  app.get('/.well-known/jwks.json', dashboardAccess, (_req, res) => {
    res.setHeader('Cache-Control', 'no-cache');
    res.json(mesh.registry.publicJwks());
  });
  app.get('/api/quarantine', dashboardAccess, (_req, res) => void res.json(mesh.quarantine.list()));
  app.get('/api/audit', dashboardAccess, (req, res) => {
    const limit = Math.min(Number(req.query.limit) || 100, 500);
    const decision = req.query.decision as 'ALLOW' | 'MONITOR' | 'STEP_UP_AUTH' | 'BLOCK' | undefined;
    res.json(mesh.audit.recent(limit, decision ? { decision } : undefined));
  });
  app.get('/api/audit/verify', dashboardAccess, (_req, res) => void res.json(mesh.audit.verify()));
  app.get('/api/audit/summary', dashboardAccess, (_req, res) => void res.json(mesh.audit.summary()));

  // ── Simulator (demo) ──────────────────────────────────────────────────────
  app.get('/api/simulator/scenarios', dashboardAccess, (_req, res) => void res.json(listScenarios()));
  app.post('/api/simulator/run-all', dashboardAccess, async (_req, res, next) => {
    try {
      res.json(await runAll(simCtx));
    } catch (err) {
      next(err);
    }
  });
  app.post('/api/simulator/:id', dashboardAccess, async (req, res, next) => {
    try {
      const result = await runScenario(simCtx, String(req.params.id));
      if (!result) {
        res.status(404).json({ error: 'UNKNOWN_SCENARIO' });
        return;
      }
      res.json(result);
    } catch (err) {
      next(err);
    }
  });

  // ── Admin operations (always protected) ───────────────────────────────────
  app.post('/admin/services', requireAdmin, async (req, res) => {
    try {
      const { serviceId, displayName, publicJwk, kid } = req.body as { serviceId: string; displayName: string; publicJwk: JWK; kid: string };
      const { totpSecret } = await mesh.registry.register({ serviceId, displayName: displayName ?? serviceId, publicJwk, kid });
      res.status(201).json({ serviceId, totpSecret }); // the secret is shown exactly once
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });
  app.post('/admin/services/:id/rotate-key', requireAdmin, async (req, res) => {
    try {
      const { publicJwk, kid, graceSec } = req.body as { publicJwk: JWK; kid: string; graceSec?: number };
      await mesh.registry.rotateKey(String(req.params.id), publicJwk, kid, (graceSec ?? 900) * 1000);
      res.json({ rotated: true });
    } catch (err) {
      res.status(400).json({ error: (err as Error).message });
    }
  });
  app.post('/admin/services/:id/status', requireAdmin, (req, res) => {
    const status = (req.body as { status?: string }).status;
    if (status !== 'ACTIVE' && status !== 'DISABLED' && status !== 'REVOKED') {
      res.status(400).json({ error: 'status must be ACTIVE, DISABLED or REVOKED' });
      return;
    }
    try {
      mesh.registry.setStatus(String(req.params.id), status);
      res.json({ serviceId: req.params.id, status });
    } catch (err) {
      res.status(404).json({ error: (err as Error).message });
    }
  });
  // Emergency: kill ONE key immediately (no grace period).
  app.post('/admin/services/:id/keys/:kid/revoke', requireAdmin, (req, res) => {
    try {
      const removed = mesh.registry.revokeKey(String(req.params.id), String(req.params.kid));
      res.status(removed ? 200 : 404).json({ revoked: removed });
    } catch (err) {
      res.status(404).json({ error: (err as Error).message });
    }
  });
  app.post('/admin/tokens/revoke', requireAdmin, async (req, res) => {
    const { jti, expiresAtSec } = req.body as { jti?: string; expiresAtSec?: number };
    if (!jti) {
      res.status(400).json({ error: 'jti is required' });
      return;
    }
    await mesh.jtiStore.revoke(jti, expiresAtSec ?? Math.floor(Date.now() / 1000) + config.maxTokenLifetimeSec);
    res.json({ revoked: jti });
  });
  // Manual reload (also happens automatically when POLICY_WATCH is on). An invalid
  // file is rejected with 422 and the previous policies stay active.
  app.post('/admin/policies/reload', requireAdmin, (_req, res) => {
    const result = mesh.policyStore.reload();
    res.status(result.ok ? 200 : 422).json({ ...result, status: mesh.policyStore.status() });
  });
  app.post('/admin/quarantine/:id/release', requireAdmin, (req, res) => {
    res.json({ released: mesh.quarantine.release(String(req.params.id)) });
  });

  // ── Mock backends + static dashboard ──────────────────────────────────────
  app.use('/downstream', createDownstreamRouter());
  app.use(express.static(path.join(process.cwd(), 'public')));

  // ── Error handler: always JSON, never a stack trace ───────────────────────
  app.use((err: Error & { status?: number; type?: string }, _req: Request, res: Response, _next: NextFunction) => {
    const status = err.status ?? 500;
    if (status >= 500) console.error('[error]', err);
    const message = err.type === 'entity.parse.failed' ? 'Malformed JSON body' : status === 413 ? 'Body too large' : status >= 500 ? 'Internal error' : err.message;
    res.status(status).json({ error: message });
  });

  // ── Lifecycle ─────────────────────────────────────────────────────────────
  // Optional automated rotation of the demo services' keys. The grace period must
  // outlive the longest token, otherwise a token signed just before a rotation
  // could be rejected mid-flight.
  const stopRotations: Array<() => void> = [];
  if (config.keyRotationMs > 0) {
    const graceMs = (config.maxTokenLifetimeSec + config.clockToleranceSec) * 1000;
    for (const client of clients.values()) {
      stopRotations.push(
        startAutoRotation(client, {
          intervalMs: config.keyRotationMs,
          register: (jwk, kid) => mesh.registry.rotateKey(client.serviceId, jwk, kid, graceMs),
          onError: (err) => console.error(`[rotation] ${client.serviceId} failed:`, (err as Error).message),
        }),
      );
    }
  }

  const server = createServer(app);
  if (config.policyWatch && mesh.policyStore.hasFile) mesh.policyStore.watch();
  attachWebSocket(server, mesh.bus, (url) => config.publicDashboard || safeEqual(url.searchParams.get('key') ?? '', config.adminApiKey));

  return {
    server,
    mesh,
    clients,
    listen: (port) =>
      new Promise((resolve, reject) => {
        server.once('error', reject);
        server.listen(port, () => {
          const actual = (server.address() as { port: number }).port;
          selfBase = `http://127.0.0.1:${actual}`;
          resolve(actual);
        });
      }),
    close: () =>
      new Promise((resolve) => {
        mesh.policyStore.close();
        stopRotations.forEach((stop) => stop());
        server.closeAllConnections?.();
        server.close(() => resolve());
      }),
  };
}
