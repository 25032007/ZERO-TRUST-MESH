/**
 * Phase 4 tests: the read-only threat API exposes EXISTING correlator state,
 * and versioned threat events ride the EXISTING WebSocket connection.
 *
 * Nothing here tests detection itself (covered by threat*.test.ts); these
 * prove exposure correctness: same risk, no duplicates, bounded output,
 * honest empty/404 states, and additive real-time events.
 */
import assert from 'node:assert/strict';
import { after, before, test } from 'node:test';
import { WebSocket } from 'ws';
import { loadConfig } from '../src/config.js';
import { createApp, type App } from '../src/server.js';

let app: App;
let base: string;

before(async () => {
  app = await createApp(loadConfig({ ADMIN_API_KEY: 'threat-api-key', PORT: '0' }));
  base = `http://127.0.0.1:${await app.listen(0)}`;
});
after(async () => app.close());

const get = (path: string) => fetch(`${base}${path}`).then((r) => r.json());
const callProxy = async (from: string, to: string, path: string, init: RequestInit = {}) => {
  const token = await app.clients.get(from)!.signToken();
  return fetch(`${base}/api/proxy${path}`, { ...init, headers: { authorization: `Bearer ${token}`, 'x-destination-service': to, ...(init.headers ?? {}) } });
};

/** Poll until cond() is true or the deadline passes (never a fixed sleep). */
async function waitFor(cond: () => Promise<boolean> | boolean, timeoutMs = 5000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    if (await cond()) return;
    if (Date.now() > deadline) throw new Error('timed out waiting for condition');
    await new Promise((r) => setTimeout(r, 25));
  }
}

// ── Empty states are honest ──────────────────────────────────────────────────

test('threat API returns valid empty collections before any threat traffic', async () => {
  const list = (await get('/api/threats/findings')) as { findings: unknown[]; nextCursor: null; total: number };
  assert.deepEqual(list, { findings: [], nextCursor: null, total: 0 });
  const cats = (await get('/api/threats/categories')) as { categories: unknown[]; totalActiveFindings: number };
  assert.deepEqual(cats, { categories: [], totalActiveFindings: 0 });
  const paths = (await get('/api/threats/attack-paths')) as { paths: unknown[]; totalActiveFindings: number };
  assert.deepEqual(paths, { paths: [], totalActiveFindings: 0 });
  const summary = (await get('/api/threats/summary')) as { totalActiveFindings: number; findings: unknown[] };
  assert.deepEqual(summary, { totalActiveFindings: 0, findings: [] });
});

test('unknown finding and investigation ids are 404 JSON, never a stack trace', async () => {
  for (const p of ['/api/threats/findings/nope', '/api/threats/investigations/edge%3Aa-%3Eb']) {
    const res = await fetch(`${base}${p}`);
    assert.equal(res.status, 404);
    const body = (await res.json()) as { error: string };
    assert.match(body.error, /^(FINDING_NOT_FOUND|INVESTIGATION_NOT_FOUND)$/);
  }
});

// ── Real traffic produces real findings ──────────────────────────────────────

test('a token replay surfaces as an AUTHENTICATION_TOKEN_ABUSE finding with the pipeline risk', async () => {
  const token = await app.clients.get('frontend-service')!.signToken({ jti: 'phase4-replay-1' });
  const h = { authorization: `Bearer ${token}`, 'x-destination-service': 'orders-service' };
  assert.equal((await fetch(`${base}/api/proxy/orders/list`, { headers: h })).status, 200);
  const replay = await fetch(`${base}/api/proxy/orders/list`, { headers: h });
  assert.equal(replay.headers.get('x-zt-decision'), 'BLOCK');
  const pipelineRisk = Number(replay.headers.get('x-zt-risk'));

  const list = (await get('/api/threats/findings?category=AUTHENTICATION_TOKEN_ABUSE')) as { findings: Array<{ category: string; severity: string; riskScore: number; confidenceScore: number; reason: string; decision: string }> ; total: number };
  assert.ok(list.total >= 1);
  assert.ok(list.findings.every((f) => f.category === 'AUTHENTICATION_TOKEN_ABUSE'));
  const replayFinding = list.findings.find((f) => f.reason === 'TOKEN_REPLAY')!;
  assert.ok(replayFinding, 'expected a TOKEN_REPLAY finding');
  // The three analyst concepts stay distinct: HIGH severity, 0-100 confidence, pipeline risk.
  assert.equal(replayFinding.severity, 'HIGH');
  assert.equal(replayFinding.riskScore, pipelineRisk);
  assert.equal(replayFinding.riskScore, 90);
  assert.ok(replayFinding.confidenceScore >= 0 && replayFinding.confidenceScore <= 100);
  assert.equal(replayFinding.decision, 'BLOCK');
});

test('repeated policy denials update ONE finding: recurrence grows, contributions never duplicate', async () => {
  await callProxy('orders-service', 'database-service', '/database/rows');
  await callProxy('orders-service', 'database-service', '/database/rows');
  const list = (await get('/api/threats/findings?category=AUTHORIZATION_POLICY_VIOLATION&source=orders-service')) as {
    findings: Array<{ findingId: string; recurrence?: { count: number }; riskScore: number; contributionIds: string[]; evidenceCount: number }>;
  };
  const f = list.findings.find((x) => x.recurrence && x.recurrence.count >= 2);
  assert.ok(f, 'expected one finding with recurrence from the repeated edge');
  assert.equal(new Set(f!.contributionIds).size, f!.contributionIds.length);
  const detail = (await get(`/api/threats/findings/${encodeURIComponent(f!.findingId)}`)) as {
    evidenceIds: string[]; evidence: unknown[]; signals: unknown[]; decisionContext: object; assessment: { explanation: string };
  };
  assert.equal(new Set(detail.evidenceIds).size, detail.evidenceIds.length);
  assert.ok(detail.evidence.length <= 100, 'evidence stays bounded');
  assert.ok(detail.evidence.length > 0 && detail.signals.length > 0);
  assert.ok(detail.decisionContext && detail.assessment.explanation.length > 0);
});

test('finding detail exposes risk, confidence, severity, and context without secrets', async () => {
  const list = (await get('/api/threats/findings?limit=1')) as { findings: Array<{ findingId: string }> };
  const detail = (await get(`/api/threats/findings/${encodeURIComponent(list.findings[0].findingId)}`)) as Record<string, unknown>;
  for (const field of ['findingId', 'openedAt', 'lastSeenAt', 'category', 'severity', 'confidenceScore', 'riskScore', 'riskModelVersion', 'status', 'affectedServices', 'decisionContext', 'evidenceIds', 'evidence', 'signals', 'detectorSummary', 'contributionIds']) {
    assert.ok(detail[field] !== undefined, `detail exposes ${field}`);
  }
  const blob = JSON.stringify(detail);
  assert.ok(!/Bearer eyJ|BEGIN .*PRIVATE|totpSecret/i.test(blob), 'no tokens, keys, or secrets leak');
});

test('categories aggregate active findings and never claim to be risk', async () => {
  const cats = (await get('/api/threats/categories')) as {
    totalActiveFindings: number;
    categories: Array<{ category: string; findingCount: number; findingIds: string[]; exposureScore: number; maxSeverity: string; maxConfidence: number; lastSeenAt: number }>;
  };
  assert.ok(cats.totalActiveFindings >= 2);
  assert.ok(cats.categories.length >= 2);
  for (const c of cats.categories) {
    assert.ok(c.findingCount >= 1 && c.findingIds.length <= 20 && c.findingIds.length >= 1);
    assert.ok(typeof c.exposureScore === 'number' && c.lastSeenAt > 0);
  }
});

test('an investigation groups every finding sharing its correlation key', async () => {
  const list = (await get('/api/threats/findings?limit=50')) as { findings: Array<{ correlationKey?: string }> };
  const key = list.findings.find((f) => f.correlationKey)?.correlationKey!;
  assert.ok(key, 'expected at least one correlated finding');
  const inv = (await get(`/api/threats/investigations/${encodeURIComponent(key)}`)) as {
    correlationKey: string; findings: Array<{ correlationKey?: string }>; evidence: unknown[]; affectedServices: string[]; firstSeenAt: number; lastSeenAt: number; decisions: unknown[];
  };
  assert.equal(inv.correlationKey, key);
  assert.ok(inv.findings.length >= 1 && inv.findings.every((f) => f.correlationKey === key));
  assert.ok(inv.evidence.length >= 1 && inv.affectedServices.length >= 1);
  assert.ok(inv.firstSeenAt <= inv.lastSeenAt && inv.decisions.length >= 1);
});

test('lateral movement produces a real attack path with the observed service chain', async () => {
  const trace = `phase4-trace-${Date.now()}`;
  const hop = async (from: string, to: string, path: string, method = 'GET') => {
    const token = await app.clients.get(from)!.signToken();
    return fetch(`${base}/api/proxy${path}`, { method, headers: { authorization: `Bearer ${token}`, 'x-destination-service': to, 'x-trace-id': trace } });
  };
  assert.equal((await hop('frontend-service', 'orders-service', '/orders/list')).status, 200);
  assert.equal((await hop('orders-service', 'payments-service', '/payments/charge', 'POST')).status, 200);
  const third = await hop('payments-service', 'database-service', '/database/rows');
  assert.equal(third.headers.get('x-zt-decision'), 'BLOCK');
  assert.equal(third.headers.get('x-zt-reason'), 'LATERAL_MOVEMENT');

  const paths = (await get('/api/threats/attack-paths')) as {
    totalActiveFindings: number;
    paths: Array<{ services: string[]; traceId?: string; category: string; severity: string }>;
  };
  assert.ok(paths.totalActiveFindings >= 1);
  const lateral = paths.paths.find((p) => p.traceId === trace);
  assert.ok(lateral, 'expected the observed trace as an attack path');
  assert.deepEqual(lateral!.services, ['frontend-service', 'orders-service', 'payments-service', 'database-service']);
  assert.equal(lateral!.category, 'LATERAL_MOVEMENT');
  assert.equal(lateral!.severity, 'CRITICAL');
});

// ── Bounds, filters, auth, abuse ─────────────────────────────────────────────

test('pagination is bounded server-side and cursors walk the full list', async () => {
  const first = (await get('/api/threats/findings?limit=1')) as { findings: Array<{ findingId: string }>; nextCursor: string | null; total: number };
  assert.equal(first.findings.length, 1);
  if (first.total > 1) {
    assert.ok(first.nextCursor);
    const second = (await get(`/api/threats/findings?limit=1&cursor=${first.nextCursor}`)) as { findings: Array<{ findingId: string }> };
    assert.equal(second.findings.length, 1);
    assert.notEqual(second.findings[0].findingId, first.findings[0].findingId);
  }
  const huge = (await get('/api/threats/findings?limit=100000')) as { findings: unknown[] };
  assert.ok(huge.findings.length <= 200, 'server clamps runaway limits');
  const junk = (await get('/api/threats/findings?limit=-5&cursor=bogus')) as { findings: unknown[]; total: number };
  assert.ok(Array.isArray(junk.findings), 'garbage pagination falls back to sane defaults');
});

test('filters select stored fields only; unknown values give a valid empty list', async () => {
  const none = (await get('/api/threats/findings?category=MADE_UP')) as { findings: unknown[]; total: number };
  assert.deepEqual(none, { findings: [], nextCursor: null, total: 0 });
  const src = (await get('/api/threats/findings?source=frontend-service&limit=50')) as { findings: Array<{ source?: string }>; total: number };
  assert.ok(src.total >= 1 && src.findings.every((f) => f.source === 'frontend-service'));
  const long = 'x'.repeat(500);
  const ignored = await get(`/api/threats/findings?source=${long}`);
  assert.equal((ignored as { total: number }).total >= 0, true);
});

test('private dashboard mode protects threat routes with the existing admin key', async () => {
  const priv = await createApp(loadConfig({ ADMIN_API_KEY: 'priv-threat-key', PUBLIC_DASHBOARD: 'false', PORT: '0' }));
  const port = await priv.listen(0);
  const url = `http://127.0.0.1:${port}/api/threats/findings`;
  try {
    assert.equal((await fetch(url)).status, 401);
    assert.equal((await fetch(url, { headers: { 'x-admin-key': 'priv-threat-key' } })).status, 200);
    assert.equal((await fetch(url, { headers: { 'x-admin-key': 'wrong' } })).status, 401);
  } finally {
    await priv.close();
  }
});

// ── WebSocket: additive, versioned, same connection ──────────────────────────

test('threat finding events arrive versioned on the existing WS connection alongside decisions', async () => {
  const ws = new WebSocket(`ws://127.0.0.1:${new URL(base).port}/ws`);
  await new Promise<void>((resolve, reject) => {
    ws.on('open', () => resolve());
    ws.on('error', reject);
  });
  const seen = { decision: false, threat: null as null | { findingId: string; category: string } };
  ws.on('message', (raw) => {
    const msg = JSON.parse(String(raw)) as { type: string; data: { findingId?: string; category?: string } };
    if (msg.type === 'decision') seen.decision = true;
    if (msg.type === 'threat.finding.v1' && msg.data.findingId && msg.data.category) {
      seen.threat = { findingId: msg.data.findingId, category: msg.data.category };
    }
  });
  // Fresh denied edge so this test owns its finding regardless of execution order.
  await callProxy('users-service', 'database-service', '/database/rows');
  await waitFor(() => seen.decision && seen.threat !== null);
  assert.ok(seen.threat!.findingId.length > 0);
  ws.close();
});

// ── Summary endpoint: badge counts from the same state, nothing new ──────────

test('threat summary returns the active count plus a bounded preview', async () => {
  const summary = (await get('/api/threats/summary')) as { totalActiveFindings: number; findings: Array<{ findingId: string; category: string; severity: string; riskScore: number }> };
  assert.equal(typeof summary.totalActiveFindings, 'number');
  assert.ok(Array.isArray(summary.findings));
  assert.ok(summary.findings.length <= 5, 'preview stays bounded');
  for (const f of summary.findings) {
    assert.ok(f.findingId.length > 0 && f.category.length > 0 && f.severity.length > 0);
    assert.equal(typeof f.riskScore, 'number');
  }
});

test('threat summary count matches the unfiltered findings list total', async () => {
  const summary = (await get('/api/threats/summary')) as { totalActiveFindings: number };
  const list = (await get('/api/threats/findings?limit=200')) as { total: number };
  assert.equal(summary.totalActiveFindings, list.total);
});

test('threat summary on a fresh app is an honest empty, and stays key-protected in private mode', async () => {
  const priv = await createApp(loadConfig({ ADMIN_API_KEY: 'priv-summary-key', PUBLIC_DASHBOARD: 'false', PORT: '0' }));
  const port = await priv.listen(0);
  const url = `http://127.0.0.1:${port}/api/threats/summary`;
  try {
    assert.equal((await fetch(url)).status, 401);
    const res = await fetch(url, { headers: { 'x-admin-key': 'priv-summary-key' } });
    assert.equal(res.status, 200);
    assert.deepEqual(await res.json(), { totalActiveFindings: 0, findings: [] });
  } finally {
    await priv.close();
  }
});

test('threat summary exposes no secrets, tokens, or payloads', async () => {
  const summary = await get('/api/threats/summary');
  const blob = JSON.stringify(summary);
  assert.ok(!/Bearer eyJ|BEGIN .*PRIVATE|totpSecret|password|x-mesh-internal/i.test(blob));
});
