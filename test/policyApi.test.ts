import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { after, before, test } from 'node:test';
import { loadConfig } from '../src/config.js';
import { createApp, type App } from '../src/server.js';

const policyDoc = (destination: string) =>
  JSON.stringify({ version: 1, policies: [{ id: 'f-to-o', source: 'frontend-service', destination, methods: ['GET'], allowPaths: ['/orders'], description: '' }] });

let app: App;
let base: string;
let dir: string;
let file: string;

before(async () => {
  dir = mkdtempSync(path.join(tmpdir(), 'ztm-api-'));
  file = path.join(dir, 'policies.json');
  writeFileSync(file, policyDoc('orders-service'));
  app = await createApp(loadConfig({ ADMIN_API_KEY: 'k', PORT: '0', POLICY_FILE: file, POLICY_WATCH: 'true' }));
  base = `http://127.0.0.1:${await app.listen(0)}`;
});
after(async () => {
  await app.close();
  rmSync(dir, { recursive: true, force: true });
});

const status = async () => (await (await fetch(`${base}/api/policies/status`)).json()) as { version: string; policyCount: number; rejectedReloads: number; lastError?: { errors: string[] } };
const callOrders = async () => {
  const token = await app.clients.get('frontend-service')!.signToken();
  return fetch(`${base}/api/proxy/orders/list`, { headers: { authorization: `Bearer ${token}`, 'x-destination-service': 'orders-service' } });
};
const admin = (p: string) => fetch(`${base}${p}`, { method: 'POST', headers: { 'x-admin-key': 'k' } });
const until = async (cond: () => Promise<boolean>, ms = 4000) => {
  const end = Date.now() + ms;
  while (Date.now() < end) {
    if (await cond()) return true;
    await new Promise((r) => setTimeout(r, 30));
  }
  return false;
};

test('policy status endpoint reports the loaded file and version', async () => {
  const s = await status();
  assert.equal(s.policyCount, 1);
  assert.match(s.version, /^[0-9a-f]{12}$/);
  assert.equal((await callOrders()).status, 200);
});

test('editing the file changes real proxy behaviour without a restart (hot reload)', async () => {
  const before = await status();
  writeFileSync(file, policyDoc('payments-service')); // orders no longer permitted
  const changed = await until(async () => (await status()).version !== before.version);
  assert.equal(changed, true, 'watcher did not pick up the edit');
  const res = await callOrders();
  assert.equal(res.status, 403);
  assert.equal(res.headers.get('x-zt-reason'), 'NO_POLICY');
});

test('an invalid edit is rejected with 422 on manual reload and the previous policies keep working', async () => {
  writeFileSync(file, policyDoc('orders-service'));
  assert.equal((await admin('/admin/policies/reload')).status, 200);
  assert.equal((await callOrders()).status, 200);

  writeFileSync(file, '{ this is not json');
  const res = await admin('/admin/policies/reload');
  assert.equal(res.status, 422);
  assert.equal((await callOrders()).status, 200); // still enforcing the last good file
  const s = await status();
  assert.ok(s.rejectedReloads >= 1);
  assert.match(s.lastError!.errors.join(' '), /not valid JSON/);
});

test('policy reload requires the admin key', async () => {
  assert.equal((await fetch(`${base}/admin/policies/reload`, { method: 'POST' })).status, 401);
});
