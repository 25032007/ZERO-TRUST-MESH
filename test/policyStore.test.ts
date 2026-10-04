import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import { PolicyEngine } from '../src/policy/policyEngine.js';
import { PolicyStore } from '../src/policy/policyStore.js';

const doc = (extra: object = {}, dest = 'b-service') =>
  JSON.stringify({ version: 1, policies: [{ id: 'a-to-b', source: 'a-service', destination: dest, methods: ['GET'], description: '' }], ...extra });

function tmpFile(content: string) {
  const dir = mkdtempSync(path.join(tmpdir(), 'ztm-policy-'));
  const file = path.join(dir, 'policies.json');
  writeFileSync(file, content);
  return { dir, file, cleanup: () => rmSync(dir, { recursive: true, force: true }) };
}

const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function until(cond: () => boolean, ms = 4000) {
  const end = Date.now() + ms;
  while (!cond() && Date.now() < end) await sleep(25);
  return cond();
}

test('initial load applies the file and computes a version', () => {
  const t = tmpFile(doc());
  try {
    const engine = new PolicyEngine();
    const store = new PolicyStore(engine, t.file);
    store.loadInitial();
    assert.equal(engine.evaluate('a-service', 'b-service', 'GET', '/').allowed, true);
    const s = store.status();
    assert.equal(s.policyCount, 1);
    assert.match(s.version, /^[0-9a-f]{12}$/);
  } finally {
    t.cleanup();
  }
});

test('an invalid FIRST load throws (fail fast, never run unprotected)', () => {
  const t = tmpFile('{not json');
  try {
    assert.throws(() => new PolicyStore(new PolicyEngine(), t.file).loadInitial(), /Invalid policy file/);
  } finally {
    t.cleanup();
  }
  assert.throws(() => new PolicyStore(new PolicyEngine(), '/definitely/missing.json').loadInitial(), /cannot read file/);
});

test('a valid edit is applied on reload and the version changes', () => {
  const t = tmpFile(doc());
  try {
    const engine = new PolicyEngine();
    const store = new PolicyStore(engine, t.file);
    store.loadInitial();
    const v1 = store.status().version;
    writeFileSync(t.file, doc({}, 'c-service'));
    assert.equal(store.reload().ok, true);
    assert.equal(engine.evaluate('a-service', 'b-service', 'GET', '/').reason, 'NO_POLICY');
    assert.equal(engine.evaluate('a-service', 'c-service', 'GET', '/').allowed, true);
    assert.notEqual(store.status().version, v1);
    assert.equal(store.status().reloads, 1);
  } finally {
    t.cleanup();
  }
});

test('an INVALID edit is rejected: old policies stay active and the error is recorded', () => {
  const t = tmpFile(doc());
  try {
    const engine = new PolicyEngine();
    const store = new PolicyStore(engine, t.file);
    store.loadInitial();
    const v1 = store.status().version;
    writeFileSync(t.file, JSON.stringify({ version: 1, policies: [{ id: 'x', source: 'a-service', destination: 'b-service', methods: ['GET'], alowPaths: ['/'] }] }));
    const r = store.reload();
    assert.equal(r.ok, false);
    assert.equal(engine.evaluate('a-service', 'b-service', 'GET', '/').allowed, true); // unchanged
    const s = store.status();
    assert.equal(s.version, v1);
    assert.equal(s.rejectedReloads, 1);
    assert.match(s.lastError!.errors.join(' '), /alowPaths/);

    writeFileSync(t.file, doc()); // fix the file -> error clears
    assert.equal(store.reload().ok, true);
    assert.equal(store.status().lastError, undefined);
  } finally {
    t.cleanup();
  }
});

test('dry-run and workflows come from the file; DRY_RUN env forces dry-run on', () => {
  const t = tmpFile(doc({ dryRun: false, allowedWorkflows: [['a-service', 'b-service', 'c-service']] }));
  try {
    const engine = new PolicyEngine();
    new PolicyStore(engine, t.file, false).loadInitial();
    assert.equal(engine.dryRun, false);
    assert.equal(engine.isKnownWorkflow(['a-service', 'b-service', 'c-service']), true);

    const forced = new PolicyEngine();
    new PolicyStore(forced, t.file, true).loadInitial();
    assert.equal(forced.dryRun, true);
  } finally {
    t.cleanup();
  }
});

test('hot reload: editing the file on disk updates the engine without a restart', async () => {
  const t = tmpFile(doc());
  const engine = new PolicyEngine();
  const store = new PolicyStore(engine, t.file);
  try {
    store.loadInitial();
    store.watch(50);
    await sleep(100);
    writeFileSync(t.file, doc({}, 'c-service'));
    const applied = await until(() => engine.evaluate('a-service', 'c-service', 'GET', '/').allowed);
    assert.equal(applied, true, 'watcher did not apply the edit in time');
  } finally {
    store.close();
    t.cleanup();
  }
});

test('useInline sets policies without a file', () => {
  const engine = new PolicyEngine();
  const store = new PolicyStore(engine, undefined);
  store.useInline([{ id: 'p', source: 'a', destination: 'b', methods: ['GET'], description: '' }]);
  assert.equal(store.hasFile, false);
  assert.equal(store.status().policyCount, 1);
  assert.equal(store.reload().ok, false);
});
