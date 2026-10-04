import assert from 'node:assert/strict';
import { test } from 'node:test';
import { parsePolicyDocument } from '../src/policy/policyFile.js';

const good = {
  version: 1,
  policies: [{ id: 'a-to-b', source: 'a-service', destination: 'b-service', methods: ['GET'], allowPaths: ['/x'], description: 'ok' }],
};
const parse = (o: unknown) => parsePolicyDocument(JSON.stringify(o));

test('a valid document parses and gets sensible defaults', () => {
  const r = parse(good);
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.doc.dryRun, false);
    assert.deepEqual(r.doc.allowedWorkflows, []);
    assert.equal(r.doc.policies[0].id, 'a-to-b');
  }
});

test('optional fields are carried through (effect, priority, mode, hours, workflows)', () => {
  const r = parse({
    version: 1,
    dryRun: true,
    policies: [{ id: 'p', source: 'a-service', destination: 'b-service', methods: ['POST'], effect: 'deny', priority: 7, mode: 'dry-run', hoursUtc: { start: 9, end: 17 }, denyPaths: ['/admin'], description: 'd' }],
    allowedWorkflows: [['a-service', 'b-service', 'c-service']],
  });
  assert.equal(r.ok, true);
  if (r.ok) {
    assert.equal(r.doc.dryRun, true);
    assert.deepEqual(r.doc.policies[0].hoursUtc, { start: 9, end: 17 });
    assert.equal(r.doc.policies[0].priority, 7);
    assert.equal(r.doc.allowedWorkflows.length, 1);
  }
});

test('invalid JSON and non-object documents are rejected', () => {
  assert.equal(parsePolicyDocument('{oops').ok, false);
  assert.equal(parsePolicyDocument('[]').ok, false);
  assert.equal(parsePolicyDocument('null').ok, false);
});

test('typos are errors, not silent no-ops (unknown keys)', () => {
  const r = parse({ ...good, policies: [{ ...good.policies[0], alowPaths: ['/x'] }] });
  assert.equal(r.ok, false);
  if (!r.ok) assert.match(r.errors.join('\n'), /unknown key "alowPaths"/);
  const top = parse({ ...good, polcies: [] });
  assert.equal(top.ok, false);
});

test('all problems are reported at once', () => {
  const r = parse({
    version: 2,
    policies: [
      { id: 'BAD ID', source: 'x', destination: 'b-service', methods: ['get'], description: 1 },
      { id: 'dup', source: 'a-service', destination: 'b-service', methods: ['GET'] },
      { id: 'dup', source: 'a-service', destination: 'b-service', methods: ['GET'] },
    ],
  });
  assert.equal(r.ok, false);
  if (!r.ok) {
    const text = r.errors.join('\n');
    assert.match(text, /"version" must be 1/);
    assert.match(text, /policies\[0\]\.id/);
    assert.match(text, /policies\[0\]\.source/);
    assert.match(text, /policies\[0\]\.methods/);
    assert.match(text, /duplicate id "dup"/);
    assert.ok(r.errors.length >= 5);
  }
});

test('value ranges are enforced (hours, priority, enums, paths, workflows)', () => {
  const bad = (patch: object) => parse({ version: 1, policies: [{ ...good.policies[0], ...patch }] });
  assert.equal(bad({ hoursUtc: { start: 17, end: 9 } }).ok, false);
  assert.equal(bad({ hoursUtc: { start: 0, end: 25 } }).ok, false);
  assert.equal(bad({ priority: 5000 }).ok, false);
  assert.equal(bad({ priority: 1.5 }).ok, false);
  assert.equal(bad({ effect: 'maybe' }).ok, false);
  assert.equal(bad({ mode: 'audit' }).ok, false);
  assert.equal(bad({ allowPaths: ['no-slash'] }).ok, false);
  assert.equal(bad({ methods: [] }).ok, false);
  assert.equal(parse({ version: 1, policies: [], allowedWorkflows: [['a-service', 'b-service']] }).ok, false);
});
