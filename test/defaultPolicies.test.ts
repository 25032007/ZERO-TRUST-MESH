import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { DEFAULT_POLICIES } from '../src/policy/policyEngine.js';
import { parsePolicyDocument } from '../src/policy/policyFile.js';

// The built-in fallback (TypeScript) and the shipped file must never drift apart.
test('policies/default.json is valid and identical to the built-in DEFAULT_POLICIES', () => {
  const parsed = parsePolicyDocument(readFileSync('policies/default.json', 'utf8'));
  assert.equal(parsed.ok, true, parsed.ok ? '' : parsed.errors.join('; '));
  if (!parsed.ok) return;
  const normalise = (list: unknown) => JSON.parse(JSON.stringify(list));
  assert.deepEqual(normalise(parsed.doc.policies), normalise(DEFAULT_POLICIES));
  assert.equal(parsed.doc.dryRun, false);
});
