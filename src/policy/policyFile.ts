/**
 * Policy-as-code: parse and STRICTLY validate a policy document.
 *
 * Why strict? A policy file is security configuration. A typo such as
 * "alowPaths" must never silently turn into "no path restriction" — so unknown
 * keys are errors, and ALL errors are reported at once (not just the first) so an
 * operator can fix a file in one pass.
 *
 * Document shape (JSON):
 * {
 *   "version": 1,
 *   "dryRun": false,                       // optional: log-only mode for the whole file
 *   "policies": [ { "id": "...", "source": "...", "destination": "...", "methods": ["GET"], ... } ],
 *   "allowedWorkflows": [ ["a-service", "b-service", "c-service"] ]   // optional
 * }
 */
import type { Policy } from './policyEngine.js';

export interface PolicyDocument {
  version: 1;
  dryRun: boolean;
  policies: Policy[];
  /** Declared multi-hop call chains that are NOT lateral movement (see LateralMovementDetector). */
  allowedWorkflows: string[][];
}

export type ParseResult = { ok: true; doc: PolicyDocument } | { ok: false; errors: string[] };

const SERVICE_ID = /^[a-z0-9][a-z0-9-]{1,62}$/;
const POLICY_ID = /^[a-z0-9][a-z0-9._-]{0,80}$/;
const METHODS = new Set(['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'HEAD', 'OPTIONS']);

const DOC_KEYS = new Set(['version', 'dryRun', 'policies', 'allowedWorkflows']);
const POLICY_KEYS = new Set(['id', 'source', 'destination', 'methods', 'allowPaths', 'denyPaths', 'hoursUtc', 'effect', 'priority', 'mode', 'description']);

const isObject = (v: unknown): v is Record<string, unknown> => typeof v === 'object' && v !== null && !Array.isArray(v);

export function parsePolicyDocument(text: string): ParseResult {
  let raw: unknown;
  try {
    raw = JSON.parse(text);
  } catch (err) {
    return { ok: false, errors: [`not valid JSON: ${(err as Error).message}`] };
  }
  return validatePolicyDocument(raw);
}

export function validatePolicyDocument(raw: unknown): ParseResult {
  const errors: string[] = [];
  if (!isObject(raw)) return { ok: false, errors: ['document must be a JSON object'] };

  for (const key of Object.keys(raw)) if (!DOC_KEYS.has(key)) errors.push(`unknown top-level key "${key}"`);
  if (raw.version !== 1) errors.push('"version" must be 1');
  if (raw.dryRun !== undefined && typeof raw.dryRun !== 'boolean') errors.push('"dryRun" must be a boolean');

  const policies: Policy[] = [];
  if (!Array.isArray(raw.policies)) {
    errors.push('"policies" must be an array');
  } else {
    const seen = new Set<string>();
    raw.policies.forEach((entry, i) => {
      const where = `policies[${i}]`;
      const policy = validatePolicy(entry, where, errors);
      if (!policy) return;
      if (seen.has(policy.id)) errors.push(`${where}: duplicate id "${policy.id}"`);
      seen.add(policy.id);
      policies.push(policy);
    });
  }

  const allowedWorkflows: string[][] = [];
  if (raw.allowedWorkflows !== undefined) {
    if (!Array.isArray(raw.allowedWorkflows)) {
      errors.push('"allowedWorkflows" must be an array of arrays');
    } else {
      raw.allowedWorkflows.forEach((wf, i) => {
        const ok = Array.isArray(wf) && wf.length >= 3 && wf.every((s) => typeof s === 'string' && SERVICE_ID.test(s));
        if (!ok) errors.push(`allowedWorkflows[${i}]: must be an array of at least 3 valid service ids`);
        else allowedWorkflows.push(wf as string[]);
      });
    }
  }

  if (errors.length > 0) return { ok: false, errors };
  return { ok: true, doc: { version: 1, dryRun: raw.dryRun === true, policies, allowedWorkflows } };
}

function validatePolicy(entry: unknown, where: string, errors: string[]): Policy | undefined {
  const before = errors.length;
  if (!isObject(entry)) {
    errors.push(`${where}: must be an object`);
    return undefined;
  }
  for (const key of Object.keys(entry)) if (!POLICY_KEYS.has(key)) errors.push(`${where}: unknown key "${key}"`);

  const str = (key: string, re: RegExp) => {
    const v = entry[key];
    if (typeof v !== 'string' || !re.test(v)) errors.push(`${where}.${key}: missing or invalid`);
    return v as string;
  };
  const id = str('id', POLICY_ID);
  const source = str('source', SERVICE_ID);
  const destination = str('destination', SERVICE_ID);

  const methods = entry.methods;
  if (!Array.isArray(methods) || methods.length === 0 || !methods.every((m) => typeof m === 'string' && METHODS.has(m))) {
    errors.push(`${where}.methods: must be a non-empty array of upper-case HTTP methods`);
  }

  const paths = (key: 'allowPaths' | 'denyPaths') => {
    const v = entry[key];
    if (v === undefined) return undefined;
    if (!Array.isArray(v) || !v.every((p) => typeof p === 'string' && p.startsWith('/'))) {
      errors.push(`${where}.${key}: must be an array of paths starting with "/"`);
      return undefined;
    }
    return v as string[];
  };
  const allowPaths = paths('allowPaths');
  const denyPaths = paths('denyPaths');

  let hoursUtc: Policy['hoursUtc'];
  if (entry.hoursUtc !== undefined) {
    const h = entry.hoursUtc;
    if (isObject(h) && Number.isInteger(h.start) && Number.isInteger(h.end) && (h.start as number) >= 0 && (h.end as number) <= 24 && (h.start as number) < (h.end as number)) {
      hoursUtc = { start: h.start as number, end: h.end as number };
    } else {
      errors.push(`${where}.hoursUtc: must be {start,end} integers with 0 <= start < end <= 24`);
    }
  }

  if (entry.effect !== undefined && entry.effect !== 'allow' && entry.effect !== 'deny') errors.push(`${where}.effect: must be "allow" or "deny"`);
  if (entry.mode !== undefined && entry.mode !== 'enforce' && entry.mode !== 'dry-run') errors.push(`${where}.mode: must be "enforce" or "dry-run"`);
  if (entry.priority !== undefined && !(Number.isInteger(entry.priority) && Math.abs(entry.priority as number) <= 1000)) {
    errors.push(`${where}.priority: must be an integer between -1000 and 1000`);
  }
  if (entry.description !== undefined && typeof entry.description !== 'string') errors.push(`${where}.description: must be a string`);

  if (errors.length > before) return undefined;
  return {
    id,
    source,
    destination,
    methods: methods as string[],
    allowPaths,
    denyPaths,
    hoursUtc,
    effect: entry.effect as Policy['effect'],
    priority: entry.priority as number | undefined,
    mode: entry.mode as Policy['mode'],
    description: (entry.description as string | undefined) ?? '',
  };
}
