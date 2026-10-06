/**
 * Path safety boundary for authorization and forwarding.
 *
 * WHY this exists: the policy engine authorizes a path string while the HTTP
 * client (`fetch`) normalizes dot-segments and percent-encoding when it builds
 * the downstream URL. Authorizing `/database/./admin/users` (raw) and then
 * forwarding it (normalized to `/database/admin/users`) lets one string pass
 * the check while a different resource is fetched. The fix is fail-closed:
 * any path whose meaning could change under URL normalization is rejected
 * BEFORE authorization, so the exact string that passes the policy is also
 * the exact string that is forwarded.
 *
 * Three helpers, all pure (no clock, no state):
 *   isSafePath         — strict validator; rejects traversal/encoding ambiguity
 *   canonicalizePath   — single deterministic canonical form for one raw path;
 *                        the pipeline authorizes AND forwards exactly this string
 *   pathMatchesPrefix  — segment-aware prefix check for allow/deny lists
 */

/**
 * True only for paths whose meaning cannot change under URL normalization.
 *
 * Rejects: dot-segments (even single `.`), backslashes, encoded separators
 * (`%2F`, `%5C`, any case — decoding them would change segmentation),
 * encoded dots (`%2E` — decoding them would create dot-segments), malformed
 * percent-encoding (fail closed), and anything not starting with `/`.
 */
export function isSafePath(path: unknown): path is string {
  if (typeof path !== 'string' || path.length === 0 || !path.startsWith('/')) return false;
  if (path.includes('\\')) return false;
  // Encoded separators or dots would re-segment the path (or create
  // dot-segments) once the HTTP client decodes them — reject them raw.
  if (/%(?:2f|5c|2e)/i.test(path)) return false;
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return false; // malformed encoding: fail closed, never guess
  }
  if (decoded.includes('\\')) return false;
  for (const segment of decoded.split('/')) {
    if (segment === '.' || segment === '..') return false;
  }
  return true;
}

/**
 * Deterministic canonical form of one raw request path, or null when the
 * path must fail closed (INVALID_PATH upstream).
 *
 * WHY each step exists (all verified against this stack's real behavior —
 * Express `req.path` decodes nothing; `fetch`/undici strips dot-segments,
 * raw or `%2e`-encoded, and otherwise passes bytes through):
 *
 * 1. Raw fail-closed checks, identical to isSafePath: dot-segments or
 *    encoded dots/separators in the raw string are never given a meaning.
 * 2. Exactly ONE decodeURIComponent: mirrors the single decode the HTTP
 *    layer applies. Never looped — looping would decode MORE times than the
 *    forwarder does (`%2561` must stay deniable-as-`%61`, not become `a`).
 * 3. Re-validate the decoded form for the same dangerous sequences
 *    (double-encoding guard: `%252e` decodes to a dot-form the forwarder
 *    would strip) plus `?`, `#` (would restructure the request URL) and
 *    control characters (the URL parser silently strips tabs/newlines).
 *    Any leftover `%` can only come from `%25` and is rejected: after one
 *    clean decode no bare `%` may remain, so the canonical form carries no
 *    encoding ambiguity at all.
 * 4. Collapse `/{2,}` to `/` so `/foo//bar` and `/foo/bar` authorize (and
 *    forward) identically instead of depending on downstream slash handling.
 * 5. Reject dot-segments (fail closed, never rewritten into something else).
 * 6. Serialize through the same WHATWG URL parser `fetch()` uses, and
 *    authorize THAT string: it is byte-identical to the request-target on
 *    the wire (e.g. a decoded space re-encodes as `%20` downstream, so the
 *    policy must see the `%20` form too).
 *
 * Case is preserved end to end: Express routing, `fetch`, and
 * pathMatchesPrefix are all case-sensitive, so `/Admin` and `/admin` stay
 * distinct everywhere and fail closed against lowercase-only policies.
 */
export function canonicalizePath(path: unknown): string | null {
  if (typeof path !== 'string' || path.length === 0 || !path.startsWith('/')) return null;
  if (path.includes('\\')) return null;
  if (/%(?:2f|5c|2e)/i.test(path)) return null;
  let decoded: string;
  try {
    decoded = decodeURIComponent(path);
  } catch {
    return null; // malformed encoding: fail closed, never guess
  }
  if (decoded.includes('\\')) return null;
  if (/%(?:2f|5c|2e)/i.test(decoded)) return null;
  if (/[?#%]/.test(decoded)) return null;
  if (/[\u0000-\u001f\u007f]/.test(decoded)) return null;
  const collapsed = decoded.replace(/\/{2,}/g, '/');
  for (const segment of collapsed.split('/')) {
    if (segment === '.' || segment === '..') return null;
  }
  // Authorize the wire form, not the decoded form.
  let serialized: string;
  try {
    serialized = new URL(`http://internal.invalid${collapsed}`).pathname;
  } catch {
    return null;
  }
  if (/[?#\\]/.test(serialized)) return null;
  for (const segment of serialized.split('/')) {
    if (segment === '.' || segment === '..') return null;
  }
  return serialized;
}

/**
 * Segment-aware prefix match for policy path lists.
 *
 * `/orders` matches `/orders`, `/orders/` and `/orders/list`, but NOT
 * `/orders-admin` or `/orders2` (raw `startsWith` would wrongly allow those).
 * A `/` prefix matches every absolute path, same as before.
 */
export function pathMatchesPrefix(path: string, prefix: string): boolean {
  if (prefix === '/') return path.startsWith('/');
  if (path === prefix) return true;
  return path.startsWith(prefix.endsWith('/') ? prefix : `${prefix}/`);
}
