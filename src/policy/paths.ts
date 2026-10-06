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
 * Two helpers, both pure (no clock, no state):
 *   isSafePath         — strict validator; rejects traversal/encoding ambiguity
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
