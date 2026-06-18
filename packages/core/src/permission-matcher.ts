/**
 * Laravel/spatie-style wildcard permission matching.
 *
 * A GRANTED permission (the left-hand side) may contain `*` wildcard segments;
 * the REQUIRED ability (the check) is always a concrete, literal string. Matching
 * is segment-based on the `.` separator:
 *
 * - exact string equality matches (`posts.update` ⇒ `posts.update`).
 * - a trailing `*` segment matches ONE-OR-MORE remaining segments
 *   (`posts.*` ⇒ `posts.update`, `posts.update.draft`) — but not zero
 *   (`posts.*` does NOT match the bare `posts`).
 * - a bare `*` grant matches anything.
 * - `*` only matches at a segment boundary, so `posts.*` does NOT match
 *   `comments.update`.
 *
 * Only the GRANTED side is expanded — a `*` in the required ability is treated
 * literally, since a check is never a pattern.
 */
export function permissionMatches(granted: string, required: string): boolean {
  if (granted === required) return true;
  if (granted === '*') return true;

  const grantedParts = granted.split('.');
  const requiredParts = required.split('.');

  for (let i = 0; i < grantedParts.length; i++) {
    const g = grantedParts[i];
    if (g === '*') {
      // A trailing `*` matches one-or-more remaining required segments.
      // (Only the final segment may be a wildcard; an interior `*` still works
      // positionally but a trailing `*` is the idiomatic form.)
      if (i === grantedParts.length - 1) {
        return requiredParts.length > i;
      }
      // interior wildcard: this single segment is consumed; continue matching.
      if (requiredParts[i] === undefined) return false;
      continue;
    }
    if (g !== requiredParts[i]) return false;
  }

  // All granted segments consumed and matched exactly → only a true match when
  // the required ability has no extra trailing segments.
  return grantedParts.length === requiredParts.length;
}

/** True when ANY permission in the granted set satisfies the required ability. */
export function permissionSatisfied(granted: Iterable<string>, required: string): boolean {
  for (const g of granted) {
    if (permissionMatches(g, required)) return true;
  }
  return false;
}
