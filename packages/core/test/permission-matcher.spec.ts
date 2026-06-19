import { describe, expect, it } from 'vitest';
import { permissionMatches, permissionSatisfied } from '../src/permission-matcher.js';

/**
 * Laravel/spatie-style wildcard permission matching. A GRANTED permission may
 * contain `*` segments; the REQUIRED ability is the concrete check.
 *
 * Semantics (segment-based on `.`):
 * - exact string equality matches.
 * - a trailing `*` segment matches one-or-more remaining segments
 *   (`posts.*` → `posts.update`, `posts.update.draft`).
 * - a bare `*` matches anything.
 * - `*` only matches at a segment boundary (`posts.*` does NOT match `comments.update`).
 */
describe('permissionMatches (single granted vs required)', () => {
  it('exact match', () => {
    expect(permissionMatches('posts.update', 'posts.update')).toBe(true);
  });

  it('posts.* matches posts.update', () => {
    expect(permissionMatches('posts.*', 'posts.update')).toBe(true);
  });

  it('posts.* matches a deeper segment posts.update.draft', () => {
    expect(permissionMatches('posts.*', 'posts.update.draft')).toBe(true);
  });

  it('* matches anything', () => {
    expect(permissionMatches('*', 'posts.update')).toBe(true);
    expect(permissionMatches('*', 'comments.delete')).toBe(true);
    expect(permissionMatches('*', 'anything')).toBe(true);
  });

  it('posts.* does NOT match comments.update (non-match)', () => {
    expect(permissionMatches('posts.*', 'comments.update')).toBe(false);
  });

  it('posts.* requires at least one trailing segment (does not match bare "posts")', () => {
    expect(permissionMatches('posts.*', 'posts')).toBe(false);
  });

  it('exact non-match', () => {
    expect(permissionMatches('posts.update', 'posts.delete')).toBe(false);
  });

  it('a required wildcard is NOT expanded (only granted side has wildcard semantics)', () => {
    // The check side is always concrete; a literal `*` in the check matches only a literal grant.
    expect(permissionMatches('posts.update', 'posts.*')).toBe(false);
  });
});

describe('permissionSatisfied (granted set vs required)', () => {
  it('true when any granted permission matches', () => {
    expect(permissionSatisfied(['comments.read', 'posts.*'], 'posts.update')).toBe(true);
  });

  it('false when none match', () => {
    expect(permissionSatisfied(['comments.*', 'posts.read'], 'posts.update')).toBe(false);
  });

  it('global * grant satisfies everything', () => {
    expect(permissionSatisfied(['*'], 'anything.at.all')).toBe(true);
  });

  it('empty grant set satisfies nothing', () => {
    expect(permissionSatisfied([], 'posts.update')).toBe(false);
  });
});
