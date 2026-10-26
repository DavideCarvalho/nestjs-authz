import { describe, expect, it } from 'vitest';
import {
  CompiledPermissions,
  permissionMatches,
  permissionSatisfied,
} from '../src/permission-matcher.js';

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

describe('CompiledPermissions (precompiled granted set)', () => {
  const edgeGrants = [
    '*',
    'posts.*',
    'posts.*.draft',
    '*.update',
    'posts.update',
    'posts',
    'post*',
    'posts.**',
    '',
    '.',
    'posts.',
    '.*',
    '*.*',
    'a.*.*',
  ];
  const edgeChecks = [
    'posts',
    'posts.update',
    'posts.update.draft',
    'posts.edit.draft',
    'comments.update',
    'post*',
    'posts.*',
    'posts.**',
    '*',
    '',
    '.',
    'posts.',
    'a',
    'a.b',
    'a.b.c',
    'a.b.c.d',
  ];

  it('agrees with permissionSatisfied on every single-grant edge case', () => {
    for (const g of edgeGrants) {
      const compiled = new CompiledPermissions([g]);
      for (const r of edgeChecks) {
        expect(compiled.satisfies(r), `${JSON.stringify(g)} vs ${JSON.stringify(r)}`).toBe(
          permissionSatisfied([g], r),
        );
      }
    }
  });

  it('agrees with permissionSatisfied on random grant sets', () => {
    let seed = 42;
    const rand = (n: number) => {
      seed = (seed * 1103515245 + 12345) % 2147483648;
      return seed % n;
    };
    const segments = ['a', 'b', 'c', '*', '', 'a*'];
    const name = () =>
      Array.from({ length: 1 + rand(4) }, () => segments[rand(segments.length)]).join('.');
    for (let round = 0; round < 500; round++) {
      const granted = Array.from({ length: rand(6) }, name);
      const compiled = new CompiledPermissions(granted);
      for (let i = 0; i < 20; i++) {
        const required = name();
        expect(compiled.satisfies(required), `${JSON.stringify(granted)} vs ${required}`).toBe(
          permissionSatisfied(granted, required),
        );
      }
    }
  });

  it('exposes the deduped granted set', () => {
    expect([...new CompiledPermissions(['a', 'b.*', 'a']).granted]).toEqual(['a', 'b.*']);
  });
});
