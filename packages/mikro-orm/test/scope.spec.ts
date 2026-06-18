import 'reflect-metadata';
import { and, eq, or, scopeAll, scopeNone, where } from '@dudousxd/nestjs-authz';
import { RawQueryFragment } from '@mikro-orm/core';
import { describe, expect, it } from 'vitest';
import { compileScope } from '../src/scope.js';

/**
 * Assert a compiled filter is the always-false predicate: a single `{ [raw('1')]: 0 }`
 * entry whose key is a `raw('1')` fragment and whose value is `0` → `WHERE 1 = 0`.
 */
function isAlwaysFalse(value: unknown): boolean {
  if (!value || typeof value !== 'object') return false;
  const entries = Object.entries(value as Record<string, unknown>);
  if (entries.length !== 1) return false;
  const [key, val] = entries[0] as [string, unknown];
  const frag = RawQueryFragment.getKnownFragment(key, false);
  return frag?.sql === '1' && val === 0;
}

describe('compileScope — constraint AST → MikroORM FilterQuery', () => {
  it('allow-all → empty filter (matches every row)', () => {
    expect(compileScope(scopeAll)).toEqual({});
  });

  it('deny-all → an always-false raw predicate (matches no row)', () => {
    expect(isAlwaysFalse(compileScope(scopeNone))).toBe(true);
  });

  it('a single equality → { field: { $eq: value } }', () => {
    expect(compileScope(eq('authorId', 7))).toEqual({ authorId: { $eq: 7 } });
  });

  it('maps every comparison operator', () => {
    expect(compileScope(where('a', 'ne', 1))).toEqual({ a: { $ne: 1 } });
    expect(compileScope(where('a', 'gt', 1))).toEqual({ a: { $gt: 1 } });
    expect(compileScope(where('a', 'gte', 1))).toEqual({ a: { $gte: 1 } });
    expect(compileScope(where('a', 'lt', 1))).toEqual({ a: { $lt: 1 } });
    expect(compileScope(where('a', 'lte', 1))).toEqual({ a: { $lte: 1 } });
  });

  it('IN / NIN map to { $in } / { $nin } with an array', () => {
    expect(compileScope(where('id', 'in', [1, 2, 3]))).toEqual({ id: { $in: [1, 2, 3] } });
    expect(compileScope(where('id', 'nin', [1, 2]))).toEqual({ id: { $nin: [1, 2] } });
    // A scalar value is wrapped into a single-element array.
    expect(compileScope(where('id', 'in', 1))).toEqual({ id: { $in: [1] } });
  });

  it('an empty IN is always-false (no row matches)', () => {
    expect(isAlwaysFalse(compileScope(where('id', 'in', [])))).toBe(true);
  });

  it('an empty NIN is always-true (every row matches → empty filter)', () => {
    expect(compileScope(where('id', 'nin', []))).toEqual({});
  });

  it('isNull / isNotNull map to $eq:null / $ne:null', () => {
    expect(compileScope(where('deletedAt', 'isNull'))).toEqual({ deletedAt: { $eq: null } });
    expect(compileScope(where('deletedAt', 'isNotNull'))).toEqual({ deletedAt: { $ne: null } });
  });

  it('AND group → { $and: [...] }', () => {
    expect(compileScope(and(eq('a', 1), eq('b', 2)))).toEqual({
      $and: [{ a: { $eq: 1 } }, { b: { $eq: 2 } }],
    });
  });

  it('OR group → { $or: [...] }', () => {
    expect(compileScope(or(eq('a', 1), eq('b', 2)))).toEqual({
      $or: [{ a: { $eq: 1 } }, { b: { $eq: 2 } }],
    });
  });

  it('nested AND/OR groups nest correctly', () => {
    expect(compileScope(and(eq('orgId', 9), or(eq('ownerId', 1), eq('published', 1))))).toEqual({
      $and: [{ orgId: { $eq: 9 } }, { $or: [{ ownerId: { $eq: 1 } }, { published: { $eq: 1 } }] }],
    });
  });

  it('rejects a hostile field name (injection via identifier)', () => {
    expect(() => compileScope(eq('id"; DROP TABLE posts; --', 1))).toThrow(/Unsafe/);
  });
});
