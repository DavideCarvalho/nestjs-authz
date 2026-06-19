import 'reflect-metadata';
import { and, eq, or, scopeAll, scopeNone, where } from '@dudousxd/nestjs-authz';
import { describe, expect, it } from 'vitest';
import { compileScope } from '../src/scope.js';

describe('compileScope — constraint AST → Prisma where', () => {
  it('allow-all → empty where (matches every row)', () => {
    expect(compileScope(scopeAll)).toEqual({});
  });

  it('deny-all → an impossible where (empty OR matches no row)', () => {
    expect(compileScope(scopeNone)).toEqual({ OR: [] });
  });

  it('a single equality → { field: { equals: value } }', () => {
    expect(compileScope(eq('authorId', 7))).toEqual({ authorId: { equals: 7 } });
  });

  it('maps every comparison operator', () => {
    expect(compileScope(where('a', 'ne', 1))).toEqual({ a: { not: 1 } });
    expect(compileScope(where('a', 'gt', 1))).toEqual({ a: { gt: 1 } });
    expect(compileScope(where('a', 'gte', 1))).toEqual({ a: { gte: 1 } });
    expect(compileScope(where('a', 'lt', 1))).toEqual({ a: { lt: 1 } });
    expect(compileScope(where('a', 'lte', 1))).toEqual({ a: { lte: 1 } });
  });

  it('IN / NIN map to { in } / { notIn } with an array', () => {
    expect(compileScope(where('id', 'in', [1, 2, 3]))).toEqual({ id: { in: [1, 2, 3] } });
    expect(compileScope(where('id', 'nin', [1, 2]))).toEqual({ id: { notIn: [1, 2] } });
    // A scalar value is wrapped into a single-element array.
    expect(compileScope(where('id', 'in', 1))).toEqual({ id: { in: [1] } });
  });

  it('an empty IN is impossible (no row matches)', () => {
    expect(compileScope(where('id', 'in', []))).toEqual({ OR: [] });
  });

  it('an empty NIN is always-true (every row matches → empty where)', () => {
    expect(compileScope(where('id', 'nin', []))).toEqual({});
  });

  it('isNull / isNotNull map to equals:null / not:null', () => {
    expect(compileScope(where('deletedAt', 'isNull'))).toEqual({ deletedAt: { equals: null } });
    expect(compileScope(where('deletedAt', 'isNotNull'))).toEqual({ deletedAt: { not: null } });
  });

  it('AND group → { AND: [...] }', () => {
    expect(compileScope(and(eq('a', 1), eq('b', 2)))).toEqual({
      AND: [{ a: { equals: 1 } }, { b: { equals: 2 } }],
    });
  });

  it('OR group → { OR: [...] }', () => {
    expect(compileScope(or(eq('a', 1), eq('b', 2)))).toEqual({
      OR: [{ a: { equals: 1 } }, { b: { equals: 2 } }],
    });
  });

  it('nested AND/OR groups nest correctly', () => {
    expect(compileScope(and(eq('orgId', 9), or(eq('ownerId', 1), eq('published', 1))))).toEqual({
      AND: [
        { orgId: { equals: 9 } },
        { OR: [{ ownerId: { equals: 1 } }, { published: { equals: 1 } }] },
      ],
    });
  });

  it('rejects a hostile field name (injection via identifier)', () => {
    expect(() => compileScope(eq('id"; DROP TABLE posts; --', 1))).toThrow(/Unsafe/);
  });
});
