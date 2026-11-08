import 'reflect-metadata';
import { describe, expect, it } from 'vitest';
import {
  type ScopeConstraint,
  and,
  eq,
  normalizeScope,
  or,
  scopeAll,
  scopeNone,
  where,
} from '../src/scope.js';

describe('scope AST builders', () => {
  it('eq builds an equality condition', () => {
    expect(eq('authorId', 7)).toEqual({ kind: 'condition', field: 'authorId', op: 'eq', value: 7 });
  });

  it('where omits value for null checks', () => {
    expect(where('deletedAt', 'isNull')).toEqual({
      kind: 'condition',
      field: 'deletedAt',
      op: 'isNull',
    });
  });

  it('and/or collapse single nodes and bottom out on empty', () => {
    const c = eq('a', 1);
    expect(and(c)).toEqual(c);
    expect(or(c)).toEqual(c);
    expect(and()).toEqual(scopeAll);
    expect(or()).toEqual(scopeNone);
    expect(and(eq('a', 1), eq('b', 2))).toEqual({
      kind: 'and',
      nodes: [eq('a', 1), eq('b', 2)],
    });
  });

  it('normalizeScope maps boolean/nullish sugar', () => {
    expect(normalizeScope(true)).toEqual(scopeAll);
    expect(normalizeScope(false)).toEqual(scopeNone);
    expect(normalizeScope(undefined)).toEqual(scopeNone);
    expect(normalizeScope(null)).toEqual(scopeNone);
    expect(normalizeScope(eq('a', 1))).toEqual(eq('a', 1));
  });
});
