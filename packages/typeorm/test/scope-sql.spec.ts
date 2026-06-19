import 'reflect-metadata';
import { and, eq, or, scopeAll, scopeNone, where } from '@dudousxd/nestjs-authz';
import { describe, expect, it } from 'vitest';
import { compileScope } from '../src/scope.js';

describe('compileScope — constraint AST → parameterized SQL', () => {
  it('allow-all → no predicate (undefined)', () => {
    expect(compileScope(scopeAll, 'p')).toBeUndefined();
  });

  it('deny-all → an always-false predicate, no params', () => {
    const out = compileScope(scopeNone, 'p');
    expect(out).toEqual({ sql: '1 = 0', params: {} });
  });

  it('a single equality → "alias"."field" = :param', () => {
    const out = compileScope(eq('authorId', 7), 'p', 'post');
    expect(out).toEqual({ sql: '"post"."authorId" = :p_0', params: { p_0: 7 } });
  });

  it('omits the alias prefix when none is given', () => {
    const out = compileScope(eq('authorId', 7), 'p');
    expect(out).toEqual({ sql: '"authorId" = :p_0', params: { p_0: 7 } });
  });

  it('AND group joins with AND and numbers params uniquely', () => {
    const out = compileScope(and(eq('a', 1), eq('b', 2)), 'p');
    expect(out).toEqual({
      sql: '("a" = :p_0 AND "b" = :p_1)',
      params: { p_0: 1, p_1: 2 },
    });
  });

  it('OR group joins with OR', () => {
    const out = compileScope(or(eq('a', 1), eq('b', 2)), 'p');
    expect(out?.sql).toBe('("a" = :p_0 OR "b" = :p_1)');
  });

  it('nested groups parenthesize correctly', () => {
    const out = compileScope(and(eq('orgId', 9), or(eq('ownerId', 1), eq('public', true))), 'p');
    expect(out?.sql).toBe('("orgId" = :p_0 AND ("ownerId" = :p_1 OR "public" = :p_2))');
    expect(out?.params).toEqual({ p_0: 9, p_1: 1, p_2: true });
  });

  it('IN expands to an array-bound parameter with (...)', () => {
    const out = compileScope(where('id', 'in', [1, 2, 3]), 'p');
    expect(out).toEqual({ sql: '"id" IN (:...p_0)', params: { p_0: [1, 2, 3] } });
  });

  it('an empty IN is always-false (no row matches)', () => {
    const out = compileScope(where('id', 'in', []), 'p');
    expect(out).toEqual({ sql: '1 = 0', params: {} });
  });

  it('isNull / isNotNull bind no parameter', () => {
    expect(compileScope(where('deletedAt', 'isNull'), 'p')).toEqual({
      sql: '"deletedAt" IS NULL',
      params: {},
    });
    expect(compileScope(where('deletedAt', 'isNotNull'), 'p')).toEqual({
      sql: '"deletedAt" IS NOT NULL',
      params: {},
    });
  });

  it('maps the comparison operators', () => {
    expect(compileScope(where('a', 'ne', 1), 'p')?.sql).toBe('"a" != :p_0');
    expect(compileScope(where('a', 'gt', 1), 'p')?.sql).toBe('"a" > :p_0');
    expect(compileScope(where('a', 'gte', 1), 'p')?.sql).toBe('"a" >= :p_0');
    expect(compileScope(where('a', 'lt', 1), 'p')?.sql).toBe('"a" < :p_0');
    expect(compileScope(where('a', 'lte', 1), 'p')?.sql).toBe('"a" <= :p_0');
    expect(compileScope(where('a', 'nin', [1]), 'p')?.sql).toBe('"a" NOT IN (:...p_0)');
  });

  it('rejects a hostile field name (SQL injection via identifier)', () => {
    expect(() => compileScope(eq('id"; DROP TABLE posts; --', 1), 'p')).toThrow(/Unsafe/);
  });

  it('rejects a hostile alias', () => {
    expect(() => compileScope(eq('id', 1), 'p', 'post"; --')).toThrow(/Unsafe/);
  });

  it('honors an injected dialect escaper (MySQL backtick quoting)', () => {
    // `applyScopeConstraint` passes the DataSource driver's escaper; MySQL/MariaDB quote
    // identifiers with backticks and reject `"..."`. The compiler must use it verbatim.
    const backtick = (id: string) => `\`${id}\``;
    const out = compileScope(eq('authorId', 7), 'p', 'post', backtick);
    expect(out).toEqual({ sql: '`post`.`authorId` = :p_0', params: { p_0: 7 } });

    const noAlias = compileScope(eq('authorId', 7), 'p', undefined, backtick);
    expect(noAlias?.sql).toBe('`authorId` = :p_0');
  });

  it('still validates identifiers even with a custom escaper', () => {
    const backtick = (id: string) => `\`${id}\``;
    expect(() => compileScope(eq('id`; --', 1), 'p', 'post', backtick)).toThrow(/Unsafe/);
  });
});
