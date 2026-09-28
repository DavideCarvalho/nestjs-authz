import 'reflect-metadata';
import { and, eq, or, scopeAll, scopeNone, where } from '@dudousxd/nestjs-authz';
import type { SQL } from 'drizzle-orm';
import { PgDialect, boolean, integer, pgTable, text, timestamp } from 'drizzle-orm/pg-core';
import { describe, expect, it } from 'vitest';
import { compileScope } from '../src/scope.js';

const posts = pgTable('posts', {
  id: integer('id').primaryKey(),
  authorId: integer('author_id').notNull(),
  published: boolean('published').notNull(),
  title: text('title').notNull(),
  deletedAt: timestamp('deleted_at', { mode: 'date' }),
});

const dialect = new PgDialect();
const render = (s: SQL | undefined) => {
  if (!s) return undefined;
  const { sql, params } = dialect.sqlToQuery(s);
  return { sql, params };
};

describe('compileScope — constraint AST → Drizzle SQL', () => {
  it('allow-all → no predicate (undefined)', () => {
    expect(compileScope(scopeAll, posts)).toBeUndefined();
  });

  it('deny-all → an always-false predicate, no params', () => {
    expect(render(compileScope(scopeNone, posts))).toEqual({ sql: '1 = 0', params: [] });
  });

  it('a single equality binds the value (resolved by property key)', () => {
    expect(render(compileScope(eq('authorId', 7), posts))).toEqual({
      sql: '"posts"."author_id" = $1',
      params: [7],
    });
  });

  it('also resolves a field by its physical column name', () => {
    expect(render(compileScope(eq('author_id', 7), posts))?.sql).toBe('"posts"."author_id" = $1');
  });

  it('AND / OR groups and nesting', () => {
    const out = render(
      compileScope(and(eq('authorId', 9), or(eq('published', true), eq('id', 1))), posts),
    );
    expect(out?.sql).toBe(
      '("posts"."author_id" = $1 and ("posts"."published" = $2 or "posts"."id" = $3))',
    );
    expect(out?.params).toEqual([9, true, 1]);
  });

  it('comparison operators', () => {
    const out = render(
      compileScope(
        and(
          where('id', 'gt', 1),
          where('id', 'gte', 2),
          where('id', 'lt', 3),
          where('id', 'lte', 4),
          where('id', 'ne', 5),
        ),
        posts,
      ),
    );
    expect(out?.sql).toBe(
      '("posts"."id" > $1 and "posts"."id" >= $2 and "posts"."id" < $3 and "posts"."id" <= $4 and "posts"."id" <> $5)',
    );
  });

  it('IN / NOT IN bind each value; a scalar is wrapped', () => {
    expect(render(compileScope(where('id', 'in', [1, 2]), posts))).toEqual({
      sql: '"posts"."id" in ($1, $2)',
      params: [1, 2],
    });
    expect(render(compileScope(where('id', 'nin', 3), posts))).toEqual({
      sql: '"posts"."id" not in ($1)',
      params: [3],
    });
  });

  it('empty IN → always-false, empty NOT IN → always-true', () => {
    expect(render(compileScope(where('id', 'in', []), posts))?.sql).toBe('1 = 0');
    expect(render(compileScope(where('id', 'nin', []), posts))?.sql).toBe('1 = 1');
  });

  it('empty AND → always-true, empty OR → always-false', () => {
    expect(render(compileScope({ kind: 'and', nodes: [] }, posts))?.sql).toBe('1 = 1');
    expect(render(compileScope({ kind: 'or', nodes: [] }, posts))?.sql).toBe('1 = 0');
  });

  it('isNull / isNotNull bind no parameter', () => {
    expect(render(compileScope(where('deletedAt', 'isNull'), posts))).toEqual({
      sql: '"posts"."deleted_at" is null',
      params: [],
    });
    expect(render(compileScope(where('deletedAt', 'isNotNull'), posts))?.sql).toBe(
      '"posts"."deleted_at" is not null',
    );
  });

  it('values are mapped through the column (Date → ISO string for timestamp)', () => {
    const at = new Date('2026-01-02T03:04:05.000Z');
    const out = render(compileScope(where('deletedAt', 'lt', at), posts));
    expect(out?.params).toEqual(['2026-01-02T03:04:05.000Z']);
  });

  it('an explicit column map is an allowlist', () => {
    const cols = { owner: posts.authorId };
    expect(render(compileScope(eq('owner', 1), cols))?.sql).toBe('"posts"."author_id" = $1');
    expect(() => compileScope(eq('title', 'x'), cols)).toThrow(/Unknown scope field "title"/);
  });

  it('an unknown / hostile field throws instead of reaching SQL', () => {
    expect(() => compileScope(eq('authorId"; DROP TABLE posts; --', 1), posts)).toThrow(
      /Unknown scope field/,
    );
    // Prototype keys are not columns.
    expect(() => compileScope(eq('constructor', 1), posts)).toThrow(/Unknown scope field/);
  });

  it('an unsupported operator throws', () => {
    expect(() =>
      compileScope({ kind: 'condition', field: 'id', op: 'like' as never, value: 1 }, posts),
    ).toThrow(/Unsupported scope operator/);
  });
});
