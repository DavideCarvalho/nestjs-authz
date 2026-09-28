import 'reflect-metadata';
import {
  CONTEXT_ACCESSOR,
  Gate,
  Policy,
  PolicyRegistry,
  type ScopeConstraint,
  and as scopeAnd,
  eq as scopeEq,
  or as scopeOr,
  where,
} from '@dudousxd/nestjs-authz';
import { Test } from '@nestjs/testing';
import { and, asc, eq } from 'drizzle-orm';
import { integer, pgTable, serial, text } from 'drizzle-orm/pg-core';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { applyScope, compileScope } from '../src/scope.js';
import {
  type TestDb,
  describeIntegration,
  openDb,
  targetDialect,
  uniquePrefix,
} from './support/db.js';

/** A uniquely-named `posts` table per test, so a shared Postgres never sees stale rows. */
function makePosts() {
  return pgTable(`${uniquePrefix()}_posts`, {
    id: serial('id').primaryKey(),
    authorId: integer('author_id').notNull(),
    published: integer('published').notNull().default(0),
    title: text('title').notNull(),
  });
}
type Posts = ReturnType<typeof makePosts>;

class Post {}

interface Author {
  id: number;
  isAdmin?: boolean;
}

async function buildGate(opts: ConstructorParameters<typeof Gate>[1] = {}): Promise<Gate> {
  @Policy(Post)
  class PostPolicy {
    // A user sees their OWN posts, or any PUBLISHED post.
    scope(user: Author): ScopeConstraint {
      return scopeOr(scopeEq('authorId', user.id), scopeEq('published', 1));
    }
  }
  const moduleRef = await Test.createTestingModule({
    providers: [
      PolicyRegistry,
      {
        provide: Gate,
        useFactory: (r: PolicyRegistry) => new Gate(r, opts),
        inject: [PolicyRegistry],
      },
    ],
  }).compile();
  moduleRef.get(PolicyRegistry).register(new PostPolicy());
  return moduleRef.get(Gate);
}

describeIntegration(`Drizzle applyScope (integration, ${targetDialect()})`, () => {
  let t: TestDb;
  let posts: Posts;

  beforeEach(async () => {
    t = await openDb();
    posts = makePosts();
    const name = (posts as unknown as { [k: symbol]: string })[Symbol.for('drizzle:Name')];
    await t.query(
      `CREATE TABLE "${name}" (id serial primary key, author_id integer not null, published integer not null default 0, title text not null)`,
    );
    await t.db.insert(posts).values([
      { authorId: 1, published: 0, title: 'a-draft' },
      { authorId: 1, published: 1, title: 'a-pub' },
      { authorId: 2, published: 0, title: 'b-draft' },
      { authorId: 2, published: 1, title: 'b-pub' },
    ]);
  });

  afterEach(async () => {
    await t.close();
  });

  const titles = async (where: ReturnType<typeof compileScope>) =>
    (await t.db.select().from(posts).where(where).orderBy(asc(posts.title))).map((r) => r.title);

  it('filters a collection to the rows the user may access (own + published)', async () => {
    const gate = await buildGate();
    const scope = await applyScope(gate.forUser({ id: 2 }), Post, posts);
    expect(await titles(scope)).toEqual(['a-pub', 'b-draft', 'b-pub']);
  });

  it('composes with extra criteria via and()', async () => {
    const gate = await buildGate();
    const scope = await applyScope(gate.forUser({ id: 2 }), Post, posts);
    expect(await titles(and(scope, eq(posts.published, 0)))).toEqual(['b-draft']);
  });

  it('super-admin → allow-all: no predicate, all rows returned', async () => {
    const gate = await buildGate({ superAdmin: (u: unknown) => (u as Author).isAdmin === true });
    const scope = await applyScope(gate.forUser({ id: 1, isAdmin: true }), Post, posts);
    expect(scope).toBeUndefined();
    expect(await titles(scope)).toHaveLength(4);
  });

  it('anonymous → deny-all: always-false predicate, no rows', async () => {
    const accessor = {
      traceId: () => undefined,
      tenantId: () => undefined,
      userRef: () => undefined,
      get: () => undefined,
    };
    @Policy(Post)
    class PostPolicy {
      scope(user: Author): ScopeConstraint {
        return scopeEq('authorId', user.id);
      }
    }
    const moduleRef = await Test.createTestingModule({
      providers: [
        PolicyRegistry,
        {
          provide: Gate,
          useFactory: (r: PolicyRegistry) => new Gate(r, {}, accessor),
          inject: [PolicyRegistry],
        },
        { provide: CONTEXT_ACCESSOR, useValue: accessor },
      ],
    }).compile();
    moduleRef.get(PolicyRegistry).register(new PostPolicy());
    const scope = await applyScope(moduleRef.get(Gate), Post, posts);
    expect(await titles(scope)).toEqual([]);
  });

  it('IN / NOT IN and nested AND/OR run against real Postgres', async () => {
    expect(await titles(compileScope(where('authorId', 'in', [1]), posts))).toEqual([
      'a-draft',
      'a-pub',
    ]);
    expect(await titles(compileScope(where('authorId', 'nin', [1]), posts))).toEqual([
      'b-draft',
      'b-pub',
    ]);
    expect(await titles(compileScope(where('authorId', 'in', []), posts))).toEqual([]);
    expect(
      await titles(
        compileScope(
          scopeAnd(
            scopeEq('published', 1),
            scopeOr(scopeEq('authorId', 1), scopeEq('authorId', 2)),
          ),
          posts,
        ),
      ),
    ).toEqual(['a-pub', 'b-pub']);
  });

  it('a hostile field name throws and the table is intact', async () => {
    expect(() => compileScope(scopeEq('authorId"; DROP TABLE posts; --', 1), posts)).toThrow(
      /Unknown scope field/,
    );
    expect(await titles(undefined)).toHaveLength(4);
  });
});
