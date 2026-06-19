import 'reflect-metadata';
import {
  CONTEXT_ACCESSOR,
  Gate,
  Policy,
  PolicyRegistry,
  type ScopeConstraint,
  and,
  eq,
  or,
  where,
} from '@dudousxd/nestjs-authz';
import {
  Entity,
  type EntityManager,
  MikroORM,
  PrimaryKey,
  Property,
} from '@mikro-orm/better-sqlite';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { applyScope, compileScope } from '../src/scope.js';

/** A plain domain entity to scope a collection over (not part of the RBAC schema). */
@Entity({ tableName: 'posts' })
class Post {
  @PrimaryKey({ type: 'number', autoincrement: true })
  id!: number;

  @Property({ type: 'number' })
  authorId!: number;

  @Property({ type: 'number' })
  published!: number;

  @Property({ type: 'string' })
  title!: string;
}

interface Author {
  id: number;
  isAdmin?: boolean;
}

async function seed(em: EntityManager): Promise<void> {
  const rows = [
    { authorId: 1, published: 0, title: 'a-draft' },
    { authorId: 1, published: 1, title: 'a-pub' },
    { authorId: 2, published: 0, title: 'b-draft' },
    { authorId: 2, published: 1, title: 'b-pub' },
  ];
  for (const r of rows) em.create(Post, r);
  await em.flush();
}

function buildGate(opts: ConstructorParameters<typeof Gate>[1] = {}): Promise<Gate> {
  return (async () => {
    @Policy(Post)
    class PostPolicy {
      // A user sees their OWN posts, or any PUBLISHED post.
      scope(user: Author): ScopeConstraint {
        return or(eq('authorId', user.id), eq('published', 1));
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
  })();
}

describe('MikroORM applyScope (integration, sqlite)', () => {
  let orm: MikroORM;
  let em: EntityManager;

  beforeEach(async () => {
    orm = await MikroORM.init({
      dbName: ':memory:',
      entities: [Post],
      allowGlobalContext: true,
    });
    await orm.getSchemaGenerator().createSchema();
    em = orm.em.fork();
    await seed(em);
  });

  afterEach(async () => {
    await orm.close(true);
  });

  it('filters a collection to the rows the user may access (own + published)', async () => {
    const gate = await buildGate();
    const filter = await applyScope<Post>(gate.forUser({ id: 2 }), Post);
    const rows = await em.fork().find(Post, filter, { orderBy: { title: 'asc' } });
    // user 2 → own (b-draft, b-pub) + published (a-pub, b-pub) = a-pub, b-draft, b-pub
    expect(rows.map((r) => r.title)).toEqual(['a-pub', 'b-draft', 'b-pub']);
  });

  it('super-admin → allow-all: empty filter, all rows returned', async () => {
    const gate = await buildGate({ superAdmin: (u: unknown) => (u as Author).isAdmin === true });
    const filter = await applyScope<Post>(gate.forUser({ id: 1, isAdmin: true }), Post);
    expect(filter).toEqual({});
    expect(await em.fork().count(Post, filter)).toBe(4);
  });

  it('anonymous → deny-all: always-false filter, no rows', async () => {
    const accessor = {
      traceId: () => undefined,
      tenantId: () => undefined,
      userRef: () => undefined,
      get: () => undefined,
    };
    @Policy(Post)
    class PostPolicy {
      scope(user: Author): ScopeConstraint {
        return or(eq('authorId', user.id), eq('published', 1));
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
    const gate = moduleRef.get(Gate);

    const filter = await applyScope<Post>(gate, Post);
    expect(await em.fork().count(Post, filter)).toBe(0);
  });

  it('IN constraint filters by a set', async () => {
    const rows = await em.fork().find(Post, compileScope<Post>(where('authorId', 'in', [1])));
    expect(rows.every((r) => r.authorId === 1)).toBe(true);
    expect(rows).toHaveLength(2);
  });

  it('an empty IN returns no rows', async () => {
    const rows = await em.fork().find(Post, compileScope<Post>(where('authorId', 'in', [])));
    expect(rows).toHaveLength(0);
  });

  it('nested AND/OR compiles and runs', async () => {
    const filter = compileScope<Post>(
      and(eq('published', 1), or(eq('authorId', 1), eq('authorId', 2))),
    );
    const rows = await em.fork().find(Post, filter);
    expect(rows.every((r) => r.published === 1)).toBe(true);
    expect(rows).toHaveLength(2);
  });

  it('a hostile field name in a constraint throws (no injection)', async () => {
    expect(() => compileScope<Post>(eq('authorId"; DROP TABLE posts; --', 1))).toThrow(/Unsafe/);
    // The table is intact.
    expect(await em.fork().count(Post, {})).toBe(4);
  });
});
