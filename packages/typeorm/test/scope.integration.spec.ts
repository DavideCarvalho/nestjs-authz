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
import { Test } from '@nestjs/testing';
import { Column, type DataSource, Entity, PrimaryGeneratedColumn } from 'typeorm';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { applyScope, applyScopeConstraint } from '../src/scope.js';
import {
  describeIntegration,
  freshSyncDataSource,
  targetDialect,
  uniqueTableName,
} from './support/datasource.js';

/**
 * The scope specs need a real table to query. To stay isolated on a SHARED container
 * (Postgres/MySQL) across `beforeEach` cycles, each test gets a freshly-named `Post`
 * entity (unique table name) that is `synchronize`-created and dropped per test — so
 * seeded rows never accumulate and runs never collide. The entity is built dynamically
 * because the table name must be unique at registration time.
 */
function makePostEntity(): new () => {
  id: number;
  authorId: number;
  published: number;
  title: string;
} {
  const tableName = uniqueTableName('posts');

  class Post {
    id!: number;
    authorId!: number;
    published!: number;
    title!: string;
  }
  Entity({ name: tableName })(Post);
  PrimaryGeneratedColumn()(Post.prototype, 'id');
  Column({ type: 'integer' })(Post.prototype, 'authorId');
  Column({ type: 'integer', default: 0 })(Post.prototype, 'published');
  Column({ type: 'varchar' })(Post.prototype, 'title');
  return Post;
}

interface Author {
  id: number;
  isAdmin?: boolean;
}

async function seed(ds: DataSource, Post: new () => object): Promise<void> {
  const repo = ds.getRepository(Post);
  await repo.save([
    { authorId: 1, published: 0, title: 'a-draft' },
    { authorId: 1, published: 1, title: 'a-pub' },
    { authorId: 2, published: 0, title: 'b-draft' },
    { authorId: 2, published: 1, title: 'b-pub' },
  ]);
}

function buildGate(
  Post: new () => object,
  opts: ConstructorParameters<typeof Gate>[1] = {},
): Promise<Gate> {
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
    const registry = moduleRef.get(PolicyRegistry);
    registry.register(new PostPolicy());
    return moduleRef.get(Gate);
  })();
}

describeIntegration(`TypeORM applyScope (integration, ${targetDialect()})`, () => {
  let ds: DataSource;
  let Post: ReturnType<typeof makePostEntity>;

  beforeEach(async () => {
    Post = makePostEntity();
    ds = await freshSyncDataSource([Post]);
    await seed(ds, Post);
  });

  afterEach(async () => {
    await ds.destroy();
  });

  it('filters a collection to the rows the user may access (own + published)', async () => {
    const gate = await buildGate(Post);
    const qb = ds.getRepository(Post).createQueryBuilder('post');
    await applyScope(qb, gate.forUser({ id: 2 }), Post);

    const rows = await qb.orderBy('post.title').getMany();
    // user 2 → own (b-draft, b-pub) + published (a-pub, b-pub) = a-pub, b-draft, b-pub
    expect(rows.map((r) => r.title)).toEqual(['a-pub', 'b-draft', 'b-pub']);
  });

  it('generated SQL contains a parameterized WHERE (no value interpolation)', async () => {
    const gate = await buildGate(Post);
    const constraint = await gate.forUser({ id: 7 }).scope(Post);
    const qb = ds.getRepository(Post).createQueryBuilder('post');
    applyScopeConstraint(qb, constraint);

    // getQuery() returns the prepared statement (placeholders); the value is bound
    // separately, never interpolated into the prepared SQL.
    const query = qb.getQuery();
    expect(query).toMatch(/WHERE/);
    // Identifier quoting is dialect-correct: backticks on MySQL, double-quotes elsewhere.
    expect(query).toContain(`${ds.driver.escape('post')}.${ds.driver.escape('authorId')}`);
    expect(query).not.toMatch(/=\s*7/);
    // The bound parameters carry the value.
    expect(Object.values(qb.getParameters())).toContain(7);
  });

  it('super-admin → allow-all: no WHERE, all rows returned', async () => {
    const gate = await buildGate(Post, {
      superAdmin: (u: unknown) => (u as Author).isAdmin === true,
    });
    const qb = ds.getRepository(Post).createQueryBuilder('post');
    await applyScope(qb, gate.forUser({ id: 1, isAdmin: true }), Post);

    const [sql] = qb.getQueryAndParameters();
    expect(sql).not.toMatch(/WHERE/);
    expect(await qb.getCount()).toBe(4);
  });

  it('anonymous → deny-all: always-false WHERE, no rows', async () => {
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

    const qb = ds.getRepository(Post).createQueryBuilder('post');
    await applyScope(qb, gate, Post);

    expect(qb.getQuery()).toMatch(/1 = 0/);
    expect(await qb.getCount()).toBe(0);
  });

  it('IN constraint filters by a set and is injection-safe', async () => {
    const qb = ds.getRepository(Post).createQueryBuilder('post');
    applyScopeConstraint(qb, where('authorId', 'in', [1]));
    expect((await qb.getMany()).every((r) => r.authorId === 1)).toBe(true);
  });

  it('a hostile field name in a constraint throws (no injection)', async () => {
    const qb = ds.getRepository(Post).createQueryBuilder('post');
    expect(() => applyScopeConstraint(qb, eq('authorId"; DROP TABLE posts; --', 1))).toThrow(
      /Unsafe/,
    );
    // The table is intact.
    expect(await ds.getRepository(Post).count()).toBe(4);
  });

  it('nested AND/OR compiles and runs', async () => {
    const qb = ds.getRepository(Post).createQueryBuilder('post');
    applyScopeConstraint(qb, and(eq('published', 1), or(eq('authorId', 1), eq('authorId', 2))));
    expect((await qb.getMany()).every((r) => r.published === 1)).toBe(true);
  });
});
