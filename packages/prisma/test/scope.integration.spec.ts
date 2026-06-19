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
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { type PrismaWhere, applyScope, compileScope } from '../src/scope.js';

/**
 * Prisma's RBAC adapter deliberately avoids a `prisma generate` step, so there is no
 * generated client to spin up an in-memory SQLite Prisma instance from. Instead we run
 * the COMPILED `where` through a faithful evaluator that implements Prisma's documented
 * `where` semantics (`equals/not/gt/gte/lt/lte/in/notIn/AND/OR`, null handling, and the
 * "empty OR matches nothing" rule). This proves the compiled object actually filters a
 * collection exactly as Prisma's query engine would — the equivalent of the other ORMs'
 * real-DB scope tests. (The store's own behavior against a real DB is covered elsewhere.)
 */
type Row = Record<string, unknown>;

function evalCondition(value: unknown, cond: Record<string, unknown>): boolean {
  return Object.entries(cond).every(([op, operand]) => {
    switch (op) {
      case 'equals':
        return value === operand;
      case 'not':
        return value !== operand;
      case 'gt':
        return (value as number) > (operand as number);
      case 'gte':
        return (value as number) >= (operand as number);
      case 'lt':
        return (value as number) < (operand as number);
      case 'lte':
        return (value as number) <= (operand as number);
      case 'in':
        return (operand as unknown[]).includes(value);
      case 'notIn':
        return !(operand as unknown[]).includes(value);
      default:
        throw new Error(`unknown condition op: ${op}`);
    }
  });
}

function matches(row: Row, where: PrismaWhere): boolean {
  return Object.entries(where).every(([key, val]) => {
    if (key === 'AND') return (val as PrismaWhere[]).every((w) => matches(row, w));
    // Prisma: an empty OR array matches nothing; otherwise any alternative.
    if (key === 'OR') return (val as PrismaWhere[]).some((w) => matches(row, w));
    if (val && typeof val === 'object')
      return evalCondition(row[key], val as Record<string, unknown>);
    return row[key] === val;
  });
}

function findMany(rows: Row[], where: PrismaWhere): Row[] {
  return rows.filter((r) => matches(r, where));
}

interface Author {
  id: number;
  isAdmin?: boolean;
}

class Post {}

const POSTS: Row[] = [
  { id: 1, authorId: 1, published: 0, title: 'a-draft' },
  { id: 2, authorId: 1, published: 1, title: 'a-pub' },
  { id: 3, authorId: 2, published: 0, title: 'b-draft' },
  { id: 4, authorId: 2, published: 1, title: 'b-pub' },
];

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

describe('Prisma applyScope (integration, in-memory where-evaluator)', () => {
  let gate: Gate;

  beforeEach(async () => {
    gate = await buildGate();
  });

  afterEach(() => {});

  it('filters a collection to the rows the user may access (own + published)', async () => {
    const w = await applyScope(gate.forUser({ id: 2 }), Post);
    const rows = findMany(POSTS, w).sort((a, b) =>
      (a.title as string).localeCompare(b.title as string),
    );
    // user 2 → own (b-draft, b-pub) + published (a-pub, b-pub) = a-pub, b-draft, b-pub
    expect(rows.map((r) => r.title)).toEqual(['a-pub', 'b-draft', 'b-pub']);
  });

  it('super-admin → allow-all: empty where, all rows returned', async () => {
    const adminGate = await buildGate({
      superAdmin: (u: unknown) => (u as Author).isAdmin === true,
    });
    const w = await applyScope(adminGate.forUser({ id: 1, isAdmin: true }), Post);
    expect(w).toEqual({});
    expect(findMany(POSTS, w)).toHaveLength(4);
  });

  it('anonymous → deny-all: impossible where, no rows', async () => {
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
    const anonGate = moduleRef.get(Gate);

    const w = await applyScope(anonGate, Post);
    expect(w).toEqual({ OR: [] });
    expect(findMany(POSTS, w)).toHaveLength(0);
  });

  it('IN constraint filters by a set', () => {
    const rows = findMany(POSTS, compileScope(where('authorId', 'in', [1])));
    expect(rows.every((r) => r.authorId === 1)).toBe(true);
    expect(rows).toHaveLength(2);
  });

  it('an empty IN returns no rows', () => {
    expect(findMany(POSTS, compileScope(where('authorId', 'in', [])))).toHaveLength(0);
  });

  it('nested AND/OR compiles and runs', () => {
    const w = compileScope(and(eq('published', 1), or(eq('authorId', 1), eq('authorId', 2))));
    const rows = findMany(POSTS, w);
    expect(rows.every((r) => r.published === 1)).toBe(true);
    expect(rows).toHaveLength(2);
  });

  it('a hostile field name in a constraint throws (no injection)', () => {
    expect(() => compileScope(eq('authorId"; DROP TABLE posts; --', 1))).toThrow(/Unsafe/);
  });
});
