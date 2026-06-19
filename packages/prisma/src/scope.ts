import { assertSafeIdentifier } from '@dudousxd/nestjs-authz';
import type {
  ScopeCondition,
  ScopeConstraint,
  ScopeNode,
  ScopeOperator,
} from '@dudousxd/nestjs-authz';
import type { Type } from '@nestjs/common';

/**
 * The minimal scope-resolving surface shared by `Gate` and `BoundGate`. Accepting
 * this (rather than `Gate`) lets the scope helpers take either a Gate (current/context
 * user) or a `gate.forUser(...)` BoundGate without a cast. Mirrors the TypeORM and
 * MikroORM adapters' `ScopeResolver` so all ORMs feel identical.
 */
export interface ScopeResolver {
  scope(entity: Type<unknown>, ability?: string): Promise<ScopeConstraint>;
}

/** A Prisma `where` object (structurally typed; the consumer's generated input is narrower). */
export type PrismaWhere = Record<string, unknown>;

/**
 * An always-false predicate as a Prisma `where`. Prisma treats an EMPTY `OR` array as
 * "match nothing" (an OR over zero alternatives can never be satisfied), which is the
 * documented, portable way to express a deny-all filter — parallel to the core AST's
 * "empty OR is the zero" rule and the TypeORM adapter's `1 = 0`.
 */
const ALWAYS_FALSE: PrismaWhere = { OR: [] };

/** Prisma filter-condition keys for the binary comparison operators. */
const BINARY_OPS: Partial<Record<ScopeOperator, 'gt' | 'gte' | 'lt' | 'lte'>> = {
  gt: 'gt',
  gte: 'gte',
  lt: 'lt',
  lte: 'lte',
};

/**
 * Compile an ORM-neutral {@link ScopeConstraint} into a Prisma `where` object.
 *
 * Terminal/empty semantics (matching the core AST and the TypeORM/MikroORM adapters):
 * - `allow-all` → `{}` (an empty where matches EVERY row);
 * - `deny-all` → `{ OR: [] }` (an empty OR matches NO row);
 * - empty `in` → no rows (`{ OR: [] }`); empty `nin` → all rows (`{}`);
 * - empty `and` group → all rows; empty `or` group → no rows.
 *
 * Operator mapping:
 * - `eq` → `{ field: { equals } }`; `ne` → `{ field: { not } }`;
 * - `gt/gte/lt/lte` → `{ field: { gt/gte/lt/lte } }`;
 * - `in/nin` → `{ field: { in/notIn: [...] } }` (a scalar value is wrapped to a single
 *   element);
 * - `isNull` → `{ field: { equals: null } }`; `isNotNull` → `{ field: { not: null } }`;
 * - `and`/`or` → `{ AND: [...] }` / `{ OR: [...] }`.
 *
 * SAFE: only VALUES come from the (untrusted) policy result and Prisma binds them as
 * parameters. Field names become object keys (a column/relation path), so each is
 * validated against {@link assertSafeIdentifier} — a hostile field throws.
 */
export function compileScope(constraint: ScopeConstraint): PrismaWhere {
  if (constraint.kind === 'all') return {};
  if (constraint.kind === 'none') return { ...ALWAYS_FALSE };

  const compileCondition = (c: ScopeCondition): PrismaWhere => {
    assertSafeIdentifier(c.field, `scope field "${c.field}"`);
    if (c.op === 'eq') return { [c.field]: { equals: c.value } };
    if (c.op === 'ne') return { [c.field]: { not: c.value } };
    if (c.op === 'isNull') return { [c.field]: { equals: null } };
    if (c.op === 'isNotNull') return { [c.field]: { not: null } };
    if (c.op === 'in' || c.op === 'nin') {
      const values = Array.isArray(c.value) ? c.value : [c.value];
      // An empty `in` matches nothing; an empty `nin` matches everything.
      if (values.length === 0) return c.op === 'in' ? { ...ALWAYS_FALSE } : {};
      const key = c.op === 'in' ? 'in' : 'notIn';
      return { [c.field]: { [key]: values } };
    }
    const token = BINARY_OPS[c.op];
    if (!token) throw new Error(`Unsupported scope operator: ${c.op}`);
    return { [c.field]: { [token]: c.value } };
  };

  const compileNode = (node: ScopeNode): PrismaWhere => {
    if (node.kind === 'condition') return compileCondition(node);
    // An empty `and` is the identity (all rows); an empty `or` is the zero (no rows).
    if (node.nodes.length === 0) return node.kind === 'and' ? {} : { ...ALWAYS_FALSE };
    const children = node.nodes.map(compileNode);
    return node.kind === 'and' ? { AND: children } : { OR: children };
  };

  return compileNode(constraint);
}

/**
 * Ergonomic entry point: resolve the query scope for the current (context) user via
 * the {@link Gate} and return the Prisma `where` to pass to `model.findMany`.
 * Equivalent to `compileScope(await gate.scope(entity, ability))`.
 *
 * Mirrors the TypeORM/MikroORM adapters' `applyScope` shape (gate + entity), but returns
 * the `where` instead of mutating a query builder, because Prisma's idiomatic collection
 * fetch is `prisma.post.findMany({ where })`:
 *
 * ```ts
 * const where = await applyScope(gate, Post);          // current user's accessible posts
 * const posts = await prisma.post.findMany({ where });
 * ```
 *
 * Combine with extra criteria via Prisma's own `AND`:
 * `prisma.post.findMany({ where: { AND: [where, { published: true }] } })`.
 */
export async function applyScope(
  gate: ScopeResolver,
  entity: Type<unknown>,
  ability = 'viewAny',
): Promise<PrismaWhere> {
  return compileScope(await gate.scope(entity, ability));
}
