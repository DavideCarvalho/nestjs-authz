import type { ScopeCondition, ScopeConstraint, ScopeNode } from '@dudousxd/nestjs-authz';
import type { Type } from '@nestjs/common';
import {
  type Column,
  type SQL,
  Table,
  and,
  eq,
  getTableColumns,
  gt,
  gte,
  inArray,
  is,
  isNotNull,
  isNull,
  lt,
  lte,
  ne,
  notInArray,
  or,
  sql,
} from 'drizzle-orm';

/**
 * The minimal scope-resolving surface shared by `Gate` and `BoundGate`. Accepting this (rather
 * than `Gate`) lets {@link applyScope} take either a Gate (current/context user) or a
 * `gate.forUser(...)` BoundGate without a cast. Mirrors the TypeORM/MikroORM/Prisma adapters.
 */
export interface ScopeResolver {
  scope(entity: Type<unknown>, ability?: string): Promise<ScopeConstraint>;
}

/**
 * Where scope `field`s resolve: a Drizzle table (fields are its property keys, e.g. `authorId`,
 * falling back to the DB column name, e.g. `author_id`), or an explicit field → column map.
 * An explicit map is an allowlist: a policy can never reach a column you did not list, and it
 * lets a scope reference columns of a JOINed table.
 */
export type ScopeColumns = Table | Record<string, Column>;

/** Always-true / always-false predicates (portable across Postgres/MySQL/SQLite). */
const ALWAYS_TRUE = () => sql`1 = 1`;
const ALWAYS_FALSE = () => sql`1 = 0`;

function columnMap(columns: ScopeColumns): Record<string, Column> {
  return is(columns, Table) ? (getTableColumns(columns) as Record<string, Column>) : columns;
}

function resolveColumn(map: Record<string, Column>, field: string): Column {
  if (Object.hasOwn(map, field)) return map[field] as Column;
  // Fall back to the physical column name (`author_id` for a property `authorId`).
  for (const column of Object.values(map)) {
    if (column.name === field) return column;
  }
  throw new Error(
    `Unknown scope field "${field}": it is not a column of the scoped table / column map.`,
  );
}

/**
 * Compile an ORM-neutral {@link ScopeConstraint} (`gate.scope(Entity)`) into a Drizzle `WHERE`.
 *
 * Returns:
 * - `undefined` for `allow-all` — pass it straight to `.where(...)` / `and(...)`, which both
 *   ignore `undefined`, so NO predicate is added (every row is visible);
 * - `1 = 0` for `deny-all` — an always-false predicate;
 * - otherwise the compiled condition tree.
 *
 * Empty semantics match the core AST and the sibling adapters: empty `in` → no rows, empty `nin`
 * → all rows, empty `and` → all rows, empty `or` → no rows.
 *
 * SAFE: fields are resolved against the table's columns (or your explicit map) — an unknown field
 * throws instead of reaching SQL — and values go through Drizzle's operators, so they are always
 * bound parameters (and mapped by the column's driver mapping, e.g. `Date` → timestamp).
 */
export function compileScope(constraint: ScopeConstraint, columns: ScopeColumns): SQL | undefined {
  if (constraint.kind === 'all') return undefined;
  if (constraint.kind === 'none') return ALWAYS_FALSE();
  const map = columnMap(columns);

  const compileCondition = (c: ScopeCondition): SQL => {
    const column = resolveColumn(map, c.field);
    const v = c.value;
    switch (c.op) {
      case 'eq':
        return eq(column, v);
      case 'ne':
        return ne(column, v);
      case 'gt':
        return gt(column, v);
      case 'gte':
        return gte(column, v);
      case 'lt':
        return lt(column, v);
      case 'lte':
        return lte(column, v);
      case 'in':
      case 'nin': {
        const values = Array.isArray(v) ? v : [v];
        // An empty `IN ()` is invalid SQL and matches nothing; an empty `NOT IN ()` matches all.
        if (values.length === 0) return c.op === 'in' ? ALWAYS_FALSE() : ALWAYS_TRUE();
        return c.op === 'in' ? inArray(column, values) : notInArray(column, values);
      }
      case 'isNull':
        return isNull(column);
      case 'isNotNull':
        return isNotNull(column);
      default:
        throw new Error(`Unsupported scope operator: ${String(c.op)}`);
    }
  };

  const compileNode = (node: ScopeNode): SQL => {
    if (node.kind === 'condition') return compileCondition(node);
    // An empty AND is the identity (true); an empty OR is the zero (false).
    if (node.nodes.length === 0) return node.kind === 'and' ? ALWAYS_TRUE() : ALWAYS_FALSE();
    const children = node.nodes.map(compileNode);
    return (node.kind === 'and' ? and(...children) : or(...children)) as SQL;
  };

  return compileNode(constraint);
}

/**
 * Ergonomic entry point: resolve the query scope for the current (context) user via the Gate and
 * compile it against `columns`. Equivalent to `compileScope(await gate.scope(entity, ability), columns)`.
 *
 * ```ts
 * const scope = await applyScope(gate, Post, posts);          // posts = your pgTable
 * const rows = await db.select().from(posts).where(and(scope, eq(posts.published, true)));
 * ```
 */
export async function applyScope(
  gate: ScopeResolver,
  entity: Type<unknown>,
  columns: ScopeColumns,
  ability = 'viewAny',
): Promise<SQL | undefined> {
  return compileScope(await gate.scope(entity, ability), columns);
}
