import type {
  ScopeCondition,
  ScopeConstraint,
  ScopeNode,
  ScopeOperator,
} from '@dudousxd/nestjs-authz';
import { type FilterQuery, raw } from '@mikro-orm/core';
import type { Type } from '@nestjs/common';

/**
 * The minimal scope-resolving surface shared by `Gate` and `BoundGate`. Accepting
 * this (rather than `Gate`) lets the scope helpers take either a Gate (current/context
 * user) or a `gate.forUser(...)` BoundGate without a cast. Mirrors the TypeORM
 * adapter's `ScopeResolver` so all ORMs feel identical.
 */
export interface ScopeResolver {
  scope(entity: Type<unknown>, ability?: string): Promise<ScopeConstraint>;
}

/**
 * SQL identifiers (column names) become object KEYS in the emitted `FilterQuery`.
 * MikroORM binds VALUES as parameters, but a field name is interpreted as a property /
 * column path, so a hostile name must never reach the driver. We restrict field names
 * to the same conservative allowlist the TypeORM adapter uses (letters/digits/underscore,
 * not leading-digit) and reject anything else loudly.
 */
const SAFE_IDENTIFIER = /^[A-Za-z_][A-Za-z0-9_]*$/;

function assertSafeIdentifier(value: string, what: string): void {
  if (!SAFE_IDENTIFIER.test(value)) {
    throw new Error(
      `Unsafe ${what}: ${JSON.stringify(value)}. Identifiers must match /^[A-Za-z_][A-Za-z0-9_]*$/ (letters, digits, underscore; not starting with a digit). This blocks injection via configured names.`,
    );
  }
}

/**
 * An always-false predicate as a MikroORM `FilterQuery`. An empty `$and` is the
 * identity (true) and an empty `$or` is silently dropped by the query builder, so
 * neither reliably encodes "no rows". A `raw(...)` fragment used as a filter KEY is the
 * portable, driver-agnostic way to force an always-false `WHERE`: `{ [raw('1')]: 0 }`
 * compiles to `WHERE 1 = 0`. The fragment is rebuilt on each call because `raw(...)`
 * fragments are single-use (each carries a one-off bound placeholder key).
 */
function alwaysFalse<T extends object>(): FilterQuery<T> {
  return { [raw('1')]: 0 } as unknown as FilterQuery<T>;
}

/** MikroORM operator tokens for the binary comparison operators. */
const BINARY_OPS: Partial<Record<ScopeOperator, '$eq' | '$ne' | '$gt' | '$gte' | '$lt' | '$lte'>> =
  {
    eq: '$eq',
    ne: '$ne',
    gt: '$gt',
    gte: '$gte',
    lt: '$lt',
    lte: '$lte',
  };

/**
 * Compile an ORM-neutral {@link ScopeConstraint} into a MikroORM {@link FilterQuery}.
 *
 * Terminal/empty semantics (matching the core AST and the TypeORM adapter):
 * - `allow-all` → `{}` (an empty filter matches EVERY row);
 * - `deny-all` → `{ [raw('1')]: 0 }` (an always-false `WHERE 1 = 0`, matches NO row);
 * - empty `in` → no rows (always-false); empty `nin` → all rows (`{}`);
 * - empty `and` group → all rows; empty `or` group → no rows.
 *
 * Operator mapping:
 * - `eq/ne/gt/gte/lt/lte` → `{ field: { $eq/$ne/$gt/$gte/$lt/$lte: value } }`;
 * - `in/nin` → `{ field: { $in/$nin: [...] } }` (a scalar value is wrapped to a single
 *   element);
 * - `isNull` → `{ field: { $eq: null } }`; `isNotNull` → `{ field: { $ne: null } }`;
 * - `and`/`or` → `{ $and: [...] }` / `{ $or: [...] }`.
 *
 * SAFE: only VALUES come from the (untrusted) policy result and MikroORM binds them as
 * parameters. Field names become object keys (a column/property path), so each is
 * validated against {@link assertSafeIdentifier} — a hostile field throws.
 */
export function compileScope<T extends object = object>(
  constraint: ScopeConstraint,
): FilterQuery<T> {
  if (constraint.kind === 'all') return {} as FilterQuery<T>;
  if (constraint.kind === 'none') return alwaysFalse<T>();

  const compileCondition = (c: ScopeCondition): FilterQuery<T> => {
    assertSafeIdentifier(c.field, `scope field "${c.field}"`);
    if (c.op === 'isNull') return { [c.field]: { $eq: null } } as FilterQuery<T>;
    if (c.op === 'isNotNull') return { [c.field]: { $ne: null } } as FilterQuery<T>;
    if (c.op === 'in' || c.op === 'nin') {
      const values = Array.isArray(c.value) ? c.value : [c.value];
      // An empty `in` matches nothing; an empty `nin` matches everything. Encode both
      // explicitly rather than emitting `{ $in: [] }` (driver-dependent).
      if (values.length === 0) {
        return c.op === 'in' ? alwaysFalse<T>() : ({} as FilterQuery<T>);
      }
      const op = c.op === 'in' ? '$in' : '$nin';
      return { [c.field]: { [op]: values } } as FilterQuery<T>;
    }
    const token = BINARY_OPS[c.op];
    if (!token) throw new Error(`Unsupported scope operator: ${c.op}`);
    return { [c.field]: { [token]: c.value } } as FilterQuery<T>;
  };

  const compileNode = (node: ScopeNode): FilterQuery<T> => {
    if (node.kind === 'condition') return compileCondition(node);
    // An empty `and` is the identity (all rows); an empty `or` is the zero (no rows).
    if (node.nodes.length === 0) {
      return node.kind === 'and' ? ({} as FilterQuery<T>) : alwaysFalse<T>();
    }
    const children = node.nodes.map(compileNode);
    const key = node.kind === 'and' ? '$and' : '$or';
    return { [key]: children } as FilterQuery<T>;
  };

  return compileNode(constraint);
}

/**
 * Ergonomic entry point: resolve the query scope for the current (context) user via
 * the {@link Gate} and return the {@link FilterQuery} to pass to `em.find` / a query
 * builder. Equivalent to `compileScope(await gate.scope(entity, ability))`.
 *
 * Mirrors the TypeORM adapter's `applyScope` shape (gate + entity), but returns the
 * filter instead of mutating a query builder, because MikroORM's idiomatic collection
 * fetch is `em.find(Entity, where)`:
 *
 * ```ts
 * const where = await applyScope(gate, Post);          // current user's accessible posts
 * const posts = await em.find(Post, where);
 * ```
 *
 * Combine with extra criteria via MikroORM's own `$and`:
 * `em.find(Post, { $and: [where, { published: 1 }] })`.
 */
export async function applyScope<T extends object = object>(
  gate: ScopeResolver,
  entity: Type<unknown>,
  ability = 'viewAny',
): Promise<FilterQuery<T>> {
  return compileScope<T>(await gate.scope(entity, ability));
}
