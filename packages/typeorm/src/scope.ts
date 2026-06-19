import type {
  ScopeCondition,
  ScopeConstraint,
  ScopeNode,
  ScopeOperator,
} from '@dudousxd/nestjs-authz';
import type { Type } from '@nestjs/common';
import type { ObjectLiteral, SelectQueryBuilder } from 'typeorm';
import { assertSafeIdentifier } from './sql.js';

/**
 * The minimal scope-resolving surface shared by `Gate` and `BoundGate`. Accepting
 * this (rather than `Gate`) lets {@link applyScope} take either a Gate (current/context
 * user) or a `gate.forUser(...)` BoundGate without a cast.
 */
export interface ScopeResolver {
  scope(entity: Type<unknown>, ability?: string): Promise<ScopeConstraint>;
}

/**
 * A compiled scope predicate: a SQL fragment using TypeORM named placeholders
 * (`:name`, `:...name` for `IN`) plus the parameter map to bind. TypeORM binds the
 * values itself (dialect-correct), so we never interpolate values — only identifiers,
 * which are validated by {@link assertSafeIdentifier}.
 */
export interface CompiledScope {
  sql: string;
  params: ObjectLiteral;
}

/** An always-false predicate (deny-all / empty `IN`). Binds no parameters. */
const ALWAYS_FALSE: CompiledScope = { sql: '1 = 0', params: {} };

/**
 * Quote a SQL identifier. Defaults to ANSI double-quotes (Postgres / SQLite), but a
 * dialect-correct escaper can be injected — MySQL/MariaDB quote with backticks and
 * REJECT `"..."` as an identifier, so `applyScopeConstraint` passes the DataSource's
 * `driver.escape` to make the compiled predicate portable across engines.
 */
export type EscapeIdentifier = (identifier: string) => string;
const ansiQuote: EscapeIdentifier = (id) => `"${id}"`;

/** TypeORM/SQL operator tokens for the binary comparison operators. */
const BINARY_OPS: Partial<Record<ScopeOperator, string>> = {
  eq: '=',
  ne: '!=',
  gt: '>',
  gte: '>=',
  lt: '<',
  lte: '<=',
};

/**
 * Compile an ORM-neutral {@link ScopeConstraint} into a parameterized SQL predicate
 * for TypeORM. Returns:
 * - `undefined` for `allow-all` — the caller adds NO `WHERE` (every row is visible);
 * - `{ sql: '1 = 0', params: {} }` for `deny-all` — an always-false predicate;
 * - otherwise the compiled condition tree.
 *
 * `paramPrefix` namespaces the generated placeholders so multiple `applyScope` calls
 * (or other `andWhere`s) on one query never collide. `alias` (the entity's query
 * alias) prefixes every column as `"alias"."field"`; omit it to emit bare `"field"`.
 *
 * SAFE: column names and the alias are interpolated into SQL, so each is validated
 * against the package's `assertSafeIdentifier` allowlist (letters/digits/underscore,
 * not leading-digit) — a hostile field/alias throws. Values are NEVER interpolated;
 * they are returned in `params` for TypeORM to bind.
 *
 * `escapeId` controls identifier quoting; it defaults to ANSI double-quotes (Postgres /
 * SQLite). `applyScopeConstraint` injects the DataSource's `driver.escape` so the
 * predicate is also valid on MySQL/MariaDB (backtick-quoted), which rejects `"..."`.
 */
export function compileScope(
  constraint: ScopeConstraint,
  paramPrefix: string,
  alias?: string,
  escapeId: EscapeIdentifier = ansiQuote,
): CompiledScope | undefined {
  if (constraint.kind === 'all') return undefined;
  if (constraint.kind === 'none') return ALWAYS_FALSE;
  if (alias !== undefined) assertSafeIdentifier(alias, `scope alias "${alias}"`);

  const params: ObjectLiteral = {};
  let counter = 0;
  const nextParam = (): string => `${paramPrefix}_${counter++}`;

  const column = (field: string): string => {
    assertSafeIdentifier(field, `scope field "${field}"`);
    return alias === undefined ? escapeId(field) : `${escapeId(alias)}.${escapeId(field)}`;
  };

  const compileCondition = (c: ScopeCondition): string => {
    const col = column(c.field);
    if (c.op === 'isNull') return `${col} IS NULL`;
    if (c.op === 'isNotNull') return `${col} IS NOT NULL`;
    if (c.op === 'in' || c.op === 'nin') {
      const values = Array.isArray(c.value) ? c.value : [c.value];
      // An empty `IN ()` is invalid SQL and matches nothing; an empty `NOT IN ()`
      // matches everything. Encode both with constant predicates.
      if (values.length === 0) return c.op === 'in' ? '1 = 0' : '1 = 1';
      const name = nextParam();
      params[name] = values;
      const not = c.op === 'nin' ? 'NOT ' : '';
      return `${col} ${not}IN (:...${name})`;
    }
    const token = BINARY_OPS[c.op];
    if (!token) throw new Error(`Unsupported scope operator: ${c.op}`);
    const name = nextParam();
    params[name] = c.value;
    return `${col} ${token} :${name}`;
  };

  const compileNode = (node: ScopeNode): string => {
    if (node.kind === 'condition') return compileCondition(node);
    const joiner = node.kind === 'and' ? ' AND ' : ' OR ';
    // An empty AND is the identity (true); an empty OR is the zero (false).
    if (node.nodes.length === 0) return node.kind === 'and' ? '1 = 1' : '1 = 0';
    return `(${node.nodes.map(compileNode).join(joiner)})`;
  };

  const sql = compileNode(constraint);
  // A top-level empty `IN` collapses to the always-false constant with no params.
  if (sql === '1 = 0' && Object.keys(params).length === 0) return ALWAYS_FALSE;
  return { sql, params };
}

let scopeApplyCounter = 0;

/**
 * Apply a {@link ScopeConstraint} to a TypeORM {@link SelectQueryBuilder} as an
 * `andWhere`, parameterized and identifier-safe. `allow-all` adds nothing; `deny-all`
 * adds an always-false predicate so the query returns no rows.
 *
 * The query's primary alias is used to qualify columns (so the predicate is correct
 * across joins). Each call uses a fresh parameter prefix, so repeated calls never
 * clash. Returns the same builder for chaining.
 */
export function applyScopeConstraint<T extends ObjectLiteral>(
  qb: SelectQueryBuilder<T>,
  constraint: ScopeConstraint,
): SelectQueryBuilder<T> {
  const prefix = `authz_scope_${scopeApplyCounter++}`;
  // Quote identifiers with the DataSource's own dialect-correct escaper so the predicate
  // is valid on MySQL/MariaDB (backticks) as well as Postgres/SQLite (double-quotes).
  const escapeId: EscapeIdentifier = (id) => qb.connection.driver.escape(id);
  const compiled = compileScope(constraint, prefix, qb.alias, escapeId);
  if (compiled) qb.andWhere(compiled.sql, compiled.params);
  return qb;
}

/**
 * Ergonomic entry point: resolve the query scope for the current (context) user via
 * the {@link Gate} and apply it to `qb` in one call. Equivalent to
 * `applyScopeConstraint(qb, await gate.scope(entity, ability))`.
 *
 * The manual path (`gate.scope(...)` + `applyScopeConstraint(...)`) remains primary;
 * this just folds the two steps together for the common list-endpoint case.
 *
 * ```ts
 * const qb = repo.createQueryBuilder('post');
 * await applyScope(qb, gate, Post);          // current user's accessible posts
 * const posts = await qb.getMany();
 * ```
 */
export async function applyScope<T extends ObjectLiteral>(
  qb: SelectQueryBuilder<T>,
  gate: ScopeResolver,
  entity: Type<unknown>,
  ability = 'viewAny',
): Promise<SelectQueryBuilder<T>> {
  return applyScopeConstraint(qb, await gate.scope(entity, ability));
}
