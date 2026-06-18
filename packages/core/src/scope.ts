import type { Resource, User } from './types.js';

/**
 * ORM-neutral query-scope constraint (the `accessibleBy` / Pundit `policy_scope` /
 * Cerbos `PlanResources` concept). Where a policy METHOD decides yes/no for a SINGLE
 * resource, a policy SCOPE produces a constraint that filters a COLLECTION to the rows
 * the user may access — applied at the DB layer instead of over-fetch-then-filter.
 *
 * The representation is a small, pure-data condition AST (no callbacks, fully
 * serializable) so every ORM adapter can walk it and emit a parameterized,
 * identifier-safe `WHERE`. Compare:
 *
 * - **CASL `accessibleBy`** — turns ability rules into an ORM `where` object.
 * - **Pundit `policy_scope`** — a Scope class returning a narrowed relation.
 * - **Cerbos Query Plan (`PlanResources`)** — returns `ALWAYS_ALLOWED` /
 *   `ALWAYS_DENIED` / a condition AST of operands. This AST mirrors that shape.
 *
 * Two terminal verdicts bracket the AST and keep it aligned with the Gate's
 * deny-by-default + super-admin/before-grant semantics:
 *
 * - {@link ScopeAll} (`allow-all`) — the user sees every row (super-admin, a
 *   `before` grant, or a permission-provider grant). No `WHERE` is added.
 * - {@link ScopeNone} (`deny-all`) — the user sees no rows (anonymous, or a policy
 *   with no `scope`/`viewAny`). The adapter emits an always-false predicate.
 */
export type ScopeConstraint = ScopeAll | ScopeNone | ScopeNode;

/** Terminal: the user may access every row — no filter is applied. */
export interface ScopeAll {
  kind: 'all';
}

/** Terminal: the user may access no rows — an always-false predicate is applied. */
export interface ScopeNone {
  kind: 'none';
}

/** A non-terminal constraint: a single condition or a boolean group of them. */
export type ScopeNode = ScopeCondition | ScopeGroup;

/** Comparison operators a {@link ScopeCondition} may use. ORM-neutral; adapters map them. */
export type ScopeOperator =
  | 'eq'
  | 'ne'
  | 'gt'
  | 'gte'
  | 'lt'
  | 'lte'
  | 'in'
  | 'nin'
  | 'isNull'
  | 'isNotNull';

/**
 * A leaf condition: `field <op> value`. `field` names a COLUMN on the scoped entity
 * (validated as a safe identifier by the adapter). `value` is bound as a parameter
 * (never interpolated). `isNull`/`isNotNull` ignore `value`.
 */
export interface ScopeCondition {
  kind: 'condition';
  field: string;
  op: ScopeOperator;
  value?: unknown;
}

/** A boolean group: AND/OR over child nodes. An empty group is the group's identity. */
export interface ScopeGroup {
  kind: 'and' | 'or';
  nodes: ScopeNode[];
}

/** The allow-all terminal (super-admin / before-grant). */
export const scopeAll: ScopeAll = { kind: 'all' };

/** The deny-all terminal (anonymous / no access). */
export const scopeNone: ScopeNone = { kind: 'none' };

/** Build a leaf `field <op> value` condition. */
export function where(field: string, op: ScopeOperator, value?: unknown): ScopeCondition {
  return op === 'isNull' || op === 'isNotNull'
    ? { kind: 'condition', field, op }
    : { kind: 'condition', field, op, value };
}

/** Shorthand for the common `field = value` (equality) condition. */
export function eq(field: string, value: unknown): ScopeCondition {
  return { kind: 'condition', field, op: 'eq', value };
}

/** Combine nodes with AND. A single node is returned as-is; empty → allow-all. */
export function and(...nodes: ScopeNode[]): ScopeConstraint {
  if (nodes.length === 0) return scopeAll;
  if (nodes.length === 1) return nodes[0] as ScopeNode;
  return { kind: 'and', nodes };
}

/** Combine nodes with OR. A single node is returned as-is; empty → deny-all. */
export function or(...nodes: ScopeNode[]): ScopeConstraint {
  if (nodes.length === 0) return scopeNone;
  if (nodes.length === 1) return nodes[0] as ScopeNode;
  return { kind: 'or', nodes };
}

/**
 * What a policy `scope` method may return:
 * - a {@link ScopeConstraint} (terminal or AST),
 * - `true` → allow-all (sugar for {@link scopeAll}),
 * - `false`/`null`/`undefined` → deny-all (sugar for {@link scopeNone}).
 *
 * May be async.
 */
export type ScopeResult = ScopeConstraint | boolean | null | undefined;

/**
 * A policy scope method. Mirrors Pundit's `Scope#resolve`: given the current user,
 * return the constraint that filters the entity's collection to the accessible rows.
 * Conventionally named `scope` on a `@Policy` class (a `viewAny`-style fallback is
 * also honored by the Gate when no `scope` is present).
 */
export type ScopeMethod = (user: User, resource?: Resource) => ScopeResult | Promise<ScopeResult>;

/** Normalize a {@link ScopeResult} (incl. boolean/nullish sugar) into a {@link ScopeConstraint}. */
export function normalizeScope(result: ScopeResult): ScopeConstraint {
  if (result == null) return scopeNone;
  if (result === true) return scopeAll;
  if (result === false) return scopeNone;
  return result;
}
