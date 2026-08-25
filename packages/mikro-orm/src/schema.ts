import type { EntityManager, MikroORM } from '@mikro-orm/core';
import {
  DEFAULT_TABLE_NAMES,
  PermissionEntity,
  RoleEntity,
  RolePermissionEntity,
  UserRoleEntity,
} from './entities.js';

/** Entity class → the table name to fall back to when the entity is not registered. */
const AUTHZ_ENTITY_TABLE_DEFAULTS: ReadonlyArray<readonly [{ name: string }, string]> = [
  [RoleEntity, DEFAULT_TABLE_NAMES.roles],
  [PermissionEntity, DEFAULT_TABLE_NAMES.permissions],
  [RolePermissionEntity, DEFAULT_TABLE_NAMES.rolePermission],
  [UserRoleEntity, DEFAULT_TABLE_NAMES.userRole],
];

/**
 * The four authz table names — used to filter the schema diff down to our tables. Read off
 * the live metadata so a host that relocated the tables (see `createAuthzEntitySchemas`)
 * still gets them created.
 */
function authzTables(em: EntityManager): string[] {
  const metadata = em.getMetadata();
  return AUTHZ_ENTITY_TABLE_DEFAULTS.map(
    ([entity, fallback]) => metadata.find(entity.name)?.tableName ?? fallback,
  );
}

/** Resolve an {@link EntityManager} from a {@link MikroORM} or an EM. */
function toEm(ormOrEm: MikroORM | EntityManager): EntityManager {
  return isOrm(ormOrEm) ? (ormOrEm.em as unknown as EntityManager) : ormOrEm;
}

/**
 * A {@link MikroORM} instance exposes its {@link EntityManager} as a (non-null) `em`
 * property; an EntityManager does not expose an `em`. That distinction is stable across
 * MikroORM 6 and 7 — v7 removed `MikroORM.getSchemaGenerator()`, so we can no longer probe
 * for it (the EM-bound generator is read via {@link generatorFor} instead).
 */
function isOrm(value: MikroORM | EntityManager): value is MikroORM {
  const candidate = value as { em?: unknown };
  return candidate.em != null && typeof candidate.em === 'object';
}

/** The platform's schema generator for a given EM (driver + EM bound). */
function generatorFor(em: EntityManager) {
  return em.getPlatform().getSchemaGenerator(em.getDriver(), em);
}

/** Statements (split, trimmed) from the non-destructive schema diff that touch our tables. */
async function authzStatements(em: EntityManager): Promise<string[]> {
  const tables = authzTables(em);
  const sql = await generatorFor(em).getUpdateSchemaSQL({ safe: true, wrap: false });
  return sql
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && tables.some((t) => new RegExp(`\\b${t}\\b`, 'i').test(s)));
}

/**
 * Returns the non-destructive SQL needed to bring only the authz RBAC tables up to date
 * (creates them / adds missing columns). Mirrors the TypeORM adapter's migration helper —
 * call it inside a MikroORM migration when you disable `autoCreateSchema`:
 *
 * ```ts
 * import { authzSchemaSql } from '@dudousxd/nestjs-authz-mikro-orm';
 * export class AddAuthz extends Migration {
 *   async up() { this.addSql(await authzSchemaSql(this.getEntityManager())); }
 * }
 * ```
 */
export async function authzSchemaSql(ormOrEm: MikroORM | EntityManager): Promise<string> {
  const statements = await authzStatements(toEm(ormOrEm));
  return statements.length ? `${statements.join(';\n')};` : '';
}

/**
 * Ensure the RBAC schema is up to date (used by the store's `ensureSchema` on bootstrap).
 *
 * Runs MikroORM's native non-destructive `safe` diff: it creates missing tables and ADDs
 * missing columns, but never drops/alters/renames existing ones, so it is safe to run on
 * every boot. Only statements touching the authz tables are applied. Accepts a
 * {@link MikroORM} or an {@link EntityManager}.
 *
 * Forward-compat rule: any column added to an authz entity after v1 MUST be nullable or
 * have a default — `ADD COLUMN` of a NOT NULL column without a default fails on a populated
 * table, and the `safe` diff never recreates the table.
 */
export async function ensureAuthzSchema(ormOrEm: MikroORM | EntityManager): Promise<void> {
  const em = toEm(ormOrEm);
  const statements = await authzStatements(em);
  if (statements.length === 0) return;
  const connection = em.getConnection();
  for (const statement of statements) {
    await connection.execute(statement);
  }
}
