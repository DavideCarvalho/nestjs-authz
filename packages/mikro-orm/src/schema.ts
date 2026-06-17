import type { EntityManager, MikroORM } from '@mikro-orm/core';

/** The four authz table names — used to filter the schema diff down to our tables. */
const AUTHZ_TABLES = [
  'authz_roles',
  'authz_permissions',
  'authz_role_permission',
  'authz_user_role',
];

/** Resolve an {@link EntityManager} from a {@link MikroORM} or an EM. */
function toEm(ormOrEm: MikroORM | EntityManager): EntityManager {
  return isOrm(ormOrEm) ? (ormOrEm.em as unknown as EntityManager) : ormOrEm;
}

function isOrm(value: MikroORM | EntityManager): value is MikroORM {
  return 'em' in (value as object) && typeof (value as MikroORM).getSchemaGenerator === 'function';
}

/** The platform's schema generator for a given EM (driver + EM bound). */
function generatorFor(em: EntityManager) {
  return em.getPlatform().getSchemaGenerator(em.getDriver(), em);
}

/** Statements (split, trimmed) from the non-destructive schema diff that touch our tables. */
async function authzStatements(em: EntityManager): Promise<string[]> {
  const sql = await generatorFor(em).getUpdateSchemaSQL({ safe: true, wrap: false });
  return sql
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && AUTHZ_TABLES.some((t) => new RegExp(`\\b${t}\\b`, 'i').test(s)));
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
