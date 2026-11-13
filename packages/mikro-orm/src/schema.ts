import type { EntityManager, MikroORM } from '@mikro-orm/core';
import {
  DEFAULT_TABLE_NAMES,
  PermissionEntity,
  RoleEntity,
  RolePermissionEntity,
  UserRoleEntity,
} from './entities.js';
import { assertSchemaSupported } from './mikro-orm-authz.store.js';

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
/** The `schema` the authz entities were built with, if any (one for all four). */
function authzSchema(em: EntityManager): string | undefined {
  const metadata = em.getMetadata();
  for (const [entity] of AUTHZ_ENTITY_TABLE_DEFAULTS) {
    const schema = metadata.find(entity.name)?.schema;
    if (schema !== undefined && schema !== '' && schema !== '*') return schema;
  }
  return undefined;
}

const isMysql = (em: EntityManager) => /mysql|maria/i.test(em.getPlatform().constructor.name);

/**
 * Create the authz `schema` (a Postgres schema, or a MySQL database) when it is missing. The
 * catalog is checked first: `CREATE SCHEMA IF NOT EXISTS` needs the CREATE privilege even when
 * the schema exists. A failure names the grant needed.
 */
async function ensureSchemaExists(em: EntityManager, schema: string): Promise<void> {
  const connection = em.getConnection();
  const rows = (await connection.execute(
    'select 1 as found from information_schema.schemata where schema_name = ?',
    [schema],
  )) as unknown[];
  if (rows.length > 0) return;
  const mysql = isMysql(em);
  const quoted = em.getPlatform().quoteIdentifier(schema);
  try {
    await connection.execute(
      mysql ? `create database if not exists ${quoted}` : `create schema if not exists ${quoted}`,
    );
  } catch (error) {
    const grant = mysql
      ? `GRANT CREATE ON *.* TO <user>, or create the database \`${schema}\` yourself`
      : `GRANT CREATE ON DATABASE <database> TO <role>, or create the schema "${schema}" yourself`;
    throw new Error(
      `nestjs-authz: could not create the ${mysql ? 'database' : 'schema'} ${JSON.stringify(schema)} for the authz tables (${(error as Error).message}). ${grant}.`,
    );
  }
}

function generatorFor(em: EntityManager) {
  return em.getPlatform().getSchemaGenerator(em.getDriver(), em);
}

/** Statements (split, trimmed) from the non-destructive schema diff that touch our tables. */
async function authzStatements(em: EntityManager): Promise<string[]> {
  const tables = authzTables(em);
  const sql = await generatorFor(em).getUpdateSchemaSQL({ safe: true, wrap: false });
  const statements = sql
    .split(';')
    .map((s) => s.trim())
    .filter((s) => s.length > 0 && tables.some((t) => new RegExp(`\\b${t}\\b`, 'i').test(s)));
  const schema = authzSchema(em);
  return schema !== undefined && isMysql(em) ? narrowToSchema(em, schema, statements) : statements;
}

/** Top-level comma split of a `create table (…)` body. */
function splitDefinitions(body: string): string[] {
  const parts: string[] = [];
  let depth = 0;
  let quote: string | undefined;
  let start = 0;
  for (let i = 0; i < body.length; i++) {
    const c = body[i];
    if (quote) {
      if (c === quote) quote = undefined;
    } else if (c === "'" || c === '`') {
      quote = c;
    } else if (c === '(') {
      depth++;
    } else if (c === ')') {
      depth--;
    } else if (c === ',' && depth === 0) {
      parts.push(body.slice(start, i).trim());
      start = i + 1;
    }
  }
  parts.push(body.slice(start).trim());
  return parts.filter((p) => p.length > 0);
}

/**
 * MikroORM introspects MySQL only in the connection's own database, so for tables in another
 * database (`schema`) its diff says "create everything" on every boot. Narrow it against that
 * database's `information_schema`: keep `create table` for missing tables, turn it into
 * `add column`s for existing ones, and drop index statements whose index exists.
 */
async function narrowToSchema(
  em: EntityManager,
  schema: string,
  statements: string[],
): Promise<string[]> {
  const connection = em.getConnection();
  const rows = (await connection.execute(
    'select table_name as t, column_name as c from information_schema.columns where table_schema = ?',
    [schema],
  )) as Array<Record<string, string>>;
  const columns = new Map<string, Set<string>>();
  for (const row of rows) {
    const table = (row.t ?? row.T ?? row.TABLE_NAME) as string;
    const column = (row.c ?? row.C ?? row.COLUMN_NAME) as string;
    if (!columns.has(table)) columns.set(table, new Set());
    columns.get(table)?.add(column);
  }
  const indexRows = (await connection.execute(
    'select table_name as t, index_name as i from information_schema.statistics where table_schema = ?',
    [schema],
  )) as Array<Record<string, string>>;
  const indexes = new Set(
    indexRows.map((r) => `${r.t ?? r.T ?? r.TABLE_NAME}.${r.i ?? r.I ?? r.INDEX_NAME}`),
  );

  const out: string[] = [];
  for (const statement of statements) {
    const create = /^create table (`[^`]+`\.`([^`]+)`) \((.*)\)[^)]*$/is.exec(statement);
    if (create) {
      const [, ref, table, body] = create as unknown as [string, string, string, string];
      const existing = columns.get(table);
      if (!existing) {
        out.push(statement);
        continue;
      }
      for (const definition of splitDefinitions(body)) {
        const column = /^`([^`]+)`\s/.exec(definition)?.[1];
        if (column !== undefined && !existing.has(column)) {
          out.push(`alter table ${ref} add ${definition}`);
        }
      }
      continue;
    }
    const index =
      /^alter table `[^`]+`\.`([^`]+)` add (?:unique |index |unique index |fulltext )?(?:index )?`([^`]+)`/i.exec(
        statement,
      ) ?? /^create (?:unique )?index `([^`]+)` on `[^`]+`\.`([^`]+)`/i.exec(statement);
    if (index) {
      const [table, name] = statement.toLowerCase().startsWith('create')
        ? [index[2], index[1]]
        : [index[1], index[2]];
      if (indexes.has(`${table}.${name}`)) continue;
    }
    out.push(statement);
  }
  return out;
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
  const em = toEm(ormOrEm);
  const statements = await authzStatements(em);
  const schema = authzSchema(em);
  // A migration also creates the schema (a MySQL database), when it has something to create.
  if (schema !== undefined && statements.some((st) => /^create table/i.test(st))) {
    const quoted = em.getPlatform().quoteIdentifier(schema);
    statements.unshift(
      isMysql(em)
        ? `create database if not exists ${quoted}`
        : `create schema if not exists ${quoted}`,
    );
  }
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
  assertSchemaSupported(em);
  const schema = authzSchema(em);
  if (schema !== undefined) await ensureSchemaExists(em, schema);
  const statements = await authzStatements(em);
  if (statements.length === 0) return;
  const connection = em.getConnection();
  for (const statement of statements) {
    await connection.execute(statement);
  }
}
