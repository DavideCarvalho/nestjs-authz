import { assertSafeIdentifier } from '@dudousxd/nestjs-authz';
import {
  getTableConfig,
  index,
  pgSchema,
  pgTable,
  primaryKey,
  timestamp,
  varchar,
} from 'drizzle-orm/pg-core';
import type { AuthzStoreOptions, TableNames } from './types.js';

/**
 * Default table names — the canonical cross-adapter names (the TypeORM, MikroORM and Prisma
 * adapters use the same ones), so a store swap keeps the data where it is.
 */
export const DEFAULT_TABLE_NAMES = {
  roles: 'authz_roles',
  permissions: 'authz_permissions',
  rolePermission: 'authz_role_permission',
  userRole: 'authz_user_role',
  userPermission: 'authz_user_permission',
} as const;

/**
 * The "no tenant" sentinel for the user-role pivot's `tenantId`. A GLOBAL (unscoped) assignment
 * stores this empty string rather than `NULL` so the column can be part of the composite primary
 * key with portable uniqueness (SQL treats `NULL`s as distinct). Same value as the TypeORM adapter.
 */
export const GLOBAL_TENANT = '';

/** Resolve BYO table names over {@link DEFAULT_TABLE_NAMES}, validating each. */
export function resolveTableNames(tableNames?: TableNames): Required<TableNames> {
  const names: Required<TableNames> = {
    roles: tableNames?.roles ?? DEFAULT_TABLE_NAMES.roles,
    permissions: tableNames?.permissions ?? DEFAULT_TABLE_NAMES.permissions,
    rolePermission: tableNames?.rolePermission ?? DEFAULT_TABLE_NAMES.rolePermission,
    userRole: tableNames?.userRole ?? DEFAULT_TABLE_NAMES.userRole,
    userPermission: tableNames?.userPermission ?? DEFAULT_TABLE_NAMES.userPermission,
  };
  for (const [key, name] of Object.entries(names)) {
    assertSafeIdentifier(name, `table name (${key})`);
  }
  return names;
}

// Columns are named exactly like the TypeORM entities / Prisma models (camelCase), so every
// adapter reads and writes the same physical schema.
const id = () => varchar('id', { length: 191 }).primaryKey();
const ref = (name: string) => varchar(name, { length: 191 }).notNull();

/**
 * Build the five RBAC tables as Drizzle `pgTable`s. Pure — call it once at module scope and
 * re-export the result from the schema file your `drizzle.config.ts` points at, so drizzle-kit
 * generates the migration for you:
 *
 * ```ts
 * // db/schema.ts
 * import { createAuthzTables } from '@dudousxd/nestjs-authz-drizzle';
 * export const authz = createAuthzTables();            // or { tableNames, schema }
 * export const { roles: authzRoles, userRole: authzUserRole } = authz;
 * ```
 *
 * Pass the SAME object to the store (`new DrizzleAuthzStore(db, { tables: authz })`) so the
 * queries and the migration can never disagree. Index/constraint names are derived from the
 * table names, so relocating the tables keeps them unique.
 */
export function createAuthzTables(opts: Pick<AuthzStoreOptions, 'tableNames' | 'schema'> = {}) {
  const names = resolveTableNames(opts.tableNames);
  if (opts.schema !== undefined) assertSafeIdentifier(opts.schema, 'schema name');
  // `pgSchema('public')` is rejected by drizzle — the default schema IS `pgTable`.
  const table = (
    opts.schema === undefined ? pgTable : pgSchema(opts.schema).table
  ) as typeof pgTable;

  const roles = table(names.roles, {
    id: id(),
    name: varchar('name', { length: 191 }).notNull().unique(`${names.roles}_name_unique`),
    guard: varchar('guard', { length: 191 }),
    createdAt: timestamp('createdAt', { mode: 'date' }).notNull().defaultNow(),
  });

  const permissions = table(names.permissions, {
    id: id(),
    name: varchar('name', { length: 191 }).notNull().unique(`${names.permissions}_name_unique`),
    guard: varchar('guard', { length: 191 }),
    createdAt: timestamp('createdAt', { mode: 'date' }).notNull().defaultNow(),
  });

  const rolePermission = table(
    names.rolePermission,
    { roleId: ref('roleId'), permissionId: ref('permissionId') },
    (t) => [
      primaryKey({ name: `${names.rolePermission}_pkey`, columns: [t.roleId, t.permissionId] }),
    ],
  );

  const userRole = table(
    names.userRole,
    {
      userType: ref('userType'),
      userId: ref('userId'),
      roleId: ref('roleId'),
      tenantId: varchar('tenantId', { length: 191 }).notNull().default(GLOBAL_TENANT),
    },
    (t) => [
      primaryKey({
        name: `${names.userRole}_pkey`,
        columns: [t.userType, t.userId, t.roleId, t.tenantId],
      }),
      index(`${names.userRole}_user_idx`).on(t.userType, t.userId),
    ],
  );

  const userPermission = table(
    names.userPermission,
    { userType: ref('userType'), userId: ref('userId'), permissionId: ref('permissionId') },
    (t) => [
      primaryKey({
        name: `${names.userPermission}_pkey`,
        columns: [t.userType, t.userId, t.permissionId],
      }),
      index(`${names.userPermission}_user_idx`).on(t.userType, t.userId),
    ],
  );

  return { roles, permissions, rolePermission, userRole, userPermission };
}

/** The table set the store queries — what {@link createAuthzTables} returns. */
export type AuthzTables = ReturnType<typeof createAuthzTables>;

/** The default tables (canonical names, default schema). */
export const authzTables: AuthzTables = createAuthzTables();

const q = (identifier: string) => `"${identifier}"`;

/**
 * The idempotent Postgres DDL for a table set — `CREATE TABLE IF NOT EXISTS` + `CREATE INDEX IF
 * NOT EXISTS`, never destructive. It is what {@link DrizzleAuthzStore.ensureSchema} runs; prefer
 * drizzle-kit (spread the tables into your schema) when you already manage migrations with it.
 * Table/schema names are read back off the Drizzle table config, so BYO names are honored.
 */
export function authzSchemaDdl(tables: AuthzTables = authzTables): string[] {
  const qualified = (t: Parameters<typeof getTableConfig>[0]) => {
    const cfg = getTableConfig(t);
    assertSafeIdentifier(cfg.name, 'table name');
    if (cfg.schema !== undefined) assertSafeIdentifier(cfg.schema, 'schema name');
    return {
      name: cfg.name,
      ref: cfg.schema ? `${q(cfg.schema)}.${q(cfg.name)}` : q(cfg.name),
      schema: cfg.schema,
    };
  };
  const roles = qualified(tables.roles);
  const permissions = qualified(tables.permissions);
  const rolePermission = qualified(tables.rolePermission);
  const userRole = qualified(tables.userRole);
  const userPermission = qualified(tables.userPermission);

  const ddl: string[] = [];
  const schemas = new Set(
    [roles, permissions, rolePermission, userRole, userPermission]
      .map((t) => t.schema)
      .filter((s): s is string => s !== undefined),
  );
  for (const schema of schemas) ddl.push(`CREATE SCHEMA IF NOT EXISTS ${q(schema)}`);

  const createTable = (ref: string, parts: string[]) =>
    `CREATE TABLE IF NOT EXISTS ${ref} (${parts.join(', ')})`;
  const vc = (column: string) => `"${column}" varchar(191) NOT NULL`;

  for (const t of [roles, permissions]) {
    ddl.push(
      createTable(t.ref, [
        '"id" varchar(191) PRIMARY KEY NOT NULL',
        vc('name'),
        '"guard" varchar(191)',
        '"createdAt" timestamp DEFAULT now() NOT NULL',
        `CONSTRAINT ${q(`${t.name}_name_unique`)} UNIQUE("name")`,
      ]),
    );
  }
  ddl.push(
    createTable(rolePermission.ref, [
      vc('roleId'),
      vc('permissionId'),
      `CONSTRAINT ${q(`${rolePermission.name}_pkey`)} PRIMARY KEY("roleId","permissionId")`,
    ]),
  );
  ddl.push(
    createTable(userRole.ref, [
      vc('userType'),
      vc('userId'),
      vc('roleId'),
      `"tenantId" varchar(191) DEFAULT '' NOT NULL`,
      `CONSTRAINT ${q(`${userRole.name}_pkey`)} PRIMARY KEY("userType","userId","roleId","tenantId")`,
    ]),
  );
  ddl.push(
    createTable(userPermission.ref, [
      vc('userType'),
      vc('userId'),
      vc('permissionId'),
      `CONSTRAINT ${q(`${userPermission.name}_pkey`)} PRIMARY KEY("userType","userId","permissionId")`,
    ]),
  );
  for (const t of [userRole, userPermission]) {
    ddl.push(
      `CREATE INDEX IF NOT EXISTS ${q(`${t.name}_user_idx`)} ON ${t.ref} ("userType","userId")`,
    );
  }
  return ddl;
}
