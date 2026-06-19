import {
  type DataSource,
  type EntityMetadata,
  type QueryRunner,
  Table,
  TableColumn,
} from 'typeorm';
import { TableUtils } from 'typeorm/schema-builder/util/TableUtils.js';
import {
  DEFAULT_TABLE_NAMES,
  PermissionEntity,
  RoleEntity,
  RolePermissionEntity,
  UserPermissionEntity,
  UserRoleEntity,
} from './entities.js';
import { assertSafeIdentifier } from './sql.js';
import type { AuthzStoreOptions, TableNames } from './types.js';

/** An entity class → its resolved table name, honoring BYO overrides + optional schema. */
interface TablePlan {
  entity: new () => object;
  name: string;
}

/** Resolve the (schema-qualified) table name for an entity, applying BYO overrides. */
function tableName(base: string, schema: string | undefined): string {
  return schema ? `${schema}.${base}` : base;
}

function resolveNames(tableNames: TableNames | undefined): {
  roles: string;
  permissions: string;
  rolePermission: string;
  userRole: string;
  userPermission: string;
} {
  return {
    roles: tableNames?.roles ?? DEFAULT_TABLE_NAMES.roles,
    permissions: tableNames?.permissions ?? DEFAULT_TABLE_NAMES.permissions,
    rolePermission: tableNames?.rolePermission ?? DEFAULT_TABLE_NAMES.rolePermission,
    userRole: tableNames?.userRole ?? DEFAULT_TABLE_NAMES.userRole,
    userPermission: tableNames?.userPermission ?? DEFAULT_TABLE_NAMES.userPermission,
  };
}

/** The four table plans (entity + resolved name) for a given options set. */
function plans(opts: AuthzStoreOptions | undefined): TablePlan[] {
  const names = resolveNames(opts?.tableNames);
  const schema = opts?.schema;
  // P4: reject hostile BYO identifiers before they reach DDL.
  for (const [key, name] of Object.entries(names)) {
    assertSafeIdentifier(name, `table name (${key})`);
  }
  if (schema !== undefined) assertSafeIdentifier(schema, 'schema name');
  return [
    { entity: RoleEntity, name: tableName(names.roles, schema) },
    { entity: PermissionEntity, name: tableName(names.permissions, schema) },
    { entity: RolePermissionEntity, name: tableName(names.rolePermission, schema) },
    { entity: UserRoleEntity, name: tableName(names.userRole, schema) },
    { entity: UserPermissionEntity, name: tableName(names.userPermission, schema) },
  ];
}

/**
 * Build a driver-portable {@link Table} from entity metadata, overriding the table name
 * so BYO names + an optional Postgres schema are honored (the metadata's own name is the
 * entity-decorator default).
 *
 * Constraint-name rewrite (Postgres-critical): TypeORM derives index / unique / primary-key
 * names by hashing the table name + columns (see `DefaultNamingStrategy.indexName` et al.).
 * `Table.create` computes those from the entity's DEFAULT name, so simply reassigning
 * `table.name` leaves the constraints carrying the OLD name's hash. Two tables created from
 * the SAME entity metadata under DIFFERENT runtime names (BYO table names, or a per-test
 * unique prefix) then emit IDENTICAL constraint names. SQLite scopes index names per-table
 * and tolerates this; Postgres treats index/constraint names as schema-global and rejects
 * the second `CREATE TABLE` with `relation "IDX_..." already exists`. So after renaming we
 * regenerate every constraint name from the NEW table name via the connection's naming
 * strategy, keeping each created table's constraints globally unique.
 */
function tableFromMetadata(
  connection: DataSource,
  metadata: EntityMetadata,
  driver: DataSource['driver'],
  name: string,
) {
  const table = Table.create(metadata, driver);
  table.name = name;

  const naming = connection.namingStrategy;
  for (const index of table.indices) {
    index.name = naming.indexName(name, index.columnNames, index.where);
  }
  for (const unique of table.uniques) {
    unique.name = naming.uniqueConstraintName(name, unique.columnNames);
  }
  for (const check of table.checks) {
    if (check.expression) check.name = naming.checkConstraintName(name, check.expression);
  }
  return table;
}

/**
 * Create the RBAC tables (roles, permissions, and the two pivots) if they don't exist.
 * Strictly non-destructive — `CREATE TABLE` only runs for a table that is absent. Call it
 * from a TypeORM migration when `autoCreateSchema: false`:
 *
 * ```ts
 * import { createAuthzTables } from '@dudousxd/nestjs-authz-typeorm';
 * export class AddAuthz1700000000000 implements MigrationInterface {
 *   async up(qr: QueryRunner) { await createAuthzTables(qr); }
 *   async down(qr: QueryRunner) { ... }
 * }
 * ```
 */
export async function createAuthzTables(
  queryRunner: QueryRunner,
  opts?: AuthzStoreOptions,
): Promise<void> {
  const driver = queryRunner.connection.driver;
  for (const plan of plans(opts)) {
    if (await queryRunner.hasTable(plan.name)) continue;
    const metadata = queryRunner.connection.getMetadata(plan.entity);
    await queryRunner.createTable(
      tableFromMetadata(queryRunner.connection, metadata, driver, plan.name),
      true,
    );
  }
}

/**
 * Add any columns present in the entity metadata but missing from the live table.
 *
 * Strictly non-destructive: it only ever ADDs columns — never drops, alters the type of,
 * renames, or otherwise touches existing columns, and is order-independent. Each missing
 * column is built from the entity's `ColumnMetadata` the same way `Table.create` derives a
 * table (via `TableUtils.createTableColumnOptions`), so the resulting `TableColumn` is
 * driver-portable across SQLite, MySQL and Postgres.
 *
 * Forward-compat rule: any column added to an authz entity after v1 MUST be nullable or have
 * a default. `ADD COLUMN` of a NOT NULL column without a default fails on a populated table.
 */
async function addMissingColumns(queryRunner: QueryRunner, plan: TablePlan): Promise<void> {
  const metadata = queryRunner.connection.getMetadata(plan.entity);
  const driver = queryRunner.connection.driver;
  const table = await queryRunner.getTable(plan.name);
  if (!table) return;

  const existing = new Set(table.columns.map((column) => column.name));
  for (const column of metadata.columns) {
    if (column.isVirtualProperty || existing.has(column.databaseName)) continue;
    const tableColumn = new TableColumn(TableUtils.createTableColumnOptions(column, driver));
    await queryRunner.addColumn(plan.name, tableColumn);
  }
}

/**
 * Ensure the RBAC schema is up to date via a DataSource (used by the store's `ensureSchema`
 * on bootstrap). For each table: creates it if missing, otherwise non-destructively adds any
 * columns that exist in the entity metadata but not yet in the live table (see
 * {@link addMissingColumns}). Never drops/alters/renames — safe to run on every boot.
 */
export async function ensureAuthzSchema(
  dataSource: DataSource,
  opts?: AuthzStoreOptions,
): Promise<void> {
  const queryRunner = dataSource.createQueryRunner();
  try {
    const driver = dataSource.driver;
    for (const plan of plans(opts)) {
      if (await queryRunner.hasTable(plan.name)) {
        await addMissingColumns(queryRunner, plan);
      } else {
        const metadata = queryRunner.connection.getMetadata(plan.entity);
        await queryRunner.createTable(
          tableFromMetadata(queryRunner.connection, metadata, driver, plan.name),
          true,
        );
      }
    }
  } finally {
    await queryRunner.release();
  }
}
