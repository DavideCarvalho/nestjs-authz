import { randomUUID } from 'node:crypto';
import { DataSource, type DataSourceOptions, type EntitySchema, type MixedList } from 'typeorm';
import { describe } from 'vitest';
import { AUTHZ_ENTITIES } from '../../src/entities.js';
import type { AuthzStoreOptions } from '../../src/types.js';

/**
 * `describe` for the integration specs, skipped when the real-engine matrix could not
 * start its container (`AUTHZ_TEST_SKIP=1`, set by the testcontainers global setup when
 * Docker is unavailable). In the default sqlite run the flag is never set, so this is a
 * plain `describe`.
 */
export const describeIntegration = process.env.AUTHZ_TEST_SKIP ? describe.skip : describe;

/**
 * Shared DataSource fixtures used by EVERY behavioral integration spec, so the SAME
 * assertions run against sqlite (the default `pnpm test`) AND real Postgres / MySQL
 * (`pnpm test:db`, see `vitest.db.config.ts`). The target dialect is selected by the
 * `AUTHZ_TEST_DIALECT` env var; the container connection config (host/port/...) is
 * injected by the testcontainers global-setup. With nothing set we fall back to an
 * in-memory sqlite database, so the fixtures are zero-config for the default run.
 *
 * Cross-test isolation: with sqlite each `:memory:` connection is its own database, but
 * a containerized Postgres/MySQL is SHARED across all tests in a file. To keep tests
 * independent without per-test database churn, every fixture call gets a UNIQUE random
 * table-name prefix — the authz tables (and the scope spec's `Post` table) are created
 * under that prefix, so concurrent / sequential tests never see each other's rows. The
 * authz table names are returned in `names` so specs assert against the resolved names
 * rather than hard-coded literals.
 */

export type TestDialect = 'sqlite' | 'postgres' | 'mysql';

/** The dialect the current run targets (`AUTHZ_TEST_DIALECT`, default sqlite). */
export function targetDialect(): TestDialect {
  const raw = process.env.AUTHZ_TEST_DIALECT;
  if (raw === 'postgres' || raw === 'mysql') return raw;
  return 'sqlite';
}

/** A short, SQL-identifier-safe unique prefix (letters/digits/underscore, not leading-digit). */
function uniquePrefix(): string {
  return `t_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
}

/** Base connection options for the target dialect (sans `entities`/`synchronize`). */
function baseOptions(): DataSourceOptions {
  const dialect = targetDialect();
  if (dialect === 'postgres') {
    return {
      type: 'postgres',
      host: process.env.AUTHZ_TEST_PG_HOST ?? 'localhost',
      port: Number(process.env.AUTHZ_TEST_PG_PORT ?? 5432),
      username: process.env.AUTHZ_TEST_PG_USER ?? 'postgres',
      password: process.env.AUTHZ_TEST_PG_PASSWORD ?? 'postgres',
      database: process.env.AUTHZ_TEST_PG_DB ?? 'authz_test',
    } as DataSourceOptions;
  }
  if (dialect === 'mysql') {
    return {
      type: 'mysql',
      host: process.env.AUTHZ_TEST_MYSQL_HOST ?? 'localhost',
      port: Number(process.env.AUTHZ_TEST_MYSQL_PORT ?? 3306),
      username: process.env.AUTHZ_TEST_MYSQL_USER ?? 'root',
      password: process.env.AUTHZ_TEST_MYSQL_PASSWORD ?? 'root',
      database: process.env.AUTHZ_TEST_MYSQL_DB ?? 'authz_test',
    } as DataSourceOptions;
  }
  return { type: 'sqlite', database: ':memory:' } as DataSourceOptions;
}

/** Resolved table names for one fixture, all under a shared unique prefix. */
export interface AuthzTableNames {
  roles: string;
  permissions: string;
  rolePermission: string;
  userRole: string;
  userPermission: string;
}

export interface AuthzFixture {
  ds: DataSource;
  /** Store options carrying the per-fixture unique table names. */
  options: AuthzStoreOptions;
  /** The resolved (prefixed) table names — assert against these, not literals. */
  names: AuthzTableNames;
  dialect: TestDialect;
}

/**
 * A fresh DataSource wired with the authz entities (NOT synchronized — the schema is
 * created on demand by the store / `ensureAuthzSchema`), plus a unique-prefixed set of
 * table names so the run is isolated on a shared container.
 */
export async function freshAuthzDataSource(): Promise<AuthzFixture> {
  const prefix = uniquePrefix();
  const names: AuthzTableNames = {
    roles: `${prefix}_roles`,
    permissions: `${prefix}_permissions`,
    rolePermission: `${prefix}_role_permission`,
    userRole: `${prefix}_user_role`,
    userPermission: `${prefix}_user_permission`,
  };
  const ds = new DataSource({
    ...baseOptions(),
    entities: [...AUTHZ_ENTITIES],
    synchronize: false,
  } as DataSourceOptions);
  await ds.initialize();
  return { ds, options: { tableNames: names }, names, dialect: targetDialect() };
}

/**
 * A fresh DataSource for the scope specs, carrying caller-supplied entities. Because the
 * scope specs rely on `synchronize: true` to materialize their throwaway entity and we
 * cannot synchronize a shared container repeatedly under one fixed name, we return the
 * connection and let the spec drop/recreate via synchronize against a UNIQUE table name
 * derived from the entity (the spec passes an entity whose `@Entity({ name })` already
 * carries a unique suffix — see `makePostEntity`).
 */
export async function freshSyncDataSource(
  entities: MixedList<string | (new () => object) | EntitySchema>,
): Promise<DataSource> {
  const ds = new DataSource({
    ...baseOptions(),
    entities,
    synchronize: true,
  } as DataSourceOptions);
  await ds.initialize();
  return ds;
}

/** A fresh unique table name for a synchronized throwaway entity in the scope specs. */
export function uniqueTableName(base: string): string {
  return `${uniquePrefix()}_${base}`;
}
