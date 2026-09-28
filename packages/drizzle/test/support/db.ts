import { randomUUID } from 'node:crypto';
import { PGlite } from '@electric-sql/pglite';
import { drizzle as drizzlePg } from 'drizzle-orm/node-postgres';
import { drizzle as drizzlePglite } from 'drizzle-orm/pglite';
import pg from 'pg';
import { describe } from 'vitest';
import type { AuthzStoreOptions, DrizzlePgDatabase, TableNames } from '../../src/types.js';

/**
 * `describe` for the integration specs, skipped when the real-Postgres run could not start its
 * container (`AUTHZ_TEST_SKIP=1`). In the default PGlite run the flag is never set.
 */
export const describeIntegration = process.env.AUTHZ_TEST_SKIP ? describe.skip : describe;

export type TestDialect = 'pglite' | 'postgres';

/** `postgres` under `pnpm test:db:pg`, otherwise the in-process PGlite. */
export function targetDialect(): TestDialect {
  return process.env.AUTHZ_TEST_DIALECT === 'postgres' ? 'postgres' : 'pglite';
}

/** A short, SQL-identifier-safe unique prefix. */
export function uniquePrefix(): string {
  return `t_${randomUUID().replace(/-/g, '').slice(0, 12)}`;
}

// One PGlite per test file (it is an in-process Postgres; starting one per test is slow).
let shared: PGlite | undefined;

export interface TestDb {
  db: DrizzlePgDatabase;
  /** Raw query escape hatch for assertions (information_schema, ...). */
  query: <T = Record<string, unknown>>(text: string, params?: unknown[]) => Promise<T[]>;
  close: () => Promise<void>;
}

/** A Drizzle database on the target dialect. Isolation comes from unique table names. */
export async function openDb(): Promise<TestDb> {
  if (targetDialect() === 'postgres') {
    const pool = new pg.Pool({
      host: process.env.AUTHZ_TEST_PG_HOST ?? 'localhost',
      port: Number(process.env.AUTHZ_TEST_PG_PORT ?? 5432),
      user: process.env.AUTHZ_TEST_PG_USER ?? 'postgres',
      password: process.env.AUTHZ_TEST_PG_PASSWORD ?? 'postgres',
      database: process.env.AUTHZ_TEST_PG_DB ?? 'authz_test',
      max: 4,
    });
    return {
      db: drizzlePg(pool) as unknown as DrizzlePgDatabase,
      query: async (text, params) => (await pool.query(text, params as unknown[])).rows,
      close: () => pool.end(),
    };
  }
  shared ??= new PGlite();
  const client = shared;
  return {
    db: drizzlePglite(client) as unknown as DrizzlePgDatabase,
    query: async <T>(text: string, params?: unknown[]) =>
      (await client.query<T>(text, params as unknown[])).rows,
    close: async () => {},
  };
}

export interface AuthzFixture extends TestDb {
  /** Store options carrying the per-fixture unique table names. */
  options: AuthzStoreOptions;
  names: Required<TableNames>;
}

/** A database plus a unique-prefixed set of authz table names (isolated on a shared server). */
export async function freshAuthzDb(): Promise<AuthzFixture> {
  const prefix = uniquePrefix();
  const names: Required<TableNames> = {
    roles: `${prefix}_roles`,
    permissions: `${prefix}_permissions`,
    rolePermission: `${prefix}_role_permission`,
    userRole: `${prefix}_user_role`,
    userPermission: `${prefix}_user_permission`,
  };
  return { ...(await openDb()), options: { tableNames: names }, names };
}
