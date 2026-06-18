import { MySqlContainer, type StartedMySqlContainer } from '@testcontainers/mysql';
import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import type { GlobalSetupContext } from 'vitest/node';

/**
 * Vitest global setup for the REAL-engine matrix (`pnpm test:db`). Reads
 * `AUTHZ_TEST_DIALECT` (`postgres` | `mysql`), spins up the matching container via
 * testcontainers, and exports its connection coordinates through `process.env` so the
 * shared `freshAuthzDataSource` fixture connects to it. The container is torn down in
 * the returned teardown.
 *
 * Docker-less / failure handling: if a container cannot start (no Docker daemon), we log
 * a clear notice and set `AUTHZ_TEST_SKIP=1`; the specs themselves are gated on it via
 * `describe.skipIf`, so the run exits green instead of red. With Docker present the
 * specs run for real.
 */

let pg: StartedPostgreSqlContainer | undefined;
let mysql: StartedMySqlContainer | undefined;

export async function setup({ provide }: GlobalSetupContext): Promise<void> {
  const dialect = process.env.AUTHZ_TEST_DIALECT ?? 'sqlite';

  try {
    if (dialect === 'postgres') {
      pg = await new PostgreSqlContainer('postgres:16-alpine')
        .withDatabase('authz_test')
        .withUsername('postgres')
        .withPassword('postgres')
        .start();
      process.env.AUTHZ_TEST_PG_HOST = pg.getHost();
      process.env.AUTHZ_TEST_PG_PORT = String(pg.getMappedPort(5432));
      process.env.AUTHZ_TEST_PG_USER = pg.getUsername();
      process.env.AUTHZ_TEST_PG_PASSWORD = pg.getPassword();
      process.env.AUTHZ_TEST_PG_DB = pg.getDatabase();
      provide('authzTestSkip', false);
    } else if (dialect === 'mysql') {
      mysql = await new MySqlContainer('mysql:8.4')
        .withDatabase('authz_test')
        .withRootPassword('root')
        .start();
      process.env.AUTHZ_TEST_MYSQL_HOST = mysql.getHost();
      process.env.AUTHZ_TEST_MYSQL_PORT = String(mysql.getMappedPort(3306));
      process.env.AUTHZ_TEST_MYSQL_USER = 'root';
      process.env.AUTHZ_TEST_MYSQL_PASSWORD = 'root';
      process.env.AUTHZ_TEST_MYSQL_DB = mysql.getDatabase();
      provide('authzTestSkip', false);
    } else {
      provide('authzTestSkip', false);
    }
  } catch (err) {
    // No Docker (or pull/start failed): skip the matrix gracefully rather than fail.
    const reason = (err as Error).message;
    console.warn(
      [
        `\n[test:db] Could not start a ${dialect} container — skipping the real-engine matrix.`,
        `          Reason: ${reason}`,
        '          Ensure Docker is running to exercise Postgres/MySQL.\n',
      ].join('\n'),
    );
    process.env.AUTHZ_TEST_SKIP = '1';
    provide('authzTestSkip', true);
  }
}

export async function teardown(): Promise<void> {
  await pg?.stop();
  await mysql?.stop();
}

declare module 'vitest' {
  interface ProvidedContext {
    authzTestSkip: boolean;
  }
}
