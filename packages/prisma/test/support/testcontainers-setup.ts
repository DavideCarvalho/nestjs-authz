import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import type { GlobalSetupContext } from 'vitest/node';

/**
 * Vitest global setup for the real-Postgres run (`pnpm test:db:pg`). Spins up a Postgres
 * container via testcontainers and exports its connection coordinates through
 * `process.env` so the spec's `pg` Pool can connect to it. The container is torn down in
 * the returned teardown.
 *
 * Docker-less / failure handling: if the container cannot start (no Docker daemon), we log
 * a clear notice and set `AUTHZ_TEST_SKIP=1`; the spec is gated on it via
 * `describe.skip`, so the run exits green instead of red. With Docker present the spec
 * runs for real against Postgres.
 */

let pg: StartedPostgreSqlContainer | undefined;

export async function setup({ provide }: GlobalSetupContext): Promise<void> {
  try {
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
  } catch (err) {
    // No Docker (or pull/start failed): skip the real-DB spec gracefully rather than fail.
    const reason = (err as Error).message;
    console.warn(
      [
        '\n[test:db:pg] Could not start a Postgres container — skipping the real-DB spec.',
        `          Reason: ${reason}`,
        '          Ensure Docker is running to exercise the $queryRaw JOIN against real Postgres.\n',
      ].join('\n'),
    );
    process.env.AUTHZ_TEST_SKIP = '1';
    provide('authzTestSkip', true);
  }
}

export async function teardown(): Promise<void> {
  await pg?.stop();
}

declare module 'vitest' {
  interface ProvidedContext {
    authzTestSkip: boolean;
  }
}
