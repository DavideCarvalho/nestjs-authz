import { PostgreSqlContainer, type StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import type { GlobalSetupContext } from 'vitest/node';

/**
 * Vitest global setup for the real-Postgres run (`pnpm test:db:pg`). Spins up a Postgres
 * container via testcontainers and exports its coordinates through `process.env` so the shared
 * fixture's `pg` Pool connects to it. When `AUTHZ_TEST_PG_HOST` is already set (an existing
 * server, e.g. in CI services), no container is started.
 *
 * Docker-less / failure handling: if the container cannot start, we log a notice and set
 * `AUTHZ_TEST_SKIP=1`; the specs are gated on it, so the run exits green instead of red.
 */

let pg: StartedPostgreSqlContainer | undefined;

export async function setup({ provide }: GlobalSetupContext): Promise<void> {
  if (process.env.AUTHZ_TEST_PG_HOST) {
    provide('authzTestSkip', false);
    return;
  }
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
    const reason = (err as Error).message;
    console.warn(
      [
        '\n[test:db:pg] Could not start a Postgres container — skipping the real-DB specs.',
        `          Reason: ${reason}`,
        '          Ensure Docker is running to exercise the store against real Postgres.\n',
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
