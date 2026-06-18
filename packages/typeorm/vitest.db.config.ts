import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

/**
 * Real-engine matrix config (`pnpm test:db`). Runs ONLY the behavioral integration
 * specs (store, schema, direct/tenant, scope, tenant-gate) against a containerized
 * database whose dialect is chosen by `AUTHZ_TEST_DIALECT` and started by the
 * testcontainers global setup. The pure-unit specs (sql / scope-sql / store-dialect)
 * stay in the default `pnpm test` run — they need no database.
 *
 * Single fork, no file parallelism: every test shares ONE container, and the fixtures
 * isolate via unique per-test table prefixes, so a single sequential worker keeps the
 * run deterministic and the container lifecycle simple.
 */
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    environment: 'node',
    globals: false,
    include: ['test/**/*.integration.spec.ts'],
    setupFiles: ['reflect-metadata'],
    globalSetup: ['test/support/testcontainers-setup.ts'],
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
