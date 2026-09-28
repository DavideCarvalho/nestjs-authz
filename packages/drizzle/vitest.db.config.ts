import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

/**
 * Real-Postgres config (`pnpm test:db:pg`). Runs ONLY the behavioral integration specs against
 * a containerized Postgres (started by the testcontainers global setup, or an existing server
 * when `AUTHZ_TEST_PG_HOST` is already set). The pure-unit specs stay in the default run.
 *
 * Single fork, no file parallelism: every test shares ONE database and the fixtures isolate via
 * unique per-test table prefixes, so a single sequential worker keeps the run deterministic.
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
