import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

/**
 * Real-Postgres config (`pnpm test:db:pg`). Runs ONLY the `*.pg.spec.ts` integration
 * spec against a containerized Postgres (started by the testcontainers global setup),
 * so the store's `$queryRaw` single-JOIN is exercised verbatim against real SQL —
 * something the in-memory fake-based default specs cannot prove.
 *
 * Single fork, no file parallelism: every test shares ONE container and isolates via
 * a per-test truncate, so a single sequential worker keeps the run deterministic and
 * the container lifecycle simple.
 */
export default defineConfig({
  plugins: [swc.vite({ module: { type: 'es6' } })],
  test: {
    environment: 'node',
    globals: false,
    include: ['test/**/*.pg.spec.ts'],
    setupFiles: ['reflect-metadata'],
    globalSetup: ['test/support/testcontainers-setup.ts'],
    pool: 'forks',
    poolOptions: { forks: { singleFork: true } },
    fileParallelism: false,
    testTimeout: 60_000,
    hookTimeout: 120_000,
  },
});
