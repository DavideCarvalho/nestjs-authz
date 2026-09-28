import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

/**
 * Default run (`pnpm test`): every spec, against an in-process Postgres (PGlite) — real
 * Postgres semantics with no Docker. `pnpm test:db:pg` re-runs the integration specs against a
 * containerized Postgres (see `vitest.db.config.ts`).
 */
export default defineConfig({
  plugins: [
    swc.vite({
      module: { type: 'es6' },
    }),
  ],
  test: {
    environment: 'node',
    globals: false,
    include: ['test/**/*.{spec,test}.ts'],
    setupFiles: ['reflect-metadata'],
    pool: 'forks',
    testTimeout: 30_000,
    hookTimeout: 60_000,
  },
});
