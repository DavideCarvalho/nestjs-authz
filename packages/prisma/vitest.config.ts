import swc from 'unplugin-swc';
import { configDefaults, defineConfig } from 'vitest/config';

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
    // The Docker-backed `*.pg.spec.ts` belongs to `pnpm test:db:pg`; exclude it here
    // so the default `pnpm test` runs only the in-memory fake-based specs.
    exclude: [...configDefaults.exclude, 'test/**/*.pg.spec.ts'],
    setupFiles: ['reflect-metadata'],
    pool: 'forks',
  },
});
