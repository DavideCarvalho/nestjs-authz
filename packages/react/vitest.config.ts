import swc from 'unplugin-swc';
import { defineConfig } from 'vitest/config';

export default defineConfig({
  plugins: [
    swc.vite({
      jsc: { transform: { react: { runtime: 'automatic' } } },
      module: { type: 'es6' },
    }),
  ],
  test: {
    environment: 'jsdom',
    globals: false,
    include: ['test/**/*.{spec,test}.{ts,tsx}'],
    pool: 'forks',
  },
});
