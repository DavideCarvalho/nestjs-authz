---
"@dudousxd/nestjs-authz": patch
"@dudousxd/nestjs-authz-client": patch
"@dudousxd/nestjs-authz-inertia": patch
"@dudousxd/nestjs-authz-react": patch
---

Fix the exported `VERSION` const shipping as `'0.0.0'`.

The build is plain `tsc` with no version injection, and `changeset version` only bumps `package.json` — leaving the `export const VERSION` in `src/index.ts` stale, so the published dist reported `'0.0.0'`. The const is now corrected to match each package's `package.json`, and a new `scripts/sync-version.mjs` (chained into the `version-packages` script) re-syncs it on every release bump to prevent future drift. Run with `--check` to fail a build on mismatch.
