---
"@dudousxd/nestjs-authz": patch
---

Document what keeps the exported `VERSION` const in sync

Comment-only change: notes above `export const VERSION` in `src/index.ts` that the
literal is rewritten from `package.json` by `scripts/sync-version.mjs`, chained into the
root `version-packages` script after `changeset version`. No runtime behaviour changes.
