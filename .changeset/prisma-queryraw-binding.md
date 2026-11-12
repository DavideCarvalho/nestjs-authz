---
"@dudousxd/nestjs-authz-prisma": patch
---

Fix the `$queryRaw` permission fast path: it is now called on the client instead of detached from it. A real `PrismaClient` threw on the unbound call, so every permission check silently fell back to the three-query path.
