---
"@dudousxd/nestjs-authz": minor
"@dudousxd/nestjs-authz-typeorm": minor
"@dudousxd/nestjs-authz-mikro-orm": minor
"@dudousxd/nestjs-authz-prisma": minor
"@dudousxd/nestjs-authz-client": minor
"@dudousxd/nestjs-authz-codegen": minor
---

Ecosystem improvements across the authz packages.

### Permissions

- **Wildcard / hierarchical permissions.** Permission strings now support wildcard
  and hierarchical matching (e.g. `posts:*` or `posts:read:*`), so a single granted
  permission can authorize a family of related actions instead of enumerating each one.

### Authorization decisions

- **Deny reason / message surfaced on `ForbiddenException`.** When a check fails, the
  reason for the denial is propagated onto the thrown `ForbiddenException`, making it
  possible to return a meaningful message to the caller and to debug authorization
  failures.
- **Gate `after` hook.** The Gate now exposes an `after` hook that runs once a decision
  has been made, enabling cross-cutting concerns such as auditing, logging, and metrics.

### Batch authorization

- **`allowsMany`** for evaluating multiple permission checks in a single call.
- **Batch `/authz/can` endpoint** so clients can resolve many checks in one round trip.
- **`createCanBatch`** client helper that batches `can` calls transparently.

### Performance

- **Request-scoped permission cache.** Permissions resolved during a request are cached
  for the lifetime of that request, avoiding repeated lookups on the hot path.

### RBAC adapters (TypeORM)

- **Direct user permissions** granted to a user independent of their roles.
- **Tenant-scoped roles** so the same role can be assigned per tenant in multi-tenant
  deployments.

### Query scoping / policy filter (ABAC)

- **ORM-neutral constraint AST.** Policies can produce a portable constraint
  representation describing which rows a subject may access.
- **Per-ORM application.** The constraint AST is translated and applied for
  **TypeORM**, **MikroORM**, and **Prisma**, giving ABAC-style query scoping that
  filters data at the database layer regardless of the ORM in use.

### Testing

- **New `@dudousxd/nestjs-authz-testing` package** with fakes and helpers for testing
  authorization in consumer applications.
- **Postgres / MySQL testcontainers + contract tests** so the ORM stores are verified
  against real database engines, and a shared contract suite keeps the adapters
  behaviorally consistent.

### Housekeeping

- **Packaging hygiene** across the published packages.
