---
"@dudousxd/nestjs-authz": minor
"@dudousxd/nestjs-authz-typeorm": minor
"@dudousxd/nestjs-authz-drizzle": minor
"@dudousxd/nestjs-authz-mikro-orm": minor
"@dudousxd/nestjs-authz-prisma": minor
---

Tenancy for nested tenants, tenant families and required tenants (nestjs-context's chain contract, read structurally, so older contexts keep working):

- A role or grant assigned at any level of the active tenant chain applies (a clinic role counts inside its units). `tenancy.kinds` picks the levels, and the context's own `kinds` apply when the module sets none.
- `tenancy.roles` maps the caller's role at every level of the chain.
- New `tenancy.family` option.
- New `tenancy.required` option, defaulting to the context's. A check with no tenant throws `TenantRequiredError` (403, `E_TENANT_REQUIRED`) instead of running in the global scope.
- Console `authorize` helpers, the MCP dev tools, and the new `runWithoutRequiredTenant(fn)` pass `required: false`.
- `describeRbac` reports the `tenantChain`.
