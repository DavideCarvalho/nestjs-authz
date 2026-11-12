---
"@dudousxd/nestjs-authz": minor
"@dudousxd/nestjs-authz-typeorm": minor
"@dudousxd/nestjs-authz-drizzle": minor
"@dudousxd/nestjs-authz-mikro-orm": minor
"@dudousxd/nestjs-authz-prisma": minor
---

Add MCP dev tools: `AuthzModule` registers `authz_explain_check`, `authz_list_effective_roles` and `authz_list_effective_permissions` in the Aviary dev-tools slot (`Symbol.for('@dudousxd/aviary:dev-tools')`, created when absent). They register without an `authorize`, so the agent dev endpoint's `devTools.authorize` gates them (open outside production, denied in production without it); a hub that cannot gate console-less libs leaves them out. `devTools: { loadSubject, loadResource }` hands checks your models (default: `resolveUser` and `resourceLoaders`); `devTools: false` turns the tools off. New: `gate.explainFor(user, ability, resource?)`, `runInTenantScope(tenantId, fn)`, and `RoleProvider.describeRbac?(user)`, which the RBAC adapters implement; the adapters honour a scope forced by `runInTenantScope` ahead of their `tenant` resolver and the context tenant.
