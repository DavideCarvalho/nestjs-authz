---
"@dudousxd/nestjs-authz": patch
---

Consume the `context:accessor` capability via `InjectCapability` from `@dudousxd/nestjs-diagnostics/nestjs` instead of a hand-copied `Symbol.for` magic string, and derive `CONTEXT_ACCESSOR` from the `capability()` factory. Resolves to the byte-identical global symbol — fully non-breaking; the `ModuleRef` fallback is unchanged. Bumps the `@dudousxd/nestjs-diagnostics` dependency to `^0.5.0`.
