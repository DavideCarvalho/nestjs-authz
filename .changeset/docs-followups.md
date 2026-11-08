---
"@dudousxd/nestjs-authz": patch
"@dudousxd/nestjs-authz-codegen": patch
---

README fixes: the codegen README no longer describes the removed `PostPolicy` → `Post` name guess and lists `@PolicyFor` among the names that must not be aliased; the core README covers the dropped `DecisionProvider` deny message and the expected boot error under `unannotated: 'allow'`.
