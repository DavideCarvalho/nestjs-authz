---
"@dudousxd/nestjs-authz-drizzle": minor
"@dudousxd/nestjs-authz-typeorm": minor
---

`AuthzRbacModule.forRoot({ connectionName, storeOptions })` (and `forRootAsync({ connectionName, storeOptions, useFactory })`) builds the store from a connection registered with NestJS's `@nestjs/drizzle` / `@nestjs/typeorm`, injecting `getDrizzleToken(connectionName)` / `getDataSourceToken(connectionName)` (`'default'` for the default connection). Both are optional peers. Passing a `store` you built yourself works as before. `AuthzRbacModuleOptions` is now a union of the two forms, and `AuthzRbacModuleAsyncOptions` takes `connectionName` next to `useFactory`.
