# `@dudousxd/nestjs-authz` — DESIGN

> Status: v1 em cima do [`@nestjs/authorization`](https://docs.nestjs.com/security/authorization) (0.1.x, NestJS 12).

## 1. O que é (e o que NÃO é)

**Os extras** que faltam no `@nestjs/authorization` oficial: RBAC persistido, helpers de `@Can`,
um `Gate` de serviço com batch e gates ad-hoc, super-admin global, query scoping, e as colas de
front (inertia/codegen/client/react) e de teste. **NÃO é authentication** e **não é mais um
engine de autorização**: quem decide é o oficial.

## 2. Decisão: em cima do oficial, não paralelo

Até a 0.x tínhamos `@Policy(Resource)`, `@Can('ability', Resource)`, `CanGuard`, `RolesGuard` e
um Gate com engine próprio. O NestJS lançou o `@nestjs/authorization` (`@Policy()`, `@Can(Policy,
'ability', args?)`, `Can.Anyone()`, `AuthorizationGuard` global e deny-by-default,
`AuthorizationService.can/authorize`, eventos de negação). Regra do dono: **o que o oficial faz,
a gente larga e usa o dele; o que falta, a gente mantém e constrói em cima.**

| Oficial (usamos) | Nosso (em cima) |
|---|---|
| `@Policy()`, `@Can()`, `Can.Anyone()`, `AuthorizationGuard`, `getUser` | `RolePolicy`, `PermissionPolicy`, `GatePolicy` (policies oficiais) |
| `AuthorizationService.can/authorize` | `Gate` (string abilities, `allowsMany`, `scope`, `define`, `hasRole`, user ambiente) |
| `before()` por policy | `AuthzPolicy` / `superAdminBefore` / `decisionProviderBefore` (super-admin global + PDP externo) |
| `AuthenticationContext.user` (`@nestjs/authentication`) | user ambiente do `Gate` (lido primeiro; nestjs-context é o fallback) |
| `args` resolver de `@Can` | `byId(Post)`, `roles()`, `permission()`, `ability()`, `staticCanArgs()` |
| evento de negação | canal `authz:decision` com allow **e** deny |
| — | `@PolicyFor(Post)` (link recurso → policy), `@Roles`/`@Permission` (açúcar) |

## 3. As camadas

**1. Policies** — do oficial. `@PolicyFor(Post)` só adiciona o link usado pelos extras:
```ts
@Policy()
@PolicyFor(Post)
class PostPolicy extends AuthzPolicy {          // AuthzPolicy = super-admin global no before()
  view(user: User | null, post: Post)   { return post.published || post.authorId === user?.id; }
  update(user: User | null, post: Post) { return post.authorId === user?.id; }
  create(user: User | null)             { return user?.verified === true; }
  scope(user: User)                     { return eq('authorId', user.id); } // query scoping
}
```

**2. RBAC** como policies oficiais:
```ts
@Can(RolePolicy, 'has', roles('admin', 'editor'))      // == @Roles('admin', 'editor')
@Can(PermissionPolicy, 'has', permission('posts.publish')) // == @Permission('posts.publish')
```
`RolePolicy` lê `user.roles`/`user.role` (ou `resolveRoles`) ∪ o `ROLE_PROVIDER` do adapter;
`PermissionPolicy` usa o `PERMISSION_PROVIDER` (wildcard `posts.*`, tenant, permissões diretas).

**3. Gates ad-hoc** — `gate.define('access-admin', fn)`, usáveis em rota por
`@Can(GatePolicy, 'allows', ability('access-admin'))`.

## 4. Enforcement

**Rota** — só o guard oficial (global, deny-by-default: rota sem `@Can`/`Can.Anyone()`/`@Public()`
é negada; convidado → 401, logado → 403):
```ts
@Patch(':id')
@Can(PostPolicy, 'update', byId(Post))  // byId carrega o Post do :id pelo ResourceResolver
update(@Req() req) { const post = authorizedResource(req, Post); }  // sem carregar 2x
```

**Serviço** — `Gate` delega toda decisão de policy ao `AuthorizationService`:
```ts
await gate.forUser(user).authorize(PostPolicy, 'update', post); // igual ao oficial
await gate.forUser(user).authorize('update', post);             // string: policy linkada ao Post
await gate.forUser(user).allowsMany([{ ability: 'update', resource: post }, ...]);
```
Ordem da string ability: `superAdmin` (recebe o recurso) → `DECISION_PROVIDER` (PDP externo:
allow/deny final, `undefined` abstém) → policy linkada (oficial: `before()` + ability, só `true`
literal libera) → permissão persistida → gate ad-hoc → `AbilityNotResolvedException`. A forma com
classe de policy é exatamente o oficial.

**A policy tem a palavra final.** Uma permissão persistida com o nome de uma ability da policy
(`update`) **não** a contorna (antes contornava, estilo spatie `Gate::before`); só `superAdmin`
curto-circuita. Permissões continuam liberando abilities nomeadas que nenhuma policy define
(`posts.publish`). Mesmo critério no `scope()`.

**User ambiente** (chamada sem `forUser`): `AuthenticationContext.user` do
`@nestjs/authentication` (peer opcional, achado pelo `ModuleRef` com a classe como token; é um
`AsyncLocalStorage`, certo no handler e em tudo que ele aguarda) → senão o ref do nestjs-context
(hidratado por `resolveUser`, uma vez por request) → senão convidado (`null`).

**Resolver de argumento sem DI.** Os resolvers do `@Can` oficial só recebem o
`ExecutionContext`. O `AuthzModule` registra no boot uma referência de módulo (resolver de
recurso, `superAdmin`, o `DECISION_PROVIDER`, `getUser` oficial) que `byId` e `AuthzPolicy` leem. Um app por processo
é o esperado; com vários, o último a subir vence.

**Args estáticos.** Resolvers cujos args não dependem da chamada (`roles`, `permission`,
`ability`, `staticCanArgs`) carregam uma propriedade não-enumerável
`Symbol.for('@dudousxd/static-can-args')` com o array de args, para o agente do Aviary avaliar
a exigência antes de oferecer uma tool.

## 5. Persistência (RBAC) — segue §3.10 do audit À RISCA

Só a camada RBAC persiste. Store = **POJO** que recebe a conexão no construtor (igual `TypeOrmStateStore` do durable), **não** `@Injectable`, sem token interno:

```ts
// nestjs-authz-typeorm
export class TypeOrmAuthzStore { constructor(private ds: DataSource, opts?: AuthzStoreOptions) {} }
export { RoleEntity, PermissionEntity, RolePermissionEntity, UserRoleEntity }  // gerencie pelo seu ORM
export { createAuthzTables, ensureAuthzSchema }                                 // migration helper + boot ensure
```

App pluga a conexão via `forRootAsync` — token é escolha do app, não da lib:
```ts
AuthzRbacModule.forRootAsync({
  inject: [getDataSourceToken('auth')],         // ou [DataSource] p/ default
  useFactory: (ds) => ({
    store: new TypeOrmAuthzStore(ds),
    autoCreateSchema: true,                      // default; non-destructive; false → migrations
    schema: 'auth',                              // schema Postgres opcional (NÃO "connection")
    tableNames: { roles, permissions, roleUser, rolePermission },  // BYO nomes
  }),
});
```

`ensureAuthzSchema` = **cria tabela faltante + adiciona coluna faltante** (non-destructive); colunas pós-v1 nullable/default. Adapters: `nestjs-authz-{typeorm,mikro-orm,prisma,drizzle}` (mikro usa `getUpdateSchemaSQL({safe:true})`; prisma consumer-managed).

## 6. Colas

| Cola | O que faz |
|---|---|
| **nestjs-authz-inertia** | compartilha `auth.can` com as abilities sem registro de toda policy oficial (linkada ou não), para o user que o guard oficial lê; redireciona 401 → login e 403 → `/403` |
| **nestjs-authz-codegen** | lê `@Can(Policy, 'ability', byId(X))`, `@Permission`, `GatePolicy` e `@Policy()`/`@PolicyFor()` e emite `can()` tipado |
| **nestjs-authz-client / react** | store de abilities + `useCan()`/`<Can>` (sem mudança de API) |
| **telescope** | canal `aviary:authz:decision` com allow **e** deny (o oficial só publica negações em `nestjs:authorization:denied`) |
| **nestjs-authz-testing** | `buildGate` num testing module real com o oficial, `expectCan`, `requirementsOf()` |

## 7. Config mínima
```ts
imports: [
  AuthorizationModule.forRoot({ getUser: (ctx) => ctx.switchToHttp().getRequest().user }),
  AuthzModule.forRoot({
    superAdmin: (u) => u?.isRoot === true,  // honrado por AuthzPolicy, RolePolicy, PermissionPolicy, Gate
    resourceResolver: new OrmResourceResolver(),  // para byId(); default lê :id e monta { id }
  }),
  AuthzRbacModule.forRootAsync({ ... }),    // opcional: RBAC persistido
]
```
`resolveUser` só vale para o user **ambiente** do `Gate` (chamada sem `forUser`, via
nestjs-context, quando o `AuthenticationContext` não tem user). Rotas nunca usam: o user vem do
`getUser` oficial.

## 7.1 Compromissos forçados pela API oficial

- **Deny-by-default.** O guard oficial nega rota sem declaração. Antes, rota sem `@Can` passava.
- **`@Roles` em classe soma (AND)** com o do método; antes o do método sobrescrevia.
- **Só `true` literal libera.** `{ allowed, message }` (`PolicyResponse`) e o hook `after` foram
  removidos: o avaliador oficial não tem "sem opinião" nem mensagem; a resposta nunca nomeia a
  policy/ability (o `AuthorizationError` carrega isso para log).
- **Policy recebe `null`** para convidado (antes, convidado era negado sem chamar a policy).
  Tipar o user como `User | null`.
- **Super-admin não é global no guard**: só policies que estendem `AuthzPolicy` (ou chamam
  `superAdminBefore`) o consultam.
- **Resolver de args sem DI** → referência de módulo registrada no boot (§4).
- **Constantes de metadata não exportadas** → lidas/escritas por string
  (`'authorization:can'`, `'authorization:policy'`, `'authorization:can-anyone'`), com teste de
  contrato (`official-contract.spec.ts`).
- **Registro oficial não exportado** → `PolicyIndex` acha policies pelo `DiscoveryService` com o
  mesmo critério (token ou metatype marcado).
- **O `@Can` string depreciado** escreve um requisito cujo `policy` é um getter preguiçoso
  (resolvido na checagem de boot do oficial), para não depender da ordem de import.
- **Allow no guard**: o oficial não emite. Um interceptor (roda depois que todos os guards
  liberaram) publica um allow por requisito; negações vêm do `AuthorizationEvents`.

## 8. Pacotes
- `@dudousxd/nestjs-authz` — extras sobre o oficial (zero DB)
- `@dudousxd/nestjs-authz-{typeorm,mikro-orm,prisma,drizzle}` — RBAC persistido (§5)
- `@dudousxd/nestjs-authz-{inertia,codegen,client,react,testing}` — colas (§6)

## 8.1 Batch, cache, direct/tenant

- **Batch (`gate.allowsMany`)** — resolve o user UMA vez e compartilha UM `PermissionCache`; um
  item que falha nega só ele. Aceita `{ ability, resource? }` e `{ policy, ability, args? }`.
  `POST /authz/can` aceita array; o client tem `createCanBatch`; o codegen emite `canBatch`.
- **Cache por request** — memo de `provider.getPermissions(user)`, `RoleProvider.getRoles(user)`
  e do `resolveUser` no store do nestjs-context. Compartilhado entre o guard oficial
  (`RolePolicy`/`PermissionPolicy`) e as chamadas do `Gate` no handler: uma busca por user por
  request. Chave = a linha que o user nomeia (classe ou `type` + `id`; objeto puro sem `type` →
  identidade). O set é compilado uma vez (`CompiledPermissions`); com `exhaustivePermissions`
  (os adapters marcam) um miss não chama `hasPermission`. Sem context, sem memo (correção intacta).
- **Permissões diretas + roles por tenant** — inalterado (adapters).

## 8.2 Query scoping (`gate.scope` + `applyScope`)

AST de condição ORM-neutra (`ScopeConstraint`: `all` | `none` | `condition` | `and`/`or`),
aplicada pelos adapters como `WHERE` parametrizado. A policy oficial declara `scope(user,
entity)` (ou o fallback no método da ability, `viewAny`). `gate.scope(Post | PostPolicy)` segue
a ordem: `superAdmin` → `all`; `planScope` do `DECISION_PROVIDER` (se não abstém) → usado como
está; `before()` `true`/`false` → `all`/`none`; convidado → `none`; o `scope()` da policy. Sem
policy ou sem método, um grant de permissão → `all`, senão `none` (a permissão não alarga o
scope de uma policy). `scope` não é ability (não
retorna boolean) e é ignorado pelas listas de abilities.

## 8.3 PDP externo (`DECISION_PROVIDER`, Cerbos em `/cerbos`)

Seam autoritativo (allow **e** deny, `undefined` abstém), ao contrário do RBAC (só grant).
Consultado logo depois do `superAdmin`: nas rotas, pelo `before()` de toda policy que estende
`AuthzPolicy` (com o primeiro argumento da ability como recurso; `RolePolicy`/`PermissionPolicy`
não consultam — suas abilities não nomeiam recurso); no `Gate`, antes da policy de uma string
ability; `allowsMany` faz um `decideMany` só; `scope()` usa `planScope`. O adapter Cerbos falha
fechado (nega).

## 8.b Matriz de testes multi-dialeto (TypeORM)

O store/scope-compiler do TypeORM emite SQL dialeto-sensível (placeholders `$n` vs `?`,
`ON CONFLICT` vs `INSERT IGNORE`, quoting de identificadores). Testar só em sqlite
escondeu bugs que **só** Postgres/MySQL reais pegam (vide REVIEW.md — bug do placeholder
`?` no pg). Para travar isso:

- **Specs comportamentais parametrizadas por dialeto.** Os fixtures compartilhados em
  `test/support/datasource.ts` (`freshAuthzDataSource`, `freshSyncDataSource`) constroem o
  `DataSource` do dialeto-alvo lido de `AUTHZ_TEST_DIALECT` (default `sqlite`). As MESMAS
  specs de `*.integration.spec.ts` rodam em sqlite (no `pnpm test` default) e em
  Postgres + MySQL reais (`pnpm test:db`). Isolamento sem churn de banco: cada fixture
  recebe um **prefixo de tabela único** (o container é compartilhado entre os testes), e o
  scope spec gera uma entidade `Post` com nome de tabela único por teste. As specs
  asseguram a superfície completa: CRUD de roles/permissions, role↔perm, user↔role
  (com tenant), permissões diretas (give/revoke), união de `getPermissionsForUser`,
  wildcard end-to-end via Gate, `ensureAuthzSchema`/`createAuthzTables` não-destrutivos e
  idempotentes, e os resultados de `applyScope`.
- **`pnpm test:db` (matriz real, separada do default).** `vitest.db.config.ts` roda só os
  `*.integration.spec.ts` num único fork sequencial; o global-setup
  `test/support/testcontainers-setup.ts` sobe Postgres (`@testcontainers/postgresql`) e
  MySQL (`@testcontainers/mysql`) e injeta a config de conexão via env. Sem Docker, o
  setup captura o erro de start, seta `AUTHZ_TEST_SKIP=1` e o `describeIntegration` vira
  `describe.skip` — o run sai verde em vez de vermelho. DevDeps adicionadas:
  `@testcontainers/postgresql`, `@testcontainers/mysql`, `pg`, `mysql2`.

**Dois bugs de dialeto encontrados e corrigidos (só pegos pelos engines reais):**

1. **Nomes de constraint colidindo no Postgres (`schema.ts`).** Ao renomear a tabela
   (BYO names / prefixo único), `Table.create` mantinha os nomes de índice/unique gerados
   pelo nome DEFAULT da entidade — então duas tabelas da MESMA entidade sob nomes
   diferentes emitiam o MESMO `IDX_…`. sqlite tolera (índice é por-tabela); Postgres
   trata nome de índice como global e rejeita o 2º `CREATE TABLE`
   (`relation "IDX_…" already exists`). Fix: após renomear, regerar os nomes de
   índice/unique/check a partir do nome NOVO via `connection.namingStrategy`.
2. **Quoting de identificador no MySQL (`scope.ts`).** `compileScope` fixava aspas duplas
   (`"alias"."field"`) — válido em Postgres/sqlite, mas MySQL/MariaDB usam crase e
   REJEITAM `"…"` como identificador. Fix: `compileScope` aceita um `escapeId` injetável
   (default = aspas duplas, mantendo os unit tests puros) e `applyScopeConstraint` passa o
   `driver.escape` do `DataSource`, tornando o predicado portável.

## 9. Não-objetivos
- Não autentica (use `@nestjs/authentication`, Passport, etc.).
- Não reimplementa o engine: decisões de policy são do `@nestjs/authorization`.
- Core não persiste — RBAC é adapter opt-in.

## 10. Depreciado (uma major) → removido depois

| Depreciado | Use |
|---|---|
| `@Can('update', Post)` (nosso) | `@Can(PostPolicy, 'update', byId(Post))` (oficial) |
| `@Can('create', Post, { classLevel: true })` | `@Can(PostPolicy, 'create')` |
| `@Can('access-admin')` | `@Can(GatePolicy, 'allows', ability('access-admin'))` |
| `@Policy(Post)` (nosso) | `@Policy()` (oficial) + `@PolicyFor(Post)` |

Removidos já na v1: `CanGuard`, `RolesGuard`, `PolicyRegistry` (→ `PolicyIndex`),
`CAN_METADATA`, `ROLES_METADATA`, `AuthzModuleOptions.policies` (→ providers ou
`AuthorizationModule.forRoot({ policies })`), `after`, `PolicyResponse`,
`PolicyNotDecoratedException`, `ResourceResolverMissingException`.
