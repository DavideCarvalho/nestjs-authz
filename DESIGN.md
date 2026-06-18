# `@dudousxd/nestjs-authz` — DESIGN

> Status: spec (impl pendente). Fase 1 do `../ECOSYSTEM-AUDIT.md`. Depende de `nestjs-context` (current user).

## 1. O que é (e o que NÃO é)

**Authorization** (o quê o user pode), idioma Laravel Gate/Policy. **NÃO é authentication** — não cria/guarda usuário, não faz login. Só lê o **current user** (do `nestjs-context`, ou recebido) e decide. Auth é BYO (Passport/JWT/session; `adonis-authkit` é Adonis, não Nest).

`authz` = autori**z**ation (authn = authenticatio**n**). Nome mantido por convenção.

## 2. Decisão de engine: PRÓPRIO thin (não wrapper)

Landscape **não** é green-field: **CASL** (`stalniy/casl`, isomórfico; `getjerry/nest-casl`) e **Casbin** (`node-casbin/nest-authz`) cobrem RBAC/ABAC. Mesmo assim → **engine próprio**, porque:
- Gate/Policy do Laravel **não é engine pesado** — é despacho fino sobre métodos TS (`update(u, post){...}` É a condição).
- CASL/Casbin resolvem *condição-como-dado* / *policy externa* — modelo que o idioma Laravel deliberadamente não tem; embrulhar importaria complexidade + mental model estranho que briga com `@Policy`.
- **Diferencial = idioma Laravel + as colas (§6)**, não o motor.

## 3. As 3 camadas

**1. Gates** — habilidade ad-hoc sem model:
```ts
gate.define('access-admin', (user) => user.role === 'staff');
```

**2. Policies** — classe por recurso (o coração):
```ts
@Policy(Post)
class PostPolicy {
  before(user) { if (user.isAdmin) return true; }          // bypass; undefined = segue
  view(user, post)   { return post.published || post.authorId === user.id; }
  update(user, post) { return post.authorId === user.id; }
  create(user)       { return user.verified; }              // ability de classe (sem instância)
}
```
Engine = **registry de policies** (por classe de recurso) + **resolver de recurso** + dispatch. ~poucas centenas de linhas.

**3. RBAC (roles/permissions persistido)** — pacote **opt-in separado** (core não tem DB, igual Laravel separa de spatie/permission):
```ts
await user.assignRole('editor');     // editor tem permission 'posts.publish'
gate.allows('posts.publish');        // policy/gate pode consultar a camada RBAC
```

## 4. Enforcement (idioma Nest)

**Decorator + guard:**
```ts
@Patch(':id')
@Can('update', Post)   // guard resolve o Post pelo :id e roda PostPolicy.update(currentUser, post)
update(@Param('id') id) {}
```

**Programático** (user vem do context, não precisa passar):
```ts
this.gate.authorize('update', post);     // throw ForbiddenException se negar
if (this.gate.allows('delete', post)) {}
```

**Resolver de recurso** (a pegadinha que justifica a lib): `@Can('update', Post)` precisa carregar a instância p/ passar à policy. Default = carrega por `:id` via ORM; override por rota; abilities de classe (`create`) pulam.

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

`ensureAuthzSchema` = **cria tabela faltante + adiciona coluna faltante** (non-destructive); colunas pós-v1 nullable/default. Adapters: `nestjs-authz-{typeorm,mikro-orm,prisma}` (mikro usa `getUpdateSchemaSQL({safe:true})`; prisma consumer-managed).

## 6. Colas (o diferencial)

| Cola | O que faz |
|---|---|
| **nestjs-context** | `gate.authorize('update', post)` lê o current user sozinho; permissions tenant-scoped via `Context.tenantId()` |
| **authkit/auth (BYO)** | guard de auth popula `Context.userRef()`; authz lê — zero acoplamento |
| **nestjs-authz-inertia** | middleware `HandleInertiaRequests`-style injeta `auth.can` nas props → front recebe `can('update', post)` |
| **nestjs-authz-codegen** | emite `can()` **tipado** no `api.ts` (ability errada = erro de compile) |
| **nestjs-authz-telescope** | watcher de autorização (ability, allow/deny, motivo, user) → aba; mata debug de 403 |
| **nestjs-authz-react** | `useCan()` + `<Can ability="update" of={post}>` |
| **filter** (depois) | policy `viewAny` aplica escopo de query no filter (só retorna o que o user pode ver) |

## 7. Config mínima
```ts
AuthzModule.forRoot({
  policies: [PostPolicy],        // ou auto-discovery por @Policy
  superAdmin: (u) => u.isAdmin,  // before-hook global
  // resolveUser?  // ⚠️ ver "current user no caminho do context" abaixo
  // resourceResolver? / idParam?  // override do resolver default (default: por :id)
});
```

### ⚠️ current user no caminho do context (`resolveUser`)

`@Can(...)` / `gate.allows(...)` (sem `forUser`) leem o current user do
`nestjs-context` como um **`UserRef` cru = `{ type, id }`** — NÃO a sua entidade
`User` hidratada. Logo, por padrão, `superAdmin: u => u.isAdmin` e checagens tipo
`post.authorId === user.id` contra uma coluna real **não enxergam campos
hidratados** no caminho do context (só `{type,id}`). Duas saídas:

1. **Hidratar** — passe `resolveUser: (ref) => loadUser(ref)` no `forRoot`; o Gate
   carrega a entidade a partir do `{type,id}` antes de policies/`before`/`superAdmin`.
   `resolveUser` retornando nullish = caminho de negação (anônimo).
2. **Comparar por id** — escreva as policies contra o `ref` (`Number(user.id) === ...`),
   sem depender de campos da entidade.

No caminho `gate.forUser(entity)` você recebe exatamente o que passou — `resolveUser`
NÃO é aplicado. `forUser(undefined|null)` = requisição anônima explícita → negação
(mesmo path que o context não-autenticado), nunca um `TypeError`/500.

### Resolver de recurso default (out-of-the-box)

`forRoot`/`forRootAsync` registram um `IdParamResourceResolver` no token
`RESOURCE_RESOLVER` automaticamente, então `@Can('update', Post)` funciona num
install limpo (lê o `:id` da rota e monta um shim `{ id }`). Override por
`resourceResolver` (instância própria, p.ex. ORM-backed) ou ajuste o nome do param
por `idParam`.

## 8. Pacotes
- `@dudousxd/nestjs-authz` — core: gates + policies + `@Can` guard + resolver (zero DB)
- `@dudousxd/nestjs-authz-{typeorm,mikro-orm,prisma}` — RBAC persistido (§5)
- `@dudousxd/nestjs-authz-{inertia,codegen,react,telescope,testing}` — colas (§6)

## 8.1 Adições pós-v1 (batch, cache, direct/tenant, testing)

Quatro melhorias coesas, todas backward-compatible (colunas nullable/defaulted, seams opcionais):

- **Batch (`gate.allowsMany`)** — autoriza N habilidades resolvendo o user UMA vez e
  compartilhando UM `PermissionCache` por lote (mata o N+1 de uma list page). Endpoint
  `POST /authz/can` aceita TAMBÉM um array (`[{ability,resource?}]` → `[{...,allowed}]`),
  e o client ganhou `createCanBatch` (faz POST só dos cache-misses, num único request).
  O codegen emite `canBatch(...)` tipado. Comparáveis: Cerbos `CheckResources` (batch),
  CASL não tem batch nativo.
- **Cache de permissões por request** — memo sobre `provider.getPermissions(user)`,
  guardado no store do nestjs-context (`Symbol.for(...request-permission-cache)`).
  Uma busca por request; standalone (sem context) degrada para sem-memo, correção
  intacta. Tenant é fixo por request, então a chave (user) basta.
- **Permissões diretas + roles por tenant (typeorm)** — `giveUserPermission`/
  `revokeUserPermission` + tabela `authz_user_permission` (spatie
  `$user->givePermissionTo`). `assignRole(user, role, { tenantId })` escopa por tenant;
  coluna `tenantId` é **defaulted `''`** (não nullable) para entrar na PK composta com
  unicidade portável entre SQLite/MySQL/Postgres (`NULL` quebraria idempotência do
  grant global). `getPermissionsForUser` = UNIÃO de role-derived (tenant-aware) +
  diretas (não escopadas). Tenant vem do nestjs-context quando presente.
- **`@dudousxd/nestjs-authz-testing`** — `buildGate`/`buildBoundGate` (Gate real,
  zero DB/Nest), `expectCan`/`expectCannot` (Pundit-style matchers; `expectCannot`
  trata ability não-resolvida como "cannot"), e `FakePermissionProvider`/
  `FakeRoleProvider` in-memory (wildcard via o matcher do core).

## 8.2 Query scoping / policy filter (`gate.scope` + `applyScope`)

O diferencial ABAC para list endpoints: hoje a authz decide sim/não para UM recurso;
para listas você ou over-fetch + filtra em memória (N+1 / risco de leak) ou escreve
`WHERE` na mão. Agora uma policy pode declarar um **scope** (conceito `accessibleBy` do
CASL / `policy_scope` do Pundit / `PlanResources` do Cerbos) que produz uma **constraint
ORM-neutra**, aplicada na camada do DB.

- **Representação escolhida — AST de condição (dado puro, não callback).** `ScopeConstraint`
  = `{ kind: 'all' }` (allow-all) | `{ kind: 'none' }` (deny-all) |
  `{ kind: 'condition', field, op, value }` | `{ kind: 'and'|'or', nodes }`. Operadores:
  `eq/ne/gt/gte/lt/lte/in/nin/isNull/isNotNull`. Builders: `eq`, `where`, `and`, `or`,
  `scopeAll`, `scopeNone`. Escolhido por ser **serializável, seguro e portável** — cada
  adapter percorre a árvore e emite `WHERE` parametrizado. Espelha o Query Plan do Cerbos
  (`ALWAYS_ALLOWED`/`ALWAYS_DENIED`/AST), diferente do `where`-object acoplado a ORM do
  CASL. (Comparados: CASL `accessibleBy`, Pundit `policy_scope`, Cerbos `PlanResources`.)
- **API core.** `@Policy(Entity)` define um método `scope(user)` (ou fallback estilo
  `viewAny`) retornando `ScopeConstraint | boolean | null`. `gate.scope(Entity, ability?)`
  / `boundGate.scope(...)` resolvem a constraint seguindo a MESMA ordem de grant do
  single-resource: super-admin / `before` / permission-provider grant → **allow-all**;
  anônimo, sem policy, ou sem método de scope → **deny-all** (deny-by-default consistente).
  Tenant do nestjs-context flui pelo permission-provider (mesmo seam do RBAC tenant-aware).
- **Aplicação TypeORM (caminho primário, manual).**
  `applyScope(qb, gate, Entity)` (resolve + aplica) ou
  `applyScopeConstraint(qb, await gate.scope(Entity))` (split). Usa placeholders nomeados
  do TypeORM (`:p`, `:...p` para `IN`) — valores SEMPRE bound, nunca interpolados;
  identificadores (coluna/alias) validados por `assertSafeIdentifier` (mesmo allowlist do
  store). `allow-all` não adiciona `WHERE`; `deny-all` adiciona `1 = 0`. `compileScope` é
  o compilador puro (testável sem DB).
- **Adapters seguintes (deferidos).** A AST e o adapter TypeORM estão prontos;
  mikro-orm / prisma reusam a MESMA `ScopeConstraint` do core (só falta o walker
  específico) — follow-up.

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
- Não autentica (não cria/loga/guarda user; só referencia por id).
- Não reimplementa CASL/Casbin (condição-como-dado / policy externa estão fora do escopo).
- Core não persiste — RBAC é adapter opt-in.
