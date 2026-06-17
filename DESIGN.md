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

## 9. Não-objetivos
- Não autentica (não cria/loga/guarda user; só referencia por id).
- Não reimplementa CASL/Casbin (condição-como-dado / policy externa estão fora do escopo).
- Core não persiste — RBAC é adapter opt-in.
