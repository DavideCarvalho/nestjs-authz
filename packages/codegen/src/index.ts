import type { RouteDescriptor } from '@dudousxd/nestjs-codegen';
import type {
  CodegenExtension,
  ExtensionContext,
  LeafModel,
} from '@dudousxd/nestjs-codegen/extension';
import { type ClassDeclaration, Node, type Project, type SourceFile, SyntaxKind } from 'ts-morph';

/**
 * A client ability discovered on a controller route (the official `@Can(Policy, 'ability', ...)`,
 * or `@Permission`), or on a policy class (`@Policy()`,
 * `@PolicyFor(Resource)`). Read statically from the AST: reflect-metadata is not available at
 * codegen time.
 */
export interface AuthzAbilityInfo {
  /** The ability string, e.g. `'update'` or `'access-admin'`. */
  ability: string;
  /** The resource class name the ability targets (from `byId(Resource)` or the policy's link). */
  resource?: string;
}

/** Per-route authz marker we attach to the route IR so `apiMembers` can read it back. */
interface AuthzRouteMarker {
  ability: string;
  resource?: string;
}

/** Options for {@link nestjsAuthzCodegen}. */
export interface AuthzCodegenOptions {
  /**
   * Server endpoint the generated `can()` helper falls back to when an ability/resource is not
   * already hydrated in the shared store. Default `'/authz/can'`. Wired through to
   * `@dudousxd/nestjs-authz-client`'s `createCan` as its `'fetch'` fallback endpoint; expose a tiny
   * controller in your app that delegates to the `Gate` (`gate.allows(ability, resource)`).
   */
  endpoint?: string;
  /**
   * Also discover `@Policy()` / `@PolicyFor(Resource)` classes and treat their public method names as class-level
   * abilities (so e.g. `PostPolicy.publish` contributes `'publish'` to the union even when no
   * route is decorated with it yet). Default `true`.
   */
  discoverPolicies?: boolean;
}

const DEFAULT_ENDPOINT = '/authz/can';

/** Built-in policies whose abilities are not client abilities themselves. */
const ROLE_POLICY = 'RolePolicy';
const PERMISSION_POLICY = 'PermissionPolicy';
const GATE_POLICY = 'GatePolicy';

/** The string literals among `args`, e.g. `permission('a', 'b')` → `['a', 'b']`. */
function stringArgs(args: Node[]): string[] {
  return args.flatMap((a) => (Node.isStringLiteral(a) ? [a.getLiteralValue()] : []));
}

/** `byId(Post)` / `staticCanArgs('x')` → its callee name and arguments. */
function callOf(node: Node | undefined): { name: string; args: Node[] } | undefined {
  if (!node || !Node.isCallExpression(node)) return undefined;
  return { name: node.getExpression().getText(), args: node.getArguments() };
}

/**
 * The resource a policy class is linked to: `@PolicyFor(Post)`, else the class name without `Policy` (`PostPolicy` → `Post`).
 */
function resourceOfPolicy(policyName: string, project: Project): string | undefined {
  for (const sourceFile of project.getSourceFiles()) {
    const classDecl = sourceFile.getClass(policyName);
    if (!classDecl) continue;
    const linked = resourceNameFromPolicy(classDecl);
    if (linked) return linked;
  }
  return policyName.endsWith('Policy')
    ? policyName.slice(0, -'Policy'.length) || undefined
    : undefined;
}

/**
 * Read the client abilities one `@Can(...)` (or sugar) decorator declares:
 *
 * - official `@Can(PostPolicy, 'update', byId(Post))` → `update` on `Post` (from `byId`, else
 *   the policy's `@PolicyFor` link, else its name)
 * - `@Can(PermissionPolicy, 'has', permission('posts.publish'))` / `@Permission('posts.publish')`
 *   → the named permissions, model-less
 * - `@Can(GatePolicy, 'allows', ability('access-admin'))` → `access-admin`
 *
 * Roles (`@Roles`, `RolePolicy`) are not client abilities.
 */
function readCanDecorator(name: string, args: Node[], project: Project): AuthzAbilityInfo[] {
  if (name === 'Permission') return stringArgs(args).map((ability) => ({ ability }));
  if (name !== 'Can') return [];
  const [first, second, third] = args;
  if (!first) return [];
  if (!Node.isIdentifier(first) || !second || !Node.isStringLiteral(second)) return [];
  const policy = first.getText();
  const ability = second.getLiteralValue();
  const resolver = callOf(third);
  if (policy === ROLE_POLICY) return [];
  if (policy === PERMISSION_POLICY || policy === GATE_POLICY) {
    return resolver ? stringArgs(resolver.args).map((a) => ({ ability: a })) : [];
  }
  const info: AuthzAbilityInfo = { ability };
  const fromById = resolver?.name === 'byId' ? resolver.args[0] : undefined;
  const resource =
    fromById && Node.isIdentifier(fromById)
      ? fromById.getText()
      : resourceOfPolicy(policy, project);
  if (resource) info.resource = resource;
  return [info];
}

/** Every client ability declared on a method or class, top-down. */
function abilitiesOn(
  decorated: { getDecorators(): Array<{ getName(): string; getArguments(): Node[] }> },
  project: Project,
): AuthzAbilityInfo[] {
  return decorated
    .getDecorators()
    .flatMap((d) => readCanDecorator(d.getName(), d.getArguments(), project));
}

/**
 * Discover the abilities on the controller method backing a route, then on its class
 * (the official guard applies both). The first one is the route's own ability.
 */
function discoverRouteAbilities(route: RouteDescriptor, project: Project): AuthzAbilityInfo[] {
  const ref = route.controllerRef;
  if (!ref) return [];
  let sourceFile: SourceFile | undefined;
  try {
    sourceFile = project.addSourceFileAtPathIfExists(ref.filePath) ?? undefined;
  } catch {
    sourceFile = undefined;
  }
  if (!sourceFile) sourceFile = project.getSourceFile(ref.filePath);
  if (!sourceFile) return [];

  const classDecl = sourceFile.getClass(ref.className);
  if (!classDecl) return [];
  const method = classDecl.getMethod(ref.methodName);
  return [...(method ? abilitiesOn(method, project) : []), ...abilitiesOn(classDecl, project)];
}

/** Names that make a class a policy: the official `@Policy()` and `@PolicyFor(X)`. */
const POLICY_DECORATORS = new Set(['Policy', 'PolicyFor']);

/** Members of a policy that are not abilities. */
const NOT_ABILITIES = new Set(['before', 'scope', 'constructor']);

/**
 * Discover the abilities of every policy class (`@Policy()`, `@PolicyFor(X)`): each public
 * instance method but `before` and `scope`, keyed to the policy's resource.
 */
function discoverPolicyAbilities(project: Project): AuthzAbilityInfo[] {
  const found: AuthzAbilityInfo[] = [];
  for (const sourceFile of project.getSourceFiles()) {
    for (const classDecl of sourceFile.getClasses()) {
      if (!classDecl.getDecorators().some((d) => POLICY_DECORATORS.has(d.getName()))) continue;
      const resource =
        resourceNameFromPolicy(classDecl) ?? resourceOfPolicy(classDecl.getName() ?? '', project);
      for (const method of classDecl.getMethods()) {
        if (method.isStatic() || method.hasModifier(SyntaxKind.PrivateKeyword)) continue;
        const name = method.getName();
        if (NOT_ABILITIES.has(name)) continue;
        const ability: AuthzAbilityInfo = { ability: name };
        if (resource) ability.resource = resource;
        found.push(ability);
      }
    }
  }
  return found;
}

/** `@PolicyFor(Post)` → `'Post'`; `undefined` without the link (the official `@Policy()` alone). */
function resourceNameFromPolicy(classDecl: ClassDeclaration): string | undefined {
  for (const decorator of classDecl.getDecorators()) {
    if (decorator.getName() !== 'PolicyFor') continue;
    const arg = decorator.getArguments()[0];
    if (arg && Node.isIdentifier(arg)) return arg.getText();
  }
  return undefined;
}

/** The string-literal union of all discovered abilities, e.g. `"update" | "create"` (or `never`). */
function abilityUnion(abilities: Set<string>): string {
  if (abilities.size === 0) return 'never';
  return [...abilities].map((a) => JSON.stringify(a)).join(' | ');
}

/** The `{ "Post": ["update", "create"] }` literal mapping each resource to its abilities. */
function resourceAbilityMapLiteral(byResource: Map<string, Set<string>>): string {
  if (byResource.size === 0) return '{}';
  const entries = [...byResource.entries()].map(
    ([resource, abilities]) =>
      `${JSON.stringify(resource)}: [${[...abilities].map((a) => JSON.stringify(a)).join(', ')}]`,
  );
  return `{ ${entries.join(', ')} }`;
}

/** The `import { ... } from '@dudousxd/nestjs-authz-client'` line the header contributes. */
function canHelperImports(): string[] {
  return [
    "import { AbilityStore, createCan, createCanBatch } from '@dudousxd/nestjs-authz-client';",
    "import type { ResourceRef, BatchAbilityResult } from '@dudousxd/nestjs-authz-client';",
  ];
}

/**
 * The top-level `can()` helper + `AuthzAbility` type contributed to `api.ts`. Rather than a
 * hand-rolled POST, this DELEGATES to `@dudousxd/nestjs-authz-client`: it exports a shared
 * `authzStore` ({@link AbilityStore}) you hydrate once (e.g. from Inertia props), and `can()` is a
 * thin typed wrapper over the store's `createCan` resolver — so a hydrated decision is answered
 * SYNCHRONOUSLY with NO request, and a cache miss uses the same configurable `'fetch'` fallback to
 * {@link AuthzCodegenOptions.endpoint}. `ability` is a compile-time-checked union of discovered
 * abilities, so a typo'd ability is a type error.
 */
function canHelperStatements(union: string, mapLiteral: string, endpoint: string): string[] {
  return [
    '/** Every authorization ability discovered from `@Can`/`@Policy` in your NestJS app. */',
    `export type AuthzAbility = ${union};`,
    '',
    '/** Map of resource class name → the abilities declared against it. */',
    `export const authzAbilities = ${mapLiteral} as const;`,
    '',
    '/**',
    ' * The shared ability store backing `can()`. Hydrate it once from your server-shared',
    " * decisions (e.g. `hydrateFromInertiaProps(authzStore, props)` from '@dudousxd/nestjs-authz-client')",
    ' * so checks resolve with no network request.',
    ' */',
    'export const authzStore = new AbilityStore();',
    '',
    '/**',
    " * Resolver from '@dudousxd/nestjs-authz-client', bound to `authzStore`. Peek-first: a hydrated",
    ` * decision returns synchronously; a cache miss POSTs to \`${endpoint}\` and reads \`{ allowed }\`.`,
    ' */',
    'const authzCan = createCan(authzStore, {',
    `  fallback: 'fetch',`,
    `  endpoint: ${JSON.stringify(endpoint)},`,
    '});',
    '',
    '/**',
    ' * Whether the current user `can` perform `ability` (optionally on a resource identified by',
    ' * `resource`). Typed against the abilities discovered at build time, so an unknown ability is a',
    " * compile error. Delegates to `@dudousxd/nestjs-authz-client`'s store/`createCan`: a hydrated",
    ' * decision is returned synchronously (no request); otherwise it falls back to the configured',
    ' * endpoint. Returns a `boolean` on a cache hit or a `Promise<boolean>` on a fetch fallback.',
    ' *',
    ' * NOTE: per-instance decisions MUST be hydrated into `authzStore` (e.g. via shared props /',
    ' * `authorizeResource`). The fetch fallback only resolves class-level abilities and ad-hoc',
    ' * gates — a resource-bound ability that misses the cache will deny.',
    ' */',
    'export function can(',
    '  ability: AuthzAbility,',
    '  resource?: ResourceRef | null,',
    '): boolean | Promise<boolean> {',
    '  return authzCan(ability, resource ?? undefined);',
    '}',
    '',
    '/**',
    " * Batch resolver from '@dudousxd/nestjs-authz-client', bound to `authzStore`. For list",
    ' * pages: answers hydrated items from the store and POSTs ALL cache-misses to',
    ` * \`${endpoint}\` in ONE request (instead of one per item).`,
    ' */',
    'const authzCanBatch = createCanBatch(authzStore, {',
    `  fallback: 'fetch',`,
    `  endpoint: ${JSON.stringify(endpoint)},`,
    '});',
    '',
    '/**',
    ' * Authorize MANY abilities at once. Each item is typed against the discovered',
    ' * abilities, so a wrong ability is a compile error. Hydrated decisions resolve with',
    ` * no request; the remaining misses are fetched from \`${endpoint}\` in a single batch.`,
    ' */',
    'export function canBatch(',
    '  items: ReadonlyArray<{ ability: AuthzAbility; resource?: ResourceRef | null }>,',
    '): Promise<BatchAbilityResult[]> {',
    '  return authzCanBatch(',
    '    items.map((i) => (i.resource == null ? { ability: i.ability } : { ability: i.ability, resource: i.resource })),',
    '  );',
    '}',
  ];
}

function markerOf(route: RouteDescriptor): AuthzRouteMarker | undefined {
  return (route.contract?.contractSource as { authz?: AuthzRouteMarker } | undefined)?.authz;
}

/**
 * `@dudousxd/nestjs-authz` codegen extension. Discovers every official `@Can(Policy, 'ability', ...)`
 * (and `@Permission`) on your controllers (and, optionally, the methods of `@Policy()` classes) and emits a typed `can()` helper
 * into your generated `api.ts`: `ability` is a string-literal union of the discovered abilities, so a
 * wrong ability is a compile error. The runtime `can()` delegates to `@dudousxd/nestjs-authz-client`
 * (a shared `AbilityStore` + `createCan`) — so a hydrated decision answers with no request, and a
 * cache miss falls back to the configured endpoint. Routes carrying a `@Can` also expose a `can()`
 * handle member (when a client layer such as TanStack is active).
 *
 * Register it in your codegen config:
 *
 * ```ts
 * defineConfig({
 *   extensions: [nestjsAuthzCodegen({ endpoint: '/authz/can' })],
 * });
 * ```
 */
export function nestjsAuthzCodegen(options: AuthzCodegenOptions = {}): CodegenExtension {
  const endpoint = options.endpoint ?? DEFAULT_ENDPOINT;
  const discoverPolicies = options.discoverPolicies ?? true;

  // Discovered once during transformRoutes, then read by apiHeader/apiMembers.
  const abilities = new Set<string>();
  const byResource = new Map<string, Set<string>>();

  function record(info: AuthzAbilityInfo): void {
    abilities.add(info.ability);
    if (info.resource) {
      const set = byResource.get(info.resource) ?? new Set<string>();
      set.add(info.ability);
      byResource.set(info.resource, set);
    }
  }

  const ext: CodegenExtension = {
    name: 'nestjs-authz',

    transformRoutes(routes, ctx) {
      const project = ctx.project();
      const out = routes.map((route) => {
        const found = discoverRouteAbilities(route, project);
        for (const each of found) record(each);
        const info = found[0];
        if (!info) return route;
        const marker: AuthzRouteMarker = { ability: info.ability };
        if (info.resource) marker.resource = info.resource;
        // Attach the marker to the route's contract so apiMembers can read it later.
        const contractSource = { ...(route.contract?.contractSource ?? {}), authz: marker };
        return { ...route, contract: { ...route.contract, contractSource } } as RouteDescriptor;
      });

      if (discoverPolicies) {
        for (const info of discoverPolicyAbilities(project)) record(info);
      }

      return out;
    },

    apiHeader() {
      if (abilities.size === 0) return undefined;
      return {
        imports: canHelperImports(),
        statements: canHelperStatements(
          abilityUnion(abilities),
          resourceAbilityMapLiteral(byResource),
          endpoint,
        ),
      };
    },

    apiMembers(leaf: LeafModel) {
      const marker = markerOf(leaf.route);
      if (!marker) return undefined;
      const resourceArg = marker.resource ? 'resource: ResourceRef | null = null' : '';
      const callResource = marker.resource ? ', resource' : '';
      return {
        // A typed `can()` pinned to THIS route's ability — no argument needed, can't be wrong.
        can: `(${resourceArg}) => can(${JSON.stringify(marker.ability)}${callResource})`,
        ability: JSON.stringify(marker.ability),
      };
    },
  };

  return ext;
}

export default nestjsAuthzCodegen;
