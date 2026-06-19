import type { RouteDescriptor } from '@dudousxd/nestjs-codegen';
import type {
  CodegenExtension,
  ExtensionContext,
  LeafModel,
} from '@dudousxd/nestjs-codegen/extension';
import { type ClassDeclaration, Node, type Project, type SourceFile } from 'ts-morph';

/**
 * The `@Can(ability, Resource?)` descriptor discovered on a controller route, plus the optional
 * class-level abilities discovered on `@Policy(Resource)` classes. Mirrors the shapes stored by
 * `@dudousxd/nestjs-authz`'s `CAN_METADATA` / `POLICY_RESOURCE_METADATA` — read statically from
 * the AST rather than from reflect-metadata (which isn't available at codegen time).
 */
export interface AuthzAbilityInfo {
  /** The ability string, e.g. `'update'` or `'access-admin'`. */
  ability: string;
  /** The resource class name the ability targets, when `@Can(ability, Resource)` names one. */
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
   * Also discover `@Policy(Resource)` classes and treat their public method names as class-level
   * abilities (so e.g. `PostPolicy.publish` contributes `'publish'` to the union even when no
   * route is decorated with it yet). Default `true`.
   */
  discoverPolicies?: boolean;
}

const DEFAULT_ENDPOINT = '/authz/can';

/** Read the ability + resource from a single `@Can(...)` decorator's arguments. */
function readCanDecorator(args: Node[]): AuthzAbilityInfo | null {
  const abilityArg = args[0];
  if (!abilityArg || !Node.isStringLiteral(abilityArg)) return null;
  const info: AuthzAbilityInfo = { ability: abilityArg.getLiteralValue() };
  const resourceArg = args[1];
  // `@Can('update', Post)` — second arg is the resource class identifier.
  if (resourceArg && Node.isIdentifier(resourceArg)) {
    info.resource = resourceArg.getText();
  }
  return info;
}

/**
 * Discover the `@Can(...)` ability on the controller method backing a route. Opens the route's
 * controller source via the shared ts-morph project, finds the method, and reads its (or its
 * class's) `@Can` decorator. Class-level `@Can` applies when the method has none.
 */
function discoverRouteAbility(route: RouteDescriptor, project: Project): AuthzAbilityInfo | null {
  const ref = route.controllerRef;
  if (!ref) return null;
  let sourceFile: SourceFile | undefined;
  try {
    sourceFile = project.addSourceFileAtPathIfExists(ref.filePath) ?? undefined;
  } catch {
    sourceFile = undefined;
  }
  if (!sourceFile) sourceFile = project.getSourceFile(ref.filePath);
  if (!sourceFile) return null;

  const classDecl = sourceFile.getClass(ref.className);
  if (!classDecl) return null;

  const method = classDecl.getMethod(ref.methodName);
  if (method) {
    const dec = method.getDecorators().find((d) => d.getName() === 'Can');
    if (dec) {
      const info = readCanDecorator(dec.getArguments());
      if (info) return info;
    }
  }

  // Fall back to a class-level `@Can(...)` guarding the whole controller.
  const classDec = classDecl.getDecorators().find((d) => d.getName() === 'Can');
  if (classDec) return readCanDecorator(classDec.getArguments());

  return null;
}

/**
 * Discover class-level abilities from `@Policy(Resource)` classes: each public, non-lifecycle
 * method name is an ability keyed to that resource. Mirrors how the authz `PolicyRegistry`
 * dispatches `PostPolicy.update(user, post)` for `@Can('update', Post)`.
 */
function discoverPolicyAbilities(project: Project): AuthzAbilityInfo[] {
  const found: AuthzAbilityInfo[] = [];
  for (const sourceFile of project.getSourceFiles()) {
    for (const classDecl of sourceFile.getClasses()) {
      const policyDec = classDecl.getDecorators().find((d) => d.getName() === 'Policy');
      if (!policyDec) continue;
      const resource = resourceNameFromPolicy(policyDec.getArguments(), classDecl);
      for (const method of classDecl.getMethods()) {
        if (method.isStatic()) continue;
        const name = method.getName();
        // Skip the optional `before(user, ability)` hook — it isn't an ability itself.
        if (name === 'before') continue;
        const ability: AuthzAbilityInfo = { ability: name };
        if (resource) ability.resource = resource;
        found.push(ability);
      }
    }
  }
  return found;
}

/** `@Policy(Post)` → `'Post'`; derive from the class name (`PostPolicy` → `Post`) as a fallback. */
function resourceNameFromPolicy(args: Node[], classDecl: ClassDeclaration): string | undefined {
  const arg = args[0];
  if (arg && Node.isIdentifier(arg)) return arg.getText();
  const className = classDecl.getName();
  if (className?.endsWith('Policy')) return className.slice(0, -'Policy'.length);
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
 * `@dudousxd/nestjs-authz` codegen extension. Discovers every `@Can(ability, Resource?)` decorator
 * on your controllers (and, optionally, `@Policy` method abilities) and emits a typed `can()` helper
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
        const info = discoverRouteAbility(route, project);
        if (!info) return route;
        record(info);
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
