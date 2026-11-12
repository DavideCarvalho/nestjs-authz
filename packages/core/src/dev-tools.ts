import {
  Inject,
  Injectable,
  Logger,
  type OnModuleDestroy,
  type OnModuleInit,
  Optional,
} from '@nestjs/common';
import { Gate } from './gate.js';
import { permissionSatisfied } from './permission-matcher.js';
import { AuthzRbac } from './rbac.js';
import { runInTenantScope } from './tenant-override.js';
import { AUTHZ_MODULE_OPTIONS } from './tokens.js';
import type { AuthzModuleOptions, User } from './types.js';

// ── the dev-tools contract (v1), re-declared: authz never imports the agent's MCP server ──

/** The process-wide slot the Aviary dev MCP endpoint serves (`@dudousxd/nestjs-agent-mcp-server`). */
export const DEV_TOOLS_SLOT = Symbol.for('@dudousxd/aviary:dev-tools');

/** One property of a {@link DevToolInputSchema}. */
export interface DevToolInputProperty {
  type: 'string' | 'number' | 'integer' | 'boolean' | 'array';
  description?: string;
  enum?: readonly string[];
  items?: { type: 'string' };
  minimum?: number;
  maximum?: number;
}

/** A dev tool's input: an object of scalar / enum / array-of-string properties. */
export interface DevToolInputSchema {
  type: 'object';
  properties: Record<string, DevToolInputProperty>;
  required?: string[];
}

/** What a tool's `run` receives besides its input. */
export interface DevToolCall {
  context: unknown;
  caller: { id: string; via: 'token' | 'session' | 'open' };
  limits: { maxRows: number; maxBytes: number };
}

/** One developer tool, as the dev-tools slot takes it. */
export interface AuthzDevTool {
  name: string;
  kind: 'read' | 'action';
  description: string;
  input: DevToolInputSchema;
  destructive?: boolean;
  available?(): boolean | Promise<boolean>;
  run(input: Record<string, unknown>, call?: DevToolCall): Promise<unknown>;
}

/**
 * A lib registration. authz has no console, so it registers WITHOUT `authorize`: the dev
 * endpoint's own `devTools.authorize` gates it.
 */
interface DevToolsLib {
  lib: string;
  title: string;
  authorize?: (context: unknown) => Promise<unknown>;
  tools: AuthzDevTool[];
}

interface DevToolsSlot {
  readonly version: 1;
  readonly libs: DevToolsLib[];
  register(lib: DevToolsLib): () => void;
  /** Optional capability probe of the hub. */
  supports?(capability: string): boolean;
}

/** The slot, created when absent (whoever loads first creates it). */
function devToolsSlot(): Partial<DevToolsSlot> {
  const holder = globalThis as Record<symbol, unknown>;
  const existing = holder[DEV_TOOLS_SLOT] as Partial<DevToolsSlot> | undefined;
  if (existing !== undefined) return existing;
  const libs: DevToolsLib[] = [];
  const slot: DevToolsSlot = {
    version: 1,
    libs,
    register(lib) {
      if (libs.some((entry) => entry.lib === lib.lib)) {
        throw new Error(`dev tools: the lib "${lib.lib}" is already registered`);
      }
      libs.push(lib);
      return () => {
        const index = libs.indexOf(lib);
        if (index !== -1) libs.splice(index, 1);
      };
    },
  };
  holder[DEV_TOOLS_SLOT] = slot;
  return slot;
}

// ── authz's tools ──────────────────────────────────────────────────────────────

/** A `{ type, id }` reference the tools take for a subject or a resource. */
export interface AuthzDevToolsRef {
  type: string;
  id: string;
}

/**
 * The `devTools` hooks of `AuthzModule.forRoot()`: load the real models behind the refs a tool
 * asks about, so policies, `superAdmin` and the decision provider see what they see in the app.
 */
export interface AuthzDevToolsOptions {
  /**
   * Load the subject (`{ type: 'user', id: '42' }` → your `User`). Default: `resolveUser`, when
   * configured. Without either, checks receive the `{ type, id }` ref itself. Return
   * `undefined`/`null` when it does not exist.
   */
  loadSubject?: (ref: AuthzDevToolsRef) => unknown | Promise<unknown>;
  /**
   * Load the resource of `authz_explain_check` (`{ type: 'Post', id: '7' }` → your `Post`).
   * Default: the `resourceLoaders` entry of that type. Without either, checks receive the
   * `{ type, id }` ref, which no `@PolicyFor` policy is linked to.
   */
  loadResource?: (ref: AuthzDevToolsRef) => unknown | Promise<unknown>;
}

/** What the tools read, at call time. */
export interface AuthzDevToolsDeps {
  gate: Gate;
  rbac: AuthzRbac;
  options: () => AuthzModuleOptions;
}

const subjectType: DevToolInputProperty = {
  type: 'string',
  description: "The subject type (default 'user').",
};
const subjectId: DevToolInputProperty = {
  type: 'string',
  description: 'The subject id (a user id, a team id…).',
};
const tenantId: DevToolInputProperty = {
  type: 'string',
  description:
    "Tenant to check in. Omitted: the scope the app's own checks would use in this request. '' forces the global scope.",
};
const limit: DevToolInputProperty = {
  type: 'integer',
  description: 'How many items to return (default 20, max 100).',
  minimum: 1,
  maximum: 100,
};
const page: DevToolInputProperty = {
  type: 'integer',
  description: 'Page number, from 1 (the `next` of the previous answer).',
  minimum: 1,
};

function intOf(value: unknown, fallback: number, max = Number.MAX_SAFE_INTEGER): number {
  return typeof value === 'number' && Number.isFinite(value)
    ? Math.max(1, Math.min(max, Math.floor(value)))
    : fallback;
}

function str(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() !== '' ? value.trim() : undefined;
}

/** One page of `items` in the `{ items, next }` shape every dev-tools list returns. */
function pageOf<T>(items: readonly T[], input: Record<string, unknown>) {
  const size = intOf(input.limit, 20, 100);
  const number = intOf(input.page, 1);
  const start = (number - 1) * size;
  return {
    items: items.slice(start, start + size),
    next: start + size < items.length ? number + 1 : null,
  };
}

function subjectOf(input: Record<string, unknown>): AuthzDevToolsRef {
  const id = str(input.subjectId);
  if (id === undefined) throw new Error('`subjectId` is required');
  return { type: str(input.subjectType) ?? 'user', id };
}

/** `tenantId` input → the forced scope (`null` = global), or `undefined` to keep the default. */
function scopeOf(input: Record<string, unknown>): string | null | undefined {
  const value = input.tenantId;
  if (value === undefined || value === null) return undefined;
  if (typeof value === 'number' && Number.isFinite(value)) return String(value);
  if (typeof value !== 'string') throw new Error('`tenantId` must be a string');
  const id = value.trim();
  return id === '' ? null : id;
}

/** Run `fn` in the forced scope, when there is one. */
function inScope<T>(scope: string | null | undefined, fn: () => Promise<T>): Promise<T> {
  return scope === undefined ? fn() : runInTenantScope(scope, fn);
}

async function load(
  hook: ((ref: AuthzDevToolsRef) => unknown | Promise<unknown>) | undefined,
  ref: AuthzDevToolsRef,
): Promise<{ loaded: boolean; value: unknown }> {
  if (hook === undefined) return { loaded: false, value: ref };
  const value = await hook(ref);
  return value === undefined || value === null
    ? { loaded: false, value: ref }
    : { loaded: true, value };
}

type Loader = AuthzDevToolsOptions['loadSubject'];

/** The loaders in effect: the `devTools` hooks, else `resolveUser` / `resourceLoaders`. */
function hooksOf(options: AuthzModuleOptions): { loadSubject: Loader; loadResource: Loader } {
  const own =
    typeof options.devTools === 'object' && options.devTools !== null ? options.devTools : {};
  const resolveUser = options.resolveUser;
  const loaders = options.resourceLoaders;
  return {
    loadSubject:
      own.loadSubject ?? (resolveUser ? (ref: AuthzDevToolsRef) => resolveUser(ref) : undefined),
    loadResource:
      own.loadResource ??
      (loaders
        ? (ref: AuthzDevToolsRef) =>
            Object.hasOwn(loaders, ref.type) ? loaders[ref.type]?.(ref.id) : undefined
        : undefined),
  };
}

const CALLER_NOTE =
  "Roles that `tenancy.roles` maps from the caller's role inside the context tenant only count for the user making the request; for another subject they are not visible here.";

const NO_SCOPE_SUPPORT =
  'The installed RBAC adapter cannot take `tenantId`: its roles and permissions are read in the scope of this request. Upgrade the adapter.';

interface RoleView {
  roles: Array<{ role: string; sources: string[] }>;
  tenant: { id: string | null; from: 'explicit' | 'global' | 'context' };
  rbac: Awaited<ReturnType<AuthzRbac['roleSourcesOf']>>['rbac'];
  warning?: string;
}

/** The subject's effective roles with their sources, in the forced scope when there is one. */
async function roleView(
  rbac: AuthzRbac,
  user: User,
  scope: string | null | undefined,
): Promise<RoleView> {
  const sources = await rbac.roleSourcesOf(user);
  const byRole = new Map<string, string[]>();
  const add = (role: string, source: string) =>
    byRole.set(role, [...(byRole.get(role) ?? []), source]);
  for (const role of sources.user) add(role, 'user');
  if (sources.rbac) {
    for (const role of sources.rbac.roles.store) add(role, 'store');
    for (const role of sources.rbac.roles.tenant) add(role, 'tenant');
  } else {
    for (const role of sources.provider) add(role, 'provider');
  }
  const id = scope !== undefined ? scope : (sources.rbac?.tenantId ?? null);
  const from =
    scope !== undefined ? (scope === null ? 'global' : 'explicit') : id ? 'context' : 'global';
  return {
    roles: [...byRole].map(([role, from]) => ({ role, sources: from })),
    tenant: { id, from },
    rbac: sources.rbac,
    ...(scope !== undefined && rbac.roles() !== undefined && sources.rbac === undefined
      ? { warning: NO_SCOPE_SUPPORT }
      : {}),
  };
}

/**
 * The authz developer tools (all read-only): explain a check, and a subject's effective roles
 * and permissions.
 */
export function authzDevTools(deps: AuthzDevToolsDeps): AuthzDevTool[] {
  return [
    {
      name: 'authz_explain_check',
      kind: 'read',
      description:
        'Why a subject can or cannot do something: the verdict and its reason (super-admin, ' +
        'decision-provider, policy, permission-provider, gate, anonymous, or unresolved when ' +
        'nothing defines the ability), what the decision provider said, the subject’s effective ' +
        'roles with their sources, and which roles or direct grants (in what the permission ' +
        'provider lists) cover the permission. ' +
        'Read-only: no decision event is published.',
      input: {
        type: 'object',
        properties: {
          subjectType,
          subjectId,
          permission: {
            type: 'string',
            description: "The permission or ability, e.g. 'posts.update' or 'update'.",
          },
          tenantId,
          resourceType: {
            type: 'string',
            description: "Type of the resource the check is about, e.g. 'Post' (with resourceId).",
          },
          resourceId: { type: 'string', description: 'Id of the resource (with resourceType).' },
        },
        required: ['subjectId', 'permission'],
      },
      async run(input) {
        const ref = subjectOf(input);
        const permission = str(input.permission);
        if (permission === undefined) throw new Error('`permission` is required');
        const resourceType = str(input.resourceType);
        const resourceId = str(input.resourceId);
        if ((resourceType === undefined) !== (resourceId === undefined)) {
          throw new Error('`resourceType` and `resourceId` go together: pass both or neither');
        }
        const scope = scopeOf(input);
        const hooks = hooksOf(deps.options());
        const resourceRef =
          resourceType !== undefined && resourceId !== undefined
            ? { type: resourceType, id: resourceId }
            : undefined;

        return inScope(scope, async () => {
          // Loaded in the requested tenant, so tenant-scoped loaders see it.
          const subject = await load(hooks.loadSubject, ref);
          const resource = resourceRef ? await load(hooks.loadResource, resourceRef) : undefined;
          const decision = await deps.gate.explainFor(
            subject.value,
            permission,
            resource?.value as object | undefined,
          );
          const view = await roleView(deps.rbac, subject.value, scope);
          // Coverage from the grants the Gate consults: the permission provider's list when it
          // has one, else the RBAC adapter's view. A role only counts for what that list holds.
          const provider = deps.rbac.permissions();
          const listed =
            typeof provider?.getPermissions === 'function'
              ? new Set((await provider.getPermissions(subject.value)) ?? [])
              : view.rbac
                ? new Set(view.rbac.permissions)
                : undefined;
          const grantingRoles: Array<{ role: string; matched: string[] }> = [];
          let directGrants: string[] = [];
          if (listed) {
            const viaRoles = new Set<string>();
            for (const { role } of view.roles) {
              const matched = (view.rbac?.rolePermissions[role] ?? []).filter(
                (p) => listed.has(p) && permissionSatisfied([p], permission),
              );
              if (matched.length === 0) continue;
              grantingRoles.push({ role, matched: [...new Set(matched)] });
              for (const p of matched) viaRoles.add(p);
            }
            directGrants = [...listed].filter(
              (p) => permissionSatisfied([p], permission) && !viaRoles.has(p),
            );
          }
          return {
            ...decision,
            subject: ref,
            permission,
            tenant: view.tenant,
            effectiveRoles: view.roles.map((r) => r.role),
            roleSources: Object.fromEntries(view.roles.map((r) => [r.role, r.sources])),
            grantingRoles,
            directGrants,
            subjectLoaded: subject.loaded,
            ...(resourceRef
              ? { resource: resourceRef, resourceLoaded: resource?.loaded === true }
              : {}),
            ...(view.warning ? { warning: view.warning } : {}),
            note: CALLER_NOTE,
          };
        });
      },
    },
    {
      name: 'authz_list_effective_roles',
      kind: 'read',
      description:
        "A subject's effective roles in a tenant, each with where it comes from: the user object " +
        "or resolveRoles ('user'), the RBAC store ('store'), the caller's role inside the context " +
        "tenant mapped by tenancy.roles ('tenant'), or a role provider that does not say ('provider').",
      input: {
        type: 'object',
        properties: { subjectType, subjectId, tenantId },
        required: ['subjectId'],
      },
      async run(input) {
        const ref = subjectOf(input);
        const scope = scopeOf(input);
        const hooks = hooksOf(deps.options());
        return inScope(scope, async () => {
          const subject = await load(hooks.loadSubject, ref);
          const view = await roleView(deps.rbac, subject.value, scope);
          return {
            subject: ref,
            tenant: view.tenant,
            items: view.roles,
            next: null,
            subjectLoaded: subject.loaded,
            ...(view.warning ? { warning: view.warning } : {}),
            note: CALLER_NOTE,
          };
        });
      },
    },
    {
      name: 'authz_list_effective_permissions',
      kind: 'read',
      description:
        "A subject's effective permissions in a tenant (role-derived and direct grants), " +
        'wildcards as stored. Paged: { items, next }.',
      input: {
        type: 'object',
        properties: { subjectType, subjectId, tenantId, limit, page },
        required: ['subjectId'],
      },
      async run(input) {
        const ref = subjectOf(input);
        const scope = scopeOf(input);
        const hooks = hooksOf(deps.options());
        return inScope(scope, async () => {
          const subject = await load(hooks.loadSubject, ref);
          const provider = deps.rbac.permissions();
          const view = await roleView(deps.rbac, subject.value, scope);
          if (typeof provider?.getPermissions !== 'function') {
            return {
              subject: ref,
              tenant: view.tenant,
              items: [],
              next: null,
              subjectLoaded: subject.loaded,
              ...(view.warning ? { warning: view.warning } : {}),
              note: provider
                ? 'The permission provider cannot list permissions (no getPermissions).'
                : 'No permission provider: install an RBAC adapter (AuthzRbacModule).',
            };
          }
          const granted = (await provider.getPermissions(subject.value)) ?? [];
          return {
            subject: ref,
            tenant: view.tenant,
            ...pageOf([...new Set(granted)].sort(), input),
            subjectLoaded: subject.loaded,
            ...(view.warning ? { warning: view.warning } : {}),
          };
        });
      },
    },
  ];
}

/** Why {@link registerAuthzDevTools} did or did not register. */
export type DevToolsRegistration = 'registered' | 'unsupported' | 'failed';

/**
 * Register the authz tools into the dev-tools slot (created when absent), without an
 * `authorize`: the dev endpoint's `devTools.authorize` gates them. A hub that says it cannot gate a
 * lib without a console (`supports('endpoint-authorize')` is false) is left alone. Never throws.
 */
export function registerAuthzDevTools(deps: AuthzDevToolsDeps): {
  outcome: DevToolsRegistration;
  unregister?: () => void;
} {
  try {
    const slot = devToolsSlot();
    if (slot.version !== 1 || typeof slot.register !== 'function') {
      return { outcome: 'unsupported' };
    }
    if (typeof slot.supports === 'function' && !slot.supports('endpoint-authorize')) {
      return { outcome: 'unsupported' };
    }
    const unregister = slot.register({
      lib: 'authz',
      title: 'Authorization (authz)',
      tools: authzDevTools(deps),
    });
    return { outcome: 'registered', unregister };
  } catch {
    return { outcome: 'failed' };
  }
}

/** Registers the authz dev tools at module init and removes them at module destroy. */
@Injectable()
export class AuthzDevTools implements OnModuleInit, OnModuleDestroy {
  private readonly logger = new Logger('AuthzDevTools');
  private readonly options: AuthzModuleOptions;
  private unregister: (() => void) | undefined;

  constructor(
    private readonly gate: Gate,
    private readonly rbac: AuthzRbac,
    @Optional() @Inject(AUTHZ_MODULE_OPTIONS) options?: AuthzModuleOptions,
  ) {
    this.options = options ?? {};
  }

  onModuleInit(): void {
    if (this.options.devTools === false) return;
    const { outcome, unregister } = registerAuthzDevTools({
      gate: this.gate,
      rbac: this.rbac,
      options: () => this.options,
    });
    this.unregister = unregister;
    if (outcome === 'unsupported') {
      this.logger.debug(
        'dev tools not registered: the installed dev-tools hub cannot gate libs without a console (needs devTools.authorize support)',
      );
    } else if (outcome === 'failed') {
      this.logger.debug('dev tools could not be registered');
    }
  }

  onModuleDestroy(): void {
    this.unregister?.();
    this.unregister = undefined;
  }
}
