import { Project } from 'ts-morph';
import { describe, expect, it } from 'vitest';
import { nestjsAuthzCodegen } from '../src/index.js';

// A ts-morph project with one in-memory controller + policy, mirroring how the host hands the
// extension a shared `ctx.project()`. The extension reads `@Can`/`@Policy` decorators off the AST.
function projectWith(source: string, filePath = '/src/posts.controller.ts'): Project {
  const project = new Project({ useInMemoryFileSystem: true });
  project.createSourceFile(filePath, source);
  return project;
}

// Minimal RouteDescriptor + ExtensionContext stand-ins. The extension only reads
// `route.controllerRef` and `ctx.project()`.
function route(className: string, methodName: string, filePath = '/src/posts.controller.ts') {
  return {
    method: 'POST',
    path: '/posts/:id',
    name: `posts.${methodName}`,
    params: [{ name: 'id', source: 'path' }],
    controllerRef: { className, methodName, filePath },
  } as never;
}

function ctxWith(project: Project) {
  return { project: () => project } as never;
}

const CONTROLLER = `
import { Controller, Post as HttpPost, Patch } from '@nestjs/common';
import { Can } from '@dudousxd/nestjs-authz';
class Post {}

@Controller('posts')
export class PostsController {
  @Patch(':id')
  @Can('update', Post)
  update() {}

  @HttpPost()
  @Can('create', Post, { classLevel: true })
  create() {}

  @HttpPost(':id/publish')
  @Can('access-admin')
  publish() {}
}
`;

describe('nestjsAuthzCodegen', () => {
  it('is a named extension with transformRoutes + apiHeader + apiMembers', () => {
    const ext = nestjsAuthzCodegen();
    expect(ext.name).toBe('nestjs-authz');
    expect(typeof ext.transformRoutes).toBe('function');
    expect(typeof ext.apiHeader).toBe('function');
    expect(typeof ext.apiMembers).toBe('function');
  });

  it('discovers @Can abilities and emits a typed AuthzAbility union', () => {
    const ext = nestjsAuthzCodegen({ discoverPolicies: false });
    const project = projectWith(CONTROLLER);
    const ctx = ctxWith(project);
    ext.transformRoutes?.(
      [
        route('PostsController', 'update'),
        route('PostsController', 'create'),
        route('PostsController', 'publish'),
      ],
      ctx,
    );

    const header = ext.apiHeader?.(ctx);
    const out = header?.statements?.join('\n') ?? '';
    const imports = header?.imports?.join('\n') ?? '';
    expect(out).toContain('export type AuthzAbility = "update" | "create" | "access-admin";');
    // a wrong ability (e.g. 'destroy') is NOT in the union, so `can('destroy')` would not typecheck.
    expect(out).not.toContain('"destroy"');
    expect(out).toContain('export function can(');
    expect(out).toContain('export const authzAbilities =');
    // The runtime delegates to @dudousxd/nestjs-authz-client (store + createCan) rather than a
    // hand-rolled POST — so a hydrated store answers with no request.
    expect(imports).toContain("from '@dudousxd/nestjs-authz-client'");
    expect(imports).toContain('AbilityStore');
    expect(imports).toContain('createCan');
    expect(out).toContain('export const authzStore = new AbilityStore();');
    expect(out).toContain('const authzCan = createCan(authzStore,');
    // No self-contained fetch POST in the emitted helper anymore.
    expect(out).not.toContain('await fetch(');
  });

  it('emits the resource → abilities map for resource-bound abilities', () => {
    const ext = nestjsAuthzCodegen({ discoverPolicies: false });
    const project = projectWith(CONTROLLER);
    const ctx = ctxWith(project);
    ext.transformRoutes?.(
      [route('PostsController', 'update'), route('PostsController', 'create')],
      ctx,
    );
    const out = ext.apiHeader?.(ctx)?.statements?.join('\n') ?? '';
    expect(out).toContain(
      'export const authzAbilities = { "Post": ["update", "create"] } as const;',
    );
  });

  it('wires the configured endpoint as the createCan fetch fallback', () => {
    const ext = nestjsAuthzCodegen({ discoverPolicies: false, endpoint: '/api/authz/check' });
    const project = projectWith(CONTROLLER);
    const ctx = ctxWith(project);
    ext.transformRoutes?.([route('PostsController', 'update')], ctx);
    const out = ext.apiHeader?.(ctx)?.statements?.join('\n') ?? '';
    expect(out).toContain('endpoint: "/api/authz/check"');
    expect(out).toContain("fallback: 'fetch'");
  });

  it('apiMembers adds a route-pinned can() to a @Can route (resource-bound)', () => {
    const ext = nestjsAuthzCodegen({ discoverPolicies: false });
    const project = projectWith(CONTROLLER);
    const ctx = ctxWith(project);
    const routes = ext.transformRoutes?.([route('PostsController', 'update')], ctx) as Array<never>;
    const members = ext.apiMembers?.({ route: routes[0] } as never, ctx);
    expect(members?.can).toBe('(resource: ResourceRef | null = null) => can("update", resource)');
    expect(members?.ability).toBe('"update"');
  });

  it('apiMembers can() takes no args for a model-less ability', () => {
    const ext = nestjsAuthzCodegen({ discoverPolicies: false });
    const project = projectWith(CONTROLLER);
    const ctx = ctxWith(project);
    const routes = ext.transformRoutes?.(
      [route('PostsController', 'publish')],
      ctx,
    ) as Array<never>;
    const members = ext.apiMembers?.({ route: routes[0] } as never, ctx);
    expect(members?.can).toBe('() => can("access-admin")');
  });

  it('apiMembers returns undefined for an undecorated route', () => {
    const ext = nestjsAuthzCodegen();
    const project = projectWith(CONTROLLER);
    const ctx = ctxWith(project);
    const members = ext.apiMembers?.({ route: { name: 'posts.list' } } as never, ctx);
    expect(members).toBeUndefined();
  });

  it('apiHeader returns undefined when no abilities were discovered', () => {
    const ext = nestjsAuthzCodegen({ discoverPolicies: false });
    const project = projectWith('export class Empty {}', '/src/empty.ts');
    const ctx = ctxWith(project);
    ext.transformRoutes?.([], ctx);
    expect(ext.apiHeader?.(ctx)).toBeUndefined();
  });

  it('discovers @Policy method names as class-level abilities when enabled', () => {
    const ext = nestjsAuthzCodegen();
    const project = projectWith(
      `
      import { Policy } from '@dudousxd/nestjs-authz';
      class Post {}
      @Policy(Post)
      export class PostPolicy {
        before() {}
        update() { return true; }
        publish() { return true; }
      }
      `,
      '/src/post.policy.ts',
    );
    const ctx = ctxWith(project);
    ext.transformRoutes?.([], ctx);
    const out = ext.apiHeader?.(ctx)?.statements?.join('\n') ?? '';
    // `before` is skipped (it's the policy hook, not an ability); update/publish are abilities.
    expect(out).toContain('export type AuthzAbility = "update" | "publish";');
    expect(out).toContain(
      'export const authzAbilities = { "Post": ["update", "publish"] } as const;',
    );
  });
});
