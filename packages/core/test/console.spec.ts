import 'reflect-metadata';
import { AuthorizationModule } from '@nestjs/authorization';
import {
  type CanActivate,
  Controller,
  type DynamicModule,
  type ExecutionContext,
  ForbiddenException,
  Get,
  type INestApplication,
  Inject,
  Injectable,
  Module,
  UnauthorizedException,
  UseGuards,
} from '@nestjs/common';
import { ModuleRef } from '@nestjs/core';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import {
  AuthzConsoleGate,
  CONSOLE_GATE,
  type ConsoleAuthorize,
  type ConsoleAuthorizeResult,
  type ConsoleAuthorizer,
  type ConsoleAuthorizerClass,
  authorizeByPermission,
  authorizeByRoles,
  authorizeByToken,
} from '../src/console.js';
import type { ContextAccessor } from '../src/context-accessor.js';
import { Gate } from '../src/gate.js';
import * as entry from '../src/index.js';
import { AuthzModule } from '../src/module.js';
import { OFFICIAL_CAN_ANYONE_METADATA } from '../src/official.js';
import { CONTEXT_ACCESSOR, PERMISSION_PROVIDER } from '../src/tokens.js';
import { asUser, bootContext, permissionTable, userFromHeader } from './support/app.js';

/** A minimal HTTP ExecutionContext. */
function httpContext(headers: Record<string, string> = {}, extra: object = {}): ExecutionContext {
  const req = { headers, ...extra };
  return {
    getType: () => 'http',
    switchToHttp: () => ({ getRequest: () => req }),
  } as unknown as ExecutionContext;
}

describe('the console gate token', () => {
  it('is the shared Aviary symbol', () => {
    expect(CONSOLE_GATE).toBe(Symbol.for('@dudousxd/aviary:console-gate'));
  });

  it('is exported from the main entry with the helpers', () => {
    expect(entry.CONSOLE_GATE).toBe(CONSOLE_GATE);
    expect(entry.AuthzConsoleGate).toBe(AuthzConsoleGate);
    expect(entry.authorizeByToken).toBe(authorizeByToken);
    expect(entry.authorizeByRoles).toBe(authorizeByRoles);
    expect(entry.authorizeByPermission).toBe(authorizeByPermission);
  });

  it('AuthzModule provides it globally', async () => {
    const { mod } = await bootContext();
    const consoleGate = mod.get<AuthzConsoleGate>(CONSOLE_GATE, { strict: false });
    expect(consoleGate).toBeInstanceOf(AuthzConsoleGate);
    expect(consoleGate).toBe(mod.get(AuthzConsoleGate));
  });
});

describe('AuthzConsoleGate.allows(name, context)', () => {
  async function boot() {
    const { mod, gate } = await bootContext();
    gate.define('console.durable', (user) => (user as { admin?: boolean } | null)?.admin === true);
    return mod.get<AuthzConsoleGate>(CONSOLE_GATE);
  }

  it("allows a user the gate allows (the user the official getUser reads, here 'x-user')", async () => {
    const consoleGate = await boot();
    expect(
      await consoleGate.allows('console.durable', httpContext(asUser({ id: 1, admin: true }))),
    ).toBe(true);
  });

  it('answers false for a user the gate denies', async () => {
    const consoleGate = await boot();
    expect(await consoleGate.allows('console.durable', httpContext(asUser({ id: 2 })))).toBe(false);
  });

  it('answers unauthenticated for a guest', async () => {
    const consoleGate = await boot();
    expect(await consoleGate.allows('console.durable', httpContext())).toEqual({
      allowed: false,
      reason: 'unauthenticated',
    });
  });

  it('denies (fail-closed) a gate name the Gate cannot resolve, without throwing', async () => {
    const consoleGate = await boot();
    expect(await consoleGate.allows('nope', httpContext(asUser({ id: 1, admin: true })))).toBe(
      false,
    );
  });

  it('returns a fresh denial object on every call', async () => {
    const consoleGate = await boot();
    const first = await consoleGate.allows('console.durable', httpContext());
    const second = await consoleGate.allows('console.durable', httpContext());
    expect(first).toEqual(second);
    expect(first).not.toBe(second);
  });

  it('reads request.user with the default getUser', async () => {
    const mod = await Test.createTestingModule({
      imports: [AuthorizationModule.forRoot(), AuthzModule.forRoot()],
    }).compile();
    mod.useLogger(false);
    await mod.init();
    mod.get(Gate).define('console.x', (user) => (user as { id?: number } | null)?.id === 7);
    const consoleGate = mod.get<AuthzConsoleGate>(CONSOLE_GATE);
    expect(await consoleGate.allows('console.x', httpContext({}, { user: { id: 7 } }))).toBe(true);
    expect(await consoleGate.allows('console.x', httpContext({}, { user: { id: 8 } }))).toBe(false);
  });

  it("falls back to the Gate's ambient user (nestjs-context's user ref)", async () => {
    const accessor: ContextAccessor = {
      traceId: () => undefined,
      tenantId: () => undefined,
      userRef: () => ({ type: 'user', id: 9 }),
      get: () => ({}),
    };
    const { mod, gate } = await bootContext({
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: accessor }],
    });
    gate.define('console.x', (user) => (user as { id?: number } | null)?.id === 9);
    const consoleGate = mod.get<AuthzConsoleGate>(CONSOLE_GATE);
    expect(await consoleGate.allows('console.x', httpContext())).toBe(true);
  });

  it('never promotes an explicit guest (getUser answered null or false) to the ambient user', async () => {
    const accessor: ContextAccessor = {
      traceId: () => undefined,
      tenantId: () => undefined,
      userRef: () => ({ type: 'user', id: 9 }),
      get: () => ({}),
    };
    for (const answer of [null, false]) {
      const mod = await Test.createTestingModule({
        imports: [
          AuthorizationModule.forRoot({ getUser: () => answer }),
          AuthzModule.forRoot({ resolveUser: (ref) => ({ id: ref.id }) }),
        ],
        providers: [{ provide: CONTEXT_ACCESSOR, useValue: accessor }],
      }).compile();
      mod.useLogger(false);
      await mod.init();
      mod.get(Gate).define('console.x', (user) => (user as { id?: number } | null)?.id === 9);
      const consoleGate = mod.get<AuthzConsoleGate>(CONSOLE_GATE);
      expect(await consoleGate.allows('console.x', httpContext())).toEqual({
        allowed: false,
        reason: 'unauthenticated',
      });
    }
  });
});

describe('authorizeByRoles / authorizeByPermission', () => {
  it('return a fresh @Injectable() class per call', () => {
    const a = authorizeByRoles({ roles: ['admin'] });
    const b = authorizeByRoles({ roles: ['ops'] });
    expect(typeof a).toBe('function');
    expect(typeof a.prototype.authorize).toBe('function');
    expect(a).not.toBe(b);
    const c = authorizeByPermission('console.view');
    expect(typeof c.prototype.authorize).toBe('function');
    expect(c).not.toBe(authorizeByPermission('console.view'));
  });

  it('reject an empty configuration', () => {
    expect(() => authorizeByRoles({ roles: [] })).toThrow(/at least one role/);
    expect(() => authorizeByPermission('')).toThrow(/non-empty/);
  });

  it('each class keeps its own roles (instances from ModuleRef.create)', async () => {
    const { mod } = await bootContext();
    const moduleRef = mod.get(ModuleRef);
    const admin = await moduleRef.create(authorizeByRoles({ roles: ['admin'] }));
    const ops = await moduleRef.create(authorizeByRoles({ roles: ['ops'] }));
    const ctx = httpContext(asUser({ id: 1, roles: ['ops'] }));
    expect(await admin.authorize(ctx)).toBe(false);
    expect(await ops.authorize(ctx)).toBe(true);
    expect(await admin.authorize(httpContext())).toEqual({
      allowed: false,
      reason: 'unauthenticated',
    });
  });

  it('honors superAdmin for roles', async () => {
    const { mod } = await bootContext({
      authz: { superAdmin: (user) => (user as { root?: boolean } | null)?.root === true },
    });
    const byRoles = await mod.get(ModuleRef).create(authorizeByRoles({ roles: ['admin'] }));
    expect(await byRoles.authorize(httpContext(asUser({ id: 1, root: true })))).toBe(true);
  });

  it('authorizeByPermission checks persisted permissions (wildcards apply)', async () => {
    const { provider } = permissionTable({ '1': ['console.*'], '2': ['posts.view'] });
    const { mod } = await bootContext({ permissions: provider });
    const byPermission = await mod.get(ModuleRef).create(authorizeByPermission('console.durable'));
    expect(await byPermission.authorize(httpContext(asUser({ id: 1 })))).toBe(true);
    expect(await byPermission.authorize(httpContext(asUser({ id: 2 })))).toBe(false);
    expect(await byPermission.authorize(httpContext())).toEqual({
      allowed: false,
      reason: 'unauthenticated',
    });
  });
});

describe('authorizeByToken', () => {
  const check = authorizeByToken({ token: 's3cret' });

  it('allows a matching bearer token', () => {
    expect(check(httpContext({ authorization: 'Bearer s3cret' }))).toBe(true);
  });

  it('is unauthenticated on a mismatch, a missing header or another scheme', () => {
    const denied = { allowed: false, reason: 'unauthenticated' };
    expect(check(httpContext({ authorization: 'Bearer wrong' }))).toEqual(denied);
    expect(check(httpContext({ authorization: 'Bearer s3cret-and-more' }))).toEqual(denied);
    expect(check(httpContext())).toEqual(denied);
    expect(check(httpContext({ authorization: 'Basic s3cret' }))).toEqual(denied);
  });

  it('ignores ?token= and custom headers', () => {
    const denied = { allowed: false, reason: 'unauthenticated' };
    expect(check(httpContext({ 'x-token': 's3cret' }, { query: { token: 's3cret' } }))).toEqual(
      denied,
    );
  });

  it('throws on an empty or missing token', () => {
    expect(() => authorizeByToken({ token: '' })).toThrow(/token/);
    expect(() => authorizeByToken({ token: undefined })).toThrow(/token/);
  });
});

// --- A fake Aviary console: resolves `authorize` the way the console libs do. ---

const CONSOLE_OPTIONS = Symbol('console-options');

interface ConsoleGateLike {
  allows(name: string, context: ExecutionContext): Promise<ConsoleAuthorizeResult>;
}

@Injectable()
class FakeConsoleGuard implements CanActivate {
  private authorizer?: ConsoleAuthorizer;

  constructor(
    private readonly moduleRef: ModuleRef,
    @Inject(CONSOLE_OPTIONS) private readonly authorize: ConsoleAuthorize,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const result = await this.run(context);
    if (result === true || (typeof result === 'object' && 'allowed' in result && result.allowed)) {
      return true;
    }
    if (typeof result === 'object' && 'allowed' in result && result.reason === 'unauthenticated') {
      throw new UnauthorizedException();
    }
    throw new ForbiddenException();
  }

  private async run(context: ExecutionContext): Promise<ConsoleAuthorizeResult> {
    const authorize = this.authorize;
    if (typeof authorize === 'string') {
      const gate = this.moduleRef.get<ConsoleGateLike>(
        Symbol.for('@dudousxd/aviary:console-gate'),
        { strict: false },
      );
      return gate.allows(authorize, context);
    }
    if (typeof authorize === 'function' && typeof authorize.prototype?.authorize === 'function') {
      this.authorizer ??= await this.moduleRef.create(authorize as ConsoleAuthorizerClass);
      return this.authorizer.authorize(context);
    }
    return (authorize as (c: ExecutionContext) => ConsoleAuthorizeResult)(context);
  }
}

@Controller('console')
@UseGuards(FakeConsoleGuard)
class FakeConsoleController {
  @Get()
  index() {
    return { ok: true };
  }
}
Reflect.defineMetadata(OFFICIAL_CAN_ANYONE_METADATA, true, FakeConsoleController);

@Module({})
class FakeConsoleModule {
  static forRoot(authorize: ConsoleAuthorize): DynamicModule {
    return {
      module: FakeConsoleModule,
      controllers: [FakeConsoleController],
      providers: [{ provide: CONSOLE_OPTIONS, useValue: authorize }, FakeConsoleGuard],
    };
  }
}

describe('an Aviary console protected through AuthzModule (e2e)', () => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  async function boot(authorize: ConsoleAuthorize) {
    const { provider } = permissionTable({ '3': ['console.view'] });
    const mod = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot({ getUser: userFromHeader }),
        AuthzModule.forRoot(),
        FakeConsoleModule.forRoot(authorize),
      ],
      providers: [{ provide: PERMISSION_PROVIDER, useValue: provider }],
    }).compile();
    app = mod.createNestApplication({ logger: false });
    app
      .get(Gate)
      .define('console.durable', (user) => (user as { admin?: boolean } | null)?.admin === true);
    await app.init();
    return app.getHttpServer();
  }

  it("resolves authorize: 'console.durable' through the console-gate token", async () => {
    const server = await boot('console.durable');
    await request(server)
      .get('/console')
      .set(asUser({ id: 1, admin: true }))
      .expect(200, { ok: true });
    await request(server)
      .get('/console')
      .set(asUser({ id: 2 }))
      .expect(403);
    await request(server).get('/console').expect(401);
  });

  it('authorize: authorizeByRoles({ roles: [admin] })', async () => {
    const server = await boot(authorizeByRoles({ roles: ['admin'] }));
    await request(server)
      .get('/console')
      .set(asUser({ id: 1, roles: ['admin'] }))
      .expect(200);
    await request(server)
      .get('/console')
      .set(asUser({ id: 2, roles: ['editor'] }))
      .expect(403);
    await request(server).get('/console').expect(401);
  });

  it("authorize: authorizeByPermission('console.view')", async () => {
    const server = await boot(authorizeByPermission('console.view'));
    await request(server)
      .get('/console')
      .set(asUser({ id: 3 }))
      .expect(200);
    await request(server)
      .get('/console')
      .set(asUser({ id: 4 }))
      .expect(403);
    await request(server).get('/console').expect(401);
  });

  it('authorize: authorizeByToken({ token })', async () => {
    const server = await boot(authorizeByToken({ token: 'tok' }));
    await request(server).get('/console').set('authorization', 'Bearer tok').expect(200);
    await request(server).get('/console').set('authorization', 'Bearer nope').expect(401);
    await request(server).get('/console?token=tok').expect(401);
  });
});
