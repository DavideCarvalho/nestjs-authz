import 'reflect-metadata';
import { Public } from '@nestjs/authentication';
import {
  AuthorizationEvents,
  AuthorizationGuard,
  AuthorizationModule,
  Can,
  Policy,
} from '@nestjs/authorization';
import { Controller, Get, type INestApplication, UseGuards } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthzGuard } from '../src/authz.guard.js';
import { Can as LegacyCan } from '../src/decorator/can.decorator.js';
import { Permission, Roles } from '../src/decorator/roles.decorator.js';
import { Gate } from '../src/gate.js';
import { AuthzModule } from '../src/module.js';
import { PERMISSION_PROVIDER } from '../src/tokens.js';
import type { AuthzModuleAsyncOptions, AuthzModuleOptions } from '../src/types.js';
import { asUser, permissionTable, userFromHeader } from './support/app.js';

interface User {
  id: number;
  roles?: string[];
}

@Policy()
class ReportPolicy {
  view(user: User | null) {
    return user?.id === 1;
  }
}

/** A controller another library mounts: it knows nothing about authorization. */
@Controller('health')
class HealthController {
  @Get()
  check() {
    return { ok: true };
  }
}

@Controller('reports')
class ReportController {
  @Get('open')
  open() {
    return { ok: true };
  }

  @Get('anyone')
  @Can.Anyone()
  anyone() {
    return { ok: true };
  }

  @Get('view')
  @Can(ReportPolicy, 'view')
  view() {
    return { ok: true };
  }

  @Get('documents')
  @LegacyCan('page.documents')
  documents() {
    return { ok: true };
  }

  @Get('admin')
  @Roles('admin')
  admin() {
    return { ok: true };
  }

  @Get('publish')
  @Permission('reports.publish')
  publish() {
    return { ok: true };
  }
}

/** Class-level requirement: every handler is checked, unless a method opens itself. */
@Controller('admin')
@Roles('admin')
class AdminController {
  @Get()
  index() {
    return { ok: true };
  }

  @Get('ping')
  @Can.Anyone()
  ping() {
    return { ok: true };
  }

  @Get('status')
  @Public()
  status() {
    return { ok: true };
  }
}

async function boot(
  options: {
    globalGuard?: boolean;
    authz?: AuthzModuleOptions;
    async?: Omit<AuthzModuleAsyncOptions, 'useFactory'> & { factory?: AuthzModuleOptions };
  } = {},
): Promise<INestApplication> {
  const authz = options.async
    ? AuthzModule.forRootAsync({ ...options.async, useFactory: () => options.async?.factory ?? {} })
    : AuthzModule.forRoot(options.authz ?? { unannotated: 'allow' });
  const mod = await Test.createTestingModule({
    imports: [
      AuthorizationModule.forRoot({
        getUser: userFromHeader,
        ...(options.globalGuard === undefined
          ? { globalGuard: false }
          : { globalGuard: options.globalGuard }),
      }),
      authz,
    ],
    controllers: [HealthController, ReportController, AdminController],
    providers: [
      ReportPolicy,
      {
        provide: PERMISSION_PROVIDER,
        useValue: permissionTable({ '1': ['reports.*'] }).provider,
      },
    ],
  }).compile();
  const app = mod.createNestApplication({ logger: false });
  await app.init();
  app.get(Gate).define('page.documents', (u) => (u as User | null)?.id === 1);
  return app;
}

describe("AuthzModule.forRoot({ unannotated: 'allow' }) — the migration mode", () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('lets a route with no requirement through, for guests too', async () => {
    app = await boot();
    const http = app.getHttpServer();
    await request(http).get('/health').expect(200, { ok: true });
    await request(http).get('/reports/open').expect(200);
    await request(http).get('/reports/anyone').expect(200);
  });

  it('enforces an official @Can() like the official guard: allow, 403, guest 401', async () => {
    app = await boot();
    const http = app.getHttpServer();
    await request(http)
      .get('/reports/view')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(http)
      .get('/reports/view')
      .set(asUser({ id: 2 }))
      .expect(403);
    await request(http).get('/reports/view').expect(401);
  });

  it('enforces the string @Can, @Roles and @Permission sugar', async () => {
    app = await boot();
    const http = app.getHttpServer();
    await request(http)
      .get('/reports/documents')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(http)
      .get('/reports/documents')
      .set(asUser({ id: 2 }))
      .expect(403);
    await request(http).get('/reports/documents').expect(401);

    await request(http)
      .get('/reports/admin')
      .set(asUser({ id: 2, roles: ['admin'] }))
      .expect(200);
    await request(http)
      .get('/reports/admin')
      .set(asUser({ id: 2 }))
      .expect(403);

    await request(http)
      .get('/reports/publish')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(http)
      .get('/reports/publish')
      .set(asUser({ id: 2 }))
      .expect(403);
  });

  it('enforces class-level requirements; Can.Anyone() and @Public() on a method lift them', async () => {
    app = await boot();
    const http = app.getHttpServer();
    await request(http)
      .get('/admin')
      .set(asUser({ id: 2, roles: ['admin'] }))
      .expect(200);
    await request(http)
      .get('/admin')
      .set(asUser({ id: 2 }))
      .expect(403);
    await request(http).get('/admin/ping').expect(200);
    await request(http).get('/admin/status').expect(200);
  });

  it('emits the official denied event', async () => {
    app = await boot();
    const events: unknown[] = [];
    app.get(AuthorizationEvents).events$.subscribe((event) => {
      events.push(event);
    });
    await request(app.getHttpServer())
      .get('/reports/view')
      .set(asUser({ id: 2 }))
      .expect(403);
    expect(events).toEqual([
      expect.objectContaining({
        type: 'denied',
        policy: 'ReportPolicy',
        ability: 'view',
        reason: 'forbidden',
        handler: 'ReportController.view',
      }),
    ]);
  });

  it('works from forRootAsync(), where the option sits next to useFactory', async () => {
    app = await boot({ async: { unannotated: 'allow' } });
    const http = app.getHttpServer();
    await request(http).get('/health').expect(200);
    await request(http).get('/reports/view').expect(401);
  });

  it('fails the startup when the factory returns it (it would be ignored)', async () => {
    await expect(boot({ async: { factory: { unannotated: 'allow' } } })).rejects.toThrow(
      /`unannotated` is in the options the forRootAsync\(\) factory returned/,
    );
  });

  it('fails the startup when the official global guard is still on', async () => {
    await expect(boot({ globalGuard: true })).rejects.toThrow(/globalGuard: false/);
  });

  it('rejects an unknown mode', () => {
    expect(() => AuthzModule.forRoot({ unannotated: 'open' as 'allow' })).toThrow(
      /must be 'allow' or 'deny'/,
    );
  });

  it('AuthzGuard is exported for @UseGuards() too', async () => {
    @Controller('scoped')
    @UseGuards(AuthzGuard)
    class ScopedController {
      @Get()
      open() {
        return { ok: true };
      }
      @Get('view')
      @Can(ReportPolicy, 'view')
      view() {
        return { ok: true };
      }
    }
    const mod = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot({ getUser: userFromHeader, globalGuard: false }),
        AuthzModule.forRoot(),
      ],
      controllers: [ScopedController],
      providers: [ReportPolicy],
    }).compile();
    app = mod.createNestApplication({ logger: false });
    await app.init();
    await request(app.getHttpServer()).get('/scoped').expect(200);
    await request(app.getHttpServer()).get('/scoped/view').expect(401);
  });
});

describe("unannotated: 'deny' (the default)", () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('registers nothing: the official global guard denies unannotated routes', async () => {
    app = await boot({ globalGuard: true, authz: {} });
    const http = app.getHttpServer();
    await request(http).get('/health').expect(401);
    await request(http)
      .get('/reports/open')
      .set(asUser({ id: 1 }))
      .expect(403);
    await request(http)
      .get('/reports/view')
      .set(asUser({ id: 1 }))
      .expect(200);
  });

  it('with the official guard off and the default mode, nothing is enforced globally', async () => {
    app = await boot({ authz: {} });
    // The app chose to bind AuthorizationGuard itself: not this library's business.
    await request(app.getHttpServer()).get('/reports/view').expect(200);
    expect(app.get(AuthorizationGuard)).toBeInstanceOf(AuthorizationGuard);
  });
});
