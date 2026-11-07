import 'reflect-metadata';
import { Public } from '@nestjs/authentication';
import {
  AuthorizationEvents,
  AuthorizationGuard,
  AuthorizationModule,
  Can,
  Policy,
} from '@nestjs/authorization';
import {
  Controller,
  Get,
  type INestApplication,
  type LoggerService,
  UseGuards,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthzGuard } from '../src/authz.guard.js';
import { Permission, Roles } from '../src/decorator/roles.decorator.js';
import { Gate } from '../src/gate.js';
import { ability } from '../src/helpers.js';
import { AuthzModule } from '../src/module.js';
import { GatePolicy } from '../src/policies/gate.policy.js';
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
  @Can(GatePolicy, 'allows', ability('page.documents'))
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
    logger?: LoggerService;
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
  const app = mod.createNestApplication({ logger: options.logger ?? false });
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

  it('enforces GatePolicy, @Roles and @Permission', async () => {
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

  it("boot: the official 'not enforced' error is the only ERROR, and AuthzModule explains it after", async () => {
    // @nestjs/authorization 0.1.3 recognizes a guard that enforces @Can() only by its brand, and
    // the brand would also make it report every route AuthzGuard lets through as "denied". So the
    // official startup check logs the routes AuthzGuard enforces as "not enforced" (README:
    // "Migrating one controller at a time"). Pinned here: when an official version stops logging
    // it, or changes it, this test says so.
    const lines: Array<{ level: string; message: string; context: string | undefined }> = [];
    const record =
      (level: string) =>
      (message: unknown, ...rest: unknown[]) =>
        lines.push({ level, message: String(message), context: rest.at(-1) as string | undefined });
    const logger: LoggerService = {
      log: record('log'),
      warn: record('warn'),
      error: record('error'),
      debug: () => {},
      verbose: () => {},
    };
    app = await boot({ logger });

    const errors = lines.filter((l) => l.level === 'error');
    expect(errors).toEqual([
      expect.objectContaining({
        message: expect.stringMatching(
          /^@Can\(\) is not enforced on ReportController\.view, ReportController\.documents, ReportController\.admin and \d+ more: AuthorizationModule has globalGuard: false/,
        ),
      }),
    ]);
    // Nothing about unannotated routes being denied: AuthzGuard lets them through.
    expect(lines.some((l) => l.message.includes('denies every call'))).toBe(false);

    const explanation = lines.findIndex(
      (l) =>
        l.context === 'AuthzModule' && l.message.includes('the global AuthzGuard enforces @Can()'),
    );
    expect(explanation).toBeGreaterThan(lines.indexOf(errors[0] as (typeof lines)[number]));
    expect(lines[explanation]?.level).toBe('log');
    // The same handlers, in the same words, as the official error.
    const named = (message: string | undefined) => /on (.+?)[:.] /.exec(message ?? '')?.[1];
    expect(named(lines[explanation]?.message)).toBe(named(errors[0]?.message));

    // And they are enforced.
    await request(app.getHttpServer()).get('/reports/view').expect(401);
    await request(app.getHttpServer())
      .get('/admin')
      .set(asUser({ id: 2 }))
      .expect(403);
  });

  it('boot: no explanation when no route declares a requirement', async () => {
    const lines: string[] = [];
    const logger: LoggerService = {
      log: (m) => lines.push(String(m)),
      warn: (m) => lines.push(String(m)),
      error: (m) => lines.push(`ERROR ${String(m)}`),
    };
    const mod = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot({ getUser: userFromHeader, globalGuard: false }),
        AuthzModule.forRoot({ unannotated: 'allow' }),
      ],
      controllers: [HealthController],
    }).compile();
    app = mod.createNestApplication({ logger });
    await app.init();
    expect(lines.filter((l) => l.startsWith('ERROR'))).toEqual([]);
    expect(lines.some((l) => l.includes('AuthzGuard enforces'))).toBe(false);
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
