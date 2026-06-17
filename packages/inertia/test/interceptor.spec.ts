import 'reflect-metadata';
import { AuthzModule, CONTEXT_ACCESSOR, Policy } from '@dudousxd/nestjs-authz';
import {
  Controller,
  Get,
  type INestApplication,
  Injectable,
  type MiddlewareConsumer,
  Module,
  type NestMiddleware,
  type NestModule,
  Req,
} from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { afterEach, describe, expect, it } from 'vitest';
import { AuthzInertiaModule } from '../src/module.js';
import type { InertiaShareable } from '../src/types.js';

class Post {}

@Policy(Post)
class PostPolicy {
  create(user: { id: number } | undefined) {
    return user?.id === 1;
  }
  publish() {
    return false;
  }
}

const stubContext = { userRef: () => ({ type: 'User', id: 1 }) };

type SharingRequest = { inertia: InertiaShareable & { shared: Record<string, unknown> } };

/** Fake Inertia middleware: attaches a `req.inertia` whose `share` merges into `shared`. */
@Injectable()
class FakeInertiaMiddleware implements NestMiddleware {
  use(req: Record<string, unknown>, _res: unknown, next: () => void): void {
    const shared: Record<string, unknown> = {};
    req.inertia = {
      shared,
      share(input: Record<string, unknown>) {
        Object.assign(shared, input);
        return this;
      },
    } satisfies InertiaShareable & { shared: Record<string, unknown> };
    next();
  }
}

@Controller()
class ProbeController {
  // Echo back whatever the interceptor shared, so the test can assert it.
  @Get('probe')
  probe(@Req() req: SharingRequest): unknown {
    return req.inertia.shared;
  }
}

@Module({
  imports: [AuthzModule.forRoot({ policies: [PostPolicy] }), AuthzInertiaModule.forRoot()],
  controllers: [ProbeController],
  providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
})
class AppModule implements NestModule {
  configure(consumer: MiddlewareConsumer): void {
    consumer.apply(FakeInertiaMiddleware).forRoutes('*');
  }
}

async function get(app: INestApplication, path: string): Promise<unknown> {
  const server = app.getHttpServer();
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as { port: number };
  const { request } = await import('node:http');
  const body = await new Promise<string>((resolve, reject) => {
    const r = request({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      let data = '';
      res.on('data', (c) => {
        data += c;
      });
      res.on('end', () => resolve(data));
    });
    r.on('error', reject);
    r.end();
  });
  return JSON.parse(body);
}

describe('AuthzInertiaInterceptor — auto-shares props.auth.can via req.inertia', () => {
  let app: INestApplication | undefined;

  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  it('shares the resolved class abilities under auth.can before the handler runs', async () => {
    const mod = await Test.createTestingModule({ imports: [AppModule] }).compile();
    app = mod.createNestApplication();
    await app.init();

    const shared = (await get(app, '/probe')) as { auth: { can: Record<string, boolean> } };
    expect(shared.auth.can['post.create']).toBe(true);
    expect(shared.auth.can['post.publish']).toBe(false);
  });
});
