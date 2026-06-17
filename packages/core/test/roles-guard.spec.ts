import 'reflect-metadata';
import { Controller, Get, type INestApplication } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { Roles } from '../src/decorator/roles.decorator.js';
import { AuthzModule } from '../src/module.js';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';

@Controller('admin')
class AdminController {
  @Get('panel')
  @Roles('admin', 'teacher')
  panel() {
    return { ok: true };
  }

  @Get('open')
  open() {
    return { ok: true };
  }
}

// A context accessor whose user carries `role` directly (zero RBAC tables).
function contextFor(role: string | undefined) {
  return { userRef: () => (role === undefined ? undefined : { type: 'User', id: 1, role }) };
}

describe('RolesGuard (Nest testing module)', () => {
  let app: INestApplication;

  async function boot(role: string | undefined): Promise<void> {
    const mod = await Test.createTestingModule({
      // resolveRoles reads off the raw context userRef (which carries `role`).
      imports: [AuthzModule.forRoot({})],
      controllers: [AdminController],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: contextFor(role) }],
    }).compile();
    app = mod.createNestApplication();
    await app.init();
  }

  afterEach(async () => {
    await app?.close();
  });

  it('allows when the user has one of the listed roles', async () => {
    await boot('teacher');
    await request(app.getHttpServer()).get('/admin/panel').expect(200, { ok: true });
  });

  it('denies with 403 when the user has none of the listed roles', async () => {
    await boot('student');
    await request(app.getHttpServer()).get('/admin/panel').expect(403);
  });

  it('denies with 403 when there is no authenticated user', async () => {
    await boot(undefined);
    await request(app.getHttpServer()).get('/admin/panel').expect(403);
  });

  it('is inert on routes without @Roles', async () => {
    await boot('student');
    await request(app.getHttpServer()).get('/admin/open').expect(200, { ok: true });
  });
});
