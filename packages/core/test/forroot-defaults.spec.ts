import 'reflect-metadata';
import { Controller, Get, type INestApplication, Injectable, Param } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import { Can } from '../src/decorator/can.decorator.js';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import { AuthzModule } from '../src/module.js';
import { CONTEXT_ACCESSOR } from '../src/tokens.js';
import type { AuthzModuleOptions } from '../src/types.js';

class Doc {
  id!: string;
}

@Policy(Doc)
class DocPolicy {
  // Works on the default IdParamResourceResolver shim, which only carries `id`.
  view(_user: { id: number }, doc: Doc) {
    return doc.id === '1'; // only doc #1 is viewable
  }
}

@Controller('docs')
class DocController {
  @Get(':id')
  @Can('view', Doc)
  view(@Param('id') id: string) {
    return { id };
  }
}

const stubContext = {
  userRef: () => ({ type: 'User', id: 1 }),
  traceId: () => undefined,
  tenantId: () => undefined,
  get: () => undefined,
};

describe('forRoot default ResourceResolver (P2)', () => {
  let app: INestApplication;

  afterEach(async () => {
    await app?.close();
  });

  it('@Can on an instance route works WITHOUT manually providing a resolver', async () => {
    // CLEAN install: no RESOURCE_RESOLVER, no resourceResolver option.
    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot({ policies: [DocPolicy] })],
      controllers: [DocController],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    app = mod.createNestApplication();
    await app.init();

    // Default IdParamResourceResolver reads :id → shim { id: '1' } → policy allows.
    await request(app.getHttpServer()).get('/docs/1').expect(200, { id: '1' });
    // doc #2 → policy denies.
    await request(app.getHttpServer()).get('/docs/2').expect(403);
  });

  it('honors the idParam knob for the default resolver', async () => {
    @Controller('items')
    class ItemController {
      @Get(':slug')
      @Can('view', Doc)
      view(@Param('slug') slug: string) {
        return { slug };
      }
    }

    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot({ policies: [DocPolicy], idParam: 'slug' })],
      controllers: [ItemController],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    app = mod.createNestApplication();
    await app.init();

    // `:slug` is read as the id → doc with id '1' is viewable.
    await request(app.getHttpServer()).get('/items/1').expect(200, { slug: '1' });
    await request(app.getHttpServer()).get('/items/2').expect(403);
  });

  it("a typo'd ability maps to 4xx (AbilityNotResolved), not a 500", async () => {
    @Controller('typo')
    class TypoController {
      @Get()
      @Can('nonexistent') // ad-hoc gate that was never defined
      go() {
        return { ok: true };
      }
    }

    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot()],
      controllers: [TypoController],
      providers: [{ provide: CONTEXT_ACCESSOR, useValue: stubContext }],
    }).compile();
    app = mod.createNestApplication();
    await app.init();

    // BadRequestException → 400, not an unhandled 500.
    await request(app.getHttpServer()).get('/typo').expect(400);
  });
});

describe('forRootAsync registers resolved policies (P11)', () => {
  let app: INestApplication;

  afterEach(async () => {
    await app?.close();
  });

  it('an async-configured policy actually dispatches', async () => {
    @Policy(class Thing {})
    @Injectable()
    class ThingPolicy {
      do(user: { ok?: boolean }) {
        return user.ok === true;
      }
    }

    const mod = await Test.createTestingModule({
      imports: [
        AuthzModule.forRootAsync({
          useFactory: (): AuthzModuleOptions => ({ policies: [ThingPolicy] }),
        }),
      ],
      // ThingPolicy is NOT registered as an app provider — the bootstrap must
      // pick it up from the resolved AUTHZ_MODULE_OPTIONS.policies and register it.
    }).compile();
    app = mod.createNestApplication();
    await app.init();

    const gate = app.get(Gate);
    expect(await gate.forUser({ ok: true }).allows('do')).toBe(true);
    expect(await gate.forUser({ ok: false }).allows('do')).toBe(false);
  });
});
