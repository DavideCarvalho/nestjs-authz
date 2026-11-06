import 'reflect-metadata';
import { Can, Policy } from '@nestjs/authorization';
import { Controller, Get, type INestApplication } from '@nestjs/common';
import request from 'supertest';
import { afterEach, describe, expect, it } from 'vitest';
import {
  STATIC_CAN_ARGS,
  byId,
  getStaticCanArgs,
  permission,
  roles,
  staticCanArgs,
} from '../src/helpers.js';
import {
  OFFICIAL_CAN_ANYONE_METADATA,
  OFFICIAL_CAN_METADATA,
  OFFICIAL_POLICY_METADATA,
  isOfficialPolicy,
  readCanRequirements,
  routeRequirements,
} from '../src/official.js';
import { asUser, bootApp } from './support/app.js';

/**
 * `@nestjs/authorization` does not export its metadata keys, so this package spells
 * them. These tests fail if the official package stops writing or honoring them.
 */
describe('contract with @nestjs/authorization metadata', () => {
  let app: INestApplication | undefined;
  afterEach(async () => {
    await app?.close();
    app = undefined;
  });

  @Policy()
  class FlagPolicy {
    on(_user: unknown, flag: string) {
      return flag === 'on';
    }
  }

  it('the official decorators write under the keys this package reads', () => {
    class Ctl {
      @Can(FlagPolicy, 'on', staticCanArgs('on'))
      a() {}
      @Can.Anyone()
      b() {}
    }
    expect(Reflect.getMetadata(OFFICIAL_POLICY_METADATA, FlagPolicy)).toBe(true);
    expect(isOfficialPolicy(FlagPolicy)).toBe(true);
    const [req] = readCanRequirements(Ctl.prototype.a);
    expect(req).toMatchObject({ policy: FlagPolicy, ability: 'on' });
    expect(Reflect.getMetadata(OFFICIAL_CAN_METADATA, Ctl.prototype.a)).toHaveLength(1);
    expect(Reflect.getMetadata(OFFICIAL_CAN_ANYONE_METADATA, Ctl.prototype.b)).toBe(true);
  });

  it('the official guard enforces requirements written by hand under the keys', async () => {
    @Controller('flags')
    class FlagController {
      @Get('on')
      on() {
        return { ok: true };
      }
      @Get('off')
      off() {
        return { ok: true };
      }
      @Get('open')
      open() {
        return { ok: true };
      }
    }
    Reflect.defineMetadata(
      OFFICIAL_CAN_METADATA,
      [{ policy: FlagPolicy, ability: 'on', args: staticCanArgs('on') }],
      FlagController.prototype.on,
    );
    Reflect.defineMetadata(
      OFFICIAL_CAN_METADATA,
      [{ policy: FlagPolicy, ability: 'on', args: staticCanArgs('off') }],
      FlagController.prototype.off,
    );
    Reflect.defineMetadata(OFFICIAL_CAN_ANYONE_METADATA, true, FlagController.prototype.open);
    ({ app } = await bootApp({ controllers: [FlagController], providers: [FlagPolicy] }));
    const http = app.getHttpServer();
    await request(http)
      .get('/flags/on')
      .set(asUser({ id: 1 }))
      .expect(200);
    await request(http)
      .get('/flags/off')
      .set(asUser({ id: 1 }))
      .expect(403);
    await request(http).get('/flags/open').expect(200);
  });

  it('a class marked only by hand is discovered as an official policy', async () => {
    class HandPolicy {
      ok() {
        return true;
      }
    }
    Reflect.defineMetadata(OFFICIAL_POLICY_METADATA, true, HandPolicy);
    @Controller('hand')
    class HandController {
      @Get()
      @Can(HandPolicy, 'ok')
      get() {
        return { ok: true };
      }
    }
    // Injectable() is what the official @Policy() adds besides the marker.
    const { Injectable } = await import('@nestjs/common');
    Injectable()(HandPolicy);
    ({ app } = await bootApp({ controllers: [HandController], providers: [HandPolicy] }));
    await request(app.getHttpServer()).get('/hand').expect(200);
  });

  it('routeRequirements mirrors the official order: class, then method; Anyone lifts the class', () => {
    @Can(FlagPolicy, 'on', staticCanArgs('on'))
    class Ctl {
      @Can(FlagPolicy, 'on', staticCanArgs('m'))
      both() {}
      @Can.Anyone()
      lifted() {}
    }
    expect(routeRequirements(Ctl, Ctl.prototype.both).map((r) => getStaticCanArgs(r.args))).toEqual(
      [['on'], ['m']],
    );
    expect(routeRequirements(Ctl, Ctl.prototype.lifted)).toEqual([]);
  });
});

describe('static @Can() arguments', () => {
  it('marks the resolver with a non-enumerable Symbol.for key holding the args', () => {
    const resolver = roles('admin', 'editor');
    expect(STATIC_CAN_ARGS).toBe(Symbol.for('@dudousxd/static-can-args'));
    expect((resolver as unknown as Record<symbol, unknown>)[STATIC_CAN_ARGS]).toEqual([
      'admin',
      'editor',
    ]);
    expect(Object.keys(resolver)).toEqual([]);
    expect(Object.getOwnPropertyDescriptor(resolver, STATIC_CAN_ARGS)?.enumerable).toBe(false);
    expect(getStaticCanArgs(permission('posts.update'))).toEqual(['posts.update']);
  });

  it('call-dependent resolvers are not marked', () => {
    class Post {}
    expect(getStaticCanArgs(byId(Post))).toBeUndefined();
  });
});
