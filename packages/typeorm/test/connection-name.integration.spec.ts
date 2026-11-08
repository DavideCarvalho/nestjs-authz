import 'reflect-metadata';
import { AuthzModule, Gate } from '@dudousxd/nestjs-authz';
import { AuthorizationModule } from '@nestjs/authorization';
import { Test } from '@nestjs/testing';
import { TypeOrmModule, getDataSourceToken } from '@nestjs/typeorm';
import type { DataSourceOptions } from 'typeorm';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { AUTHZ_RBAC_STORE, AuthzRbacModule } from '../src/authz-rbac.module.js';
import { TypeOrmAuthzStore } from '../src/typeorm-authz.store.js';
import {
  type AuthzFixture,
  describeIntegration,
  freshAuthzDataSource,
} from './support/datasource.js';

/** Registers the fixture's (already initialized) DataSource with @nestjs/typeorm. */
function typeOrmWith(fx: AuthzFixture, name?: string) {
  return TypeOrmModule.forRootAsync({
    ...(name ? { name } : {}),
    useFactory: () => fx.ds.options as DataSourceOptions,
    dataSourceFactory: async () => fx.ds,
  });
}

describeIntegration('AuthzRbacModule connectionName (@nestjs/typeorm)', () => {
  let fx: AuthzFixture;

  beforeEach(async () => {
    fx = await freshAuthzDataSource();
    const seed = new TypeOrmAuthzStore(fx.ds, fx.options);
    await seed.ensureSchema();
    await seed.givePermissionToRole('editor', 'posts.publish');
    await seed.assignRole({ type: 'user', id: 42 }, 'editor');
  });

  afterEach(async () => {
    if (fx.ds.isInitialized) await fx.ds.destroy();
  });

  it("forRoot({ connectionName: 'default' }) builds the store from getDataSourceToken()", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        typeOrmWith(fx),
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRoot({
          connectionName: 'default',
          storeOptions: fx.options,
          autoCreateSchema: false,
        }),
      ],
    }).compile();
    await moduleRef.init();

    expect(moduleRef.get(getDataSourceToken())).toBe(fx.ds);
    expect(moduleRef.get(AUTHZ_RBAC_STORE)).toBeInstanceOf(TypeOrmAuthzStore);
    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ type: 'user', id: 42 }).allows('posts.publish')).toBe(true);
    expect(await gate.forUser({ type: 'user', id: 42 }).hasRole('editor')).toBe(true);
    await moduleRef.close();
  });

  it('forRootAsync({ connectionName }) uses a named data source; the factory supplies the rest', async () => {
    let mapped = false;
    const moduleRef = await Test.createTestingModule({
      imports: [
        typeOrmWith(fx, 'authz'),
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRootAsync({
          connectionName: 'authz',
          storeOptions: fx.options,
          useFactory: () => ({
            autoCreateSchema: false,
            userRefFrom: (user) => {
              mapped = true;
              return { type: 'user', id: (user as { uid: number }).uid };
            },
          }),
        }),
      ],
    }).compile();
    await moduleRef.init();

    expect(moduleRef.get(getDataSourceToken('authz'))).toBe(fx.ds);
    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ uid: 42 }).allows('posts.publish')).toBe(true);
    expect(mapped).toBe(true);
    await moduleRef.close();
  });

  it('forRoot({ store }) still takes a store the app built', async () => {
    const store = new TypeOrmAuthzStore(fx.ds, fx.options);
    const moduleRef = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRoot({ store, autoCreateSchema: false }),
      ],
    }).compile();
    await moduleRef.init();
    expect(moduleRef.get(AUTHZ_RBAC_STORE)).toBe(store);
    await moduleRef.close();
  });
});
