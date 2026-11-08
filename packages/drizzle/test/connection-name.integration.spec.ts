import 'reflect-metadata';
import { AuthzModule, Gate } from '@dudousxd/nestjs-authz';
import { AuthorizationModule } from '@nestjs/authorization';
import { DrizzleModule, getDrizzleToken } from '@nestjs/drizzle';
import { Test } from '@nestjs/testing';
import { afterEach, beforeEach, expect, it } from 'vitest';
import { AUTHZ_RBAC_STORE, AuthzRbacModule } from '../src/authz-rbac.module.js';
import { DrizzleAuthzStore } from '../src/drizzle-authz.store.js';
import { type AuthzFixture, describeIntegration, freshAuthzDb } from './support/db.js';

describeIntegration('AuthzRbacModule connectionName (@nestjs/drizzle)', () => {
  let fx: AuthzFixture;

  beforeEach(async () => {
    fx = await freshAuthzDb();
    const seed = new DrizzleAuthzStore(fx.db, fx.options);
    await seed.ensureSchema();
    await seed.givePermissionToRole('editor', 'posts.publish');
    await seed.assignRole({ type: 'user', id: 42 }, 'editor');
  });

  afterEach(async () => {
    await fx.close();
  });

  it("forRoot({ connectionName: 'default' }) builds the store from getDrizzleToken()", async () => {
    const moduleRef = await Test.createTestingModule({
      imports: [
        DrizzleModule.forRoot({ db: fx.db, autoCloseConnection: false }),
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRoot({ connectionName: 'default', storeOptions: fx.options }),
      ],
    }).compile();
    await moduleRef.init();

    expect(moduleRef.get(getDrizzleToken())).toBe(fx.db);
    const store = moduleRef.get<DrizzleAuthzStore>(AUTHZ_RBAC_STORE);
    expect(store).toBeInstanceOf(DrizzleAuthzStore);
    expect(store.tables.roles).toBeDefined();
    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ type: 'user', id: 42 }).allows('posts.publish')).toBe(true);
    expect(await gate.forUser({ type: 'user', id: 42 }).hasRole('editor')).toBe(true);
    await moduleRef.close();
  });

  it('forRootAsync({ connectionName }) uses a named connection; the factory supplies the rest', async () => {
    let mapped = false;
    const moduleRef = await Test.createTestingModule({
      imports: [
        DrizzleModule.forRoot({ name: 'authz', db: fx.db, autoCloseConnection: false }),
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRootAsync({
          connectionName: 'authz',
          storeOptions: fx.options,
          useFactory: () => ({
            userRefFrom: (user) => {
              mapped = true;
              return { type: 'user', id: (user as { uid: number }).uid };
            },
          }),
        }),
      ],
    }).compile();
    await moduleRef.init();

    expect(moduleRef.get(getDrizzleToken('authz'))).toBe(fx.db);
    const gate = moduleRef.get(Gate);
    expect(await gate.forUser({ uid: 42 }).allows('posts.publish')).toBe(true);
    expect(mapped).toBe(true);
    await moduleRef.close();
  });

  it('forRootAsync({ useFactory }) still takes a store the app built', async () => {
    const store = new DrizzleAuthzStore(fx.db, fx.options);
    const moduleRef = await Test.createTestingModule({
      imports: [
        AuthorizationModule.forRoot(),
        AuthzModule.forRoot(),
        AuthzRbacModule.forRootAsync({ useFactory: () => ({ store }) }),
      ],
    }).compile();
    await moduleRef.init();
    expect(moduleRef.get(AUTHZ_RBAC_STORE)).toBe(store);
    await moduleRef.close();
  });

  it('rejects connectionName returned from the async factory', async () => {
    await expect(
      Test.createTestingModule({
        imports: [
          AuthorizationModule.forRoot(),
          AuthzModule.forRoot(),
          AuthzRbacModule.forRootAsync({
            useFactory: () => ({ connectionName: 'authz' }) as never,
          }),
        ],
      }).compile(),
    ).rejects.toThrow(/pass connectionName next to useFactory/);
  });
});
