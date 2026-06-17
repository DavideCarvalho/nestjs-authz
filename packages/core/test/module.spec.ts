import 'reflect-metadata';
import { Injectable } from '@nestjs/common';
import { Test } from '@nestjs/testing';
import { describe, expect, it } from 'vitest';
import { Policy } from '../src/decorator/policy.decorator.js';
import { Gate } from '../src/gate.js';
import { AuthzModule } from '../src/module.js';
import { PolicyRegistry } from '../src/policy-registry.js';
import { AUTHZ_MODULE_OPTIONS } from '../src/tokens.js';
import type { AuthzModuleOptions, AuthzModuleOptionsFactory } from '../src/types.js';

class Article {
  constructor(
    public id: number,
    public authorId: number,
  ) {}
}

@Policy(Article)
class ArticlePolicy {
  update(user: { id: number }, article: Article) {
    return article.authorId === user.id;
  }
}

// Auto-discovered policy (not passed in `policies: []`).
@Policy(class Comment {})
@Injectable()
class CommentPolicy {
  delete() {
    return true;
  }
}

describe('AuthzModule', () => {
  it('forRoot exposes Gate + registry + options token', async () => {
    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot({ policies: [ArticlePolicy] })],
    }).compile();
    await mod.init();

    expect(mod.get(Gate)).toBeInstanceOf(Gate);
    expect(mod.get(PolicyRegistry)).toBeInstanceOf(PolicyRegistry);
    expect(mod.get(AUTHZ_MODULE_OPTIONS)).toMatchObject({ policies: [ArticlePolicy] });
  });

  it('registers explicit policies so the gate dispatches', async () => {
    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot({ policies: [ArticlePolicy] })],
    }).compile();
    await mod.init();

    const gate = mod.get(Gate);
    expect(await gate.forUser({ id: 1 }).allows('update', new Article(1, 1))).toBe(true);
    expect(await gate.forUser({ id: 2 }).allows('update', new Article(1, 1))).toBe(false);
  });

  it('auto-discovers @Policy providers registered in the module', async () => {
    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRoot()],
      providers: [CommentPolicy],
    }).compile();
    await mod.init();

    const registry = mod.get(PolicyRegistry);
    expect(registry.all().some((p) => p instanceof CommentPolicy)).toBe(true);
  });

  it('applies the global superAdmin hook', async () => {
    const mod = await Test.createTestingModule({
      imports: [
        AuthzModule.forRoot({
          policies: [ArticlePolicy],
          superAdmin: (u) => (u as { root?: boolean }).root === true,
        }),
      ],
    }).compile();
    await mod.init();

    const gate = mod.get(Gate);
    expect(await gate.forUser({ id: 99, root: true }).allows('update', new Article(1, 1))).toBe(
      true,
    );
  });

  it('forRootAsync useFactory resolves options', async () => {
    const mod = await Test.createTestingModule({
      imports: [
        AuthzModule.forRootAsync({
          useFactory: () => ({ policies: [ArticlePolicy] }),
        }),
      ],
    }).compile();
    await mod.init();

    expect(mod.get(AUTHZ_MODULE_OPTIONS)).toMatchObject({ policies: [ArticlePolicy] });
  });

  it('forRootAsync useClass registers and resolves the factory class', async () => {
    @Injectable()
    class OptionsFactory implements AuthzModuleOptionsFactory {
      createAuthzOptions(): AuthzModuleOptions {
        return { policies: [ArticlePolicy] };
      }
    }

    const mod = await Test.createTestingModule({
      imports: [AuthzModule.forRootAsync({ useClass: OptionsFactory })],
    }).compile();
    await mod.init();

    expect(mod.get(AUTHZ_MODULE_OPTIONS)).toMatchObject({ policies: [ArticlePolicy] });
  });
});
