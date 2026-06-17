import { BadRequestException } from '@nestjs/common';

export abstract class AuthzException extends Error {
  constructor(message: string) {
    super(message);
    this.name = new.target.name;
  }
}

export class PolicyNotDecoratedException extends AuthzException {
  constructor(public readonly policyName: string) {
    super(`${policyName} is missing @Policy(Resource). Decorate it with the resource class.`);
  }
}

/**
 * Thrown when an ability cannot be matched to any policy method or ad-hoc gate.
 *
 * This is a *programming* error (typically a typo'd ability name), not an
 * authorization denial — so it maps to a `400 Bad Request` HttpException rather
 * than surfacing as a 500. (A genuine denial throws `ForbiddenException` → 403.)
 */
export class AbilityNotResolvedException extends BadRequestException {
  override readonly name = 'AbilityNotResolvedException';
  constructor(public readonly ability: string) {
    super(
      `Ability "${ability}" could not be resolved. No matching policy method or gate.define('${ability}', ...).`,
    );
  }
}

/**
 * Thrown when a class-level ability (`gate.allows('create')`, no resource) is
 * ambiguous: more than one registered policy defines a method with that name, so
 * picking one by Map-insertion order would be a silent, arbitrary choice. Pass an
 * explicit resource class (`gate.allows('create', Post)`) to disambiguate.
 */
export class AmbiguousAbilityException extends BadRequestException {
  override readonly name = 'AmbiguousAbilityException';
  constructor(
    public readonly ability: string,
    public readonly policyNames: string[],
  ) {
    super(
      `Ability "${ability}" is ambiguous: it is defined by multiple policies (${policyNames.join(
        ', ',
      )}). Pass the resource class explicitly, e.g. gate.allows('${ability}', Resource).`,
    );
  }
}

export class ResourceResolverMissingException extends AuthzException {
  constructor(public readonly ability: string) {
    super(
      `@Can('${ability}', Resource) needs an instance but no ResourceResolver is registered. Register one via AuthzModule.forRoot or pass the resource programmatically.`,
    );
  }
}
