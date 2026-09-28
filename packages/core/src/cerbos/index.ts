// `@dudousxd/nestjs-authz/cerbos` — a DecisionProvider backed by a Cerbos PDP. Structural client
// types only: bring your own `@cerbos/http` / `@cerbos/grpc` client (no runtime dependency here).
export {
  CerbosDecisionProvider,
  type CerbosClientLike,
  type CerbosDecisionProviderOptions,
  type CerbosPrincipal,
  type CerbosResource,
  type CerbosResourceQuery,
  type CerbosValue,
} from './cerbos-decision.provider.js';
export {
  CerbosPlanUnsupportedError,
  cerbosPlanToScope,
  type CerbosFieldMapper,
  type CerbosPlanLike,
  type CerbosPlanOperand,
} from './plan.js';
