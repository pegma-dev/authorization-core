/**
 * Trusted test-only construction hooks.
 *
 * Production consumers import from `@pegma/authorization-tokens`; this
 * subpath exists so deterministic tests can control clocks, entropy, and the
 * network without making any of them request-populated issuance inputs.
 */
export {
  createAccessGrantIssuerInternal as createTestAccessGrantIssuer,
  type AccessGrantIssuerDependencies,
} from "./issuer.js";
export {
  createAccessGrantVerifierInternal as createTestAccessGrantVerifier,
  type AccessGrantVerifierDependencies,
} from "./verifier.js";
export type { JwksFetchResult, JwksFetcher } from "./jwks.js";
