import type { IdentityLinkKey } from "@pegma/authorization-contracts";

/**
 * Minimal Auth0 claims accepted after the host has verified the token or
 * session that supplied them.
 */
export interface Auth0IssuerSubjectClaims {
  readonly iss: string;
  readonly sub: string;
}

const readOwnStringClaim = (
  claims: object,
  name: keyof Auth0IssuerSubjectClaims,
): string => {
  const descriptor = Object.getOwnPropertyDescriptor(claims, name);
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    typeof descriptor.value !== "string" ||
    descriptor.value.trim().length === 0
  ) {
    throw new TypeError(
      `Auth0 claims must contain a nonblank own string ${name} data property`,
    );
  }

  return descriptor.value;
};

/**
 * Projects already-verified Auth0 issuer and subject claims into an identity
 * link key.
 *
 * This function does not decode or verify tokens. It preserves both nonblank
 * claim values exactly and rejects malformed claim containers.
 */
export const identityLinkKeyFromVerifiedAuth0Claims = (
  claims: Auth0IssuerSubjectClaims,
): IdentityLinkKey => {
  if (typeof claims !== "object" || claims === null) {
    throw new TypeError("Auth0 claims must be an object");
  }

  const issuer = readOwnStringClaim(claims, "iss");
  const subject = readOwnStringClaim(claims, "sub");

  return Object.freeze({ issuer, subject });
};
