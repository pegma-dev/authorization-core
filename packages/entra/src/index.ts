import type { IdentityLinkKey } from "@pegma/authorization-contracts";

/**
 * Minimal Entra claims accepted after the host has verified the token that
 * supplied them. `oid` is the tenant-scoped stable object id; `sub` is
 * pairwise per app registration and is deliberately not accepted.
 */
export interface EntraIssuerObjectIdClaims {
  readonly iss: string;
  readonly oid: string;
}

const V2_ISSUER_SUFFIX = "/v2.0";
const V1_ISSUER_PREFIX = "https://sts.windows.net/";

const readOwnStringClaim = (
  claims: object,
  name: keyof EntraIssuerObjectIdClaims,
): string => {
  const descriptor = Object.getOwnPropertyDescriptor(claims, name);
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    typeof descriptor.value !== "string" ||
    descriptor.value.trim().length === 0
  ) {
    throw new TypeError(
      `Entra claims must contain a nonblank own string ${name} data property`,
    );
  }

  return descriptor.value;
};

const assertV2Issuer = (issuer: string): void => {
  if (issuer.endsWith(V2_ISSUER_SUFFIX)) {
    return;
  }

  if (issuer.startsWith(V1_ISSUER_PREFIX)) {
    throw new TypeError(
      "Entra claims issuer uses the v1 token profile (sts.windows.net); configure the app registration for v2 tokens so the issuer ends with /v2.0",
    );
  }

  throw new TypeError("Entra claims issuer must end with /v2.0");
};

/**
 * Projects already-verified Entra issuer and object-id claims into an identity
 * link key.
 *
 * This function does not decode or verify tokens. It preserves both nonblank
 * claim values exactly, accepts only the v2 issuer profile, and rejects
 * malformed claim containers. Pairwise `sub` is never read.
 */
export const identityLinkKeyFromVerifiedEntraClaims = (
  claims: EntraIssuerObjectIdClaims,
): IdentityLinkKey => {
  if (typeof claims !== "object" || claims === null) {
    throw new TypeError("Entra claims must be an object");
  }

  const issuer = readOwnStringClaim(claims, "iss");
  const subject = readOwnStringClaim(claims, "oid");
  assertV2Issuer(issuer);

  return Object.freeze({ issuer, subject });
};
