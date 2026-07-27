import type { Store } from "@pegma/storage-core";
import { compactVerify } from "jose";

import type { AcceptedAccessGrantPolicy } from "./issuer.js";
import {
  ACCESS_GRANT_ALGORITHM,
  ACCESS_GRANT_PROFILE_VERSION,
  ACCESS_GRANT_TYPE,
  AccessGrantError,
  CLAIM_FIELDS,
  canonicalPermissions,
  decodeCanonicalBase64Url,
  exactRecord,
  fail,
  HEADER_FIELDS,
  isBoundedIdentity,
  isCanonicalBase64Url32,
  isCanonicalPermissions,
  isKid,
  isNumericDate,
  isPolicyDigest,
  isPolicyVersion,
  MAX_ACCESS_GRANT_LIFETIME_SECONDS,
  MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS,
  parseStrictJson,
  policyPair,
} from "./internal.js";
import {
  defaultJwksFetcher,
  getSharedJwksCache,
  type JwksFetcher,
} from "./jwks.js";
import { createReplayConsumer } from "./replay.js";

export interface VerifiedAccessGrant {
  readonly issuer: string;
  readonly applicationId: string;
  readonly audience: string;
  readonly principalId: string;
  readonly expiresAt: number;
  readonly issuedAt: number;
  readonly jti: string;
  readonly profileVersion: typeof ACCESS_GRANT_PROFILE_VERSION;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly permissions: readonly string[];
}

export interface AccessGrantVerifierConfiguration {
  readonly issuer: string;
  readonly applicationId: string;
  readonly audience: string;
  readonly allowedPermissions: readonly string[];
  readonly acceptedPolicies: readonly AcceptedAccessGrantPolicy[];
  readonly jwksUrl: string;
  readonly jwksCacheAgeMs: number;
}

export interface AccessGrantVerifierDependencies {
  readonly verifierWallNowEpochMs: () => number;
  readonly jwksMonotonicNowMs: () => number;
  readonly replayStoreNowEpochMs: () => number;
  readonly fetchJwks: JwksFetcher;
}

export interface AccessGrantVerifier {
  /**
   * Verify every V1 invariant and atomically consume the grant before return.
   *
   * There is intentionally no verify-only public operation.
   */
  verifyAndConsume(compact: string): Promise<VerifiedAccessGrant>;
}

interface ParsedGrant {
  readonly header: Readonly<{
    alg: typeof ACCESS_GRANT_ALGORITHM;
    kid: string;
    typ: typeof ACCESS_GRANT_TYPE;
  }>;
  readonly claims: Readonly<{
    iss: string;
    application_id: string;
    aud: string;
    sub: string;
    exp: number;
    iat: number;
    jti: string;
    profile_version: typeof ACCESS_GRANT_PROFILE_VERSION;
    policy_version: string;
    policy_digest: string;
    permissions: readonly string[];
  }>;
  readonly payloadBytes: Uint8Array;
}

function parseCompactGrant(compact: string): ParsedGrant {
  if (typeof compact !== "string") {
    fail("access grant must be compact JWS text");
  }
  const segments = compact.split(".");
  if (
    segments.length !== 3 ||
    segments.some((segment) => segment.length === 0)
  ) {
    fail("access grant must have exactly three compact segments");
  }
  const [encodedHeader, encodedPayload, encodedSignature] = segments as [
    string,
    string,
    string,
  ];
  const headerBytes = decodeCanonicalBase64Url(
    encodedHeader,
    "protected header",
  );
  const payloadBytes = decodeCanonicalBase64Url(encodedPayload, "payload");
  const signatureBytes = decodeCanonicalBase64Url(
    encodedSignature,
    "signature",
  );
  if (signatureBytes.byteLength !== 64) {
    fail("ES256 compact signature must be 64 bytes");
  }

  const headerValue = exactRecord(
    parseStrictJson(headerBytes, "protected header"),
    HEADER_FIELDS,
    "protected header",
  );
  if (
    headerValue["alg"] !== ACCESS_GRANT_ALGORITHM ||
    headerValue["typ"] !== ACCESS_GRANT_TYPE ||
    !isKid(headerValue["kid"])
  ) {
    fail("protected header is not an access-grant V1 header");
  }

  const claimsValue = exactRecord(
    parseStrictJson(payloadBytes, "claims"),
    CLAIM_FIELDS,
    "claims",
  );
  if (
    typeof claimsValue["iss"] !== "string" ||
    claimsValue["iss"].length === 0 ||
    !isBoundedIdentity(claimsValue["application_id"]) ||
    typeof claimsValue["aud"] !== "string" ||
    claimsValue["aud"].length === 0 ||
    !isBoundedIdentity(claimsValue["sub"]) ||
    !isNumericDate(claimsValue["exp"]) ||
    !isNumericDate(claimsValue["iat"]) ||
    claimsValue["exp"] <= claimsValue["iat"] ||
    claimsValue["exp"] - claimsValue["iat"] >
      MAX_ACCESS_GRANT_LIFETIME_SECONDS ||
    !isCanonicalBase64Url32(claimsValue["jti"]) ||
    claimsValue["profile_version"] !== ACCESS_GRANT_PROFILE_VERSION ||
    !isPolicyVersion(claimsValue["policy_version"]) ||
    !isPolicyDigest(claimsValue["policy_digest"]) ||
    !isCanonicalPermissions(claimsValue["permissions"])
  ) {
    fail("access-grant claims are malformed");
  }

  return {
    header: {
      alg: ACCESS_GRANT_ALGORITHM,
      kid: headerValue["kid"],
      typ: ACCESS_GRANT_TYPE,
    },
    claims: {
      iss: claimsValue["iss"],
      application_id: claimsValue["application_id"],
      aud: claimsValue["aud"],
      sub: claimsValue["sub"],
      exp: claimsValue["exp"],
      iat: claimsValue["iat"],
      jti: claimsValue["jti"],
      profile_version: ACCESS_GRANT_PROFILE_VERSION,
      policy_version: claimsValue["policy_version"],
      policy_digest: claimsValue["policy_digest"],
      permissions: Object.freeze([...claimsValue["permissions"]]),
    },
    payloadBytes,
  };
}

export const productionVerifierDependencies: AccessGrantVerifierDependencies =
  Object.freeze({
    verifierWallNowEpochMs: () => Date.now(),
    jwksMonotonicNowMs: () => performance.now(),
    replayStoreNowEpochMs: () => Date.now(),
    fetchJwks: defaultJwksFetcher,
  });

export function createAccessGrantVerifierInternal(
  configuration: AccessGrantVerifierConfiguration,
  store: Store,
  dependencies: AccessGrantVerifierDependencies,
): AccessGrantVerifier {
  const issuer = configuration.issuer;
  const applicationId = configuration.applicationId;
  const audience = configuration.audience;
  const jwksUrl = configuration.jwksUrl;
  const jwksCacheAgeMs = configuration.jwksCacheAgeMs;
  const verifierWallNowEpochMs = dependencies.verifierWallNowEpochMs;
  const jwksMonotonicNowMs = dependencies.jwksMonotonicNowMs;
  const replayStoreNowEpochMs = dependencies.replayStoreNowEpochMs;
  const fetchJwks = dependencies.fetchJwks;
  if (
    issuer.length === 0 ||
    !isBoundedIdentity(applicationId) ||
    audience.length === 0
  ) {
    fail("access-grant verifier configuration is malformed");
  }
  const permissions = new Set(
    canonicalPermissions(configuration.allowedPermissions),
  );
  const policies = new Set<string>();
  for (const policy of configuration.acceptedPolicies) {
    if (!isPolicyVersion(policy.version) || !isPolicyDigest(policy.digest)) {
      fail("accepted access-grant policy is malformed");
    }
    policies.add(policyPair(policy.version, policy.digest));
  }
  const jwks = getSharedJwksCache({
    issuer,
    url: jwksUrl,
    maxAgeMs: jwksCacheAgeMs,
    monotonicNowMs: jwksMonotonicNowMs,
    fetcher: fetchJwks,
  });
  const replay = createReplayConsumer(store, replayStoreNowEpochMs);
  const requireGrantTimeWindow = (claims: ParsedGrant["claims"]): void => {
    const wallNow = verifierWallNowEpochMs();
    if (!Number.isFinite(wallNow) || wallNow < 0) {
      fail("verifier wall clock is invalid");
    }
    const now = Math.floor(wallNow / 1_000);
    if (
      !Number.isSafeInteger(now) ||
      claims.iat > now + MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS ||
      now >= claims.exp
    ) {
      fail("access grant is outside its time window");
    }
  };

  return Object.freeze({
    async verifyAndConsume(compact: string): Promise<VerifiedAccessGrant> {
      try {
        const parsed = parseCompactGrant(compact);
        const claims = parsed.claims;
        const key = await jwks.resolve(parsed.header.kid);
        const verified = await compactVerify(compact, key, {
          algorithms: [ACCESS_GRANT_ALGORITHM],
        });
        if (
          verified.payload.byteLength !== parsed.payloadBytes.byteLength ||
          !verified.payload.every(
            (byte, index) => byte === parsed.payloadBytes[index],
          )
        ) {
          fail("verified access-grant payload changed");
        }
        if (
          claims.iss !== issuer ||
          claims.application_id !== applicationId ||
          claims.aud !== audience ||
          !policies.has(
            policyPair(claims.policy_version, claims.policy_digest),
          ) ||
          !claims.permissions.every((permission) => permissions.has(permission))
        ) {
          fail("access grant is not accepted by this verifier");
        }

        requireGrantTimeWindow(claims);

        await replay.consume({
          issuer: claims.iss,
          applicationId: claims.application_id,
          audience: claims.aud,
          jti: claims.jti,
          retainThrough: claims.exp + MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS,
        });
        requireGrantTimeWindow(claims);

        return Object.freeze({
          issuer: claims.iss,
          applicationId: claims.application_id,
          audience: claims.aud,
          principalId: claims.sub,
          expiresAt: claims.exp,
          issuedAt: claims.iat,
          jti: claims.jti,
          profileVersion: claims.profile_version,
          policyVersion: claims.policy_version,
          policyDigest: claims.policy_digest,
          permissions: claims.permissions,
        });
      } catch {
        // Runtime failures intentionally share one response so callers cannot
        // probe keys, policies, permissions, principals, or replay state.
        throw new AccessGrantError();
      }
    },
  });
}

/** Create a production verifier using a host-supplied storage-core Store. */
export function createAccessGrantVerifier(
  configuration: AccessGrantVerifierConfiguration,
  store: Store,
): AccessGrantVerifier {
  return createAccessGrantVerifierInternal(
    configuration,
    store,
    productionVerifierDependencies,
  );
}
