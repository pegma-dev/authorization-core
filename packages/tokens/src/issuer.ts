import type { AccessContext } from "@pegma/authorization-contracts";
import { base64url, CompactSign } from "jose";
import type { Store } from "@pegma/storage-core";

import {
  ACCESS_GRANT_ALGORITHM,
  ACCESS_GRANT_PROFILE_VERSION,
  ACCESS_GRANT_TYPE,
  canonicalPermissions,
  fail,
  GuardedMonotonicClock,
  isBoundedIdentity,
  isCanonicalBase64Url32,
  isCanonicalPermissions,
  isKid,
  isNumericDate,
  isPolicyDigest,
  isPolicyVersion,
  MAX_ACCESS_GRANT_LIFETIME_SECONDS,
  MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS,
  MAX_SOURCE_AUTHORIZATION_LIFETIME_MS,
  policyPair,
} from "./internal.js";
import { createJtiReserver } from "./jti-reservation.js";

export interface AcceptedAccessGrantPolicy {
  readonly version: string;
  readonly digest: string;
}

export type AccessGrantSourceScope =
  | Readonly<{ readonly kind: "application" }>
  | Readonly<{
      readonly kind: "organization";
      readonly organizationId: string;
    }>;

export interface SourceAuthorizationSnapshot {
  readonly applicationId: string;
  readonly context: AccessContext;
  readonly policyDigest: string;
  readonly scope: AccessGrantSourceScope;
  /**
   * Absolute cache/read lifetime beginning at the sample immediately before
   * this snapshot's authoritative source reader was called.
   */
  readonly maximumLifetimeMs: number;
}

export interface AccessGrantIssuerConfiguration<ReadRequest> {
  readonly issuer: string;
  readonly applicationId: string;
  readonly kid: string;
  readonly signingKey: CryptoKey;
  readonly audiences: Readonly<Record<string, readonly string[]>>;
  readonly acceptedPolicies: readonly AcceptedAccessGrantPolicy[];
  readonly sourceReader: (
    request: ReadRequest,
  ) => SourceAuthorizationSnapshot | Promise<SourceAuthorizationSnapshot>;
}

export interface AccessGrantIssuerDependencies {
  readonly monotonicNowMs: () => number;
  readonly wallNowEpochMs: () => number;
  readonly randomBytes32: () => Uint8Array;
}

interface BoundSourceAuthorization {
  readonly owner: object;
  readonly domain: IssuerDomainState;
  readonly applicationId: string;
  readonly context: AccessContext;
  readonly policyDigest: string;
  readonly scope: AccessGrantSourceScope;
  readonly expiresAtMonotonicMs: number;
}

interface IssuerDomainState {
  failed: boolean;
}

/** Opaque evidence returned only by an issuer's trusted source reader. */
export class AuthoritativeSourceAuthorizationRead {}

/** Opaque, issuer-local source authorization accepted by issue(). */
export class SourceAuthorizationCapability {}

const sourceReads = new WeakMap<
  AuthoritativeSourceAuthorizationRead,
  BoundSourceAuthorization
>();
const sourceCapabilities = new WeakMap<
  SourceAuthorizationCapability,
  BoundSourceAuthorization
>();

export interface IssueAccessGrantInput {
  readonly audience: string;
  readonly requestedPermissions: readonly string[];
  readonly source: SourceAuthorizationCapability;
}

export interface AccessGrantIssuer<ReadRequest> {
  readSourceAuthorization(
    request: ReadRequest,
  ): Promise<AuthoritativeSourceAuthorizationRead>;
  bindSourceAuthorization(
    read: AuthoritativeSourceAuthorizationRead,
  ): SourceAuthorizationCapability;
  issue(input: IssueAccessGrantInput): Promise<string>;
}

function snapshotStringArray(
  value: readonly string[],
  field: string,
): string[] {
  if (!Array.isArray(value)) {
    fail(`${field} must be an array`);
  }
  const copy: string[] = [];
  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index) || typeof value[index] !== "string") {
      fail(`${field} must be a dense string array`);
    }
    copy.push(value[index]);
  }
  return Object.freeze(copy) as string[];
}

function snapshotContext(value: AccessContext): AccessContext {
  if (typeof value !== "object" || value === null) {
    fail("source access context must be an object");
  }
  return Object.freeze({
    principalId: value.principalId,
    policyVersion: value.policyVersion,
    roles: snapshotStringArray(value.roles, "context.roles"),
    entitlements: snapshotStringArray(
      value.entitlements,
      "context.entitlements",
    ),
    permissions: snapshotStringArray(value.permissions, "context.permissions"),
  });
}

function snapshotScope(value: AccessGrantSourceScope): AccessGrantSourceScope {
  if (typeof value !== "object" || value === null) {
    fail("source scope must be an object");
  }
  if (value.kind === "application") {
    return Object.freeze({ kind: "application" });
  }
  if (
    value.kind === "organization" &&
    typeof value.organizationId === "string" &&
    value.organizationId.length > 0
  ) {
    return Object.freeze({
      kind: "organization",
      organizationId: value.organizationId,
    });
  }
  fail("source scope is malformed");
}

function requireSigningKey(key: CryptoKey): void {
  const algorithm = key.algorithm;
  if (
    key.type !== "private" ||
    algorithm.name !== "ECDSA" ||
    !("namedCurve" in algorithm) ||
    (algorithm as EcKeyAlgorithm).namedCurve !== "P-256" ||
    !key.usages.includes("sign")
  ) {
    fail("access-grant issuer requires a private P-256 signing key");
  }
}

function defaultRandomBytes32(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(32));
}

export const productionIssuerDependencies: AccessGrantIssuerDependencies =
  Object.freeze({
    monotonicNowMs: () => performance.now(),
    wallNowEpochMs: () => Date.now(),
    randomBytes32: defaultRandomBytes32,
  });

export function createAccessGrantIssuerInternal<ReadRequest>(
  configuration: AccessGrantIssuerConfiguration<ReadRequest>,
  store: Store,
  dependencies: AccessGrantIssuerDependencies,
): AccessGrantIssuer<ReadRequest> {
  const issuerName = configuration.issuer;
  const applicationId = configuration.applicationId;
  const signingKid = configuration.kid;
  const signingKey = configuration.signingKey;
  const sourceReader = configuration.sourceReader;
  const monotonicNowMs = dependencies.monotonicNowMs;
  const wallNowEpochMs = dependencies.wallNowEpochMs;
  const randomBytes32 = dependencies.randomBytes32;
  if (
    issuerName.length === 0 ||
    !isBoundedIdentity(applicationId) ||
    !isKid(signingKid) ||
    typeof sourceReader !== "function"
  ) {
    fail("access-grant issuer configuration is malformed");
  }
  requireSigningKey(signingKey);

  const audiencePermissions = new Map<string, ReadonlySet<string>>();
  for (const [audience, values] of Object.entries(configuration.audiences)) {
    if (audience.length === 0) {
      fail("access-grant audience must not be empty");
    }
    audiencePermissions.set(audience, new Set(canonicalPermissions(values)));
  }
  const acceptedPolicies = new Set<string>();
  for (const policy of configuration.acceptedPolicies) {
    if (!isPolicyVersion(policy.version) || !isPolicyDigest(policy.digest)) {
      fail("accepted access-grant policy is malformed");
    }
    acceptedPolicies.add(policyPair(policy.version, policy.digest));
  }

  const owner = Object.freeze({});
  const domain: IssuerDomainState = { failed: false };
  const clock = new GuardedMonotonicClock(monotonicNowMs, () => {
    domain.failed = true;
  });
  const jtiReservations = createJtiReserver(store);
  const readGrantWindow = (source: BoundSourceAuthorization) => {
    // The wall clock read deliberately precedes the monotonic sample.
    const wallNow = wallNowEpochMs();
    const monotonicNowMs = clock.sample();
    if (
      !Number.isFinite(wallNow) ||
      wallNow < 0 ||
      monotonicNowMs >= source.expiresAtMonotonicMs
    ) {
      fail("source authorization deadline is invalid or expired");
    }
    const remainingMs = source.expiresAtMonotonicMs - monotonicNowMs;
    const nominalLifetimeSeconds = Math.min(
      MAX_ACCESS_GRANT_LIFETIME_SECONDS,
      Math.floor(remainingMs / 1_000) - MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS,
    );
    if (nominalLifetimeSeconds < 1) {
      fail("not enough source authorization lifetime remains");
    }
    const iat = Math.floor(wallNow / 1_000);
    const exp = iat + nominalLifetimeSeconds;
    if (!isNumericDate(iat) || !isNumericDate(exp)) {
      fail("issuer wall clock cannot produce a valid NumericDate");
    }
    return { iat, exp };
  };

  const issuer: AccessGrantIssuer<ReadRequest> = {
    async readSourceAuthorization(
      request: ReadRequest,
    ): Promise<AuthoritativeSourceAuthorizationRead> {
      const readStartedAtMs = clock.sample();
      const source = await sourceReader(request);
      if (
        !Number.isSafeInteger(source.maximumLifetimeMs) ||
        source.maximumLifetimeMs < 1 ||
        source.maximumLifetimeMs > MAX_SOURCE_AUTHORIZATION_LIFETIME_MS
      ) {
        fail("source authorization lifetime is invalid");
      }
      const context = snapshotContext(source.context);
      const bound: BoundSourceAuthorization = Object.freeze({
        owner,
        domain,
        applicationId: source.applicationId,
        context,
        policyDigest: source.policyDigest,
        scope: snapshotScope(source.scope),
        expiresAtMonotonicMs: readStartedAtMs + source.maximumLifetimeMs,
      });
      if (!Number.isFinite(bound.expiresAtMonotonicMs)) {
        fail("source authorization deadline is invalid");
      }
      const read = Object.freeze(new AuthoritativeSourceAuthorizationRead());
      sourceReads.set(read, bound);
      return read;
    },

    bindSourceAuthorization(
      read: AuthoritativeSourceAuthorizationRead,
    ): SourceAuthorizationCapability {
      const source = sourceReads.get(read);
      if (
        source === undefined ||
        source.owner !== owner ||
        source.domain !== domain ||
        domain.failed
      ) {
        fail("source authorization read is invalid");
      }
      const capability = Object.freeze(new SourceAuthorizationCapability());
      sourceCapabilities.set(capability, source);
      return capability;
    },

    async issue(input: IssueAccessGrantInput): Promise<string> {
      const source = sourceCapabilities.get(input.source);
      if (
        source === undefined ||
        source.owner !== owner ||
        source.domain !== domain ||
        domain.failed
      ) {
        fail("source authorization capability is invalid");
      }
      if (
        source.applicationId !== applicationId ||
        source.context.policyVersion.length === 0 ||
        source.scope.kind !== "application" ||
        !acceptedPolicies.has(
          policyPair(source.context.policyVersion, source.policyDigest),
        )
      ) {
        fail("source authorization binding is not accepted");
      }
      if (
        !isBoundedIdentity(source.context.principalId) ||
        !isPolicyVersion(source.context.policyVersion) ||
        !isPolicyDigest(source.policyDigest) ||
        !isCanonicalPermissions(source.context.permissions)
      ) {
        fail("source authorization snapshot is malformed");
      }

      const allowed = audiencePermissions.get(input.audience);
      if (allowed === undefined) {
        fail("access-grant audience is not configured");
      }
      const requested = canonicalPermissions(input.requestedPermissions);
      if (requested.length === 0) {
        fail("access grant must contain at least one permission");
      }
      const sourcePermissions = new Set(source.context.permissions);
      for (const permission of requested) {
        if (!sourcePermissions.has(permission) || !allowed.has(permission)) {
          fail("requested permission is not authorized");
        }
      }

      readGrantWindow(source);

      const random = randomBytes32();
      if (!(random instanceof Uint8Array) || random.byteLength !== 32) {
        fail("issuer random source returned an invalid identifier");
      }
      const jti = base64url.encode(random);
      if (!isCanonicalBase64Url32(jti)) {
        fail("issuer random source returned a malformed identifier");
      }
      await jtiReservations.reserve({
        issuer: issuerName,
        applicationId,
        jti,
      });
      const { iat, exp } = readGrantWindow(source);

      const payload = {
        iss: issuerName,
        application_id: applicationId,
        aud: input.audience,
        sub: source.context.principalId,
        exp,
        iat,
        jti,
        profile_version: ACCESS_GRANT_PROFILE_VERSION,
        policy_version: source.context.policyVersion,
        policy_digest: source.policyDigest,
        permissions: requested,
      };
      const compact = await new CompactSign(
        new TextEncoder().encode(JSON.stringify(payload)),
      )
        .setProtectedHeader({
          alg: ACCESS_GRANT_ALGORITHM,
          kid: signingKid,
          typ: ACCESS_GRANT_TYPE,
        })
        .sign(signingKey);
      readGrantWindow(source);
      return compact;
    },
  };
  return Object.freeze(issuer);
}

/** Create a production issuer with process-owned clocks and CSPRNG. */
export function createAccessGrantIssuer<ReadRequest>(
  configuration: AccessGrantIssuerConfiguration<ReadRequest>,
  store: Store,
): AccessGrantIssuer<ReadRequest> {
  return createAccessGrantIssuerInternal(
    configuration,
    store,
    productionIssuerDependencies,
  );
}
