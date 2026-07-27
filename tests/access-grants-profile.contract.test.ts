import { Buffer } from "node:buffer";

import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  AccessContext,
  AccessSubject,
} from "@pegma/authorization-contracts";

const PROFILE_TYPE = "pegma-access-grant+jwt";
const PROFILE_VERSION = 1;
const ALGORITHM = "ES256";
const MAX_TOKEN_LIFETIME_SECONDS = 30;
const MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS = 5;
const FUTURE_IAT_TOLERANCE_SECONDS = 5;
const MAX_JWKS_CACHE_AGE_MS = 60_000;
const UNKNOWN_KID_REFRESH_INTERVAL_MS = 5_000;

const PERMISSION_PATTERN =
  /^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*)*$/;
const POLICY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const POLICY_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;
const KID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const BASE64URL_32_BYTE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ASCII_CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;

type JsonEntries = readonly (readonly [string, unknown])[];

type ProtectedHeader = Readonly<{
  alg: typeof ALGORITHM;
  kid: string;
  typ: typeof PROFILE_TYPE;
}>;

type AccessGrantClaims = Readonly<{
  iss: string;
  application_id: string;
  aud: string;
  sub: string;
  exp: number;
  iat: number;
  jti: string;
  profile_version: typeof PROFILE_VERSION;
  policy_version: string;
  policy_digest: string;
  permissions: readonly string[];
}>;

type TestPublicJwk = Readonly<{
  kty: "EC";
  crv: "P-256";
  x: string;
  y: string;
  use: "sig";
  alg: typeof ALGORITHM;
  kid: string;
}>;

type TestCompactGrant = Readonly<{
  header: JsonEntries;
  claims: JsonEntries;
  signatureValid: boolean;
}>;

type BoundSourceAuthorization = Readonly<{
  configuration: TestIssuerConfiguration;
  applicationId: string;
  context: AccessContext;
  policyVersion: string;
  policyDigest: string;
  scope:
    | Readonly<{ kind: "application" }>
    | Readonly<{ kind: "organization"; organizationId: string }>;
  expiresAtMonotonicMs: number;
}>;

class SourceAuthorizationCapability {}

const boundSourceAuthorizations = new WeakMap<
  SourceAuthorizationCapability,
  BoundSourceAuthorization
>();

type IssueInput = Readonly<{
  configuration: TestIssuerConfiguration;
  audience: string;
  requestedPermissions: readonly string[];
  source: SourceAuthorizationCapability;
}>;

function fail(message: string): never {
  throw new Error(message);
}

function entriesFromRecord(
  value: Readonly<Record<string, unknown>>,
): JsonEntries {
  return Object.entries(value);
}

function exactRecord(
  entries: JsonEntries,
  exactFields: readonly string[],
  kind: string,
): Readonly<Record<string, unknown>> {
  const allowed = new Set(exactFields);
  const result: Record<string, unknown> = Object.create(null) as Record<
    string,
    unknown
  >;
  for (const [name, value] of entries) {
    if (Object.hasOwn(result, name)) {
      fail(`${kind} has a duplicate field`);
    }
    if (!allowed.has(name)) {
      fail(`${kind} has an unknown field`);
    }
    result[name] = value;
  }
  if (Object.keys(result).length !== exactFields.length) {
    fail(`${kind} is missing a required field`);
  }
  return result;
}

function isCanonicalStrings(values: readonly string[]): boolean {
  return (
    values.length > 0 &&
    values.every(
      (value, index) =>
        PERMISSION_PATTERN.test(value) &&
        value.length <= 255 &&
        (index === 0 || values[index - 1]! < value),
    )
  );
}

function canonicalizePermissions(values: readonly string[]): readonly string[] {
  for (const value of values) {
    if (
      typeof value !== "string" ||
      value.length > 255 ||
      !PERMISSION_PATTERN.test(value)
    ) {
      fail("permission is malformed");
    }
  }
  return Object.freeze([...new Set(values)].sort());
}

function isPrincipalId(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    [...value].length <= 255 &&
    value.trim() === value &&
    !ASCII_CONTROL_PATTERN.test(value)
  );
}

function isNumericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

function isCanonicalBase64Url32(value: unknown): value is string {
  if (typeof value !== "string" || !BASE64URL_32_BYTE_PATTERN.test(value)) {
    return false;
  }
  const decoded = Buffer.from(value, "base64url");
  return decoded.length === 32 && decoded.toString("base64url") === value;
}

function base64Url32(fillByte: number): string {
  return Buffer.alloc(32, fillByte).toString("base64url");
}

function policyPair(version: string, digest: string): string {
  return JSON.stringify([version, digest]);
}

class TestGuardedMonotonicClock {
  readonly #read: () => number;
  #lastObservedMs: number | undefined;
  #failed = false;

  constructor(read: () => number) {
    this.#read = read;
  }

  sample(): number {
    if (this.#failed) {
      fail("issuer monotonic clock domain has failed");
    }
    const sample = this.#read();
    if (
      !Number.isFinite(sample) ||
      sample < 0 ||
      (this.#lastObservedMs !== undefined && sample < this.#lastObservedMs)
    ) {
      this.#failed = true;
      fail("issuer monotonic clock is invalid or regressed");
    }
    this.#lastObservedMs = sample;
    return sample;
  }
}

type TestIssuerState = Readonly<{
  monotonicClock: TestGuardedMonotonicClock;
  wallNowEpochMs: () => number;
  randomBytes32: () => Uint8Array;
  issuedJtis: Set<string>;
}>;

const testIssuerStates = new WeakMap<
  TestIssuerConfiguration,
  TestIssuerState
>();

class TestIssuerConfiguration {
  readonly issuer: string;
  readonly applicationId: string;
  readonly kid: string;
  readonly #audiencePermissions: ReadonlyMap<string, readonly string[]>;
  readonly #acceptedPolicies: ReadonlySet<string>;

  constructor(input: {
    issuer: string;
    applicationId: string;
    kid: string;
    monotonicNowMs: () => number;
    wallNowEpochMs: () => number;
    randomBytes32: () => Uint8Array;
    audiences: Readonly<Record<string, readonly string[]>>;
    acceptedPolicies: readonly Readonly<{
      version: string;
      digest: string;
    }>[];
  }) {
    if (
      input.issuer.length === 0 ||
      !isPrincipalId(input.applicationId) ||
      !KID_PATTERN.test(input.kid)
    ) {
      fail("issuer configuration is malformed");
    }
    const audiencePermissions = new Map<string, readonly string[]>();
    for (const [audience, permissions] of Object.entries(input.audiences)) {
      if (audience.length === 0) {
        fail("issuer audience is malformed");
      }
      audiencePermissions.set(
        audience,
        Object.freeze([...canonicalizePermissions(permissions)]),
      );
    }
    this.issuer = input.issuer;
    this.applicationId = input.applicationId;
    this.kid = input.kid;
    this.#audiencePermissions = audiencePermissions;
    this.#acceptedPolicies = new Set(
      input.acceptedPolicies.map(({ version, digest }) =>
        policyPair(version, digest),
      ),
    );
    testIssuerStates.set(this, {
      monotonicClock: new TestGuardedMonotonicClock(input.monotonicNowMs),
      wallNowEpochMs: input.wallNowEpochMs,
      randomBytes32: input.randomBytes32,
      issuedJtis: new Set(),
    });
    Object.freeze(this);
  }

  permissionsForAudience(audience: string): readonly string[] {
    const permissions = this.#audiencePermissions.get(audience);
    if (permissions === undefined) {
      fail("audience is not configured for issuance");
    }
    return permissions;
  }

  acceptsPolicy(version: string, digest: string): boolean {
    return this.#acceptedPolicies.has(policyPair(version, digest));
  }
}

function bindSourceAuthorization(
  configuration: TestIssuerConfiguration,
  input: Readonly<{
    context: AccessContext;
    policyDigest: string;
    scope:
      | Readonly<{ kind: "application" }>
      | Readonly<{ kind: "organization"; organizationId: string }>;
    maximumLifetimeMs: number;
  }>,
): SourceAuthorizationCapability {
  const state = testIssuerStates.get(configuration);
  if (state === undefined) {
    fail("issuer state is unavailable");
  }
  if (
    !Number.isSafeInteger(input.maximumLifetimeMs) ||
    input.maximumLifetimeMs < 1 ||
    input.maximumLifetimeMs > 60_000
  ) {
    fail("source authorization lifetime is invalid");
  }
  const readStartedAtMs = state.monotonicClock.sample();
  const capability = new SourceAuthorizationCapability();
  boundSourceAuthorizations.set(
    capability,
    Object.freeze({
      configuration,
      applicationId: configuration.applicationId,
      context: input.context,
      policyVersion: input.context.policyVersion,
      policyDigest: input.policyDigest,
      scope: Object.freeze({ ...input.scope }),
      expiresAtMonotonicMs: readStartedAtMs + input.maximumLifetimeMs,
    }),
  );
  return Object.freeze(capability);
}

class TestVerifierConfiguration {
  readonly issuer: string;
  readonly applicationId: string;
  readonly audience: string;
  readonly jwksUrl: string;
  readonly #acceptedPolicies: ReadonlySet<string>;
  readonly #allowedPermissions: ReadonlySet<string>;

  constructor(input: {
    issuer: string;
    applicationId: string;
    audience: string;
    jwksUrl: string;
    acceptedPolicies: readonly Readonly<{
      version: string;
      digest: string;
    }>[];
    allowedPermissions: readonly string[];
  }) {
    if (
      input.issuer.length === 0 ||
      !isPrincipalId(input.applicationId) ||
      input.audience.length === 0 ||
      !input.jwksUrl.startsWith("https://")
    ) {
      fail("verifier configuration is malformed");
    }
    this.issuer = input.issuer;
    this.applicationId = input.applicationId;
    this.audience = input.audience;
    this.jwksUrl = input.jwksUrl;
    this.#acceptedPolicies = new Set(
      input.acceptedPolicies.map(({ version, digest }) =>
        policyPair(version, digest),
      ),
    );
    this.#allowedPermissions = new Set(
      canonicalizePermissions(input.allowedPermissions),
    );
    Object.freeze(this);
  }

  acceptsPolicy(version: string, digest: string): boolean {
    return this.#acceptedPolicies.has(policyPair(version, digest));
  }

  acceptsPermissions(permissions: readonly string[]): boolean {
    return permissions.every((permission) =>
      this.#allowedPermissions.has(permission),
    );
  }
}

function issueAccessGrant(input: IssueInput): TestCompactGrant {
  const { configuration, requestedPermissions } = input;
  const source = boundSourceAuthorizations.get(input.source);
  const issuerState = testIssuerStates.get(configuration);
  if (
    source === undefined ||
    issuerState === undefined ||
    source.configuration !== configuration
  ) {
    fail(
      "source authorization capability is forged or belongs to another issuer",
    );
  }
  const { context } = source;
  if (
    source.applicationId !== configuration.applicationId ||
    source.policyVersion !== context.policyVersion ||
    !configuration.acceptsPolicy(source.policyVersion, source.policyDigest) ||
    source.scope.kind !== "application"
  ) {
    fail("source authorization binding does not match the access context");
  }
  const wallNowEpochMs = issuerState.wallNowEpochMs();
  const monotonicNowMs = issuerState.monotonicClock.sample();
  if (
    !Number.isFinite(wallNowEpochMs) ||
    !Number.isFinite(source.expiresAtMonotonicMs) ||
    wallNowEpochMs < 0 ||
    monotonicNowMs >= source.expiresAtMonotonicMs
  ) {
    fail("source authorization deadline is invalid or expired");
  }
  if (
    !isPrincipalId(context.principalId) ||
    !POLICY_VERSION_PATTERN.test(context.policyVersion) ||
    !POLICY_DIGEST_PATTERN.test(source.policyDigest) ||
    !isCanonicalStrings(context.permissions)
  ) {
    fail("source access context or policy identity is malformed");
  }
  if (typeof input.audience !== "string" || input.audience.length === 0) {
    fail("audience is malformed");
  }

  const permissions = canonicalizePermissions(requestedPermissions);
  if (permissions.length === 0) {
    fail("access grant permissions must be nonempty");
  }
  const contextPermissions = new Set(context.permissions);
  const audiencePermissions = new Set(
    configuration.permissionsForAudience(input.audience),
  );
  for (const permission of permissions) {
    if (
      !contextPermissions.has(permission) ||
      !audiencePermissions.has(permission)
    ) {
      fail("requested permission is outside an issuer allowlist");
    }
  }

  const remainingMs = source.expiresAtMonotonicMs - monotonicNowMs;
  const wholeRemainingSeconds = Math.floor(remainingMs / 1_000);
  const nominalLifetimeSeconds = Math.min(
    MAX_TOKEN_LIFETIME_SECONDS,
    wholeRemainingSeconds - MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS,
  );
  if (nominalLifetimeSeconds < 1) {
    fail("not enough source authorization lifetime remains");
  }
  const iat = Math.floor(wallNowEpochMs / 1_000);
  const exp = iat + nominalLifetimeSeconds;
  if (!isNumericDate(iat) || !isNumericDate(exp)) {
    fail("issued NumericDate is invalid");
  }
  const randomBytes = issuerState.randomBytes32();
  if (!(randomBytes instanceof Uint8Array) || randomBytes.byteLength !== 32) {
    fail("issuer random source returned a malformed unique identifier");
  }
  const jti = Buffer.from(randomBytes).toString("base64url");
  if (!isCanonicalBase64Url32(jti) || issuerState.issuedJtis.has(jti)) {
    fail("issuer random source repeated or returned a malformed identifier");
  }
  issuerState.issuedJtis.add(jti);

  return Object.freeze({
    header: entriesFromRecord({
      alg: ALGORITHM,
      kid: configuration.kid,
      typ: PROFILE_TYPE,
    }),
    claims: entriesFromRecord({
      iss: configuration.issuer,
      application_id: source.applicationId,
      aud: input.audience,
      sub: context.principalId,
      exp,
      iat,
      jti,
      profile_version: PROFILE_VERSION,
      policy_version: context.policyVersion,
      policy_digest: source.policyDigest,
      permissions,
    }),
    signatureValid: true,
  });
}

function parseProtectedHeader(entries: JsonEntries): ProtectedHeader {
  const value = exactRecord(entries, ["alg", "kid", "typ"], "header");
  if (
    value.alg !== ALGORITHM ||
    value.typ !== PROFILE_TYPE ||
    typeof value.kid !== "string" ||
    !KID_PATTERN.test(value.kid)
  ) {
    fail("protected header is invalid");
  }
  return value as ProtectedHeader;
}

function parseClaims(entries: JsonEntries): AccessGrantClaims {
  const value = exactRecord(
    entries,
    [
      "iss",
      "application_id",
      "aud",
      "sub",
      "exp",
      "iat",
      "jti",
      "profile_version",
      "policy_version",
      "policy_digest",
      "permissions",
    ],
    "claims",
  );
  if (
    typeof value.iss !== "string" ||
    value.iss.length === 0 ||
    !isPrincipalId(value.application_id) ||
    typeof value.aud !== "string" ||
    value.aud.length === 0 ||
    !isPrincipalId(value.sub) ||
    !isNumericDate(value.iat) ||
    !isNumericDate(value.exp) ||
    value.exp <= value.iat ||
    value.exp - value.iat > MAX_TOKEN_LIFETIME_SECONDS ||
    !isCanonicalBase64Url32(value.jti) ||
    value.profile_version !== PROFILE_VERSION ||
    typeof value.policy_version !== "string" ||
    !POLICY_VERSION_PATTERN.test(value.policy_version) ||
    typeof value.policy_digest !== "string" ||
    !POLICY_DIGEST_PATTERN.test(value.policy_digest) ||
    !Array.isArray(value.permissions) ||
    !value.permissions.every((permission) => typeof permission === "string") ||
    !isCanonicalStrings(value.permissions)
  ) {
    fail("claims are malformed");
  }
  return value as AccessGrantClaims;
}

function validatePublicJwk(value: unknown): TestPublicJwk {
  if (
    typeof value !== "object" ||
    value === null ||
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    fail("JWK is malformed");
  }
  const record = value as Readonly<Record<string, unknown>>;
  const exactFields = ["kty", "crv", "x", "y", "use", "alg", "kid"];
  if (
    Object.keys(record).length !== exactFields.length ||
    exactFields.some((field) => !Object.hasOwn(record, field)) ||
    record.kty !== "EC" ||
    record.crv !== "P-256" ||
    typeof record.x !== "string" ||
    !isCanonicalBase64Url32(record.x) ||
    typeof record.y !== "string" ||
    !isCanonicalBase64Url32(record.y) ||
    record.use !== "sig" ||
    record.alg !== ALGORITHM ||
    typeof record.kid !== "string" ||
    !KID_PATTERN.test(record.kid)
  ) {
    fail("JWK metadata is invalid");
  }
  return Object.freeze({ ...record }) as TestPublicJwk;
}

class TestJwksCache {
  readonly issuer: string;
  readonly url: string;
  readonly #maxAgeMs: number;
  readonly #fetch: () => readonly unknown[] | Promise<readonly unknown[]>;
  #keys: ReadonlyMap<string, TestPublicJwk> | undefined;
  #loadedAtMs: number | undefined;
  #lastObservedMs: number | undefined;
  #clockDomainFailed = false;
  #refreshInFlight: Promise<void> | undefined;
  #nextUnknownKidRefreshAtMs: number | undefined;

  constructor(
    issuer: string,
    url: string,
    maxAgeMs: number,
    fetch: () => readonly unknown[] | Promise<readonly unknown[]>,
  ) {
    if (issuer.length === 0 || !url.startsWith("https://")) {
      fail("JWKS issuer or URL is invalid");
    }
    if (
      !Number.isSafeInteger(maxAgeMs) ||
      maxAgeMs < 1 ||
      maxAgeMs > MAX_JWKS_CACHE_AGE_MS
    ) {
      fail("JWKS cache age is invalid");
    }
    this.issuer = issuer;
    this.url = url;
    this.#maxAgeMs = maxAgeMs;
    this.#fetch = fetch;
  }

  async resolve(kid: string, monotonicNowMs: number): Promise<TestPublicJwk> {
    if (this.#clockDomainFailed) {
      fail("JWKS clock domain has failed");
    }
    if (
      !Number.isFinite(monotonicNowMs) ||
      monotonicNowMs < 0 ||
      (this.#lastObservedMs !== undefined &&
        monotonicNowMs < this.#lastObservedMs)
    ) {
      this.#clockDomainFailed = true;
      this.#keys = undefined;
      this.#loadedAtMs = undefined;
      fail("JWKS clock is invalid or regressed");
    }
    this.#lastObservedMs = monotonicNowMs;
    const fresh =
      this.#keys !== undefined &&
      this.#loadedAtMs !== undefined &&
      monotonicNowMs - this.#loadedAtMs < this.#maxAgeMs;
    let refreshedForAge = false;
    if (!fresh) {
      await this.#refresh(monotonicNowMs);
      refreshedForAge = true;
    }
    const existing = this.#keys!.get(kid);
    if (existing !== undefined) {
      return existing;
    }
    if (refreshedForAge) {
      this.#nextUnknownKidRefreshAtMs =
        monotonicNowMs + UNKNOWN_KID_REFRESH_INTERVAL_MS;
      fail("unknown kid after required refresh");
    }
    if (
      this.#nextUnknownKidRefreshAtMs !== undefined &&
      monotonicNowMs < this.#nextUnknownKidRefreshAtMs
    ) {
      fail("unknown kid refresh is cooling down");
    }
    this.#nextUnknownKidRefreshAtMs =
      monotonicNowMs + UNKNOWN_KID_REFRESH_INTERVAL_MS;
    await this.#refresh(monotonicNowMs);
    const refreshed = this.#keys!.get(kid);
    if (refreshed === undefined) {
      fail("unknown kid after one refresh");
    }
    return refreshed;
  }

  async #refresh(monotonicNowMs: number): Promise<void> {
    if (this.#refreshInFlight !== undefined) {
      return this.#refreshInFlight;
    }
    const refresh = (async () => {
      const fetched = await this.#fetch();
      const replacement = new Map<string, TestPublicJwk>();
      for (const candidate of fetched) {
        const key = validatePublicJwk(candidate);
        if (replacement.has(key.kid)) {
          fail("JWKS contains duplicate kid");
        }
        replacement.set(key.kid, key);
      }
      if (this.#clockDomainFailed) {
        fail("JWKS clock domain has failed");
      }
      this.#keys = replacement;
      this.#loadedAtMs = monotonicNowMs;
    })();
    this.#refreshInFlight = refresh;
    try {
      await refresh;
    } finally {
      if (this.#refreshInFlight === refresh) {
        this.#refreshInFlight = undefined;
      }
    }
  }
}

type ReplayFailure = "none" | "outage" | "ambiguous";

class TestReplayStore {
  readonly #nowNumericDate: () => number;
  #failure: ReplayFailure = "none";
  readonly #consumed = new Map<string, unknown>();

  constructor(nowNumericDate: () => number) {
    this.#nowNumericDate = nowNumericDate;
  }

  setFailure(failure: ReplayFailure): void {
    this.#failure = failure;
  }

  consume(
    issuer: string,
    applicationId: string,
    audience: string,
    jti: string,
    retainUntilNumericDate: number,
  ): void {
    const now = this.#now();
    const key = JSON.stringify([issuer, applicationId, audience, jti]);
    const existing = this.#consumed.get(key);
    if (existing !== undefined) {
      const retainUntil = this.#readRetainUntil(existing);
      if (now <= retainUntil) {
        fail("access grant was already consumed");
      }
      this.#consumed.delete(key);
    }
    if (this.#failure === "outage") {
      fail("replay store is unavailable");
    }
    const record = Object.freeze({ retainUntilNumericDate });
    if (this.#failure === "ambiguous") {
      this.#consumed.set(key, record);
      fail("replay store write outcome is ambiguous");
    }
    this.#consumed.set(key, record);
  }

  corrupt(
    issuer: string,
    applicationId: string,
    audience: string,
    jti: string,
  ): void {
    this.#consumed.set(JSON.stringify([issuer, applicationId, audience, jti]), {
      retainUntilNumericDate: "corrupt",
    });
  }

  hasRecordThrough(
    issuer: string,
    applicationId: string,
    audience: string,
    jti: string,
  ): boolean {
    const existing = this.#consumed.get(
      JSON.stringify([issuer, applicationId, audience, jti]),
    );
    return (
      existing !== undefined && this.#now() <= this.#readRetainUntil(existing)
    );
  }

  #now(): number {
    const now = this.#nowNumericDate();
    if (!isNumericDate(now)) {
      fail("replay store clock is invalid");
    }
    return now;
  }

  #readRetainUntil(value: unknown): number {
    if (
      typeof value !== "object" ||
      value === null ||
      Array.isArray(value) ||
      Object.keys(value).length !== 1 ||
      !Object.hasOwn(value, "retainUntilNumericDate") ||
      !isNumericDate(
        (value as Readonly<Record<string, unknown>>).retainUntilNumericDate,
      )
    ) {
      fail("replay store record is corrupt");
    }
    return (value as Readonly<{ retainUntilNumericDate: number }>)
      .retainUntilNumericDate;
  }
}

async function verifyAndConsume(
  grant: TestCompactGrant,
  config: TestVerifierConfiguration,
  cache: TestJwksCache,
  replayStore: TestReplayStore,
  verifierNowNumericDate: number,
  monotonicNowMs: number,
): Promise<AccessGrantClaims> {
  if (
    cache.issuer !== config.issuer ||
    cache.url !== config.jwksUrl ||
    !isNumericDate(verifierNowNumericDate)
  ) {
    fail("verifier configuration or clock is invalid");
  }
  const header = parseProtectedHeader(grant.header);
  const claims = parseClaims(grant.claims);
  await cache.resolve(header.kid, monotonicNowMs);
  if (!grant.signatureValid) {
    fail("signature is invalid");
  }
  if (
    claims.iss !== config.issuer ||
    claims.application_id !== config.applicationId ||
    claims.aud !== config.audience
  ) {
    fail("issuer, application, or audience does not match");
  }
  if (!config.acceptsPolicy(claims.policy_version, claims.policy_digest)) {
    fail("policy identity is not accepted");
  }
  if (!config.acceptsPermissions(claims.permissions)) {
    fail("permission is not accepted for this audience");
  }
  if (
    claims.iat > verifierNowNumericDate + FUTURE_IAT_TOLERANCE_SECONDS ||
    verifierNowNumericDate >= claims.exp
  ) {
    fail("access grant is outside its time window");
  }
  replayStore.consume(
    claims.iss,
    claims.application_id,
    claims.aud,
    claims.jti,
    claims.exp + MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS,
  );
  return claims;
}

const digest =
  "sha256:ad1b38ea08c91e2e66d6ab4d2f19a70dee7c067ba3c3223a2728f5d2f74a17e3";
const issuer = "https://authorization.example.test";
const jwksUrl = `${issuer}/.well-known/jwks.json`;
const applicationId = "authorization-core";
const audience = "support-api";
const billingAudience = "billing-api";
const kid = "key-2026-07-26-001";
let issuerMonotonicNowMs = 0;
let issuerWallNowEpochMs = 1_785_087_000_999;
let nextRandomFillByte = 1;

const context: AccessContext = Object.freeze({
  principalId: "principal_123",
  policyVersion: "2026-07-26.1",
  roles: Object.freeze(["support"]),
  entitlements: Object.freeze(["plan.pro"]),
  permissions: Object.freeze([
    "account.read.own",
    "support.queue.read",
    "support.ticket.reply.any",
  ]),
});

function createIssuerConfiguration(
  overrides: Partial<{
    applicationId: string;
    monotonicNowMs: () => number;
    wallNowEpochMs: () => number;
    randomBytes32: () => Uint8Array;
  }> = {},
): TestIssuerConfiguration {
  return new TestIssuerConfiguration({
    issuer,
    applicationId: overrides.applicationId ?? applicationId,
    kid,
    monotonicNowMs: overrides.monotonicNowMs ?? (() => issuerMonotonicNowMs),
    wallNowEpochMs: overrides.wallNowEpochMs ?? (() => issuerWallNowEpochMs),
    randomBytes32:
      overrides.randomBytes32 ??
      (() => {
        const fillByte = nextRandomFillByte;
        nextRandomFillByte += 1;
        return new Uint8Array(32).fill(fillByte);
      }),
    audiences: {
      [audience]: ["support.queue.read", "support.ticket.reply.any"],
      [billingAudience]: ["account.read.own"],
    },
    acceptedPolicies: [{ version: context.policyVersion, digest }],
  });
}

const issuerConfiguration = createIssuerConfiguration();

const publicKey = (keyId = kid): TestPublicJwk => ({
  kty: "EC",
  crv: "P-256",
  x: base64Url32(2),
  y: base64Url32(3),
  use: "sig",
  alg: ALGORITHM,
  kid: keyId,
});

function sourceAuthorization(
  overrides: Partial<{
    configuration: TestIssuerConfiguration;
    context: AccessContext;
    policyDigest: string;
    scope:
      | Readonly<{ kind: "application" }>
      | Readonly<{ kind: "organization"; organizationId: string }>;
    maximumLifetimeMs: number;
  }> = {},
): SourceAuthorizationCapability {
  return bindSourceAuthorization(
    overrides.configuration ?? issuerConfiguration,
    {
      context: overrides.context ?? context,
      policyDigest: overrides.policyDigest ?? digest,
      scope: overrides.scope ?? { kind: "application" },
      maximumLifetimeMs: overrides.maximumLifetimeMs ?? 60_000,
    },
  );
}

function issue(overrides: Partial<IssueInput> = {}): TestCompactGrant {
  const configuration = overrides.configuration ?? issuerConfiguration;
  return issueAccessGrant({
    configuration,
    audience,
    requestedPermissions: [
      "support.ticket.reply.any",
      "support.queue.read",
      "support.queue.read",
    ],
    source: overrides.source ?? sourceAuthorization({ configuration }),
    ...overrides,
  });
}

function verifier(
  overrides: Partial<{
    issuer: string;
    applicationId: string;
    audience: string;
    jwksUrl: string;
    acceptedPolicies: readonly Readonly<{
      version: string;
      digest: string;
    }>[];
    allowedPermissions: readonly string[];
  }> = {},
): TestVerifierConfiguration {
  return new TestVerifierConfiguration({
    issuer,
    applicationId,
    audience,
    jwksUrl,
    acceptedPolicies: [{ version: context.policyVersion, digest }],
    allowedPermissions: ["support.queue.read", "support.ticket.reply.any"],
    ...overrides,
  });
}

function jwksCache(
  fetch: () => readonly unknown[] | Promise<readonly unknown[]> = () => [
    publicKey(),
  ],
): TestJwksCache {
  return new TestJwksCache(issuer, jwksUrl, MAX_JWKS_CACHE_AGE_MS, fetch);
}

async function verifyFresh(
  grant: TestCompactGrant,
  config = verifier(),
): Promise<AccessGrantClaims> {
  return verifyAndConsume(
    grant,
    config,
    jwksCache(),
    new TestReplayStore(() => 1_785_087_001),
    1_785_087_001,
    0,
  );
}

function replaceClaim(
  grant: TestCompactGrant,
  name: string,
  value: unknown,
): TestCompactGrant {
  return {
    ...grant,
    claims: grant.claims.map(([claimName, claimValue]) =>
      claimName === name ? [claimName, value] : [claimName, claimValue],
    ),
  };
}

describe("Pegma access-grant profile V1 test-local contract", () => {
  it("issues only a canonical nonempty subset allowed by context and audience", () => {
    const grant = issue();
    const claims = parseClaims(grant.claims);

    expect(claims.permissions).toEqual([
      "support.queue.read",
      "support.ticket.reply.any",
    ]);
    expect(Object.keys(claims)).toEqual(
      expect.arrayContaining([
        "iss",
        "application_id",
        "aud",
        "sub",
        "exp",
        "iat",
        "jti",
        "profile_version",
        "policy_version",
        "policy_digest",
        "permissions",
      ]),
    );
    expect(
      ["roles", "entitlements", "principalId"].some((name) =>
        Object.hasOwn(claims, name),
      ),
    ).toBe(false);

    expect(() =>
      issue({
        requestedPermissions: ["support.queue.write"],
      }),
    ).toThrow("outside an issuer allowlist");
    expect(() =>
      issue({
        requestedPermissions: ["account.read.own"],
      }),
    ).toThrow("outside an issuer allowlist");
    expect(() => issue({ requestedPermissions: [] })).toThrow("nonempty");
  });

  it("binds each audience to immutable issuer and verifier permission allowlists", async () => {
    const grant = issue();
    await expect(
      verifyFresh(grant, verifier({ audience: billingAudience })),
    ).rejects.toThrow("issuer, application, or audience does not match");
    await expect(
      verifyFresh(replaceClaim(grant, "aud", [audience, billingAudience])),
    ).rejects.toThrow("claims are malformed");

    expect(() =>
      issue({
        audience,
        requestedPermissions: ["account.read.own"],
      }),
    ).toThrow("outside an issuer allowlist");
    const billingGrant = issue({
      audience: billingAudience,
      requestedPermissions: ["account.read.own"],
    });
    await expect(
      verifyFresh(
        billingGrant,
        verifier({
          audience: billingAudience,
          allowedPermissions: ["account.read.own"],
        }),
      ),
    ).resolves.toMatchObject({ aud: billingAudience });
    await expect(
      verifyFresh(
        replaceClaim(billingGrant, "aud", audience),
        verifier({ allowedPermissions: ["support.queue.read"] }),
      ),
    ).rejects.toThrow("permission is not accepted for this audience");
  });

  it("binds the signed grant and replay identity to one exact application", async () => {
    const grant = issue();
    expect(parseClaims(grant.claims).application_id).toBe(applicationId);
    await expect(
      verifyFresh(
        grant,
        verifier({ applicationId: "another-host-application" }),
      ),
    ).rejects.toThrow("issuer, application, or audience does not match");

    const store = new TestReplayStore(() => 100);
    const replayJti = base64Url32(201);
    store.consume(issuer, applicationId, audience, replayJti, 105);
    expect(() =>
      store.consume(
        issuer,
        "another-host-application",
        audience,
        replayJti,
        105,
      ),
    ).not.toThrow();
  });

  it("rejects forged capabilities and capabilities from a restarted issuer", () => {
    const opaqueSource = sourceAuthorization();
    expect(Object.keys(opaqueSource)).toEqual([]);
    expect(JSON.stringify(opaqueSource)).toBe("{}");
    expect(() =>
      issue({ source: new SourceAuthorizationCapability() }),
    ).toThrow("capability is forged");

    let restartedNowMs = 0;
    const restarted = createIssuerConfiguration({
      monotonicNowMs: () => restartedNowMs,
    });
    const originalSource = sourceAuthorization();
    const restartedSource = sourceAuthorization({
      configuration: restarted,
    });

    expect(() =>
      issue({ configuration: restarted, source: originalSource }),
    ).toThrow("belongs to another issuer");
    expect(() => issue({ source: restartedSource })).toThrow(
      "belongs to another issuer",
    );
    expect(() =>
      issue({
        source: sourceAuthorization({
          policyDigest: `sha256:${"0".repeat(64)}`,
        }),
      }),
    ).toThrow("source authorization binding does not match");

    restartedNowMs = 1;
    expect(
      issue({ configuration: restarted, source: restartedSource }),
    ).toBeDefined();
  });

  it("permanently fails an issuer clock domain after any regression", () => {
    let monotonicNowMs = 100;
    const guardedIssuer = createIssuerConfiguration({
      monotonicNowMs: () => monotonicNowMs,
    });
    const source = sourceAuthorization({
      configuration: guardedIssuer,
    });

    monotonicNowMs = 200;
    expect(issue({ configuration: guardedIssuer, source })).toBeDefined();
    monotonicNowMs = 150;
    expect(() => issue({ configuration: guardedIssuer, source })).toThrow(
      "clock is invalid or regressed",
    );
    monotonicNowMs = 200;
    expect(() => issue({ configuration: guardedIssuer, source })).toThrow(
      "clock domain has failed",
    );
  });

  it("reserves the maximum negative verifier offset inside the source deadline", () => {
    const sixSeconds = parseClaims(
      issue({
        source: sourceAuthorization({ maximumLifetimeMs: 6_000 }),
      }).claims,
    );
    expect(sixSeconds.exp - sixSeconds.iat).toBe(1);

    expect(() =>
      issue({
        source: sourceAuthorization({ maximumLifetimeMs: 5_999 }),
      }),
    ).toThrow("not enough source authorization lifetime");

    const capped = parseClaims(issue().claims);
    expect(capped.exp - capped.iat).toBe(MAX_TOKEN_LIFETIME_SECONDS);
    expect(
      capped.exp + MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS - capped.iat,
    ).toBeLessThanOrEqual(60);
  });

  it("samples monotonic time after the wall clock so pauses cannot extend the source deadline", () => {
    let monotonicNowMs = 0;
    const pausingIssuer = createIssuerConfiguration({
      monotonicNowMs: () => monotonicNowMs,
      wallNowEpochMs: () => {
        monotonicNowMs = 5_001;
        return issuerWallNowEpochMs;
      },
    });
    const source = sourceAuthorization({
      configuration: pausingIssuer,
      maximumLifetimeMs: 6_000,
    });

    expect(() => issue({ configuration: pausingIssuer, source })).toThrow(
      "not enough source authorization lifetime",
    );
  });

  it("owns unique identifier generation and fails closed on malformed or repeated output", () => {
    const callerChosenJti = base64Url32(99);
    const issuerOwned = issue({
      jti: callerChosenJti,
    } as Partial<IssueInput>);
    expect(parseClaims(issuerOwned.claims).jti).not.toBe(callerChosenJti);

    const malformedIssuer = createIssuerConfiguration({
      randomBytes32: () => new Uint8Array(31),
    });
    expect(() =>
      issue({
        configuration: malformedIssuer,
        source: sourceAuthorization({ configuration: malformedIssuer }),
      }),
    ).toThrow("random source returned a malformed unique identifier");

    const repeatedBytes = new Uint8Array(32).fill(42);
    const repeatingIssuer = createIssuerConfiguration({
      randomBytes32: () => repeatedBytes,
    });
    expect(
      issue({
        configuration: repeatingIssuer,
        source: sourceAuthorization({ configuration: repeatingIssuer }),
      }),
    ).toBeDefined();
    expect(() =>
      issue({
        configuration: repeatingIssuer,
        source: sourceAuthorization({ configuration: repeatingIssuer }),
      }),
    ).toThrow("random source repeated");
  });

  it("uses zero expiration leeway and retains replay state for every real accepted instant", async () => {
    const realIssueEpochSeconds = 2_000_000_010;
    const sourceMonotonicNowMs = 10_000;
    const sourceDeadlineMonotonicMs = 20_000;
    const realSourceDeadlineEpochSeconds = realIssueEpochSeconds + 10;
    const issuerWallAtIssueMs = realIssueEpochSeconds * 1_000;
    let sourceMonotonicClockMs = sourceMonotonicNowMs;
    const timingIssuer = createIssuerConfiguration({
      monotonicNowMs: () => sourceMonotonicClockMs,
      wallNowEpochMs: () => issuerWallAtIssueMs,
    });

    for (
      let realNow = realIssueEpochSeconds;
      realNow < realSourceDeadlineEpochSeconds;
      realNow += 1
    ) {
      const grant = issue({
        configuration: timingIssuer,
        source: sourceAuthorization({
          configuration: timingIssuer,
          maximumLifetimeMs: sourceDeadlineMonotonicMs - sourceMonotonicNowMs,
        }),
      });
      const claims = parseClaims(grant.claims);
      const verifierWallNow = realNow - MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS;
      let replayStoreNow = realNow;
      const replayStore = new TestReplayStore(() => replayStoreNow);

      expect(realNow).toBeLessThan(realSourceDeadlineEpochSeconds);
      await expect(
        verifyAndConsume(
          grant,
          verifier(),
          jwksCache(),
          replayStore,
          verifierWallNow,
          realNow - realIssueEpochSeconds,
        ),
      ).resolves.toMatchObject({ exp: realIssueEpochSeconds + 5 });
      expect(
        replayStore.hasRecordThrough(
          issuer,
          applicationId,
          audience,
          claims.jti,
        ),
      ).toBe(true);

      replayStoreNow = realSourceDeadlineEpochSeconds;
      expect(claims.exp + MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS).toBe(
        realSourceDeadlineEpochSeconds,
      );
      expect(
        replayStore.hasRecordThrough(
          issuer,
          applicationId,
          audience,
          claims.jti,
        ),
      ).toBe(true);
    }

    const boundaryGrant = issue({
      configuration: timingIssuer,
      source: sourceAuthorization({
        configuration: timingIssuer,
        maximumLifetimeMs: sourceDeadlineMonotonicMs - sourceMonotonicNowMs,
      }),
    });
    await expect(
      verifyAndConsume(
        boundaryGrant,
        verifier(),
        jwksCache(),
        new TestReplayStore(() => realSourceDeadlineEpochSeconds),
        realSourceDeadlineEpochSeconds - MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS,
        10_000,
      ),
    ).rejects.toThrow("outside its time window");
  });

  it("requires an exact accepted policy version and digest pair", async () => {
    await expect(
      verifyFresh(
        issue(),
        verifier({
          acceptedPolicies: [
            {
              version: context.policyVersion,
              digest: `sha256:${"0".repeat(64)}`,
            },
            { version: "2026-07-26.2", digest },
          ],
        }),
      ),
    ).rejects.toThrow("policy identity is not accepted");
  });

  it("separates token kind and rejects wrong algorithm or key metadata", async () => {
    const grant = issue();
    const noncanonicalCoordinate = `${base64Url32(0).slice(0, -1)}B`;
    await expect(
      verifyFresh({
        ...grant,
        header: grant.header.map(([name, value]) =>
          name === "typ" ? [name, "JWT"] : [name, value],
        ),
      }),
    ).rejects.toThrow("protected header is invalid");
    await expect(
      verifyFresh({
        ...grant,
        header: grant.header.map(([name, value]) =>
          name === "alg" ? [name, "none"] : [name, value],
        ),
      }),
    ).rejects.toThrow("protected header is invalid");
    await expect(
      verifyAndConsume(
        grant,
        verifier(),
        new TestJwksCache(issuer, jwksUrl, MAX_JWKS_CACHE_AGE_MS, () => [
          { ...publicKey(), alg: "ES384" },
        ]),
        new TestReplayStore(() => 1_785_087_001),
        1_785_087_001,
        0,
      ),
    ).rejects.toThrow("JWK metadata is invalid");
    await expect(
      verifyAndConsume(
        grant,
        verifier(),
        new TestJwksCache(issuer, jwksUrl, MAX_JWKS_CACHE_AGE_MS, () => [
          { ...publicKey(), x: noncanonicalCoordinate },
        ]),
        new TestReplayStore(() => 1_785_087_001),
        1_785_087_001,
        0,
      ),
    ).rejects.toThrow("JWK metadata is invalid");
    await expect(
      verifyAndConsume(
        grant,
        verifier(),
        new TestJwksCache(
          issuer,
          "https://untrusted.example.test/jwks.json",
          MAX_JWKS_CACHE_AGE_MS,
          () => [publicKey()],
        ),
        new TestReplayStore(() => 1_785_087_001),
        1_785_087_001,
        0,
      ),
    ).rejects.toThrow("verifier configuration or clock is invalid");
  });

  it("excludes organization confinement and organization-derived permissions", async () => {
    expect(() =>
      issue({
        source: sourceAuthorization({
          scope: {
            kind: "organization",
            organizationId: "organization_alpha",
          },
        }),
      }),
    ).toThrow("source authorization binding does not match");

    const grant = issue();
    await expect(
      verifyFresh({
        ...grant,
        claims: [...grant.claims, ["organization_id", "organization_alpha"]],
      }),
    ).rejects.toThrow("claims has an unknown field");
  });

  it("rejects malformed, duplicate, unknown, and noncanonical claims", async () => {
    const grant = issue();
    const noncanonicalJti = `${base64Url32(0).slice(0, -1)}B`;
    await expect(
      verifyFresh({
        ...grant,
        claims: [...grant.claims, ["aud", audience]],
      }),
    ).rejects.toThrow("claims has a duplicate field");
    await expect(
      verifyFresh({
        ...grant,
        claims: [...grant.claims, ["nonce", "unrecognized"]],
      }),
    ).rejects.toThrow("claims has an unknown field");
    await expect(
      verifyFresh(
        replaceClaim(grant, "permissions", [
          "support.ticket.reply.any",
          "support.queue.read",
        ]),
      ),
    ).rejects.toThrow("claims are malformed");
    await expect(
      verifyFresh(replaceClaim(grant, "exp", 1_785_087_030.5)),
    ).rejects.toThrow("claims are malformed");
    await expect(
      verifyFresh(replaceClaim(grant, "jti", noncanonicalJti)),
    ).rejects.toThrow("claims are malformed");
  });

  it("atomically gives concurrent replay attempts exactly one winner", async () => {
    const grant = issue();
    const replayStore = new TestReplayStore(() => 1_785_087_001);
    const cache = jwksCache();

    const concurrent = await Promise.allSettled([
      verifyAndConsume(grant, verifier(), cache, replayStore, 1_785_087_001, 0),
      verifyAndConsume(grant, verifier(), cache, replayStore, 1_785_087_001, 0),
    ]);
    expect(
      concurrent.filter(({ status }) => status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      concurrent.filter(({ status }) => status === "rejected"),
    ).toHaveLength(1);
  });

  it("fails closed on replay-store outage, ambiguity, or corruption", async () => {
    const grant = issue();
    const cache = jwksCache();

    const unavailable = new TestReplayStore(() => 1_785_087_001);
    unavailable.setFailure("outage");
    await expect(
      verifyAndConsume(grant, verifier(), cache, unavailable, 1_785_087_001, 0),
    ).rejects.toThrow("replay store is unavailable");

    const ambiguous = new TestReplayStore(() => 1_785_087_001);
    ambiguous.setFailure("ambiguous");
    await expect(
      verifyAndConsume(grant, verifier(), cache, ambiguous, 1_785_087_001, 0),
    ).rejects.toThrow("write outcome is ambiguous");
    ambiguous.setFailure("none");
    await expect(
      verifyAndConsume(grant, verifier(), cache, ambiguous, 1_785_087_001, 0),
    ).rejects.toThrow("already consumed");

    const corrupt = new TestReplayStore(() => 1_785_087_001);
    corrupt.corrupt(
      issuer,
      applicationId,
      audience,
      parseClaims(grant.claims).jti,
    );
    await expect(
      verifyAndConsume(grant, verifier(), cache, corrupt, 1_785_087_001, 0),
    ).rejects.toThrow("record is corrupt");
  });

  it("retains replay records through the bound and expires them only afterward", () => {
    let storeNow = 100;
    const store = new TestReplayStore(() => storeNow);
    const replayJti = base64Url32(202);
    store.consume(issuer, applicationId, audience, replayJti, 105);

    storeNow = 105;
    expect(
      store.hasRecordThrough(issuer, applicationId, audience, replayJti),
    ).toBe(true);
    expect(() =>
      store.consume(issuer, applicationId, audience, replayJti, 110),
    ).toThrow("already consumed");

    storeNow = 106;
    expect(
      store.hasRecordThrough(issuer, applicationId, audience, replayJti),
    ).toBe(false);
    expect(() =>
      store.consume(issuer, applicationId, audience, replayJti, 110),
    ).not.toThrow();
    expect(
      store.hasRecordThrough(issuer, applicationId, audience, replayJti),
    ).toBe(true);
  });

  it("bounds unknown-kid refresh amplification and admits rotation after cooldown", async () => {
    const oldKid = "key-2026-07-26-old";
    const newKid = "key-2026-07-26-new";
    let fetchCount = 0;
    let published: readonly TestPublicJwk[] = [publicKey(oldKid)];
    const cache = jwksCache(() => {
      fetchCount += 1;
      return published;
    });

    await expect(cache.resolve(oldKid, 0)).resolves.toMatchObject({
      kid: oldKid,
    });
    await expect(cache.resolve("random-missing-kid-001", 1)).rejects.toThrow(
      "unknown kid",
    );
    for (let index = 2; index < 100; index += 1) {
      await expect(
        cache.resolve(
          `random-missing-kid-${String(index).padStart(3, "0")}`,
          index,
        ),
      ).rejects.toThrow("cooling down");
    }
    expect(fetchCount).toBe(2);

    published = [publicKey(newKid)];
    await expect(
      cache.resolve(newKid, UNKNOWN_KID_REFRESH_INTERVAL_MS),
    ).rejects.toThrow("cooling down");
    await expect(
      cache.resolve(newKid, UNKNOWN_KID_REFRESH_INTERVAL_MS + 1),
    ).resolves.toMatchObject({ kid: newKid });
    expect(fetchCount).toBe(3);
    await expect(
      cache.resolve(oldKid, UNKNOWN_KID_REFRESH_INTERVAL_MS + 2),
    ).rejects.toThrow("cooling down");
  });

  it("shares one issuer-scoped in-flight JWKS fetch", async () => {
    let releaseFetch!: () => void;
    let fetchCount = 0;
    const fetchReleased = new Promise<void>((resolve) => {
      releaseFetch = resolve;
    });
    const cache = jwksCache(async () => {
      fetchCount += 1;
      await fetchReleased;
      return [publicKey(), publicKey("key-2026-07-26-002")];
    });

    const first = cache.resolve(kid, 0);
    const second = cache.resolve("key-2026-07-26-002", 0);
    releaseFetch();
    await expect(first).resolves.toMatchObject({ kid });
    await expect(second).resolves.toMatchObject({
      kid: "key-2026-07-26-002",
    });
    expect(fetchCount).toBe(1);
  });

  it("preserves the unknown-kid cooldown after a refresh failure", async () => {
    let fetchCount = 0;
    const cache = jwksCache(() => {
      fetchCount += 1;
      if (fetchCount > 1) {
        throw new Error("JWKS fetch failed");
      }
      return [publicKey()];
    });

    await cache.resolve(kid, 0);
    await expect(cache.resolve("random-missing-kid-001", 1)).rejects.toThrow(
      "JWKS fetch failed",
    );
    await expect(cache.resolve("random-missing-kid-002", 2)).rejects.toThrow(
      "cooling down",
    );
    expect(fetchCount).toBe(2);
  });

  it("terminally fails JWKS cache time after an advance then partial regression", async () => {
    const cache = jwksCache();
    await cache.resolve(kid, 0);
    await cache.resolve(kid, 10_000);

    await expect(cache.resolve(kid, 5_000)).rejects.toThrow(
      "clock is invalid or regressed",
    );
    await expect(cache.resolve(kid, 10_000)).rejects.toThrow(
      "clock domain has failed",
    );
  });

  it("refreshes at the exact cache-age bound and fails closed on fetch failure", async () => {
    let fetchCount = 0;
    const cache = jwksCache(() => {
      fetchCount += 1;
      if (fetchCount > 1) {
        throw new Error("JWKS fetch failed");
      }
      return [publicKey()];
    });

    await expect(cache.resolve(kid, 0)).resolves.toMatchObject({ kid });
    await expect(
      cache.resolve(kid, MAX_JWKS_CACHE_AGE_MS - 1),
    ).resolves.toMatchObject({ kid });
    expect(fetchCount).toBe(1);
    await expect(cache.resolve(kid, MAX_JWKS_CACHE_AGE_MS)).rejects.toThrow(
      "JWKS fetch failed",
    );
  });

  it("keeps the public AccessSubject and AccessContext shapes unchanged", () => {
    expectTypeOf<keyof AccessSubject>().toEqualTypeOf<
      "principalId" | "roles" | "entitlements"
    >();
    expectTypeOf<keyof AccessContext>().toEqualTypeOf<
      "principalId" | "policyVersion" | "roles" | "entitlements" | "permissions"
    >();
    expectTypeOf<keyof IssueInput>().toEqualTypeOf<
      "configuration" | "audience" | "requestedPermissions" | "source"
    >();
  });
});
