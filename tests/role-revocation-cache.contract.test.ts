import { createHash } from "node:crypto";

import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  AccessContext,
  AccessPolicy,
  AccessSubject,
  ActiveRoleAssignment,
  PrincipalId,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import { decideAccess, resolveAccess } from "@pegma/authorization-core";
import {
  createInMemoryStorageAdapter as createRawInMemoryStorageAdapter,
  type InMemoryStorageAdapter,
  type RoleAssignmentReader,
} from "@pegma/authorization-storage";

const ROLE_AUTHORIZATION_MAXIMUM_AGE_MS = 60_000;
const ROLE_INVALIDATION_TARGET_MS = 5_000;
const applicationScope: RoleAssignmentScope = { kind: "application" };
const organizationAlphaScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId: "organization_alpha",
};
const organizationBetaScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId: "organization_beta",
};
const supportPolicy: AccessPolicy = {
  version: "policy-1",
  roles: {
    support: ["support.queue.read"],
  },
};

class FakeMonotonicClock {
  #now = 0;
  readonly domainToken: symbol;

  constructor(readonly domainId = "clock-domain-a") {
    this.domainToken = Symbol(domainId);
  }

  now(): number {
    return this.#now;
  }

  advance(milliseconds: number): void {
    this.#now += milliseconds;
  }

  setUnsafe(value: number): void {
    this.#now = value;
  }
}

interface TrustedClockDomainState {
  failed: boolean;
  lastSample: number | undefined;
}

const trustedClockDomains = new WeakMap<
  FakeMonotonicClock,
  TrustedClockDomainState
>();

const sampleTrustedClock = (
  clock: FakeMonotonicClock,
  minimumSample = 0,
): number => {
  const state = trustedClockDomains.get(clock) ?? {
    failed: false,
    lastSample: undefined,
  };
  trustedClockDomains.set(clock, state);
  if (state.failed) {
    throw new Error("trusted monotonic clock domain has failed");
  }

  const now = clock.now();
  if (
    !Number.isSafeInteger(now) ||
    now < minimumSample ||
    (state.lastSample !== undefined && now < state.lastSample)
  ) {
    state.failed = true;
    throw new Error("trusted monotonic clock is invalid or regressed");
  }
  state.lastSample = now;
  return now;
};

interface PolicyIdentity {
  readonly policy: AccessPolicy;
  readonly contentDigest: string;
}

interface CachedAuthorization {
  readonly cacheToken: symbol;
  readonly applicationId: string;
  readonly principalId: PrincipalId;
  readonly scope: RoleAssignmentScope;
  readonly policyVersion: string;
  readonly policyContentDigest: string;
  readonly context: AccessContext;
  readonly clockDomainId: string;
  readonly clockDomainToken: symbol;
  readonly readStartedAtMs: number;
  readonly expiresAtMs: number;
  readonly applicationGeneration: number;
  readonly organizationGeneration: number | undefined;
}

interface DecisionPublicationFence {
  readonly applicationGeneration: number;
  readonly organizationGeneration: number | undefined;
}

interface BoundedEntitlementAuthorization {
  readonly applicationId: string;
  readonly principalId: PrincipalId;
  readonly scope: RoleAssignmentScope;
  readonly policyVersion: string;
  readonly policyContentDigest: string;
  readonly clockDomainId: string;
  readonly clockDomainToken: symbol;
  readonly entitlements: readonly string[];
  readonly readStartedAtMs: number;
  readonly expiresAtMs: number;
}

interface BoundedComposedAuthorization {
  readonly roleAuthorization: CachedAuthorization;
  readonly context: AccessContext;
  readonly clockDomainId: string;
  readonly clockDomainToken: symbol;
  readonly composedAtMs: number;
  readonly expiresAtMs: number;
}

const scopeIdentity = (
  scope: RoleAssignmentScope,
): readonly ["application"] | readonly ["organization", string] =>
  scope.kind === "application"
    ? ["application"]
    : ["organization", scope.organizationId];

const cacheKey = (
  applicationId: string,
  principalId: PrincipalId,
  scope: RoleAssignmentScope,
  policyVersion: string,
  policyContentDigest: string,
): string =>
  JSON.stringify([
    applicationId,
    principalId,
    scopeIdentity(scope),
    policyVersion,
    policyContentDigest,
  ]);

const applicationGenerationKey = (
  applicationId: string,
  principalId: PrincipalId,
): string => JSON.stringify([applicationId, principalId, "application"]);

const organizationGenerationKey = (
  applicationId: string,
  principalId: PrincipalId,
  organizationId: string,
): string =>
  JSON.stringify([applicationId, principalId, "organization", organizationId]);

const snapshotScope = (scope: RoleAssignmentScope): RoleAssignmentScope =>
  Object.freeze(
    scope.kind === "application"
      ? { kind: "application" as const }
      : {
          kind: "organization" as const,
          organizationId: scope.organizationId,
        },
  );

const snapshotPolicy = (policy: AccessPolicy): AccessPolicy => {
  const copyMapping = (
    mapping: Readonly<Record<string, readonly string[]>>,
  ): Readonly<Record<string, readonly string[]>> => {
    return Object.freeze(
      Object.fromEntries(
        Object.entries(mapping).map(([name, permissions]) => [
          name,
          Object.freeze([...permissions]),
        ]),
      ),
    );
  };

  const snapshot: {
    version: string;
    defaults?: readonly string[];
    roles?: Readonly<Record<string, readonly string[]>>;
    entitlements?: Readonly<Record<string, readonly string[]>>;
  } = { version: policy.version };
  if (policy.defaults !== undefined) {
    snapshot.defaults = Object.freeze([...policy.defaults]);
  }
  if (policy.roles !== undefined) {
    snapshot.roles = copyMapping(policy.roles);
  }
  if (policy.entitlements !== undefined) {
    snapshot.entitlements = copyMapping(policy.entitlements);
  }
  return Object.freeze(snapshot);
};

const digestPolicy = (policy: AccessPolicy): string => {
  const snapshot = snapshotPolicy(policy);
  const sortMapping = (
    mapping: Readonly<Record<string, readonly string[]>> | undefined,
  ): Readonly<Record<string, readonly string[]>> | undefined =>
    mapping === undefined
      ? undefined
      : Object.fromEntries(
          Object.entries(mapping)
            .sort(([left], [right]) =>
              left < right ? -1 : left > right ? 1 : 0,
            )
            .map(([name, permissions]) => [name, [...permissions]]),
        );
  const canonical = JSON.stringify({
    version: snapshot.version,
    defaults: snapshot.defaults === undefined ? null : [...snapshot.defaults],
    roles: sortMapping(snapshot.roles) ?? null,
    entitlements: sortMapping(snapshot.entitlements) ?? null,
  });
  return `sha256:${createHash("sha256").update(canonical).digest("hex")}`;
};

interface ApplicationBoundRoleAssignmentReader extends RoleAssignmentReader {
  readonly applicationId: string;
}

class HostApplicationRoleStore implements ApplicationBoundRoleAssignmentReader {
  readonly #applicationId: string;
  readonly #storage: InMemoryStorageAdapter;

  private constructor(applicationId: string) {
    this.#applicationId = applicationId;
    this.#storage = createRawInMemoryStorageAdapter();
  }

  static create(applicationId: string): HostApplicationRoleStore {
    return new HostApplicationRoleStore(applicationId);
  }

  get applicationId(): string {
    return this.#applicationId;
  }

  getRoleAssignment(
    assignmentId: string,
  ): ReturnType<RoleAssignmentReader["getRoleAssignment"]> {
    return this.#storage.getRoleAssignment(assignmentId);
  }

  listActiveRoleAssignments(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ): ReturnType<RoleAssignmentReader["listActiveRoleAssignments"]> {
    return this.#storage.listActiveRoleAssignments(principalId, scope);
  }

  listRoleAssignments(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ): ReturnType<RoleAssignmentReader["listRoleAssignments"]> {
    return this.#storage.listRoleAssignments(principalId, scope);
  }

  grantRoleAssignmentWithAudit(
    input: Parameters<
      InMemoryStorageAdapter["grantRoleAssignmentWithAudit"]
    >[0],
  ): ReturnType<InMemoryStorageAdapter["grantRoleAssignmentWithAudit"]> {
    return this.#storage.grantRoleAssignmentWithAudit(input);
  }

  revokeRoleAssignmentWithAudit(
    input: Parameters<
      InMemoryStorageAdapter["revokeRoleAssignmentWithAudit"]
    >[0],
  ): ReturnType<InMemoryStorageAdapter["revokeRoleAssignmentWithAudit"]> {
    return this.#storage.revokeRoleAssignmentWithAudit(input);
  }
}

const createInMemoryStorageAdapter = (): HostApplicationRoleStore =>
  HostApplicationRoleStore.create("application_a");

const bindApplicationReader = (
  expectedApplicationId: string,
  reader: ApplicationBoundRoleAssignmentReader,
): ApplicationBoundRoleAssignmentReader => {
  if (reader.applicationId !== expectedApplicationId) {
    throw new Error("reader belongs to a different application namespace");
  }
  return reader;
};

/**
 * Test-local host integration fixture. It specifies cache obligations around
 * public storage and resolver contracts without adding a runtime cache API.
 */
class BoundedRoleAuthorizationCache {
  readonly #cacheToken = Symbol("bounded-role-authorization-cache");
  readonly #entries = new Map<string, CachedAuthorization>();
  readonly #applicationGenerations = new Map<string, number>();
  readonly #organizationGenerations = new Map<string, number>();
  readonly #applicationId: string;
  readonly #reader: RoleAssignmentReader;
  readonly #clock: FakeMonotonicClock;
  #clockFailed = false;

  constructor(
    applicationReader: ApplicationBoundRoleAssignmentReader,
    clock: FakeMonotonicClock,
  ) {
    this.#applicationId = applicationReader.applicationId;
    this.#reader = applicationReader;
    this.#clock = clock;
  }

  get size(): number {
    return this.#entries.size;
  }

  async resolve(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
    policyIdentity: PolicyIdentity,
  ): Promise<CachedAuthorization> {
    const applicationId = this.#applicationId;
    const scopeSnapshot = snapshotScope(scope);
    const policySnapshot = snapshotPolicy(policyIdentity.policy);
    const policyContentDigest = policyIdentity.contentDigest;
    if (digestPolicy(policySnapshot) !== policyContentDigest) {
      throw new Error("policy content digest does not match policy snapshot");
    }
    const key = cacheKey(
      applicationId,
      principalId,
      scopeSnapshot,
      policySnapshot.version,
      policyContentDigest,
    );
    const cached = this.#entries.get(key);
    if (cached !== undefined && this.#now() < cached.expiresAtMs) {
      return cached;
    }
    this.#entries.delete(key);

    const readStartedAtMs = this.#now();

    const applicationGenerationKeyValue = applicationGenerationKey(
      applicationId,
      principalId,
    );
    const applicationGeneration = this.#generation(
      this.#applicationGenerations,
      applicationGenerationKeyValue,
    );
    const organizationGenerationKeyValue =
      scopeSnapshot.kind === "organization"
        ? organizationGenerationKey(
            applicationId,
            principalId,
            scopeSnapshot.organizationId,
          )
        : undefined;
    const organizationGeneration =
      organizationGenerationKeyValue === undefined
        ? undefined
        : this.#generation(
            this.#organizationGenerations,
            organizationGenerationKeyValue,
          );

    const applicationAssignments = await this.#reader.listActiveRoleAssignments(
      principalId,
      applicationScope,
    );
    const organizationAssignments =
      scopeSnapshot.kind === "organization"
        ? await this.#reader.listActiveRoleAssignments(
            principalId,
            scopeSnapshot,
          )
        : [];

    if (
      this.#generation(
        this.#applicationGenerations,
        applicationGenerationKeyValue,
      ) !== applicationGeneration ||
      (organizationGenerationKeyValue !== undefined &&
        this.#generation(
          this.#organizationGenerations,
          organizationGenerationKeyValue,
        ) !== organizationGeneration)
    ) {
      throw new Error("role selection changed during cache fill");
    }

    const expiresAtMs = readStartedAtMs + ROLE_AUTHORIZATION_MAXIMUM_AGE_MS;
    if (!Number.isSafeInteger(expiresAtMs) || this.#now() >= expiresAtMs) {
      throw new Error("role selection expired before cache publication");
    }

    const roles = [
      ...new Set(
        [...applicationAssignments, ...organizationAssignments].map(
          ({ role }) => role,
        ),
      ),
    ].sort();
    const entry: CachedAuthorization = Object.freeze({
      cacheToken: this.#cacheToken,
      applicationId,
      principalId,
      scope: scopeSnapshot,
      policyVersion: policySnapshot.version,
      policyContentDigest,
      context: resolveAccess(
        {
          principalId,
          roles,
        },
        policySnapshot,
      ),
      clockDomainId: this.#clock.domainId,
      clockDomainToken: this.#clock.domainToken,
      readStartedAtMs,
      expiresAtMs,
      applicationGeneration,
      organizationGeneration,
    });
    this.#entries.set(key, entry);
    return entry;
  }

  invalidateRoleChange(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ): void {
    const applicationId = this.#applicationId;
    if (scope.kind === "application") {
      this.#increment(
        this.#applicationGenerations,
        applicationGenerationKey(applicationId, principalId),
      );
    } else {
      this.#increment(
        this.#organizationGenerations,
        organizationGenerationKey(
          applicationId,
          principalId,
          scope.organizationId,
        ),
      );
    }

    for (const [key, entry] of this.#entries) {
      if (
        entry.applicationId === applicationId &&
        entry.principalId === principalId &&
        (scope.kind === "application" ||
          (entry.scope.kind === "organization" &&
            entry.scope.organizationId === scope.organizationId))
      ) {
        this.#entries.delete(key);
      }
    }
  }

  captureDecisionPublicationFence(
    authorization: CachedAuthorization,
  ): DecisionPublicationFence {
    this.#assertLocalAuthorization(authorization);
    if (this.#now() >= authorization.expiresAtMs) {
      throw new Error("authorization expired before decision checks");
    }
    const current = this.#currentDecisionPublicationFence(authorization);
    if (
      current.applicationGeneration !== authorization.applicationGeneration ||
      current.organizationGeneration !== authorization.organizationGeneration
    ) {
      throw new Error("authorization invalidated before decision checks");
    }
    return Object.freeze({
      applicationGeneration: authorization.applicationGeneration,
      organizationGeneration: authorization.organizationGeneration,
    });
  }

  assertDecisionPublicationAllowed(
    authorization: CachedAuthorization,
    fence: DecisionPublicationFence,
  ): void {
    this.#assertLocalAuthorization(authorization);
    if (this.#now() >= authorization.expiresAtMs) {
      throw new Error("authorization expired before decision publication");
    }
    if (
      fence.applicationGeneration !== authorization.applicationGeneration ||
      fence.organizationGeneration !== authorization.organizationGeneration
    ) {
      throw new Error("decision fence belongs to a different authorization");
    }
    const current = this.#currentDecisionPublicationFence(authorization);
    if (
      current.applicationGeneration !== fence.applicationGeneration ||
      current.organizationGeneration !== fence.organizationGeneration
    ) {
      throw new Error("authorization changed during decision checks");
    }
  }

  #generation(generations: Map<string, number>, key: string): number {
    return generations.get(key) ?? 0;
  }

  #increment(generations: Map<string, number>, key: string): void {
    generations.set(key, this.#generation(generations, key) + 1);
  }

  #assertLocalAuthorization(authorization: CachedAuthorization): void {
    if (
      authorization.cacheToken !== this.#cacheToken ||
      authorization.applicationId !== this.#applicationId ||
      authorization.clockDomainId !== this.#clock.domainId ||
      authorization.clockDomainToken !== this.#clock.domainToken
    ) {
      throw new Error("decision authorization belongs to a different cache");
    }
  }

  #currentDecisionPublicationFence(
    authorization: CachedAuthorization,
  ): DecisionPublicationFence {
    return {
      applicationGeneration: this.#generation(
        this.#applicationGenerations,
        applicationGenerationKey(
          authorization.applicationId,
          authorization.principalId,
        ),
      ),
      organizationGeneration:
        authorization.scope.kind === "organization"
          ? this.#generation(
              this.#organizationGenerations,
              organizationGenerationKey(
                authorization.applicationId,
                authorization.principalId,
                authorization.scope.organizationId,
              ),
            )
          : undefined,
    };
  }

  #now(): number {
    if (this.#clockFailed) {
      throw new Error("trusted monotonic clock domain has failed");
    }
    try {
      return sampleTrustedClock(this.#clock);
    } catch (error) {
      this.#clockFailed = true;
      this.#entries.clear();
      throw error;
    }
  }
}

class CountingReader implements ApplicationBoundRoleAssignmentReader {
  calls = 0;
  fail = false;

  constructor(private readonly inner: ApplicationBoundRoleAssignmentReader) {}

  get applicationId(): string {
    return this.inner.applicationId;
  }

  getRoleAssignment(
    assignmentId: string,
  ): ReturnType<RoleAssignmentReader["getRoleAssignment"]> {
    return this.inner.getRoleAssignment(assignmentId);
  }

  async listActiveRoleAssignments(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ): ReturnType<RoleAssignmentReader["listActiveRoleAssignments"]> {
    this.calls += 1;
    if (this.fail) {
      throw new Error("authoritative role read failed");
    }
    return this.inner.listActiveRoleAssignments(principalId, scope);
  }

  listRoleAssignments(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ): ReturnType<RoleAssignmentReader["listRoleAssignments"]> {
    return this.inner.listRoleAssignments(principalId, scope);
  }
}

class DeferredReader implements ApplicationBoundRoleAssignmentReader {
  readonly started: Promise<void>;
  #signalStarted!: () => void;
  #release!: () => void;
  readonly #released: Promise<void>;

  constructor(private readonly inner: ApplicationBoundRoleAssignmentReader) {
    this.started = new Promise((resolve) => {
      this.#signalStarted = resolve;
    });
    this.#released = new Promise((resolve) => {
      this.#release = resolve;
    });
  }

  get applicationId(): string {
    return this.inner.applicationId;
  }

  getRoleAssignment(
    assignmentId: string,
  ): ReturnType<RoleAssignmentReader["getRoleAssignment"]> {
    return this.inner.getRoleAssignment(assignmentId);
  }

  async listActiveRoleAssignments(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ): ReturnType<RoleAssignmentReader["listActiveRoleAssignments"]> {
    const captured = await this.inner.listActiveRoleAssignments(
      principalId,
      scope,
    );
    this.#signalStarted();
    await this.#released;
    return captured;
  }

  listRoleAssignments(
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ): ReturnType<RoleAssignmentReader["listRoleAssignments"]> {
    return this.inner.listRoleAssignments(principalId, scope);
  }

  release(): void {
    this.#release();
  }
}

const activeAssignment = (
  id: string,
  principalId: PrincipalId,
  scope: RoleAssignmentScope = applicationScope,
): ActiveRoleAssignment => ({
  id,
  principalId,
  role: "support",
  scope,
  grantedBy: { kind: "system", systemId: "role-administration" },
  grantedAtEpochMs: 1_700_000_000_000,
  status: "active",
});

const policyIdentity = (
  policy: AccessPolicy = supportPolicy,
): PolicyIdentity => ({ policy, contentDigest: digestPolicy(policy) });

const grant = async (
  storage: HostApplicationRoleStore,
  assignment: ActiveRoleAssignment,
): Promise<void> => {
  const result = await storage.grantRoleAssignmentWithAudit({
    assignment,
    auditEventId: `audit-grant-${assignment.id}`,
  });
  expect(result.status).toBe("granted");
};

const revoke = async (
  storage: HostApplicationRoleStore,
  assignmentId: string,
): Promise<RoleAssignmentScope> => {
  const current = await storage.getRoleAssignment(assignmentId);
  if (current === null) {
    throw new Error("assignment missing before test revocation");
  }
  const result = await storage.revokeRoleAssignmentWithAudit({
    assignmentId,
    expectedConcurrencyToken: current.concurrencyToken,
    revokedBy: { kind: "system", systemId: "role-administration" },
    revokedAtEpochMs: 1_700_000_000_001,
    auditEventId: `audit-revoke-${assignmentId}`,
  });
  if (result.status !== "revoked") {
    throw new Error(`unexpected revocation result: ${result.status}`);
  }
  return result.record.assignment.scope;
};

const isAllowed = (entry: CachedAuthorization): boolean =>
  decideAccess(entry.context, "support.queue.read").allowed;

const requireLocalClockDomain = (
  entry: CachedAuthorization,
  clock: FakeMonotonicClock,
): CachedAuthorization => {
  if (entry.clockDomainToken !== clock.domainToken) {
    throw new Error("foreign monotonic deadline requires authoritative reload");
  }
  return entry;
};

const sampleDecisionClock = (
  clock: FakeMonotonicClock,
  minimumSample: number,
): number => sampleTrustedClock(clock, minimumSample);

const composeAuthorization = (
  roleCache: BoundedRoleAuthorizationCache,
  roleAuthorization: CachedAuthorization,
  entitlementAuthorization: BoundedEntitlementAuthorization,
  policy: AccessPolicy,
  clock: FakeMonotonicClock,
): BoundedComposedAuthorization => {
  const policySnapshot = snapshotPolicy(policy);
  const timestamps = [
    roleAuthorization.readStartedAtMs,
    roleAuthorization.expiresAtMs,
    entitlementAuthorization.readStartedAtMs,
    entitlementAuthorization.expiresAtMs,
  ];
  if (
    timestamps.some(
      (timestamp) => !Number.isSafeInteger(timestamp) || timestamp < 0,
    ) ||
    roleAuthorization.expiresAtMs <= roleAuthorization.readStartedAtMs ||
    entitlementAuthorization.expiresAtMs <=
      entitlementAuthorization.readStartedAtMs
  ) {
    throw new Error("bounded authorization timestamps are invalid");
  }
  if (
    roleAuthorization.applicationId !==
      entitlementAuthorization.applicationId ||
    roleAuthorization.principalId !== entitlementAuthorization.principalId ||
    JSON.stringify(scopeIdentity(roleAuthorization.scope)) !==
      JSON.stringify(scopeIdentity(entitlementAuthorization.scope)) ||
    roleAuthorization.policyVersion !==
      entitlementAuthorization.policyVersion ||
    roleAuthorization.policyContentDigest !==
      entitlementAuthorization.policyContentDigest ||
    roleAuthorization.clockDomainId !==
      entitlementAuthorization.clockDomainId ||
    roleAuthorization.clockDomainToken !==
      entitlementAuthorization.clockDomainToken ||
    roleAuthorization.clockDomainId !== clock.domainId ||
    roleAuthorization.clockDomainToken !== clock.domainToken ||
    roleAuthorization.policyVersion !== policySnapshot.version ||
    roleAuthorization.policyContentDigest !== digestPolicy(policySnapshot)
  ) {
    throw new Error("bounded authorization identities do not match");
  }
  roleCache.captureDecisionPublicationFence(roleAuthorization);
  const composedAtMs = sampleDecisionClock(
    clock,
    Math.max(
      roleAuthorization.readStartedAtMs,
      entitlementAuthorization.readStartedAtMs,
    ),
  );
  const expiresAtMs = Math.min(
    roleAuthorization.expiresAtMs,
    entitlementAuthorization.expiresAtMs,
  );
  if (composedAtMs >= expiresAtMs) {
    throw new Error("bounded authorization is already expired");
  }
  return Object.freeze({
    roleAuthorization,
    context: resolveAccess(
      {
        principalId: roleAuthorization.principalId,
        roles: roleAuthorization.context.roles,
        entitlements: entitlementAuthorization.entitlements,
      },
      policySnapshot,
    ),
    clockDomainId: clock.domainId,
    clockDomainToken: clock.domainToken,
    composedAtMs,
    expiresAtMs,
  });
};

const decideBeforeDeadline = (
  roleCache: BoundedRoleAuthorizationCache,
  authorization: BoundedComposedAuthorization,
  permission: string,
  clock: FakeMonotonicClock,
): boolean => {
  roleCache.captureDecisionPublicationFence(authorization.roleAuthorization);
  if (
    authorization.clockDomainToken !== clock.domainToken ||
    sampleDecisionClock(clock, authorization.composedAtMs) >=
      authorization.expiresAtMs
  ) {
    throw new Error("composed authorization requires authoritative reload");
  }
  return decideAccess(authorization.context, permission).allowed;
};

interface DecisionResourceIdentity {
  readonly kind: string;
  readonly id: string;
  readonly ownershipVersion: string;
  readonly membershipVersion: string;
  readonly relationshipVersion: string;
}

const snapshotDecisionResource = (
  resource: DecisionResourceIdentity,
): DecisionResourceIdentity =>
  Object.freeze({
    kind: resource.kind,
    id: resource.id,
    ownershipVersion: resource.ownershipVersion,
    membershipVersion: resource.membershipVersion,
    relationshipVersion: resource.relationshipVersion,
  });

const accessDecisionKey = (
  authorization: CachedAuthorization,
  permission: string,
  resource: DecisionResourceIdentity,
): string =>
  JSON.stringify([
    cacheKey(
      authorization.applicationId,
      authorization.principalId,
      authorization.scope,
      authorization.policyVersion,
      authorization.policyContentDigest,
    ),
    permission,
    [
      resource.kind,
      resource.id,
      resource.ownershipVersion,
      resource.membershipVersion,
      resource.relationshipVersion,
    ],
  ]);

const publishDecisionKeyAfter = async (
  cache: BoundedRoleAuthorizationCache,
  authorization: CachedAuthorization,
  permission: string,
  resource: DecisionResourceIdentity,
  runAuthoritativeChecks: (
    resourceSnapshot: DecisionResourceIdentity,
  ) => Promise<boolean>,
): Promise<string> => {
  const resourceSnapshot = snapshotDecisionResource(resource);
  const publicationFence = cache.captureDecisionPublicationFence(authorization);
  if (!(await runAuthoritativeChecks(resourceSnapshot))) {
    throw new Error("authoritative resource check denied");
  }
  cache.assertDecisionPublicationAllowed(authorization, publicationFence);
  return accessDecisionKey(authorization, permission, resourceSnapshot);
};

describe("fast role-revocation cache contract", () => {
  it("expires at the exact 60,000 ms read-start deadline when invalidation is lost", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const clock = new FakeMonotonicClock();
    const nodeWithoutEvents = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", storage),
      clock,
    );

    expect(
      isAllowed(
        await nodeWithoutEvents.resolve(
          "principal_a",
          applicationScope,
          policyIdentity(),
        ),
      ),
    ).toBe(true);
    await revoke(storage, "assignment_support");

    clock.advance(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS - 1);
    expect(
      isAllowed(
        await nodeWithoutEvents.resolve(
          "principal_a",
          applicationScope,
          policyIdentity(),
        ),
      ),
    ).toBe(true);

    clock.advance(1);
    const reloaded = await nodeWithoutEvents.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    expect(isAllowed(reloaded)).toBe(false);
    expect(reloaded.readStartedAtMs).toBe(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS);
  });

  it("uses the 5,000 ms delivery target as immediate eviction, not a new deadline", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const clock = new FakeMonotonicClock();
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", storage),
      clock,
    );
    const original = await cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const scope = await revoke(storage, "assignment_support");

    clock.advance(ROLE_INVALIDATION_TARGET_MS);
    cache.invalidateRoleChange("principal_a", scope);
    const refreshed = await cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );

    expect(isAllowed(refreshed)).toBe(false);
    expect(refreshed.expiresAtMs).toBe(
      ROLE_INVALIDATION_TARGET_MS + ROLE_AUTHORIZATION_MAXIMUM_AGE_MS,
    );
    expect(original.expiresAtMs).toBe(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS);
  });

  it("rejects a pre-revocation read that tries to publish after invalidation", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const clock = new FakeMonotonicClock();
    const deferredReader = new DeferredReader(storage);
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", deferredReader),
      clock,
    );

    const pending = cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    await deferredReader.started;
    const scope = await revoke(storage, "assignment_support");
    cache.invalidateRoleChange("principal_a", scope);
    clock.advance(10_000);
    deferredReader.release();

    await expect(pending).rejects.toThrow(
      "role selection changed during cache fill",
    );
    expect(cache.size).toBe(0);
  });

  it("charges cache-fill time to the original non-sliding deadline", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const clock = new FakeMonotonicClock();
    const deferredReader = new DeferredReader(storage);
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", deferredReader),
      clock,
    );

    const pending = cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    await deferredReader.started;
    clock.advance(59_000);
    deferredReader.release();
    const filled = await pending;

    expect(filled.readStartedAtMs).toBe(0);
    expect(filled.expiresAtMs).toBe(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS);
    clock.advance(999);
    expect(
      await cache.resolve("principal_a", applicationScope, policyIdentity()),
    ).toBe(filled);
    clock.advance(1);
    const reloaded = await cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    expect(reloaded).not.toBe(filled);
    expect(reloaded.readStartedAtMs).toBe(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS);
  });

  it("binds exact application, principal, tagged scope, policy version, and policy digest", async () => {
    const applicationAStorage = createInMemoryStorageAdapter();
    const applicationBStorage =
      HostApplicationRoleStore.create("application_b");
    await grant(
      applicationAStorage,
      activeAssignment("assignment_support", "principal_a"),
    );
    const applicationAReader = new CountingReader(applicationAStorage);
    const applicationBReader = new CountingReader(applicationBStorage);
    const applicationACache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", applicationAReader),
      new FakeMonotonicClock(),
    );
    const applicationBCache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_b", applicationBReader),
      new FakeMonotonicClock(),
    );
    expect(() =>
      bindApplicationReader("application_b", applicationAReader),
    ).toThrow("reader belongs to a different application namespace");

    expect(
      isAllowed(
        await applicationACache.resolve(
          "principal_a",
          applicationScope,
          policyIdentity(),
        ),
      ),
    ).toBe(true);
    expect(
      isAllowed(
        await applicationBCache.resolve(
          "principal_a",
          applicationScope,
          policyIdentity(),
        ),
      ),
    ).toBe(false);
    await applicationACache.resolve(
      "principal_b",
      applicationScope,
      policyIdentity(),
    );
    await applicationACache.resolve(
      "principal_a",
      organizationAlphaScope,
      policyIdentity(),
    );
    await applicationACache.resolve(
      "principal_a",
      organizationBetaScope,
      policyIdentity(),
    );
    await applicationACache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity({ ...supportPolicy, version: "policy-2" }),
    );
    await applicationACache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity({
        ...supportPolicy,
        roles: { support: ["support.queue.write"] },
      }),
    );

    expect(applicationACache.size).toBe(6);
    expect(applicationBCache.size).toBe(1);
    expect(applicationAReader.calls).toBe(8);
    expect(applicationBReader.calls).toBe(1);
  });

  it("recomputes and verifies the policy digest before lookup or publication", async () => {
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      new FakeMonotonicClock(),
    );

    await expect(
      cache.resolve("principal_a", applicationScope, {
        policy: supportPolicy,
        contentDigest: "sha256:forged",
      }),
    ).rejects.toThrow("policy content digest does not match policy snapshot");
    expect(cache.size).toBe(0);
  });

  it("canonicalizes policy map keys with an exact locale-independent total order", () => {
    const composedName = "\u00e1";
    const decomposedName = "a\u0301";
    const first: AccessPolicy = {
      version: "policy-unicode",
      roles: {
        [composedName]: ["permission.composed"],
        [decomposedName]: ["permission.decomposed"],
      },
    };
    const reversed: AccessPolicy = {
      version: "policy-unicode",
      roles: {
        [decomposedName]: ["permission.decomposed"],
        [composedName]: ["permission.composed"],
      },
    };

    expect(digestPolicy(first)).toBe(digestPolicy(reversed));
  });

  it("fans application changes across organization variants and keeps organization changes exact", async () => {
    const storage = createInMemoryStorageAdapter();
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", storage),
      new FakeMonotonicClock(),
    );

    await cache.resolve("principal_a", applicationScope, policyIdentity());
    await cache.resolve(
      "principal_a",
      organizationAlphaScope,
      policyIdentity(),
    );
    await cache.resolve("principal_a", organizationBetaScope, policyIdentity());
    cache.invalidateRoleChange("principal_a", organizationAlphaScope);
    expect(cache.size).toBe(2);

    cache.invalidateRoleChange("principal_a", applicationScope);
    expect(cache.size).toBe(0);
  });

  it("invalidates cached denials after a durable audited grant", async () => {
    const storage = createInMemoryStorageAdapter();
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", storage),
      new FakeMonotonicClock(),
    );

    expect(
      isAllowed(
        await cache.resolve("principal_a", applicationScope, policyIdentity()),
      ),
    ).toBe(false);
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    cache.invalidateRoleChange("principal_a", applicationScope);

    expect(
      isAllowed(
        await cache.resolve("principal_a", applicationScope, policyIdentity()),
      ),
    ).toBe(true);
  });

  it("fails closed after expiry when the authoritative refresh fails", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const reader = new CountingReader(storage);
    const clock = new FakeMonotonicClock();
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", reader),
      clock,
    );
    expect(
      isAllowed(
        await cache.resolve("principal_a", applicationScope, policyIdentity()),
      ),
    ).toBe(true);

    reader.fail = true;
    clock.advance(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS);
    await expect(
      cache.resolve("principal_a", applicationScope, policyIdentity()),
    ).rejects.toThrow("authoritative role read failed");
    expect(cache.size).toBe(0);
  });

  it("freezes returned entries so callers cannot extend deadlines or rewrite scope", async () => {
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      new FakeMonotonicClock(),
    );
    const entry = await cache.resolve(
      "principal_a",
      organizationAlphaScope,
      policyIdentity(),
    );

    expect(Object.isFrozen(entry)).toBe(true);
    expect(Object.isFrozen(entry.scope)).toBe(true);
    expect(() => {
      (entry as { expiresAtMs: number }).expiresAtMs = Number.MAX_SAFE_INTEGER;
    }).toThrow(TypeError);
    expect(() => {
      (
        entry.scope as {
          kind: "organization";
          organizationId: string;
        }
      ).organizationId = "organization_beta";
    }).toThrow(TypeError);
    expect(entry.expiresAtMs).toBe(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS);
    expect(entry.scope).toEqual(organizationAlphaScope);
  });

  it("snapshots scope and policy inputs before an asynchronous authoritative read", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(
      storage,
      activeAssignment(
        "assignment_support",
        "principal_a",
        organizationAlphaScope,
      ),
    );
    const reader = new DeferredReader(storage);
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", reader),
      new FakeMonotonicClock(),
    );
    const mutableScope = {
      kind: "organization" as const,
      organizationId: "organization_alpha",
    };
    const mutablePolicy = {
      version: "policy-1",
      roles: { support: ["support.queue.read"] },
    };

    const pending = cache.resolve(
      "principal_a",
      mutableScope,
      policyIdentity(mutablePolicy),
    );
    await reader.started;
    mutableScope.organizationId = "organization_beta";
    mutablePolicy.version = "policy-mutated";
    mutablePolicy.roles.support[0] = "administrator";
    reader.release();
    const entry = await pending;

    expect(entry.scope).toEqual(organizationAlphaScope);
    expect(entry.policyVersion).toBe("policy-1");
    expect(isAllowed(entry)).toBe(true);
  });

  it("rejects raw monotonic deadlines from a different process clock domain", async () => {
    const sourceClock = new FakeMonotonicClock("process-a");
    const entry = await new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      sourceClock,
    ).resolve("principal_a", applicationScope, policyIdentity());
    const foreignClock = new FakeMonotonicClock("process-b");
    const sameNamedForeignClock = new FakeMonotonicClock("process-a");

    expect(() => requireLocalClockDomain(entry, foreignClock)).toThrow(
      "foreign monotonic deadline requires authoritative reload",
    );
    expect(() => requireLocalClockDomain(entry, sameNamedForeignClock)).toThrow(
      "foreign monotonic deadline requires authoritative reload",
    );
    expect(requireLocalClockDomain(entry, sourceClock)).toBe(entry);
  });

  it("fails closed when a trusted monotonic clock is invalid or regresses", async () => {
    const clock = new FakeMonotonicClock();
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      clock,
    );
    await cache.resolve("principal_a", applicationScope, policyIdentity());
    clock.advance(100);
    await cache.resolve("principal_a", applicationScope, policyIdentity());

    clock.setUnsafe(99);
    await expect(
      cache.resolve("principal_a", applicationScope, policyIdentity()),
    ).rejects.toThrow("trusted monotonic clock is invalid or regressed");
    expect(cache.size).toBe(0);

    clock.setUnsafe(100);
    await expect(
      cache.resolve("principal_a", applicationScope, policyIdentity()),
    ).rejects.toThrow("trusted monotonic clock domain has failed");

    const invalidClock = new FakeMonotonicClock();
    const invalidCache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      invalidClock,
    );
    invalidClock.setUnsafe(Number.NaN);
    await expect(
      invalidCache.resolve("principal_a", applicationScope, policyIdentity()),
    ).rejects.toThrow("trusted monotonic clock is invalid or regressed");
    invalidClock.setUnsafe(0);
    await expect(
      invalidCache.resolve("principal_a", applicationScope, policyIdentity()),
    ).rejects.toThrow("trusted monotonic clock domain has failed");
  });

  it("binds cached decisions to permission and resource relationship identity", async () => {
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      new FakeMonotonicClock(),
    );
    const entry = await cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const target: {
      kind: string;
      id: string;
      ownershipVersion: string;
      membershipVersion: string;
      relationshipVersion: string;
    } = {
      kind: "support-queue",
      id: "queue-a",
      ownershipVersion: "owner-etag-1",
      membershipVersion: "membership-etag-1",
      relationshipVersion: "etag-1",
    };

    expect(accessDecisionKey(entry, "support.queue.read", target)).not.toBe(
      accessDecisionKey(entry, "support.queue.write", target),
    );
    expect(accessDecisionKey(entry, "support.queue.read", target)).not.toBe(
      accessDecisionKey(entry, "support.queue.read", {
        ...target,
        id: "queue-b",
      }),
    );
    expect(accessDecisionKey(entry, "support.queue.read", target)).not.toBe(
      accessDecisionKey(entry, "support.queue.read", {
        ...target,
        relationshipVersion: "etag-2",
      }),
    );

    let releaseChecks!: () => void;
    const checks = new Promise<void>((resolve) => {
      releaseChecks = resolve;
    });
    let checkedSnapshot: DecisionResourceIdentity | undefined;
    const pendingKey = publishDecisionKeyAfter(
      cache,
      entry,
      "support.queue.read",
      target,
      async (resourceSnapshot) => {
        checkedSnapshot = resourceSnapshot;
        await checks;
        return (
          resourceSnapshot.id === "queue-a" &&
          resourceSnapshot.ownershipVersion === "owner-etag-1" &&
          resourceSnapshot.membershipVersion === "membership-etag-1" &&
          resourceSnapshot.relationshipVersion === "etag-1"
        );
      },
    );
    target.id = "queue-attacker";
    target.ownershipVersion = "owner-attacker";
    target.membershipVersion = "membership-attacker";
    target.relationshipVersion = "relationship-attacker";
    releaseChecks();

    expect(Object.isFrozen(checkedSnapshot)).toBe(true);
    expect(await pendingKey).toBe(
      accessDecisionKey(entry, "support.queue.read", {
        kind: "support-queue",
        id: "queue-a",
        ownershipVersion: "owner-etag-1",
        membershipVersion: "membership-etag-1",
        relationshipVersion: "etag-1",
      }),
    );
  });

  it("fences decision publication after invalidation or deadline expiry", async () => {
    const clock = new FakeMonotonicClock();
    const cache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      clock,
    );
    const entry = await cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const target: DecisionResourceIdentity = {
      kind: "support-queue",
      id: "queue-a",
      ownershipVersion: "owner-etag-1",
      membershipVersion: "membership-etag-1",
      relationshipVersion: "relationship-etag-1",
    };
    cache.invalidateRoleChange("principal_a", applicationScope);
    await expect(
      publishDecisionKeyAfter(
        cache,
        entry,
        "support.queue.read",
        target,
        async () => true,
      ),
    ).rejects.toThrow("authorization invalidated before decision checks");

    const reloaded = await cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const reloadedFence = cache.captureDecisionPublicationFence(reloaded);
    expect(() =>
      cache.assertDecisionPublicationAllowed(entry, reloadedFence),
    ).toThrow("decision fence belongs to a different authorization");

    const otherCache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      clock,
    );
    await expect(
      publishDecisionKeyAfter(
        otherCache,
        reloaded,
        "support.queue.read",
        target,
        async () => true,
      ),
    ).rejects.toThrow("decision authorization belongs to a different cache");

    let releaseInvalidatedCheck!: () => void;
    const invalidatedCheck = new Promise<void>((resolve) => {
      releaseInvalidatedCheck = resolve;
    });
    const invalidatedPublication = publishDecisionKeyAfter(
      cache,
      reloaded,
      "support.queue.read",
      target,
      async () => {
        await invalidatedCheck;
        return true;
      },
    );
    cache.invalidateRoleChange("principal_a", applicationScope);
    releaseInvalidatedCheck();
    await expect(invalidatedPublication).rejects.toThrow(
      "authorization changed during decision checks",
    );

    const deadlineEntry = await cache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    let releaseExpiredCheck!: () => void;
    const expiredCheck = new Promise<void>((resolve) => {
      releaseExpiredCheck = resolve;
    });
    const expiredPublication = publishDecisionKeyAfter(
      cache,
      deadlineEntry,
      "support.queue.read",
      target,
      async () => {
        await expiredCheck;
        return true;
      },
    );
    clock.advance(ROLE_AUTHORIZATION_MAXIMUM_AGE_MS);
    releaseExpiredCheck();
    await expect(expiredPublication).rejects.toThrow(
      "authorization expired before decision publication",
    );
  });

  it("preserves the earliest real deadline when role and entitlement facts are composed", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const clock = new FakeMonotonicClock();
    const composedPolicy: AccessPolicy = {
      version: "policy-1",
      roles: { support: ["support.queue.read"] },
      entitlements: { "plan.pro": ["billing.portal.read"] },
    };
    const roleCache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", storage),
      clock,
    );
    const roleAuthorization = await roleCache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(composedPolicy),
    );
    const entitlementAuthorization: BoundedEntitlementAuthorization =
      Object.freeze({
        applicationId: "application_a",
        principalId: "principal_a",
        scope: applicationScope,
        policyVersion: "policy-1",
        policyContentDigest: policyIdentity(composedPolicy).contentDigest,
        clockDomainId: clock.domainId,
        clockDomainToken: clock.domainToken,
        entitlements: Object.freeze(["plan.pro"]),
        readStartedAtMs: 0,
        expiresAtMs: 42_000,
      });
    const composed = composeAuthorization(
      roleCache,
      roleAuthorization,
      entitlementAuthorization,
      composedPolicy,
      clock,
    );

    expect(composed.expiresAtMs).toBe(42_000);
    clock.advance(41_999);
    expect(
      decideBeforeDeadline(roleCache, composed, "billing.portal.read", clock),
    ).toBe(true);
    clock.advance(1);
    expect(() =>
      decideBeforeDeadline(roleCache, composed, "billing.portal.read", clock),
    ).toThrow("composed authorization requires authoritative reload");
  });

  it("carries the exact role-generation fence through composition and later decisions", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const clock = new FakeMonotonicClock();
    const roleCache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", storage),
      clock,
    );
    const original = await roleCache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const entitlementAuthorization: BoundedEntitlementAuthorization =
      Object.freeze({
        applicationId: "application_a",
        principalId: "principal_a",
        scope: applicationScope,
        policyVersion: "policy-1",
        policyContentDigest: policyIdentity().contentDigest,
        clockDomainId: clock.domainId,
        clockDomainToken: clock.domainToken,
        entitlements: Object.freeze([]),
        readStartedAtMs: 0,
        expiresAtMs: 50_000,
      });

    const firstRevokedScope = await revoke(storage, "assignment_support");
    roleCache.invalidateRoleChange("principal_a", firstRevokedScope);
    expect(() =>
      composeAuthorization(
        roleCache,
        original,
        entitlementAuthorization,
        supportPolicy,
        clock,
      ),
    ).toThrow("authorization invalidated before decision checks");

    await grant(
      storage,
      activeAssignment("assignment_support_regranted", "principal_a"),
    );
    roleCache.invalidateRoleChange("principal_a", applicationScope);
    const current = await roleCache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const composed = composeAuthorization(
      roleCache,
      current,
      entitlementAuthorization,
      supportPolicy,
      clock,
    );
    expect(
      decideBeforeDeadline(roleCache, composed, "support.queue.read", clock),
    ).toBe(true);

    const secondRevokedScope = await revoke(
      storage,
      "assignment_support_regranted",
    );
    roleCache.invalidateRoleChange("principal_a", secondRevokedScope);
    expect(() =>
      decideBeforeDeadline(roleCache, composed, "support.queue.read", clock),
    ).toThrow("authorization invalidated before decision checks");
  });

  it("terminally retires cached and composed authorization after one clock-domain anomaly", async () => {
    const storage = createInMemoryStorageAdapter();
    await grant(storage, activeAssignment("assignment_support", "principal_a"));
    const clock = new FakeMonotonicClock();
    const roleCache = new BoundedRoleAuthorizationCache(storage, clock);
    const roleAuthorization = await roleCache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const entitlementAuthorization: BoundedEntitlementAuthorization = {
      applicationId: "application_a",
      principalId: "principal_a",
      scope: applicationScope,
      policyVersion: "policy-1",
      policyContentDigest: policyIdentity().contentDigest,
      clockDomainId: clock.domainId,
      clockDomainToken: clock.domainToken,
      entitlements: [],
      readStartedAtMs: 0,
      expiresAtMs: 50_000,
    };
    const composed = composeAuthorization(
      roleCache,
      roleAuthorization,
      entitlementAuthorization,
      supportPolicy,
      clock,
    );

    clock.advance(100);
    expect(
      decideBeforeDeadline(roleCache, composed, "support.queue.read", clock),
    ).toBe(true);
    clock.setUnsafe(99);
    expect(() =>
      decideBeforeDeadline(roleCache, composed, "support.queue.read", clock),
    ).toThrow("trusted monotonic clock is invalid or regressed");
    clock.setUnsafe(100);
    expect(() =>
      decideBeforeDeadline(roleCache, composed, "support.queue.read", clock),
    ).toThrow("trusted monotonic clock domain has failed");
    await expect(
      roleCache.resolve("principal_a", applicationScope, policyIdentity()),
    ).rejects.toThrow("trusted monotonic clock domain has failed");
    expect(roleCache.size).toBe(0);
  });

  it("rejects composition across principal, scope, policy, or clock identities", async () => {
    const clock = new FakeMonotonicClock("process-a");
    const roleCache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      clock,
    );
    const roleAuthorization = await roleCache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const exact: BoundedEntitlementAuthorization = Object.freeze({
      applicationId: "application_a",
      principalId: "principal_a",
      scope: applicationScope,
      policyVersion: "policy-1",
      policyContentDigest: policyIdentity().contentDigest,
      clockDomainId: "process-a",
      clockDomainToken: clock.domainToken,
      entitlements: Object.freeze(["plan.pro"]),
      readStartedAtMs: 0,
      expiresAtMs: 42_000,
    });
    const mismatches: readonly BoundedEntitlementAuthorization[] = [
      { ...exact, applicationId: "application_b" },
      { ...exact, principalId: "principal_b" },
      { ...exact, scope: organizationAlphaScope },
      { ...exact, policyVersion: "policy-2" },
      { ...exact, policyContentDigest: "sha256:other-policy" },
      { ...exact, clockDomainId: "process-b" },
      {
        ...exact,
        clockDomainToken: new FakeMonotonicClock("process-a").domainToken,
      },
    ];

    for (const mismatch of mismatches) {
      expect(() =>
        composeAuthorization(
          roleCache,
          roleAuthorization,
          mismatch,
          supportPolicy,
          clock,
        ),
      ).toThrow("bounded authorization identities do not match");
    }
    expect(() =>
      composeAuthorization(
        roleCache,
        roleAuthorization,
        exact,
        {
          version: "policy-1",
          roles: { support: ["administrator"] },
        },
        clock,
      ),
    ).toThrow("bounded authorization identities do not match");
  });

  it("rejects invalid or already expired composed input deadlines", async () => {
    const clock = new FakeMonotonicClock();
    const roleCache = new BoundedRoleAuthorizationCache(
      bindApplicationReader("application_a", createInMemoryStorageAdapter()),
      clock,
    );
    const roleAuthorization = await roleCache.resolve(
      "principal_a",
      applicationScope,
      policyIdentity(),
    );
    const exact: BoundedEntitlementAuthorization = {
      applicationId: "application_a",
      principalId: "principal_a",
      scope: applicationScope,
      policyVersion: "policy-1",
      policyContentDigest: policyIdentity().contentDigest,
      clockDomainId: clock.domainId,
      clockDomainToken: clock.domainToken,
      entitlements: ["plan.pro"],
      readStartedAtMs: 0,
      expiresAtMs: 42_000,
    };

    for (const invalid of [
      { ...exact, readStartedAtMs: Number.NaN },
      { ...exact, expiresAtMs: Number.NaN },
      { ...exact, readStartedAtMs: -1 },
      { ...exact, expiresAtMs: 0 },
    ]) {
      expect(() =>
        composeAuthorization(
          roleCache,
          roleAuthorization,
          invalid,
          supportPolicy,
          clock,
        ),
      ).toThrow("bounded authorization timestamps are invalid");
    }

    clock.advance(42_000);
    expect(() =>
      composeAuthorization(
        roleCache,
        roleAuthorization,
        exact,
        supportPolicy,
        clock,
      ),
    ).toThrow("bounded authorization is already expired");
  });

  it("keeps cache metadata out of principal-only public contracts", () => {
    expectTypeOf<keyof AccessSubject>().toEqualTypeOf<
      "principalId" | "roles" | "entitlements"
    >();
    expectTypeOf<keyof AccessContext>().toEqualTypeOf<
      "principalId" | "policyVersion" | "roles" | "entitlements" | "permissions"
    >();
    expectTypeOf<keyof RoleAssignmentReader>().toEqualTypeOf<
      "getRoleAssignment" | "listActiveRoleAssignments" | "listRoleAssignments"
    >();
  });
});
