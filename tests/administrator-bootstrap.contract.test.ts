import { createHash } from "node:crypto";

import { describe, expect, it } from "vitest";

import type {
  AccessContext,
  AccessPolicy,
  AccessSubject,
  ActiveRoleAssignment,
  PrincipalId,
  RoleAssignment,
  RoleAssignmentActor,
} from "@pegma/authorization-contracts";
import { resolveAccess } from "@pegma/authorization-core";
import {
  createInMemoryStorageAdapter,
  type InMemoryStorageAdapter,
} from "@pegma/authorization-storage";

type DeploymentBinding = Readonly<{
  environmentId: string;
  storageFingerprint: string;
  applicationId: string;
}>;

type BootstrapManifest = Readonly<{
  deployment: DeploymentBinding;
  assignment: ActiveRoleAssignment;
  auditEventId: string;
  failureCleanupAuditEventId: string;
  policyVersion: string;
  requiredPermission: string;
}>;

type GateState =
  | Readonly<{ kind: "disabled" }>
  | Readonly<{ kind: "armed"; manifestDigest: string; generation: number }>
  | Readonly<{
      kind: "executing";
      manifestDigest: string;
      generation: number;
      executionId: number;
    }>
  | Readonly<{
      kind: "cleanup_pending";
      manifestDigest: string;
      generation: number;
    }>
  | Readonly<{
      kind: "failure_cleanup_pending";
      manifestDigest: string;
      generation: number;
      reason: string;
    }>
  | Readonly<{
      kind: "failure_cleanup_executing";
      manifestDigest: string;
      generation: number;
      executionId: number;
      reason: string;
    }>
  | Readonly<{
      kind: "failed";
      manifestDigest: string;
      generation: number;
      reason: string;
    }>
  | Readonly<{ kind: "completed"; manifestDigest: string; generation: number }>
  | Readonly<{ kind: "unknown" }>;

type GateAttempt = Readonly<{
  manifestDigest: string;
  generation: number;
  executionId: number;
}>;

type BootstrapCleanup = () => Promise<
  Readonly<{
    authorityRemoved: boolean;
    credentialsRemoved: boolean;
  }>
>;

type BootstrapFailureCleanup = (attempt: GateAttempt) => Promise<
  Readonly<{
    grantAbsentOrRevoked: boolean;
    authorityRemoved: boolean;
    credentialsRemoved: boolean;
  }>
>;

/**
 * Test-local model of the host-owned durable one-shot CAS gate. Production
 * deployments must implement this state in durable operator-controlled
 * storage; this in-memory fixture is not production bootstrap infrastructure.
 */
class TestOneShotGate {
  #state: GateState;
  #nextExecutionId = 1;
  readonly #installedBeforeAdministratorGrantAuthority: boolean;

  constructor(
    initialState: GateState = { kind: "disabled" },
    installedBeforeAdministratorGrantAuthority = true,
  ) {
    this.#state = initialState;
    this.#installedBeforeAdministratorGrantAuthority =
      installedBeforeAdministratorGrantAuthority;
  }

  arm(manifestDigest: string): void {
    if (!this.#installedBeforeAdministratorGrantAuthority) {
      throw new Error(
        "bootstrap gate was not installed before administrator grant authority",
      );
    }
    if (this.#state.kind !== "disabled") {
      throw new Error("bootstrap gate cannot be armed from its current state");
    }
    this.#state = { kind: "armed", manifestDigest, generation: 1 };
  }

  assertArmed(
    manifestDigest: string,
  ): Extract<GateState, Readonly<{ kind: "armed" }>> {
    if (
      this.#state.kind !== "armed" ||
      this.#state.manifestDigest !== manifestDigest
    ) {
      throw new Error("bootstrap gate is not armed for this exact manifest");
    }
    return this.#state;
  }

  begin(manifestDigest: string): GateAttempt {
    const armed = this.assertArmed(manifestDigest);
    const attempt = Object.freeze({
      manifestDigest,
      generation: armed.generation,
      executionId: this.#nextExecutionId++,
    });
    this.#state = { kind: "executing", ...attempt };
    return attempt;
  }

  recoverExpiredExecution(
    attempt: GateAttempt,
    authorityFenced: boolean,
    quiescenceVerified: boolean,
  ): void {
    if (!authorityFenced || !quiescenceVerified) {
      throw new Error("expired bootstrap execution is not safely fenced");
    }
    if (
      this.#state.kind !== "executing" ||
      this.#state.manifestDigest !== attempt.manifestDigest ||
      this.#state.generation !== attempt.generation ||
      this.#state.executionId !== attempt.executionId
    ) {
      throw new Error("expired bootstrap execution claim does not match");
    }
    this.#state = {
      kind: "armed",
      manifestDigest: attempt.manifestDigest,
      generation: attempt.generation + 1,
    };
  }

  markCleanupPending(attempt: GateAttempt): void {
    if (
      this.#state.kind === "executing" &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation &&
      this.#state.executionId === attempt.executionId
    ) {
      this.#state = {
        kind: "cleanup_pending",
        manifestDigest: attempt.manifestDigest,
        generation: attempt.generation,
      };
      return;
    }

    if (
      (this.#state.kind === "cleanup_pending" ||
        this.#state.kind === "completed") &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation
    ) {
      return;
    }

    throw new Error("bootstrap gate cleanup-pending CAS failed");
  }

  fail(attempt: GateAttempt, reason: string): void {
    if (
      this.#state.kind === "executing" &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation &&
      this.#state.executionId === attempt.executionId
    ) {
      this.#state = {
        kind: "failure_cleanup_pending",
        manifestDigest: attempt.manifestDigest,
        generation: attempt.generation,
        reason,
      };
      return;
    }

    if (
      this.#state.kind === "failure_cleanup_pending" &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation &&
      this.#state.reason === reason
    ) {
      return;
    }

    throw new Error("bootstrap gate failure CAS failed");
  }

  beginFailureCleanup(manifestDigest: string): GateAttempt {
    if (
      this.#state.kind !== "failure_cleanup_pending" ||
      this.#state.manifestDigest !== manifestDigest
    ) {
      throw new Error(
        "bootstrap failure cleanup is not pending for this manifest",
      );
    }
    const attempt = Object.freeze({
      manifestDigest,
      generation: this.#state.generation,
      executionId: this.#nextExecutionId++,
    });
    this.#state = {
      kind: "failure_cleanup_executing",
      ...attempt,
      reason: this.#state.reason,
    };
    return attempt;
  }

  assertFailureCleanup(attempt: GateAttempt): void {
    if (
      this.#state.kind !== "failure_cleanup_executing" ||
      this.#state.manifestDigest !== attempt.manifestDigest ||
      this.#state.generation !== attempt.generation ||
      this.#state.executionId !== attempt.executionId
    ) {
      throw new Error("bootstrap failure-cleanup claim is not live");
    }
  }

  releaseFailureCleanup(attempt: GateAttempt): void {
    this.assertFailureCleanup(attempt);
    if (this.#state.kind !== "failure_cleanup_executing") {
      throw new Error("bootstrap failure-cleanup claim is not live");
    }
    this.#state = {
      kind: "failure_cleanup_pending",
      manifestDigest: attempt.manifestDigest,
      generation: attempt.generation,
      reason: this.#state.reason,
    };
  }

  completeFailureCleanup(attempt: GateAttempt): void {
    if (
      this.#state.kind === "failure_cleanup_executing" &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation &&
      this.#state.executionId === attempt.executionId
    ) {
      this.#state = {
        kind: "failed",
        manifestDigest: attempt.manifestDigest,
        generation: attempt.generation,
        reason: this.#state.reason,
      };
      return;
    }

    if (
      this.#state.kind === "failed" &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation
    ) {
      return;
    }

    throw new Error("bootstrap gate failure-cleanup CAS failed");
  }

  beginCleanup(manifestDigest: string): GateAttempt {
    if (
      (this.#state.kind !== "cleanup_pending" &&
        this.#state.kind !== "completed") ||
      this.#state.manifestDigest !== manifestDigest
    ) {
      throw new Error("bootstrap cleanup is not pending for this manifest");
    }
    return Object.freeze({
      manifestDigest,
      generation: this.#state.generation,
      executionId: 0,
    });
  }

  completeCleanup(attempt: GateAttempt): void {
    if (
      this.#state.kind === "cleanup_pending" &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation
    ) {
      this.#state = {
        kind: "completed",
        manifestDigest: attempt.manifestDigest,
        generation: attempt.generation,
      };
      return;
    }

    if (
      this.#state.kind === "completed" &&
      this.#state.manifestDigest === attempt.manifestDigest &&
      this.#state.generation === attempt.generation
    ) {
      return;
    }

    throw new Error("bootstrap gate completion CAS failed");
  }

  snapshot(): GateState {
    return this.#state;
  }
}

const systemActor: RoleAssignmentActor = Object.freeze({
  kind: "system",
  systemId: "operator-bootstrap",
});

const makeManifest = (
  overrides: Partial<{
    principalId: PrincipalId;
    role: string;
    assignmentId: string;
    auditEventId: string;
    failureCleanupAuditEventId: string;
    grantedAtEpochMs: number;
    environmentId: string;
    storageFingerprint: string;
    applicationId: string;
    policyVersion: string;
    requiredPermission: string;
  }> = {},
): BootstrapManifest =>
  Object.freeze({
    deployment: Object.freeze({
      environmentId: overrides.environmentId ?? "production",
      storageFingerprint:
        overrides.storageFingerprint ?? "azure-table:authorization-primary",
      applicationId: overrides.applicationId ?? "retiregolden",
    }),
    assignment: Object.freeze({
      id: overrides.assignmentId ?? "bootstrap-assignment-01",
      principalId: overrides.principalId ?? "account_administrator",
      role: overrides.role ?? "administrator",
      scope: Object.freeze({ kind: "application" as const }),
      grantedBy: systemActor,
      grantedAtEpochMs: overrides.grantedAtEpochMs ?? 1_800_000_000_000,
      status: "active" as const,
    }),
    auditEventId: overrides.auditEventId ?? "bootstrap-event-01",
    failureCleanupAuditEventId:
      overrides.failureCleanupAuditEventId ?? "bootstrap-failure-cleanup-01",
    policyVersion:
      overrides.policyVersion ?? "administrator-bootstrap-contract",
    requiredPermission: overrides.requiredPermission ?? "administration.access",
  });

const manifestDigest = (manifest: BootstrapManifest): string =>
  createHash("sha256")
    .update(
      JSON.stringify({
        environmentId: manifest.deployment.environmentId,
        storageFingerprint: manifest.deployment.storageFingerprint,
        applicationId: manifest.deployment.applicationId,
        assignmentId: manifest.assignment.id,
        principalId: manifest.assignment.principalId,
        role: manifest.assignment.role,
        scope: manifest.assignment.scope,
        grantedBy: manifest.assignment.grantedBy,
        grantedAtEpochMs: manifest.assignment.grantedAtEpochMs,
        auditEventId: manifest.auditEventId,
        failureCleanupAuditEventId: manifest.failureCleanupAuditEventId,
        policyVersion: manifest.policyVersion,
        requiredPermission: manifest.requiredPermission,
      }),
    )
    .digest("hex");

const grantFieldsEqual = (
  left: RoleAssignment,
  right: ActiveRoleAssignment,
): boolean =>
  left.id === right.id &&
  left.principalId === right.principalId &&
  left.role === right.role &&
  left.scope.kind === "application" &&
  right.scope.kind === "application" &&
  left.grantedBy.kind === "system" &&
  right.grantedBy.kind === "system" &&
  left.grantedBy.systemId === right.grantedBy.systemId &&
  left.grantedAtEpochMs === right.grantedAtEpochMs;

const assignmentsEqual = (
  left: ActiveRoleAssignment,
  right: ActiveRoleAssignment,
): boolean =>
  grantFieldsEqual(left, right) &&
  left.status === "active" &&
  right.status === "active";

const administratorPolicy: AccessPolicy = Object.freeze({
  version: "administrator-bootstrap-contract",
  roles: Object.freeze({
    administrator: Object.freeze(["administration.access"]),
  }),
});

const completedBootstrapCleanup: BootstrapCleanup = async () =>
  Object.freeze({
    authorityRemoved: true,
    credentialsRemoved: true,
  });

const resumeBootstrapCleanup = async (
  gate: TestOneShotGate,
  manifest: BootstrapManifest,
  cleanup: BootstrapCleanup,
): Promise<void> => {
  const attempt = gate.beginCleanup(manifestDigest(manifest));
  const result = await cleanup();
  if (!result.authorityRemoved || !result.credentialsRemoved) {
    throw new Error("bootstrap cleanup is not verified");
  }
  gate.completeCleanup(attempt);
};

const resumeBootstrapFailureCleanup = async (
  gate: TestOneShotGate,
  manifest: BootstrapManifest,
  cleanup: BootstrapFailureCleanup,
): Promise<void> => {
  const attempt = gate.beginFailureCleanup(manifestDigest(manifest));
  let result: Awaited<ReturnType<BootstrapFailureCleanup>>;
  try {
    result = await cleanup(attempt);
  } catch (error) {
    gate.releaseFailureCleanup(attempt);
    throw error;
  }
  if (
    !result.grantAbsentOrRevoked ||
    !result.authorityRemoved ||
    !result.credentialsRemoved
  ) {
    gate.releaseFailureCleanup(attempt);
    throw new Error("bootstrap failure cleanup is not verified");
  }
  gate.completeFailureCleanup(attempt);
};

const reconcileFailedBootstrapGrant = async (
  gate: TestOneShotGate,
  attempt: GateAttempt,
  storage: InMemoryStorageAdapter,
  manifest: BootstrapManifest,
): Promise<boolean> => {
  gate.assertFailureCleanup(attempt);
  const exact = await storage.getRoleAssignment(manifest.assignment.id);
  if (exact === null) {
    const orphanedHistory = await storage.listRoleAssignmentAuditEvents(
      manifest.assignment.id,
    );
    return orphanedHistory.length === 0;
  }
  if (!grantFieldsEqual(exact.assignment, manifest.assignment)) {
    return false;
  }
  const history = await storage.listRoleAssignmentAuditEvents(
    manifest.assignment.id,
  );
  const grant = history[0];
  if (
    grant?.sequence !== 1 ||
    grant.event.kind !== "granted" ||
    grant.event.id !== manifest.auditEventId ||
    !grantFieldsEqual(grant.event.assignment, manifest.assignment)
  ) {
    return false;
  }
  if (exact.assignment.status === "revoked") {
    const active = await storage.listActiveRoleAssignments(
      manifest.assignment.principalId,
      manifest.assignment.scope,
    );
    return !active.some(({ id }) => id === manifest.assignment.id);
  }

  gate.assertFailureCleanup(attempt);
  const result = await storage.revokeRoleAssignmentWithAudit({
    assignmentId: manifest.assignment.id,
    expectedConcurrencyToken: exact.concurrencyToken,
    revokedBy: { kind: "system", systemId: "bootstrap-failure-cleanup" },
    revokedAtEpochMs: manifest.assignment.grantedAtEpochMs,
    reason: "administrator bootstrap failed",
    auditEventId: manifest.failureCleanupAuditEventId,
  });
  if (result.status !== "revoked") return false;

  const durable = await storage.getRoleAssignment(manifest.assignment.id);
  const active = await storage.listActiveRoleAssignments(
    manifest.assignment.principalId,
    manifest.assignment.scope,
  );
  return (
    durable !== null &&
    durable.assignment.status === "revoked" &&
    grantFieldsEqual(durable.assignment, manifest.assignment) &&
    !active.some(({ id }) => id === manifest.assignment.id)
  );
};

/**
 * Executable test-local composition of the documented host procedure.
 *
 * Production must use a durable adapter and durable CAS gate. It must never
 * use createInMemoryStorageAdapter or copy this fixture as production code.
 */
const runOneShotAdministratorGrant = async (
  gate: TestOneShotGate,
  authoritativePrincipalIds: ReadonlySet<PrincipalId>,
  observedDeployment: DeploymentBinding,
  storage: InMemoryStorageAdapter,
  policy: AccessPolicy,
  manifest: BootstrapManifest,
  cleanup: BootstrapCleanup = completedBootstrapCleanup,
  loadCurrentPolicy: () => AccessPolicy = () => policy,
): Promise<AccessContext> => {
  const digest = manifestDigest(manifest);
  gate.assertArmed(digest);

  if (!authoritativePrincipalIds.has(manifest.assignment.principalId)) {
    throw new Error("authoritative host principal does not exist");
  }

  if (manifest.assignment.scope.kind !== "application") {
    throw new Error("administrator bootstrap requires application scope");
  }

  if (
    observedDeployment.environmentId !== manifest.deployment.environmentId ||
    observedDeployment.storageFingerprint !==
      manifest.deployment.storageFingerprint ||
    observedDeployment.applicationId !== manifest.deployment.applicationId
  ) {
    throw new Error("observed deployment does not match bootstrap manifest");
  }

  const exactRolePermissions =
    policy.roles !== undefined &&
    Object.hasOwn(policy.roles, manifest.assignment.role)
      ? policy.roles[manifest.assignment.role]
      : undefined;
  if (
    policy.version !== manifest.policyVersion ||
    exactRolePermissions === undefined ||
    !exactRolePermissions.includes(manifest.requiredPermission)
  ) {
    throw new Error(
      "manifest administrator role does not map to required permission",
    );
  }

  const attempt = gate.begin(digest);
  const result = await storage.grantRoleAssignmentWithAudit({
    assignment: manifest.assignment,
    auditEventId: manifest.auditEventId,
  });
  if (result.status === "conflict") {
    gate.fail(attempt, `role_storage_${result.reason}`);
    throw new Error(`bootstrap grant conflict: ${result.reason}`);
  }

  const exact = await storage.getRoleAssignment(manifest.assignment.id);
  if (
    exact === null ||
    exact.assignment.status !== "active" ||
    !assignmentsEqual(exact.assignment, manifest.assignment)
  ) {
    gate.fail(attempt, "assignment_readback");
    throw new Error("bootstrap assignment readback is not exact and active");
  }

  const history = await storage.listRoleAssignmentAuditEvents(
    manifest.assignment.id,
  );
  if (
    history.length !== 1 ||
    history[0]?.sequence !== 1 ||
    history[0].event.kind !== "granted" ||
    history[0].event.id !== manifest.auditEventId ||
    !assignmentsEqual(history[0].event.assignment, manifest.assignment)
  ) {
    gate.fail(attempt, "audit_readback");
    throw new Error("bootstrap audit readback is not the exact grant");
  }

  const active = await storage.listActiveRoleAssignments(
    manifest.assignment.principalId,
    manifest.assignment.scope,
  );
  const matching = active.filter((candidate) =>
    assignmentsEqual(candidate, manifest.assignment),
  );
  if (matching.length !== 1) {
    gate.fail(attempt, "active_selection_readback");
    throw new Error("bootstrap active selection readback is not exact");
  }

  const currentPolicy = loadCurrentPolicy();
  if (!authoritativePrincipalIds.has(manifest.assignment.principalId)) {
    gate.fail(attempt, "authoritative_principal_revalidation");
    throw new Error("authoritative host principal is no longer active");
  }
  const currentRolePermissions =
    currentPolicy.roles !== undefined &&
    Object.hasOwn(currentPolicy.roles, manifest.assignment.role)
      ? currentPolicy.roles[manifest.assignment.role]
      : undefined;
  if (
    currentPolicy.version !== manifest.policyVersion ||
    currentRolePermissions === undefined ||
    !currentRolePermissions.includes(manifest.requiredPermission)
  ) {
    gate.fail(attempt, "authoritative_policy_revalidation");
    throw new Error("authoritative policy changed during bootstrap");
  }

  const subject: AccessSubject = Object.freeze({
    principalId: manifest.assignment.principalId,
    roles: Object.freeze(active.map(({ role }) => role)),
  });
  const context = resolveAccess(subject, currentPolicy);
  if (!context.permissions.includes(manifest.requiredPermission)) {
    gate.fail(attempt, "policy_resolution_readback");
    throw new Error("administrator policy permission was not resolved");
  }

  gate.markCleanupPending(attempt);
  await resumeBootstrapCleanup(gate, manifest, cleanup);
  return context;
};

const arm = (gate: TestOneShotGate, manifest: BootstrapManifest): void =>
  gate.arm(manifestDigest(manifest));

const observedDeploymentFor = (
  manifest: BootstrapManifest,
): DeploymentBinding =>
  Object.freeze({
    environmentId: manifest.deployment.environmentId,
    storageFingerprint: manifest.deployment.storageFingerprint,
    applicationId: manifest.deployment.applicationId,
  });

describe("administrator bootstrap host composition", () => {
  it("grants the exact application administrator and verifies policy mapping", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(gate, manifest);

    const context = await runOneShotAdministratorGrant(
      gate,
      new Set([manifest.assignment.principalId]),
      observedDeploymentFor(manifest),
      storage,
      administratorPolicy,
      manifest,
    );

    expect(context).toEqual({
      principalId: "account_administrator",
      policyVersion: "administrator-bootstrap-contract",
      roles: ["administrator"],
      entitlements: [],
      permissions: ["administration.access"],
    });
    expect(gate.snapshot()).toEqual({
      kind: "completed",
      manifestDigest: manifestDigest(manifest),
      generation: 1,
    });
  });

  it("fences expired work and serializes concurrent same-manifest runs", async () => {
    const storage = createInMemoryStorageAdapter();
    const crashGate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(crashGate, manifest);

    const lostAttempt = crashGate.begin(manifestDigest(manifest));
    // Models a committed write followed by response loss under the first claim.
    await storage.grantRoleAssignmentWithAudit({
      assignment: manifest.assignment,
      auditEventId: manifest.auditEventId,
    });
    crashGate.recoverExpiredExecution(lostAttempt, true, true);
    expect(() => crashGate.markCleanupPending(lostAttempt)).toThrow(
      "bootstrap gate cleanup-pending CAS failed",
    );
    await expect(
      runOneShotAdministratorGrant(
        crashGate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).resolves.toMatchObject({ permissions: ["administration.access"] });
    await expect(
      storage.listRoleAssignmentAuditEvents(manifest.assignment.id),
    ).resolves.toHaveLength(1);

    const concurrentStorage = createInMemoryStorageAdapter();
    const concurrentGate = new TestOneShotGate();
    arm(concurrentGate, manifest);
    const outcomes = await Promise.allSettled([
      runOneShotAdministratorGrant(
        concurrentGate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        concurrentStorage,
        administratorPolicy,
        manifest,
      ),
      runOneShotAdministratorGrant(
        concurrentGate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        concurrentStorage,
        administratorPolicy,
        manifest,
      ),
    ]);
    expect(
      outcomes.filter(({ status }) => status === "fulfilled"),
    ).toHaveLength(1);
    expect(outcomes.filter(({ status }) => status === "rejected")).toHaveLength(
      1,
    );
    await expect(
      concurrentStorage.listRoleAssignmentAuditEvents(manifest.assignment.id),
    ).resolves.toHaveLength(1);
  });

  it("resumes cleanup after verification without replaying the role grant", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(gate, manifest);

    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
        async () => ({
          authorityRemoved: false,
          credentialsRemoved: false,
        }),
      ),
    ).rejects.toThrow("bootstrap cleanup is not verified");
    expect(gate.snapshot()).toEqual({
      kind: "cleanup_pending",
      manifestDigest: manifestDigest(manifest),
      generation: 1,
    });
    await expect(
      storage.listRoleAssignmentAuditEvents(manifest.assignment.id),
    ).resolves.toHaveLength(1);
    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).rejects.toThrow("bootstrap gate is not armed for this exact manifest");

    await resumeBootstrapCleanup(gate, manifest, completedBootstrapCleanup);
    expect(gate.snapshot()).toEqual({
      kind: "completed",
      manifestDigest: manifestDigest(manifest),
      generation: 1,
    });
    await expect(
      storage.listRoleAssignmentAuditEvents(manifest.assignment.id),
    ).resolves.toHaveLength(1);
  });

  it("revokes a possibly committed grant before terminal failure", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest({
      grantedAtEpochMs: Number.MAX_SAFE_INTEGER,
    });
    arm(gate, manifest);
    await storage.grantRoleAssignmentWithAudit({
      assignment: manifest.assignment,
      auditEventId: manifest.auditEventId,
    });

    gate.fail(gate.begin(manifestDigest(manifest)), "contradictory_readback");
    await expect(
      resumeBootstrapFailureCleanup(gate, manifest, async () => ({
        grantAbsentOrRevoked: false,
        authorityRemoved: false,
        credentialsRemoved: false,
      })),
    ).rejects.toThrow("bootstrap failure cleanup is not verified");
    expect(gate.snapshot()).toMatchObject({
      kind: "failure_cleanup_pending",
      reason: "contradictory_readback",
    });
    await expect(
      resumeBootstrapFailureCleanup(gate, manifest, async (cleanupAttempt) => {
        await expect(
          runOneShotAdministratorGrant(
            gate,
            new Set([manifest.assignment.principalId]),
            observedDeploymentFor(manifest),
            storage,
            administratorPolicy,
            manifest,
          ),
        ).rejects.toThrow(
          "bootstrap gate is not armed for this exact manifest",
        );
        return {
          grantAbsentOrRevoked: await reconcileFailedBootstrapGrant(
            gate,
            cleanupAttempt,
            storage,
            manifest,
          ),
          authorityRemoved: true,
          credentialsRemoved: true,
        };
      }),
    ).resolves.toBeUndefined();

    expect(gate.snapshot()).toEqual({
      kind: "failed",
      manifestDigest: manifestDigest(manifest),
      generation: 1,
      reason: "contradictory_readback",
    });
    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toMatchObject({ assignment: { status: "revoked" } });
    await expect(
      storage.listRoleAssignmentAuditEvents(manifest.assignment.id),
    ).resolves.toHaveLength(2);
    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).rejects.toThrow("bootstrap gate is not armed for this exact manifest");
  });

  it("quarantines a revoked lifecycle with contradictory grant fields", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    const contradictory = makeManifest({
      principalId: "account_other",
      auditEventId: "contradictory-grant-event",
    });
    const grant = await storage.grantRoleAssignmentWithAudit({
      assignment: contradictory.assignment,
      auditEventId: contradictory.auditEventId,
    });
    if (grant.status === "conflict") {
      throw new Error("expected contradictory lifecycle fixture to be granted");
    }
    await storage.revokeRoleAssignmentWithAudit({
      assignmentId: contradictory.assignment.id,
      expectedConcurrencyToken: grant.record.concurrencyToken,
      revokedBy: { kind: "system", systemId: "fixture-revoker" },
      revokedAtEpochMs: contradictory.assignment.grantedAtEpochMs + 1,
      auditEventId: "contradictory-revoke-event",
    });
    arm(gate, manifest);
    gate.fail(gate.begin(manifestDigest(manifest)), "contradictory_readback");

    await expect(
      resumeBootstrapFailureCleanup(gate, manifest, async (cleanupAttempt) => ({
        grantAbsentOrRevoked: await reconcileFailedBootstrapGrant(
          gate,
          cleanupAttempt,
          storage,
          manifest,
        ),
        authorityRemoved: true,
        credentialsRemoved: true,
      })),
    ).rejects.toThrow("bootstrap failure cleanup is not verified");
    expect(gate.snapshot()).toMatchObject({
      kind: "failure_cleanup_pending",
      reason: "contradictory_readback",
    });
  });

  it("quarantines a lifecycle with a mismatched grant audit ID", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    const grant = await storage.grantRoleAssignmentWithAudit({
      assignment: manifest.assignment,
      auditEventId: "unrelated-grant-event",
    });
    if (grant.status === "conflict") {
      throw new Error("expected audit mismatch fixture to be granted");
    }
    await storage.revokeRoleAssignmentWithAudit({
      assignmentId: manifest.assignment.id,
      expectedConcurrencyToken: grant.record.concurrencyToken,
      revokedBy: { kind: "system", systemId: "fixture-revoker" },
      revokedAtEpochMs: manifest.assignment.grantedAtEpochMs,
      auditEventId: "unrelated-revoke-event",
    });
    arm(gate, manifest);
    gate.fail(gate.begin(manifestDigest(manifest)), "grant_audit_mismatch");

    await expect(
      resumeBootstrapFailureCleanup(gate, manifest, async (cleanupAttempt) => ({
        grantAbsentOrRevoked: await reconcileFailedBootstrapGrant(
          gate,
          cleanupAttempt,
          storage,
          manifest,
        ),
        authorityRemoved: true,
        credentialsRemoved: true,
      })),
    ).rejects.toThrow("bootstrap failure cleanup is not verified");
    expect(gate.snapshot()).toMatchObject({
      kind: "failure_cleanup_pending",
      reason: "grant_audit_mismatch",
    });
  });

  it("refuses an absent authoritative principal before storage mutation", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(gate, manifest);

    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set(),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).rejects.toThrow("authoritative host principal does not exist");
    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();
    expect(gate.snapshot()).toMatchObject({ kind: "armed" });
  });

  it("refuses a gate installed after administrator grant authority", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate({ kind: "disabled" }, false);
    const manifest = makeManifest();

    expect(() => arm(gate, manifest)).toThrow(
      "bootstrap gate was not installed before administrator grant authority",
    );
    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();
    expect(gate.snapshot()).toEqual({ kind: "disabled" });
  });

  it("rejects observed deployment mismatches before storage mutation", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(gate, manifest);

    const mismatchedBindings: readonly DeploymentBinding[] = [
      { ...observedDeploymentFor(manifest), environmentId: "staging" },
      {
        ...observedDeploymentFor(manifest),
        storageFingerprint: "azure-table:authorization-secondary",
      },
      {
        ...observedDeploymentFor(manifest),
        applicationId: "other-application",
      },
    ];

    for (const observedDeployment of mismatchedBindings) {
      await expect(
        runOneShotAdministratorGrant(
          gate,
          new Set([manifest.assignment.principalId]),
          observedDeployment,
          storage,
          administratorPolicy,
          manifest,
        ),
      ).rejects.toThrow(
        "observed deployment does not match bootstrap manifest",
      );
    }

    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();
    expect(gate.snapshot()).toMatchObject({ kind: "armed" });
  });

  it("rejects organization scope before storage mutation", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const base = makeManifest();
    const manifest: BootstrapManifest = Object.freeze({
      ...base,
      assignment: Object.freeze({
        ...base.assignment,
        scope: Object.freeze({
          kind: "organization",
          organizationId: "organization_alpha",
        }),
      }),
    });
    arm(gate, manifest);

    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).rejects.toThrow("administrator bootstrap requires application scope");
    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();
    expect(gate.snapshot()).toMatchObject({ kind: "armed" });
  });

  it("isolates exact principals and application scope", async () => {
    const storage = createInMemoryStorageAdapter();
    await storage.grantRoleAssignmentWithAudit({
      assignment: {
        ...makeManifest({
          principalId: "account_other",
          assignmentId: "other-principal",
          role: "support",
        }).assignment,
      },
      auditEventId: "other-principal-event",
    });
    await storage.grantRoleAssignmentWithAudit({
      assignment: {
        ...makeManifest({
          assignmentId: "other-scope",
          role: "support",
        }).assignment,
        scope: { kind: "organization", organizationId: "organization_alpha" },
      },
      auditEventId: "other-scope-event",
    });

    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(gate, manifest);
    const context = await runOneShotAdministratorGrant(
      gate,
      new Set([manifest.assignment.principalId]),
      observedDeploymentFor(manifest),
      storage,
      administratorPolicy,
      manifest,
    );

    expect(context.roles).toEqual(["administrator"]);
    await expect(
      storage.listActiveRoleAssignments("account_other", {
        kind: "application",
      }),
    ).resolves.toHaveLength(1);
    await expect(
      storage.listActiveRoleAssignments(manifest.assignment.principalId, {
        kind: "organization",
        organizationId: "organization_alpha",
      }),
    ).resolves.toMatchObject([{ role: "support" }]);
  });

  it("fails closed on role tuple conflicts", async () => {
    const storage = createInMemoryStorageAdapter();
    const manifest = makeManifest();
    await storage.grantRoleAssignmentWithAudit({
      assignment: {
        ...manifest.assignment,
        id: "existing-different-assignment",
      },
      auditEventId: "existing-different-event",
    });
    const gate = new TestOneShotGate();
    arm(gate, manifest);

    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).rejects.toThrow("bootstrap grant conflict: active_tuple");
    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();
    expect(gate.snapshot()).toEqual({
      kind: "failure_cleanup_pending",
      manifestDigest: manifestDigest(manifest),
      generation: 1,
      reason: "role_storage_active_tuple",
    });
    await resumeBootstrapFailureCleanup(
      gate,
      manifest,
      async (cleanupAttempt) => ({
        grantAbsentOrRevoked: await reconcileFailedBootstrapGrant(
          gate,
          cleanupAttempt,
          storage,
          manifest,
        ),
        authorityRemoved: true,
        credentialsRemoved: true,
      }),
    );
    expect(gate.snapshot()).toEqual({
      kind: "failed",
      manifestDigest: manifestDigest(manifest),
      generation: 1,
      reason: "role_storage_active_tuple",
    });

    const existing = await storage.getRoleAssignment(
      "existing-different-assignment",
    );
    if (existing === null) throw new Error("expected conflicting assignment");
    await storage.revokeRoleAssignmentWithAudit({
      assignmentId: existing.assignment.id,
      expectedConcurrencyToken: existing.concurrencyToken,
      revokedBy: { kind: "system", systemId: "conflict-removal" },
      revokedAtEpochMs: existing.assignment.grantedAtEpochMs + 1,
      auditEventId: "existing-different-revoke",
    });
    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).rejects.toThrow("bootstrap gate is not armed for this exact manifest");
    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();
  });

  it("rejects revoked exact replay and recovers only with fresh IDs", async () => {
    const storage = createInMemoryStorageAdapter();
    const first = makeManifest();
    const bootstrapGate = new TestOneShotGate();
    arm(bootstrapGate, first);

    // Models a committed bootstrap grant that was revoked before an ambiguous
    // attempt could reconcile and complete its still-armed gate.
    await storage.grantRoleAssignmentWithAudit({
      assignment: first.assignment,
      auditEventId: first.auditEventId,
    });
    const versioned = await storage.getRoleAssignment(first.assignment.id);
    if (versioned === null) throw new Error("expected bootstrap assignment");
    await storage.revokeRoleAssignmentWithAudit({
      assignmentId: first.assignment.id,
      expectedConcurrencyToken: versioned.concurrencyToken,
      revokedBy: { kind: "system", systemId: "access-revocation" },
      revokedAtEpochMs: first.assignment.grantedAtEpochMs + 1,
      auditEventId: "bootstrap-revoke-01",
    });

    await expect(
      runOneShotAdministratorGrant(
        bootstrapGate,
        new Set([first.assignment.principalId]),
        observedDeploymentFor(first),
        storage,
        administratorPolicy,
        first,
      ),
    ).rejects.toThrow("bootstrap assignment readback is not exact and active");
    expect(bootstrapGate.snapshot()).toEqual({
      kind: "failure_cleanup_pending",
      manifestDigest: manifestDigest(first),
      generation: 1,
      reason: "assignment_readback",
    });
    await resumeBootstrapFailureCleanup(
      bootstrapGate,
      first,
      async (cleanupAttempt) => ({
        grantAbsentOrRevoked: await reconcileFailedBootstrapGrant(
          bootstrapGate,
          cleanupAttempt,
          storage,
          first,
        ),
        authorityRemoved: true,
        credentialsRemoved: true,
      }),
    );
    expect(bootstrapGate.snapshot()).toEqual({
      kind: "failed",
      manifestDigest: manifestDigest(first),
      generation: 1,
      reason: "assignment_readback",
    });

    const fresh = makeManifest({
      assignmentId: "bootstrap-assignment-02",
      auditEventId: "bootstrap-event-02",
      failureCleanupAuditEventId: "bootstrap-failure-cleanup-02",
      grantedAtEpochMs: first.assignment.grantedAtEpochMs + 2,
    });
    // Recovery is a separately approved break-glass authority. It never resets
    // or re-arms bootstrap, whether bootstrap remained armed after ambiguity
    // or had already completed.
    const breakGlassAuthorization = new TestOneShotGate();
    arm(breakGlassAuthorization, fresh);
    await expect(
      runOneShotAdministratorGrant(
        breakGlassAuthorization,
        new Set([fresh.assignment.principalId]),
        observedDeploymentFor(fresh),
        storage,
        administratorPolicy,
        fresh,
      ),
    ).resolves.toMatchObject({ permissions: ["administration.access"] });
  });

  it("revalidates the authoritative principal before cleanup", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    const principals = new Set([manifest.assignment.principalId]);
    arm(gate, manifest);

    await expect(
      runOneShotAdministratorGrant(
        gate,
        principals,
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
        completedBootstrapCleanup,
        () => {
          principals.delete(manifest.assignment.principalId);
          return administratorPolicy;
        },
      ),
    ).rejects.toThrow("authoritative host principal is no longer active");
    expect(gate.snapshot()).toMatchObject({
      kind: "failure_cleanup_pending",
      reason: "authoritative_principal_revalidation",
    });
  });

  it("revalidates the manifest policy version before cleanup", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(gate, manifest);

    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
        completedBootstrapCleanup,
        () => ({
          version: "administrator-policy-replaced",
          roles: { administrator: [] },
        }),
      ),
    ).rejects.toThrow("authoritative policy changed during bootstrap");
    expect(gate.snapshot()).toMatchObject({
      kind: "failure_cleanup_pending",
      reason: "authoritative_policy_revalidation",
    });
  });

  it("requires the exact manifest role to supply the required permission", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest({
      role: "future-administrator",
      requiredPermission: "administration.access",
    });
    await storage.grantRoleAssignmentWithAudit({
      assignment: makeManifest({
        assignmentId: "unrelated-administrator",
      }).assignment,
      auditEventId: "unrelated-administrator-event",
    });
    arm(gate, manifest);

    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        storage,
        administratorPolicy,
        manifest,
      ),
    ).rejects.toThrow(
      "manifest administrator role does not map to required permission",
    );
    expect(gate.snapshot()).toMatchObject({ kind: "armed" });
    await expect(
      storage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();

    const defaultStorage = createInMemoryStorageAdapter();
    const defaultGate = new TestOneShotGate();
    arm(defaultGate, manifest);
    await expect(
      runOneShotAdministratorGrant(
        defaultGate,
        new Set([manifest.assignment.principalId]),
        observedDeploymentFor(manifest),
        defaultStorage,
        {
          version: "administrator-bootstrap-default-negative-control",
          defaults: ["administration.access"],
        },
        manifest,
      ),
    ).rejects.toThrow(
      "manifest administrator role does not map to required permission",
    );
    expect(defaultGate.snapshot()).toMatchObject({ kind: "armed" });
    await expect(
      defaultStorage.getRoleAssignment(manifest.assignment.id),
    ).resolves.toBeNull();
  });

  it("keeps bootstrap metadata out of AccessSubject and AccessContext", async () => {
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    const manifest = makeManifest();
    arm(gate, manifest);
    const context = await runOneShotAdministratorGrant(
      gate,
      new Set([manifest.assignment.principalId]),
      observedDeploymentFor(manifest),
      storage,
      administratorPolicy,
      manifest,
    );

    expect(context).not.toHaveProperty("assignmentId");
    expect(context).not.toHaveProperty("auditEventId");
    expect(context).not.toHaveProperty("scope");
    expect(context).not.toHaveProperty("grantedBy");
    expect(context).not.toHaveProperty("environmentId");
    expect(context).not.toHaveProperty("storageFingerprint");
  });

  it("rejects other manifests and disabled, unknown, or completed gates before mutation", async () => {
    const reviewed = makeManifest();
    const storage = createInMemoryStorageAdapter();
    const gate = new TestOneShotGate();
    arm(gate, reviewed);

    const otherPrincipal = makeManifest({ principalId: "account_other" });
    const otherScope: BootstrapManifest = Object.freeze({
      ...reviewed,
      assignment: Object.freeze({
        ...reviewed.assignment,
        scope: Object.freeze({
          kind: "organization",
          organizationId: "organization_alpha",
        }),
      }),
    });
    const otherManifests = [
      otherPrincipal,
      makeManifest({ role: "other-administrator-role" }),
      makeManifest({ environmentId: "staging" }),
      makeManifest({ storageFingerprint: "azure-table:other" }),
      makeManifest({ applicationId: "other-application" }),
      otherScope,
    ];

    for (const other of otherManifests) {
      await expect(
        runOneShotAdministratorGrant(
          gate,
          new Set([other.assignment.principalId]),
          observedDeploymentFor(other),
          storage,
          administratorPolicy,
          other,
        ),
      ).rejects.toThrow("bootstrap gate is not armed for this exact manifest");
    }
    await expect(
      storage.getRoleAssignment(reviewed.assignment.id),
    ).resolves.toBeNull();

    for (const closedGate of [
      new TestOneShotGate(),
      new TestOneShotGate({ kind: "unknown" }),
    ]) {
      await expect(
        runOneShotAdministratorGrant(
          closedGate,
          new Set([reviewed.assignment.principalId]),
          observedDeploymentFor(reviewed),
          storage,
          administratorPolicy,
          reviewed,
        ),
      ).rejects.toThrow("bootstrap gate is not armed for this exact manifest");
    }

    await runOneShotAdministratorGrant(
      gate,
      new Set([reviewed.assignment.principalId]),
      observedDeploymentFor(reviewed),
      storage,
      administratorPolicy,
      reviewed,
    );
    await expect(
      runOneShotAdministratorGrant(
        gate,
        new Set([reviewed.assignment.principalId]),
        observedDeploymentFor(reviewed),
        storage,
        administratorPolicy,
        reviewed,
      ),
    ).rejects.toThrow("bootstrap gate is not armed for this exact manifest");
    expect(() => gate.arm(manifestDigest(reviewed))).toThrow(
      "bootstrap gate cannot be armed from its current state",
    );
  });
});
