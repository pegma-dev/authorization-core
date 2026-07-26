import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  AccessContext,
  AccessSubject,
  ActiveRoleAssignment,
  IdentityAdapter,
  IdentityLinkKey,
  PrincipalId,
  RevokedRoleAssignment,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentId,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import { resolveAccess } from "@pegma/authorization-core";
import type {
  AppendRoleAssignmentAuditEventResult,
  CreateRoleAssignmentResult,
  PrincipalLookupStore,
  RevokeRoleAssignmentCommand,
  RevokeRoleAssignmentResult,
  RoleAssignmentAuditEvent,
  RoleAssignmentAuditEventId,
  RoleAssignmentAuditStore,
  RoleAssignmentConcurrencyToken,
  RoleAssignmentStore,
  SequencedRoleAssignmentAuditEvent,
  VersionedRoleAssignment,
} from "@pegma/authorization-storage";

const principalId = "principal_alpha";
const otherPrincipalId = "principal_beta";
const applicationScope: RoleAssignmentScope = { kind: "application" };
const organizationAlphaScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId: "organization_alpha",
};
const organizationBetaScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId: "organization_beta",
};
const grantor: RoleAssignmentActor = {
  kind: "principal",
  principalId: "principal_admin",
};
const revoker: RoleAssignmentActor = {
  kind: "system",
  systemId: "role-administration",
};

const scopesEqual = (
  left: RoleAssignmentScope,
  right: RoleAssignmentScope,
): boolean =>
  left.kind === "application"
    ? right.kind === "application"
    : right.kind === "organization" &&
      left.organizationId === right.organizationId;

const actorsEqual = (
  left: RoleAssignmentActor,
  right: RoleAssignmentActor,
): boolean =>
  left.kind === "principal"
    ? right.kind === "principal" && left.principalId === right.principalId
    : right.kind === "system" && left.systemId === right.systemId;

const grantsEqual = (
  left: RoleAssignment,
  right: ActiveRoleAssignment,
): boolean =>
  left.id === right.id &&
  left.principalId === right.principalId &&
  left.role === right.role &&
  scopesEqual(left.scope, right.scope) &&
  actorsEqual(left.grantedBy, right.grantedBy) &&
  left.grantedAtEpochMs === right.grantedAtEpochMs;

const revocationsEqual = (
  assignment: RevokedRoleAssignment,
  command: RevokeRoleAssignmentCommand,
): boolean =>
  actorsEqual(assignment.revokedBy, command.revokedBy) &&
  assignment.revokedAtEpochMs === command.revokedAtEpochMs &&
  assignment.reason === command.reason;

const assignmentsEqual = (
  left: RoleAssignment,
  right: RoleAssignment,
): boolean => {
  if (!grantsEqual(left, { ...right, status: "active" })) {
    return false;
  }
  if (left.status !== right.status) {
    return false;
  }
  return left.status === "active"
    ? true
    : right.status === "revoked" &&
        actorsEqual(left.revokedBy, right.revokedBy) &&
        left.revokedAtEpochMs === right.revokedAtEpochMs &&
        left.reason === right.reason;
};

const eventsEqual = (
  left: RoleAssignmentAuditEvent,
  right: RoleAssignmentAuditEvent,
): boolean =>
  left.id === right.id &&
  left.kind === right.kind &&
  assignmentsEqual(left.assignment, right.assignment);

const cloneAssignment = (assignment: RoleAssignment): RoleAssignment =>
  assignment.status === "active"
    ? {
        ...assignment,
        scope: { ...assignment.scope },
        grantedBy: { ...assignment.grantedBy },
      }
    : {
        ...assignment,
        scope: { ...assignment.scope },
        grantedBy: { ...assignment.grantedBy },
        revokedBy: { ...assignment.revokedBy },
      };

const cloneActiveAssignment = (
  assignment: ActiveRoleAssignment,
): ActiveRoleAssignment => ({
  ...assignment,
  scope: { ...assignment.scope },
  grantedBy: { ...assignment.grantedBy },
});

class TestPrincipalLookupStore implements PrincipalLookupStore {
  readonly #links = new Map<string, Map<string, PrincipalId>>();
  failReads = false;

  link(key: IdentityLinkKey, linkedPrincipalId: PrincipalId): void {
    const subjects =
      this.#links.get(key.issuer) ?? new Map<string, PrincipalId>();
    subjects.set(key.subject, linkedPrincipalId);
    this.#links.set(key.issuer, subjects);
  }

  async resolvePrincipalId(key: IdentityLinkKey): Promise<PrincipalId | null> {
    if (this.failReads) {
      throw new Error("identity lookup unavailable");
    }
    return this.#links.get(key.issuer)?.get(key.subject) ?? null;
  }
}

class TestRoleAssignmentStore implements RoleAssignmentStore {
  readonly #records = new Map<RoleAssignmentId, VersionedRoleAssignment>();
  #nextToken = 1;
  failReads = false;

  async getRoleAssignment(
    assignmentId: RoleAssignmentId,
  ): Promise<VersionedRoleAssignment | null> {
    this.#requireReadable();
    return this.#records.get(assignmentId) ?? null;
  }

  async listActiveRoleAssignments(
    selectedPrincipalId: PrincipalId,
    selectedScope: RoleAssignmentScope,
  ): Promise<readonly ActiveRoleAssignment[]> {
    this.#requireReadable();
    return [...this.#records.values()]
      .map(({ assignment }) => assignment)
      .filter(
        (assignment): assignment is ActiveRoleAssignment =>
          assignment.status === "active" &&
          assignment.principalId === selectedPrincipalId &&
          scopesEqual(assignment.scope, selectedScope),
      )
      .map((assignment) => cloneAssignment(assignment) as ActiveRoleAssignment);
  }

  async createRoleAssignment(
    assignment: ActiveRoleAssignment,
  ): Promise<CreateRoleAssignmentResult> {
    const existing = this.#records.get(assignment.id);
    if (existing !== undefined) {
      return grantsEqual(existing.assignment, assignment)
        ? { status: "unchanged", record: existing }
        : { status: "conflict", reason: "assignment_id" };
    }

    if (
      [...this.#records.values()].some(
        ({ assignment: candidate }) =>
          candidate.status === "active" &&
          candidate.principalId === assignment.principalId &&
          candidate.role === assignment.role &&
          scopesEqual(candidate.scope, assignment.scope),
      )
    ) {
      return { status: "conflict", reason: "active_tuple" };
    }

    const record = this.#version(cloneActiveAssignment(assignment));
    this.#records.set(assignment.id, record);
    return { status: "created", record };
  }

  async revokeRoleAssignment(
    command: RevokeRoleAssignmentCommand,
  ): Promise<RevokeRoleAssignmentResult> {
    const existing = this.#records.get(command.assignmentId);
    if (existing === undefined) {
      return { status: "not_found" };
    }
    if (existing.assignment.status === "revoked") {
      const revokedRecord: VersionedRoleAssignment<RevokedRoleAssignment> = {
        assignment: existing.assignment,
        concurrencyToken: existing.concurrencyToken,
      };
      return revocationsEqual(existing.assignment, command)
        ? { status: "unchanged", record: revokedRecord }
        : { status: "conflict", reason: "lifecycle" };
    }
    if (existing.concurrencyToken !== command.expectedConcurrencyToken) {
      return { status: "conflict", reason: "concurrency" };
    }
    if (command.revokedAtEpochMs < existing.assignment.grantedAtEpochMs) {
      return { status: "conflict", reason: "lifecycle" };
    }

    const revoked: RevokedRoleAssignment = {
      ...existing.assignment,
      status: "revoked",
      revokedBy: { ...command.revokedBy },
      revokedAtEpochMs: command.revokedAtEpochMs,
      ...(command.reason === undefined ? {} : { reason: command.reason }),
    };
    const record = this.#version(revoked);
    this.#records.set(command.assignmentId, record);
    return { status: "revoked", record };
  }

  #requireReadable(): void {
    if (this.failReads) {
      throw new Error("role assignment read unavailable");
    }
  }

  #version<Assignment extends RoleAssignment>(
    assignment: Assignment,
  ): VersionedRoleAssignment<Assignment> {
    const concurrencyToken: RoleAssignmentConcurrencyToken = `version_${this.#nextToken}`;
    this.#nextToken += 1;
    return { assignment, concurrencyToken };
  }
}

class TestRoleAssignmentAuditStore implements RoleAssignmentAuditStore {
  readonly #byAssignment = new Map<
    RoleAssignmentId,
    SequencedRoleAssignmentAuditEvent[]
  >();
  readonly #byEventId = new Map<
    RoleAssignmentAuditEventId,
    SequencedRoleAssignmentAuditEvent
  >();
  failAppends = false;
  failReads = false;

  async appendRoleAssignmentAuditEvent(
    event: RoleAssignmentAuditEvent,
  ): Promise<AppendRoleAssignmentAuditEventResult> {
    if (this.failAppends) {
      throw new Error("audit append unavailable");
    }
    const existing = this.#byEventId.get(event.id);
    if (existing !== undefined) {
      return eventsEqual(existing.event, event)
        ? { status: "unchanged", record: existing }
        : { status: "conflict", reason: "event_id" };
    }

    const assignmentId = event.assignment.id;
    const history = this.#byAssignment.get(assignmentId) ?? [];
    const expectedKind = history.length === 0 ? "granted" : "revoked";
    if (
      event.kind !== expectedKind ||
      history.length >= 2 ||
      (event.kind === "revoked" &&
        !grantsEqual(event.assignment, {
          ...history[0]!.event.assignment,
          status: "active",
        }))
    ) {
      return { status: "conflict", reason: "lifecycle_position" };
    }

    const record: SequencedRoleAssignmentAuditEvent = {
      sequence: history.length + 1,
      event: {
        ...event,
        assignment: cloneAssignment(event.assignment),
      } as RoleAssignmentAuditEvent,
    };
    history.push(record);
    this.#byAssignment.set(assignmentId, history);
    this.#byEventId.set(event.id, record);
    return { status: "appended", record };
  }

  async listRoleAssignmentAuditEvents(
    assignmentId: RoleAssignmentId,
  ): Promise<readonly SequencedRoleAssignmentAuditEvent[]> {
    if (this.failReads) {
      throw new Error("audit read unavailable");
    }
    return [...(this.#byAssignment.get(assignmentId) ?? [])];
  }
}

const activeAssignment = (
  id: RoleAssignmentId,
  overrides: Partial<ActiveRoleAssignment> = {},
): ActiveRoleAssignment => ({
  id,
  principalId,
  role: "support",
  scope: applicationScope,
  grantedBy: grantor,
  grantedAtEpochMs: 1_700_000_000_000,
  status: "active",
  ...overrides,
});

const requireRecord = (
  result: CreateRoleAssignmentResult,
): VersionedRoleAssignment => {
  if (result.status === "conflict") {
    throw new Error("expected role assignment record");
  }
  return result.record;
};

describe("PrincipalLookupStore conformance", () => {
  it("is structurally compatible with IdentityAdapter and looks up exact delimiter-safe keys", async () => {
    expectTypeOf<PrincipalLookupStore>().toMatchTypeOf<IdentityAdapter>();
    const store = new TestPrincipalLookupStore();
    store.link({ issuer: "a|b", subject: "c" }, principalId);
    store.link({ issuer: "a", subject: "b|c" }, otherPrincipalId);

    await expect(
      store.resolvePrincipalId({ issuer: "a|b", subject: "c" }),
    ).resolves.toBe(principalId);
    await expect(
      store.resolvePrincipalId({ issuer: "a", subject: "b|c" }),
    ).resolves.toBe(otherPrincipalId);
    await expect(
      store.resolvePrincipalId({ issuer: "A|b", subject: "c" }),
    ).resolves.toBeNull();
    await expect(
      store.resolvePrincipalId({ issuer: "a|b", subject: "C" }),
    ).resolves.toBeNull();
  });

  it("distinguishes definitive absence from operational failure", async () => {
    const store = new TestPrincipalLookupStore();
    await expect(
      store.resolvePrincipalId({ issuer: "issuer", subject: "absent" }),
    ).resolves.toBeNull();
    store.failReads = true;
    await expect(
      store.resolvePrincipalId({ issuer: "issuer", subject: "absent" }),
    ).rejects.toThrow("identity lookup unavailable");
  });
});

describe("RoleAssignmentStore conformance", () => {
  it("narrows successful revoke records to revoked lifecycle evidence", () => {
    type SuccessfulRevokeResult = Exclude<
      RevokeRoleAssignmentResult,
      { readonly status: "not_found" | "conflict" }
    >;
    type CreatedResult = Extract<
      CreateRoleAssignmentResult,
      { readonly status: "created" }
    >;
    type UnchangedCreateResult = Extract<
      CreateRoleAssignmentResult,
      { readonly status: "unchanged" }
    >;

    expectTypeOf<
      SuccessfulRevokeResult["record"]["assignment"]
    >().toEqualTypeOf<RevokedRoleAssignment>();
    expectTypeOf<
      VersionedRoleAssignment["assignment"]
    >().toEqualTypeOf<RoleAssignment>();
    expectTypeOf<
      CreatedResult["record"]["assignment"]
    >().toEqualTypeOf<ActiveRoleAssignment>();
    expectTypeOf<
      UnchangedCreateResult["record"]["assignment"]
    >().toEqualTypeOf<RoleAssignment>();
  });

  it("isolates active reads by exact principal and mandatory exact scope", async () => {
    const store = new TestRoleAssignmentStore();
    await store.createRoleAssignment(activeAssignment("application"));
    await store.createRoleAssignment(
      activeAssignment("other_principal", {
        principalId: otherPrincipalId,
      }),
    );
    await store.createRoleAssignment(
      activeAssignment("organization_alpha", {
        role: "organization-admin",
        scope: organizationAlphaScope,
      }),
    );
    await store.createRoleAssignment(
      activeAssignment("organization_beta", {
        role: "billing",
        scope: organizationBetaScope,
      }),
    );

    await expect(
      store.listActiveRoleAssignments(principalId, applicationScope),
    ).resolves.toMatchObject([{ id: "application" }]);
    await expect(
      store.listActiveRoleAssignments(principalId, organizationAlphaScope),
    ).resolves.toMatchObject([{ id: "organization_alpha" }]);
    await expect(
      store.listActiveRoleAssignments(principalId, organizationBetaScope),
    ).resolves.toMatchObject([{ id: "organization_beta" }]);
    await expect(
      store.listActiveRoleAssignments(otherPrincipalId, organizationAlphaScope),
    ).resolves.toEqual([]);
  });

  it("excludes revoked records from active selection but retains exact-ID evidence", async () => {
    const store = new TestRoleAssignmentStore();
    const created = requireRecord(
      await store.createRoleAssignment(activeAssignment("revoked")),
    );
    const result = await store.revokeRoleAssignment({
      assignmentId: "revoked",
      expectedConcurrencyToken: created.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_001_000,
      reason: "access removed",
    });

    expect(result.status).toBe("revoked");
    await expect(
      store.listActiveRoleAssignments(principalId, applicationScope),
    ).resolves.toEqual([]);
    await expect(store.getRoleAssignment("revoked")).resolves.toMatchObject({
      assignment: {
        id: "revoked",
        grantedBy: grantor,
        grantedAtEpochMs: 1_700_000_000_000,
        status: "revoked",
        revokedBy: revoker,
        revokedAtEpochMs: 1_700_000_001_000,
      },
    });
  });

  it("returns idempotent create, assignment-ID conflict, and active-tuple conflict distinctly", async () => {
    const store = new TestRoleAssignmentStore();
    const input = activeAssignment("one");
    await expect(store.createRoleAssignment(input)).resolves.toMatchObject({
      status: "created",
    });
    await expect(store.createRoleAssignment(input)).resolves.toMatchObject({
      status: "unchanged",
    });
    await expect(
      store.createRoleAssignment(activeAssignment("one", { role: "admin" })),
    ).resolves.toEqual({
      status: "conflict",
      reason: "assignment_id",
    });
    await expect(
      store.createRoleAssignment(activeAssignment("two")),
    ).resolves.toEqual({
      status: "conflict",
      reason: "active_tuple",
    });
  });

  it("never reactivates a revoked lifecycle when identical create is replayed", async () => {
    const store = new TestRoleAssignmentStore();
    const input = activeAssignment("never-reactivate");
    const created = requireRecord(await store.createRoleAssignment(input));
    await store.revokeRoleAssignment({
      assignmentId: input.id,
      expectedConcurrencyToken: created.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_001_000,
    });

    const replay = await store.createRoleAssignment(input);
    expect(replay.status).toBe("unchanged");
    if (replay.status !== "conflict") {
      expect(replay.record.assignment.status).toBe("revoked");
    }
  });

  it("returns one winner for distinct IDs targeting one active tuple", async () => {
    const store = new TestRoleAssignmentStore();
    // This deterministic fixture verifies result semantics, not backend
    // interleaving; concrete adapters need a real race conformance test.
    const results = await Promise.all([
      store.createRoleAssignment(activeAssignment("racer_one")),
      store.createRoleAssignment(activeAssignment("racer_two")),
    ]);

    expect(results.filter(({ status }) => status === "created")).toHaveLength(
      1,
    );
    expect(results).toContainEqual({
      status: "conflict",
      reason: "active_tuple",
    });
  });

  it("advances the token, preserves grant evidence, rejects stale tokens, and supports exact replay", async () => {
    const store = new TestRoleAssignmentStore();
    const input = activeAssignment("conditional");
    const created = requireRecord(await store.createRoleAssignment(input));
    const command: RevokeRoleAssignmentCommand = {
      assignmentId: input.id,
      expectedConcurrencyToken: created.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_001_000,
      reason: "rotation",
    };
    const revoked = await store.revokeRoleAssignment(command);
    expect(revoked.status).toBe("revoked");
    if (revoked.status === "revoked") {
      expect(revoked.record.concurrencyToken).not.toBe(
        created.concurrencyToken,
      );
      expect(revoked.record.assignment).toMatchObject({
        id: input.id,
        principalId: input.principalId,
        role: input.role,
        scope: input.scope,
        grantedBy: input.grantedBy,
        grantedAtEpochMs: input.grantedAtEpochMs,
      });
    }
    await expect(store.revokeRoleAssignment(command)).resolves.toMatchObject({
      status: "unchanged",
    });
    await expect(
      store.revokeRoleAssignment({
        ...command,
        revokedAtEpochMs: command.revokedAtEpochMs + 1,
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });

    const active = requireRecord(
      await store.createRoleAssignment(
        activeAssignment("stale-token", { role: "admin" }),
      ),
    );
    await expect(
      store.revokeRoleAssignment({
        ...command,
        assignmentId: "stale-token",
        expectedConcurrencyToken: `${active.concurrencyToken}-stale`,
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
  });

  it("prevents a delayed old-ID revoke from affecting a fresh regrant", async () => {
    const store = new TestRoleAssignmentStore();
    const old = requireRecord(
      await store.createRoleAssignment(activeAssignment("old")),
    );
    await store.revokeRoleAssignment({
      assignmentId: "old",
      expectedConcurrencyToken: old.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_001_000,
    });
    await store.createRoleAssignment(
      activeAssignment("fresh", { grantedAtEpochMs: 1_700_000_002_000 }),
    );

    await expect(
      store.revokeRoleAssignment({
        assignmentId: "old",
        expectedConcurrencyToken: old.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: 1_700_000_003_000,
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    await expect(
      store.listActiveRoleAssignments(principalId, applicationScope),
    ).resolves.toMatchObject([{ id: "fresh" }]);
  });

  it("distinguishes definitive empty and not-found results from read failure", async () => {
    const store = new TestRoleAssignmentStore();
    await expect(store.getRoleAssignment("absent")).resolves.toBeNull();
    await expect(
      store.listActiveRoleAssignments(principalId, applicationScope),
    ).resolves.toEqual([]);
    await expect(
      store.revokeRoleAssignment({
        assignmentId: "absent",
        expectedConcurrencyToken: "version_absent",
        revokedBy: revoker,
        revokedAtEpochMs: 1_700_000_001_000,
      }),
    ).resolves.toEqual({ status: "not_found" });
    store.failReads = true;
    await expect(store.getRoleAssignment("absent")).rejects.toThrow(
      "role assignment read unavailable",
    );
    await expect(
      store.listActiveRoleAssignments(principalId, applicationScope),
    ).rejects.toThrow("role assignment read unavailable");
  });
});

describe("RoleAssignmentAuditStore conformance", () => {
  it("assigns positive per-assignment sequence and lists strictly increasing lifecycle order", async () => {
    const store = new TestRoleAssignmentAuditStore();
    const active = activeAssignment("audited");
    const revoked: RevokedRoleAssignment = {
      ...active,
      status: "revoked",
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_001_000,
    };

    await expect(
      store.appendRoleAssignmentAuditEvent({
        id: "event_granted",
        kind: "granted",
        assignment: active,
      }),
    ).resolves.toMatchObject({
      status: "appended",
      record: { sequence: 1 },
    });
    await expect(
      store.appendRoleAssignmentAuditEvent({
        id: "event_revoked",
        kind: "revoked",
        assignment: revoked,
      }),
    ).resolves.toMatchObject({
      status: "appended",
      record: { sequence: 2 },
    });
    await expect(
      store.appendRoleAssignmentAuditEvent({
        id: "event_other_assignment",
        kind: "granted",
        assignment: activeAssignment("audited_independently"),
      }),
    ).resolves.toMatchObject({
      status: "appended",
      record: { sequence: 1 },
    });
    const events = await store.listRoleAssignmentAuditEvents(active.id);
    expect(events.map(({ sequence }) => sequence)).toEqual([1, 2]);
    expect(
      events.every(
        ({ sequence }) => Number.isSafeInteger(sequence) && sequence > 0,
      ),
    ).toBe(true);
  });

  it("makes exact replay idempotent and distinguishes event-ID from lifecycle-position conflict", async () => {
    const store = new TestRoleAssignmentAuditStore();
    const granted: RoleAssignmentAuditEvent = {
      id: "event_one",
      kind: "granted",
      assignment: activeAssignment("audit-conflicts"),
    };
    await store.appendRoleAssignmentAuditEvent(granted);
    await expect(
      store.appendRoleAssignmentAuditEvent(granted),
    ).resolves.toMatchObject({ status: "unchanged", record: { sequence: 1 } });
    await expect(
      store.appendRoleAssignmentAuditEvent({
        ...granted,
        kind: "granted",
        assignment: activeAssignment("different-assignment"),
      }),
    ).resolves.toEqual({ status: "conflict", reason: "event_id" });
    await expect(
      store.appendRoleAssignmentAuditEvent({
        ...granted,
        id: "event_duplicate_grant",
      }),
    ).resolves.toEqual({
      status: "conflict",
      reason: "lifecycle_position",
    });
    await expect(
      store.appendRoleAssignmentAuditEvent({
        id: "event_revoked_without_grant",
        kind: "revoked",
        assignment: {
          ...activeAssignment("revoked-without-grant"),
          status: "revoked",
          revokedBy: revoker,
          revokedAtEpochMs: 1_700_000_001_000,
        },
      }),
    ).resolves.toEqual({
      status: "conflict",
      reason: "lifecycle_position",
    });
  });

  it("rejects audit failures instead of presenting partial success or definitive emptiness", async () => {
    const store = new TestRoleAssignmentAuditStore();
    const event: RoleAssignmentAuditEvent = {
      id: "event_failure",
      kind: "granted",
      assignment: activeAssignment("audit-failure"),
    };
    store.failAppends = true;
    await expect(store.appendRoleAssignmentAuditEvent(event)).rejects.toThrow(
      "audit append unavailable",
    );
    store.failAppends = false;
    store.failReads = true;
    await expect(
      store.listRoleAssignmentAuditEvents(event.assignment.id),
    ).rejects.toThrow("audit read unavailable");
  });

  it("keeps mutation and audit operations explicitly separate and therefore non-atomic", async () => {
    const roles = new TestRoleAssignmentStore();
    const audit = new TestRoleAssignmentAuditStore();
    const assignment = activeAssignment("non-atomic");
    await roles.createRoleAssignment(assignment);
    audit.failAppends = true;

    await expect(
      audit.appendRoleAssignmentAuditEvent({
        id: "event_non_atomic",
        kind: "granted",
        assignment,
      }),
    ).rejects.toThrow("audit append unavailable");
    await expect(roles.getRoleAssignment(assignment.id)).resolves.toMatchObject(
      {
        assignment: { status: "active" },
      },
    );
  });
});

describe("authorization boundary", () => {
  it("keeps storage metadata out of AccessSubject and AccessContext and unknown roles deny by default", () => {
    expectTypeOf<keyof AccessSubject>().toEqualTypeOf<
      "principalId" | "roles" | "entitlements"
    >();
    expectTypeOf<keyof AccessContext>().toEqualTypeOf<
      "principalId" | "policyVersion" | "roles" | "entitlements" | "permissions"
    >();

    const context = resolveAccess(
      { principalId, roles: ["provider|subject", "unknown-role"] },
      { version: "storage-contract", roles: { support: ["support.read"] } },
    );
    expect(context.permissions).toEqual([]);
    expect(context).not.toHaveProperty("assignmentId");
    expect(context).not.toHaveProperty("scope");
    expect(context).not.toHaveProperty("audit");
    expect(context).not.toHaveProperty("issuer");
    expect(context).not.toHaveProperty("subject");
  });
});
