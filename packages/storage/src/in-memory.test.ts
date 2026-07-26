import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  ActiveRoleAssignment,
  IdentityLink,
  RevokedRoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import {
  createInMemoryStorageAdapter,
  type AuditedRoleAssignmentMutationStore,
  type InMemoryStorageAdapter,
  type RoleAssignmentAuditReader,
  type RoleAssignmentReader,
} from "@pegma/authorization-storage";

const applicationScope: RoleAssignmentScope = { kind: "application" };
const organizationScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId: "organization_alpha",
};
const grantor: RoleAssignmentActor = {
  kind: "principal",
  principalId: "principal_admin",
};
const revoker: RoleAssignmentActor = {
  kind: "system",
  systemId: "role-administration",
};

const activeAssignment = (
  id: string,
  overrides: Partial<ActiveRoleAssignment> = {},
): ActiveRoleAssignment => ({
  id,
  principalId: "principal_alpha",
  role: "support",
  scope: applicationScope,
  grantedBy: grantor,
  grantedAtEpochMs: 1_700_000_000_000,
  status: "active",
  ...overrides,
});

const grant = (
  adapter: InMemoryStorageAdapter,
  assignment: ActiveRoleAssignment,
  auditEventId = `grant:${assignment.id}`,
) => adapter.grantRoleAssignmentWithAudit({ assignment, auditEventId });

const requireGrant = async (
  adapter: InMemoryStorageAdapter,
  assignment: ActiveRoleAssignment,
  auditEventId = `grant:${assignment.id}`,
) => {
  const result = await grant(adapter, assignment, auditEventId);
  if (result.status !== "granted") {
    throw new Error(`expected granted, received ${result.status}`);
  }
  return result;
};

describe("createInMemoryStorageAdapter", () => {
  it("exposes only safe combined mutations and both reader contracts", () => {
    const adapter = createInMemoryStorageAdapter();
    expectTypeOf(adapter).toMatchTypeOf<RoleAssignmentReader>();
    expectTypeOf(adapter).toMatchTypeOf<RoleAssignmentAuditReader>();
    expectTypeOf(adapter).toMatchTypeOf<AuditedRoleAssignmentMutationStore>();
    expect(Object.isFrozen(adapter)).toBe(true);
    expect("createRoleAssignment" in adapter).toBe(false);
    expect("revokeRoleAssignment" in adapter).toBe(false);
    expect("appendRoleAssignmentAuditEvent" in adapter).toBe(false);
  });

  it("resolves empty and seeded identity links by exact safe tuple", async () => {
    const empty = createInMemoryStorageAdapter();
    await expect(
      empty.resolvePrincipalId({ issuer: "issuer", subject: "subject" }),
    ).resolves.toBeNull();

    const adapter = createInMemoryStorageAdapter({
      identityLinks: [
        {
          key: { issuer: "a|b", subject: "c" },
          principalId: "principal_delimiter_one",
        },
        {
          key: { issuer: "a", subject: "b|c" },
          principalId: "principal_delimiter_two",
        },
        {
          key: { issuer: "__proto__", subject: "constructor" },
          principalId: "principal_prototype",
        },
        {
          key: { issuer: "issuer\u0000x", subject: "subject\u0000y" },
          principalId: "principal_nul",
        },
      ],
    });

    await expect(
      adapter.resolvePrincipalId({ issuer: "a|b", subject: "c" }),
    ).resolves.toBe("principal_delimiter_one");
    await expect(
      adapter.resolvePrincipalId({ issuer: "a", subject: "b|c" }),
    ).resolves.toBe("principal_delimiter_two");
    await expect(
      adapter.resolvePrincipalId({
        issuer: "__proto__",
        subject: "constructor",
      }),
    ).resolves.toBe("principal_prototype");
    await expect(
      adapter.resolvePrincipalId({
        issuer: "issuer\u0000x",
        subject: "subject\u0000y",
      }),
    ).resolves.toBe("principal_nul");
    await expect(
      adapter.resolvePrincipalId({ issuer: "A|b", subject: "c" }),
    ).resolves.toBeNull();
  });

  it("accepts identical seed duplicates and rejects conflicting duplicates", async () => {
    const link: IdentityLink = {
      key: { issuer: "issuer", subject: "subject" },
      principalId: "principal_alpha",
    };
    const adapter = createInMemoryStorageAdapter({
      identityLinks: [link, structuredClone(link)],
    });
    await expect(adapter.resolvePrincipalId(link.key)).resolves.toBe(
      "principal_alpha",
    );
    expect(() =>
      createInMemoryStorageAdapter({
        identityLinks: [link, { ...link, principalId: "principal_beta" }],
      }),
    ).toThrow("cannot seed multiple principals");
  });

  it("detaches identity seeds before returning", async () => {
    const key = { issuer: "issuer", subject: "subject" };
    const links: IdentityLink[] = [{ key, principalId: "principal_alpha" }];
    const adapter = createInMemoryStorageAdapter({ identityLinks: links });
    key.issuer = "changed";
    links[0] = {
      key: { issuer: "other", subject: "other" },
      principalId: "principal_beta",
    };
    await expect(
      adapter.resolvePrincipalId({ issuer: "issuer", subject: "subject" }),
    ).resolves.toBe("principal_alpha");
  });

  it("returns fresh, recursively frozen, detached role and audit snapshots", async () => {
    const scope = {
      kind: "organization" as const,
      organizationId: "organization_alpha",
    };
    const actor = {
      kind: "principal" as const,
      principalId: "principal_admin",
    };
    const assignment = activeAssignment("frozen", {
      scope,
      grantedBy: actor,
    });
    const adapter = createInMemoryStorageAdapter();
    const result = await requireGrant(adapter, assignment);

    scope.organizationId = "changed";
    actor.principalId = "changed";
    (assignment as { role: string }).role = "changed";

    expect(result.record.assignment.role).toBe("support");
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(result.record)).toBe(true);
    expect(Object.isFrozen(result.record.assignment)).toBe(true);
    expect(Object.isFrozen(result.record.assignment.scope)).toBe(true);
    expect(Object.isFrozen(result.record.assignment.grantedBy)).toBe(true);
    expect(Object.isFrozen(result.auditRecord)).toBe(true);
    expect(Object.isFrozen(result.auditRecord.event)).toBe(true);

    const firstRead = await adapter.getRoleAssignment("frozen");
    const secondRead = await adapter.getRoleAssignment("frozen");
    expect(firstRead).not.toBe(secondRead);
    expect(firstRead?.assignment).not.toBe(secondRead?.assignment);
    const firstHistory = await adapter.listRoleAssignmentAuditEvents("frozen");
    const secondHistory = await adapter.listRoleAssignmentAuditEvents("frozen");
    expect(firstHistory).not.toBe(secondHistory);
    expect(firstHistory[0]).not.toBe(secondHistory[0]);
    expect(Object.isFrozen(firstHistory)).toBe(true);
    expect(Object.isFrozen(firstHistory[0]?.event.assignment)).toBe(true);
  });

  it("reads exact IDs and isolates active selection by principal and scope", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("application"));
    await requireGrant(
      adapter,
      activeAssignment("other-principal", {
        principalId: "principal_beta",
      }),
    );
    await requireGrant(
      adapter,
      activeAssignment("organization", {
        role: "organization-admin",
        scope: organizationScope,
      }),
    );

    await expect(adapter.getRoleAssignment("absent")).resolves.toBeNull();
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toMatchObject([{ id: "application" }]);
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", organizationScope),
    ).resolves.toMatchObject([{ id: "organization" }]);
    await expect(
      adapter.listActiveRoleAssignments("principal_beta", organizationScope),
    ).resolves.toEqual([]);
  });

  it("atomically grants sequence one and revokes sequence two", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(
      adapter,
      activeAssignment("lifecycle"),
      "event_grant",
    );
    expect(granted.auditRecord).toMatchObject({
      sequence: 1,
      event: { id: "event_grant", kind: "granted" },
    });
    const revoked = await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: "lifecycle",
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      reason: "rotation",
      auditEventId: "event_revoke",
    });
    expect(revoked).toMatchObject({
      status: "revoked",
      auditRecord: {
        sequence: 2,
        event: { id: "event_revoke", kind: "revoked" },
      },
      record: {
        assignment: {
          status: "revoked",
          grantedBy: grantor,
          revokedBy: revoker,
          reason: "rotation",
        },
      },
    });
    expect(
      await adapter.listActiveRoleAssignments(
        "principal_alpha",
        applicationScope,
      ),
    ).toEqual([]);
    expect(
      await adapter.listRoleAssignmentAuditEvents("lifecycle"),
    ).toHaveLength(2);
  });

  it("replays exact grants and revokes without advancing counters", async () => {
    const adapter = createInMemoryStorageAdapter();
    const assignment = activeAssignment("replay");
    const firstGrant = await requireGrant(adapter, assignment, "grant_replay");
    const secondGrant = await grant(adapter, assignment, "grant_replay");
    expect(secondGrant).toMatchObject({
      status: "unchanged",
      record: { concurrencyToken: firstGrant.record.concurrencyToken },
      auditRecord: { sequence: 1 },
    });
    const revokeCommand = {
      assignmentId: "replay",
      expectedConcurrencyToken: firstGrant.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: assignment.grantedAtEpochMs,
      auditEventId: "revoke_replay",
    } as const;
    const firstRevoke =
      await adapter.revokeRoleAssignmentWithAudit(revokeCommand);
    const secondRevoke =
      await adapter.revokeRoleAssignmentWithAudit(revokeCommand);
    expect(firstRevoke.status).toBe("revoked");
    expect(secondRevoke).toMatchObject({
      status: "unchanged",
      auditRecord: { sequence: 2 },
    });
    if (firstRevoke.status !== "revoked") {
      throw new Error("expected revoked");
    }
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...revokeCommand,
        expectedConcurrencyToken: "arbitrary-token",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...revokeCommand,
        expectedConcurrencyToken: firstRevoke.record.concurrencyToken,
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
    expect(
      await adapter.listRoleAssignmentAuditEvents(assignment.id),
    ).toHaveLength(2);

    const fresh = await requireGrant(adapter, activeAssignment("counter"));
    expect(fresh.record.concurrencyToken).toBe("version_3");
  });

  it("never reactivates a revoked lifecycle on grant replay", async () => {
    const adapter = createInMemoryStorageAdapter();
    const assignment = activeAssignment("no-reactivate");
    const granted = await requireGrant(adapter, assignment, "grant_event");
    await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: assignment.id,
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: assignment.grantedAtEpochMs,
      auditEventId: "revoke_event",
    });
    const replay = await grant(adapter, assignment, "grant_event");
    expect(replay).toMatchObject({
      status: "unchanged",
      record: { assignment: { status: "revoked" } },
      auditRecord: { sequence: 1, event: { kind: "granted" } },
    });
  });

  it("applies role-side conflict precedence and never partially writes", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("original"), "event_original");

    await expect(
      grant(
        adapter,
        activeAssignment("original", { role: "admin" }),
        "event_original",
      ),
    ).resolves.toEqual({
      status: "conflict",
      reason: "assignment_id",
    });
    await expect(
      grant(adapter, activeAssignment("second"), "event_original"),
    ).resolves.toEqual({ status: "conflict", reason: "active_tuple" });
    expect(await adapter.getRoleAssignment("second")).toBeNull();
    expect(await adapter.listRoleAssignmentAuditEvents("second")).toEqual([]);
  });

  it("rolls back event-ID and lifecycle-position grant conflicts for retry", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(
      adapter,
      activeAssignment("first", { role: "first" }),
      "shared_event",
    );
    await expect(
      grant(
        adapter,
        activeAssignment("second", { role: "second" }),
        "shared_event",
      ),
    ).resolves.toEqual({ status: "conflict", reason: "event_id" });
    await expect(
      grant(
        adapter,
        activeAssignment("first", { role: "first" }),
        "different_event",
      ),
    ).resolves.toEqual({
      status: "conflict",
      reason: "lifecycle_position",
    });

    const retry = await requireGrant(
      adapter,
      activeAssignment("second", { role: "second" }),
      "second_event",
    );
    expect(retry.record.concurrencyToken).toBe("version_2");
  });

  it("rejects stale tokens, competing revocations, and invalid lifecycle order without mutation", async () => {
    const adapter = createInMemoryStorageAdapter();
    const assignment = activeAssignment("revoke-conflicts");
    const granted = await requireGrant(adapter, assignment);
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: assignment.id,
        expectedConcurrencyToken: "stale",
        revokedBy: revoker,
        revokedAtEpochMs: assignment.grantedAtEpochMs,
        auditEventId: "stale_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: assignment.id,
        expectedConcurrencyToken: granted.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: assignment.grantedAtEpochMs - 1,
        auditEventId: "early_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });

    const completed = await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: assignment.id,
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: assignment.grantedAtEpochMs,
      auditEventId: "completed_event",
    });
    expect(completed.status).toBe("revoked");
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: assignment.id,
        expectedConcurrencyToken: granted.record.concurrencyToken,
        revokedBy: { kind: "system", systemId: "competitor" },
        revokedAtEpochMs: assignment.grantedAtEpochMs,
        auditEventId: "competitor_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    expect(
      await adapter.listRoleAssignmentAuditEvents(assignment.id),
    ).toHaveLength(2);
  });

  it("rolls back revoke event conflicts and permits a clean retry", async () => {
    const adapter = createInMemoryStorageAdapter();
    const occupied = await requireGrant(
      adapter,
      activeAssignment("occupied", { role: "occupied" }),
      "occupied_event",
    );
    expect(occupied.status).toBe("granted");
    const target = await requireGrant(
      adapter,
      activeAssignment("target", { role: "target" }),
      "target_grant",
    );
    const command = {
      assignmentId: "target",
      expectedConcurrencyToken: target.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
    } as const;
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...command,
        auditEventId: "occupied_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "event_id" });
    expect((await adapter.getRoleAssignment("target"))?.assignment.status).toBe(
      "active",
    );
    const retry = await adapter.revokeRoleAssignmentWithAudit({
      ...command,
      auditEventId: "target_revoke",
    });
    expect(retry).toMatchObject({
      status: "revoked",
      record: { concurrencyToken: "version_3" },
    });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...command,
        auditEventId: "other_revoke",
      }),
    ).resolves.toEqual({
      status: "conflict",
      reason: "lifecycle_position",
    });
  });

  it.each([
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
  ])(
    "rejects invalid grant timestamp %s without state changes",
    (timestamp) => {
      const adapter = createInMemoryStorageAdapter();
      expect(() =>
        adapter.grantRoleAssignmentWithAudit({
          assignment: activeAssignment("invalid", {
            grantedAtEpochMs: timestamp,
          }),
          auditEventId: "invalid_event",
        }),
      ).toThrow("non-negative safe integer");
    },
  );

  it.each([
    -1,
    1.5,
    Number.NaN,
    Number.POSITIVE_INFINITY,
    Number.NEGATIVE_INFINITY,
    Number.MAX_SAFE_INTEGER + 1,
  ])(
    "rejects invalid revoke timestamp %s without state changes",
    async (timestamp) => {
      const adapter = createInMemoryStorageAdapter();
      const granted = await requireGrant(adapter, activeAssignment("invalid"));
      expect(() =>
        adapter.revokeRoleAssignmentWithAudit({
          assignmentId: "invalid",
          expectedConcurrencyToken: granted.record.concurrencyToken,
          revokedBy: revoker,
          revokedAtEpochMs: timestamp,
          auditEventId: "invalid_revoke",
        }),
      ).toThrow("non-negative safe integer");
      expect(
        (await adapter.getRoleAssignment("invalid"))?.assignment.status,
      ).toBe("active");
    },
  );

  it("rolls back a synchronous preparation exception from a hostile getter", async () => {
    const adapter = createInMemoryStorageAdapter();
    const command = {
      get assignment(): ActiveRoleAssignment {
        throw new Error("hostile getter");
      },
      auditEventId: "never-read",
    };
    expect(() => adapter.grantRoleAssignmentWithAudit(command)).toThrow(
      "hostile getter",
    );
    await expect(adapter.getRoleAssignment("anything")).resolves.toBeNull();
  });

  it("synchronously linearizes Promise.all grants and identical replays within one instance", async () => {
    const adapter = createInMemoryStorageAdapter();
    const competing = await Promise.all([
      grant(adapter, activeAssignment("winner-a"), "event-a"),
      grant(adapter, activeAssignment("winner-b"), "event-b"),
    ]);
    expect(competing.map(({ status }) => status).sort()).toEqual([
      "conflict",
      "granted",
    ]);

    const replayAdapter = createInMemoryStorageAdapter();
    const assignment = activeAssignment("same");
    const identical = await Promise.all([
      grant(replayAdapter, assignment, "same-event"),
      grant(replayAdapter, assignment, "same-event"),
    ]);
    expect(identical.map(({ status }) => status).sort()).toEqual([
      "granted",
      "unchanged",
    ]);
  });

  it("synchronously linearizes identical and competing revokes within one instance", async () => {
    const identicalAdapter = createInMemoryStorageAdapter();
    const identicalGrant = await requireGrant(
      identicalAdapter,
      activeAssignment("identical-revoke"),
    );
    const identicalCommand = {
      assignmentId: "identical-revoke",
      expectedConcurrencyToken: identicalGrant.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "identical-revoke-event",
    } as const;
    const identical = await Promise.all([
      identicalAdapter.revokeRoleAssignmentWithAudit(identicalCommand),
      identicalAdapter.revokeRoleAssignmentWithAudit(identicalCommand),
    ]);
    expect(identical.map(({ status }) => status).sort()).toEqual([
      "revoked",
      "unchanged",
    ]);

    const competingAdapter = createInMemoryStorageAdapter();
    const competingGrant = await requireGrant(
      competingAdapter,
      activeAssignment("competing-revoke"),
    );
    const competing = await Promise.all([
      competingAdapter.revokeRoleAssignmentWithAudit({
        assignmentId: "competing-revoke",
        expectedConcurrencyToken: competingGrant.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: 1_700_000_000_001,
        auditEventId: "competing-a",
      }),
      competingAdapter.revokeRoleAssignmentWithAudit({
        assignmentId: "competing-revoke",
        expectedConcurrencyToken: competingGrant.record.concurrencyToken,
        revokedBy: { kind: "system", systemId: "other" },
        revokedAtEpochMs: 1_700_000_000_001,
        auditEventId: "competing-b",
      }),
    ]);
    expect(competing.filter(({ status }) => status === "revoked")).toHaveLength(
      1,
    );
    expect(
      competing.filter(({ status }) => status === "conflict"),
    ).toHaveLength(1);
  });

  it("keeps assignment and event IDs exact and delimiter/prototype/NUL safe", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(
      adapter,
      activeAssignment("__proto__", { role: "prototype" }),
      "constructor",
    );
    await requireGrant(
      adapter,
      activeAssignment("a|b", { role: "delimiter-one" }),
      "c",
    );
    await requireGrant(
      adapter,
      activeAssignment("a", { role: "delimiter-two" }),
      "b|c",
    );
    await requireGrant(
      adapter,
      activeAssignment("assignment\u0000id", { role: "nul" }),
      "event\u0000id",
    );

    await expect(adapter.getRoleAssignment("__proto__")).resolves.toMatchObject(
      { assignment: { role: "prototype" } },
    );
    await expect(adapter.getRoleAssignment("a|b")).resolves.toMatchObject({
      assignment: { role: "delimiter-one" },
    });
    await expect(adapter.getRoleAssignment("a")).resolves.toMatchObject({
      assignment: { role: "delimiter-two" },
    });
    await expect(
      adapter.listRoleAssignmentAuditEvents("assignment\u0000id"),
    ).resolves.toMatchObject([{ event: { id: "event\u0000id" } }]);
  });

  it("prevents an old-ID revoke from affecting a fresh regrant", async () => {
    const adapter = createInMemoryStorageAdapter();
    const oldGrant = await requireGrant(adapter, activeAssignment("old"));
    await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: "old",
      expectedConcurrencyToken: oldGrant.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "old_revoke",
    });
    const freshGrant = await requireGrant(adapter, activeAssignment("fresh"));
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: "old",
        expectedConcurrencyToken: oldGrant.record.concurrencyToken,
        revokedBy: { kind: "system", systemId: "late-command" },
        revokedAtEpochMs: 1_700_000_000_002,
        auditEventId: "late_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    expect((await adapter.getRoleAssignment("fresh"))?.assignment.status).toBe(
      "active",
    );
    expect(freshGrant.record.assignment.id).toBe("fresh");
  });

  it("isolates instances and permits the same literal in separate ID namespaces", async () => {
    const first = createInMemoryStorageAdapter();
    const second = createInMemoryStorageAdapter();
    const firstGrant = await requireGrant(
      first,
      activeAssignment("same"),
      "same",
    );
    const secondGrant = await requireGrant(
      second,
      activeAssignment("same"),
      "same",
    );
    expect(firstGrant.record.concurrencyToken).toBe("version_1");
    expect(secondGrant.record.concurrencyToken).toBe("version_1");
    expect(firstGrant.auditRecord.event.id).toBe("same");
    expect(firstGrant.record.assignment.id).toBe("same");
    await expect(second.getRoleAssignment("same")).resolves.toMatchObject({
      assignment: { status: "active" },
    });
  });

  it("returns not_found without allocating a token or audit sequence", async () => {
    const adapter = createInMemoryStorageAdapter();
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: "absent",
        expectedConcurrencyToken: "token",
        revokedBy: revoker,
        revokedAtEpochMs: 0,
        auditEventId: "absent_event",
      }),
    ).resolves.toEqual({ status: "not_found" });
    const granted = await requireGrant(adapter, activeAssignment("first"));
    expect(granted.record.concurrencyToken).toBe("version_1");
  });

  it("derives revocation evidence from the stored grant", async () => {
    const adapter = createInMemoryStorageAdapter();
    const assignment = activeAssignment("evidence", {
      grantedBy: { kind: "system", systemId: "bootstrap" },
      scope: organizationScope,
    });
    const granted = await requireGrant(adapter, assignment);
    const result = await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: "evidence",
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: assignment.grantedAtEpochMs,
      reason: "complete",
      auditEventId: "evidence_revoke",
    });
    if (result.status !== "revoked") {
      throw new Error("expected revoked");
    }
    const revoked: RevokedRoleAssignment = result.record.assignment;
    expect(revoked).toMatchObject({
      id: assignment.id,
      principalId: assignment.principalId,
      role: assignment.role,
      scope: organizationScope,
      grantedBy: assignment.grantedBy,
      grantedAtEpochMs: assignment.grantedAtEpochMs,
    });
  });
});
