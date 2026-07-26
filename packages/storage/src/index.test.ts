import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  AccessContext,
  AccessSubject,
  ActiveRoleAssignment,
  IdentityAdapter,
  IdentityLink,
  RevokedRoleAssignment,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import { resolveAccess } from "@pegma/authorization-core";
import { createMemoryStore } from "@pegma/storage-core";
import {
  createInMemoryStorageAdapter,
  createRoleStore,
  type AuditedRoleAssignmentMutationStore,
  type CreateRoleAssignmentResult,
  type InMemoryStorageAdapter,
  type PrincipalLookupStore,
  type RevokeRoleAssignmentResult,
  type RoleAssignmentAuditReader,
  type RoleAssignmentReader,
  type VersionedRoleAssignment,
} from "@pegma/authorization-storage";

const applicationScope: RoleAssignmentScope = { kind: "application" };
const organizationScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId: "organization_alpha",
};
const otherOrganizationScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId: "organization_beta",
};
/** A raw control character, spelled without writing one into this file. */
const NUL = String.fromCharCode(0);
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

describe("storage port surface", () => {
  it("keeps the read, audit, and safe-mutation contracts on one adapter", () => {
    const adapter = createInMemoryStorageAdapter();
    expectTypeOf<PrincipalLookupStore>().toMatchTypeOf<IdentityAdapter>();
    expectTypeOf(adapter).toMatchTypeOf<PrincipalLookupStore>();
    expectTypeOf(adapter).toMatchTypeOf<RoleAssignmentReader>();
    expectTypeOf(adapter).toMatchTypeOf<RoleAssignmentAuditReader>();
    expectTypeOf(adapter).toMatchTypeOf<AuditedRoleAssignmentMutationStore>();
    expect(Object.isFrozen(adapter)).toBe(true);
    expect("createRoleAssignment" in adapter).toBe(false);
    expect("revokeRoleAssignment" in adapter).toBe(false);
    expect("appendRoleAssignmentAuditEvent" in adapter).toBe(false);
  });

  it("narrows successful records to their exact lifecycle evidence", () => {
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

  it("binds any storage-core store to one host application namespace", async () => {
    const store = createMemoryStore();
    const first = createRoleStore(store, "application_one");
    const second = createRoleStore(store, "application_two");

    await requireGrant(first, activeAssignment("shared-literal"), "shared");
    await requireGrant(second, activeAssignment("shared-literal"), "shared");

    await expect(
      first.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toMatchObject([{ id: "shared-literal" }]);
    await expect(
      second.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toMatchObject([{ id: "shared-literal" }]);
    expect(Object.isFrozen(first)).toBe(true);
  });
});

describe("principal lookup", () => {
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
          key: { issuer: `issuer${NUL}x`, subject: `subject${NUL}y` },
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
        issuer: `issuer${NUL}x`,
        subject: `subject${NUL}y`,
      }),
    ).resolves.toBe("principal_nul");
  });

  it("treats issuer and subject as an exact case-sensitive tuple", async () => {
    const adapter = createInMemoryStorageAdapter({
      identityLinks: [
        { key: { issuer: "a|b", subject: "c" }, principalId: "principal_one" },
      ],
    });
    await expect(
      adapter.resolvePrincipalId({ issuer: "A|b", subject: "c" }),
    ).resolves.toBeNull();
    await expect(
      adapter.resolvePrincipalId({ issuer: "a|b", subject: "C" }),
    ).resolves.toBeNull();
    await expect(
      adapter.resolvePrincipalId({ issuer: "a", subject: "b|c" }),
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
});

describe("role assignment reads", () => {
  it("reads exact IDs and isolates active selection by principal and scope", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("application"));
    await requireGrant(
      adapter,
      activeAssignment("other-principal", { principalId: "principal_beta" }),
    );
    await requireGrant(
      adapter,
      activeAssignment("organization", {
        role: "organization-admin",
        scope: organizationScope,
      }),
    );
    await requireGrant(
      adapter,
      activeAssignment("other-organization", {
        role: "billing",
        scope: otherOrganizationScope,
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
      adapter.listActiveRoleAssignments(
        "principal_alpha",
        otherOrganizationScope,
      ),
    ).resolves.toMatchObject([{ id: "other-organization" }]);
    await expect(
      adapter.listActiveRoleAssignments("principal_beta", organizationScope),
    ).resolves.toEqual([]);
  });

  it("returns every active role a principal holds in one exact scope", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("support"));
    await requireGrant(adapter, activeAssignment("admin", { role: "admin" }));
    await requireGrant(
      adapter,
      activeAssignment("billing", { role: "billing" }),
    );

    const active = await adapter.listActiveRoleAssignments(
      "principal_alpha",
      applicationScope,
    );
    expect([...active].map(({ role }) => role).sort()).toEqual([
      "admin",
      "billing",
      "support",
    ]);
  });

  it("returns fresh, frozen, detached role and audit snapshots", async () => {
    const scope = {
      kind: "organization" as const,
      organizationId: "organization_alpha",
    };
    const actor = {
      kind: "principal" as const,
      principalId: "principal_admin",
    };
    const assignment = activeAssignment("frozen", { scope, grantedBy: actor });
    const adapter = createInMemoryStorageAdapter();
    const result = await requireGrant(adapter, assignment);

    scope.organizationId = "changed";
    actor.principalId = "changed";
    (assignment as { role: string }).role = "changed";

    expect(result.record.assignment.role).toBe("support");
    expect(result.record.assignment.scope).toEqual({
      kind: "organization",
      organizationId: "organization_alpha",
    });
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

  it("reports definitive absence for an unknown assignment history", async () => {
    const adapter = createInMemoryStorageAdapter();
    await expect(
      adapter.listRoleAssignmentAuditEvents("absent"),
    ).resolves.toEqual([]);
    await expect(
      adapter.listActiveRoleAssignments("principal_absent", applicationScope),
    ).resolves.toEqual([]);
  });
});

describe("audited grant", () => {
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
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toEqual([]);
    const history = await adapter.listRoleAssignmentAuditEvents("lifecycle");
    expect(history.map(({ sequence }) => sequence)).toEqual([1, 2]);
    expect(history[0]?.event.assignment.status).toBe("active");
    expect(history[1]?.event.assignment.status).toBe("revoked");
  });

  it("keeps the grant event as active evidence after revocation", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(
      adapter,
      activeAssignment("evidence"),
      "grant_evidence",
    );
    await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: "evidence",
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "revoke_evidence",
    });
    const history = await adapter.listRoleAssignmentAuditEvents("evidence");
    expect(history[0]).toMatchObject({
      sequence: 1,
      event: {
        id: "grant_evidence",
        kind: "granted",
        assignment: { status: "active", grantedAtEpochMs: 1_700_000_000_000 },
      },
    });
  });

  it("advances the record token across a lifecycle change", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(adapter, activeAssignment("token"));
    const revoked = await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: "token",
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "token_revoke",
    });
    if (revoked.status !== "revoked") throw new Error("expected revoked");
    expect(revoked.record.concurrencyToken).not.toBe(
      granted.record.concurrencyToken,
    );
    const read = await adapter.getRoleAssignment("token");
    expect(read?.concurrencyToken).toBe(revoked.record.concurrencyToken);
  });

  it("replays an exact grant as unchanged without a second event", async () => {
    const adapter = createInMemoryStorageAdapter();
    const assignment = activeAssignment("replay");
    const first = await requireGrant(adapter, assignment, "grant_replay");
    const second = await grant(adapter, assignment, "grant_replay");
    expect(second).toMatchObject({
      status: "unchanged",
      record: { concurrencyToken: first.record.concurrencyToken },
      auditRecord: { sequence: 1, event: { id: "grant_replay" } },
    });
    await expect(
      adapter.listRoleAssignmentAuditEvents("replay"),
    ).resolves.toHaveLength(1);
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

  it("refuses a second active assignment for one exact tuple", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("original"), "event_original");

    await expect(
      grant(adapter, activeAssignment("second"), "event_second"),
    ).resolves.toEqual({ status: "conflict", reason: "active_tuple" });
    await expect(adapter.getRoleAssignment("second")).resolves.toBeNull();
    await expect(
      adapter.listRoleAssignmentAuditEvents("second"),
    ).resolves.toEqual([]);
  });

  it("permits a fresh-ID regrant once the tuple is retired", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(adapter, activeAssignment("first"));
    await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: "first",
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "first_revoke",
    });
    const regrant = await requireGrant(
      adapter,
      activeAssignment("second", { grantedAtEpochMs: 1_700_000_000_002 }),
    );
    expect(regrant.record.assignment.id).toBe("second");
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toMatchObject([{ id: "second" }]);
  });

  it("refuses a different event ID for an existing assignment ID", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("occupied"), "first_event");
    await expect(
      grant(adapter, activeAssignment("occupied"), "different_event"),
    ).resolves.toEqual({ status: "conflict", reason: "event_id" });
    await expect(
      adapter.listRoleAssignmentAuditEvents("occupied"),
    ).resolves.toHaveLength(1);
  });

  it("keeps different scopes and principals in independent tuples", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("application-scope"));
    await requireGrant(
      adapter,
      activeAssignment("organization-scope", { scope: organizationScope }),
    );
    await requireGrant(
      adapter,
      activeAssignment("other-principal", { principalId: "principal_beta" }),
    );
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toHaveLength(1);
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", organizationScope),
    ).resolves.toHaveLength(1);
    await expect(
      adapter.listActiveRoleAssignments("principal_beta", applicationScope),
    ).resolves.toHaveLength(1);
  });

  it("returns one winner for distinct IDs targeting one active tuple", async () => {
    const adapter = createInMemoryStorageAdapter();
    const results = await Promise.all([
      grant(adapter, activeAssignment("racer_one"), "event_one"),
      grant(adapter, activeAssignment("racer_two"), "event_two"),
    ]);

    expect(results.filter(({ status }) => status === "granted")).toHaveLength(
      1,
    );
    expect(results).toContainEqual({
      status: "conflict",
      reason: "active_tuple",
    });
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toHaveLength(1);
  });

  it("settles concurrent identical grants as one grant and one replay", async () => {
    const adapter = createInMemoryStorageAdapter();
    const assignment = activeAssignment("same");
    const results = await Promise.all([
      grant(adapter, assignment, "same-event"),
      grant(adapter, assignment, "same-event"),
    ]);
    expect(results.map(({ status }) => status).sort()).toEqual([
      "granted",
      "unchanged",
    ]);
    await expect(
      adapter.listRoleAssignmentAuditEvents("same"),
    ).resolves.toHaveLength(1);
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
    async (timestamp) => {
      const adapter = createInMemoryStorageAdapter();
      await expect(
        adapter.grantRoleAssignmentWithAudit({
          assignment: activeAssignment("invalid", {
            grantedAtEpochMs: timestamp,
          }),
          auditEventId: "invalid_event",
        }),
      ).rejects.toThrow("non-negative safe integer");
      await expect(adapter.getRoleAssignment("invalid")).resolves.toBeNull();
    },
  );

  it("rejects a non-active assignment on the grant path", async () => {
    const adapter = createInMemoryStorageAdapter();
    const revoked = {
      ...activeAssignment("not-active"),
      status: "revoked",
    } as unknown as ActiveRoleAssignment;
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment: revoked,
        auditEventId: "invalid_event",
      }),
    ).rejects.toThrow("a grant requires an active role assignment");
  });

  it("keeps assignment, role, and event IDs delimiter, prototype, and NUL safe", async () => {
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
      activeAssignment(`assignment${NUL}id`, { role: "nul" }),
      `event${NUL}id`,
    );

    await expect(adapter.getRoleAssignment("__proto__")).resolves.toMatchObject(
      {
        assignment: { role: "prototype" },
      },
    );
    await expect(adapter.getRoleAssignment("a|b")).resolves.toMatchObject({
      assignment: { role: "delimiter-one" },
    });
    await expect(adapter.getRoleAssignment("a")).resolves.toMatchObject({
      assignment: { role: "delimiter-two" },
    });
    await expect(
      adapter.listRoleAssignmentAuditEvents(`assignment${NUL}id`),
    ).resolves.toMatchObject([{ event: { id: `event${NUL}id` } }]);
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toHaveLength(4);
  });

  it("keeps principals whose IDs differ only by the key separator distinct", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(
      adapter,
      activeAssignment("left", { principalId: "a|b" }),
      "left_event",
    );
    await requireGrant(
      adapter,
      activeAssignment("right", { principalId: "a%7Cb" }),
      "right_event",
    );
    await expect(
      adapter.listActiveRoleAssignments("a|b", applicationScope),
    ).resolves.toMatchObject([{ id: "left" }]);
    await expect(
      adapter.listActiveRoleAssignments("a%7Cb", applicationScope),
    ).resolves.toMatchObject([{ id: "right" }]);
  });

  it("isolates instances and permits the same literal in separate namespaces", async () => {
    const first = createInMemoryStorageAdapter();
    const second = createInMemoryStorageAdapter();
    await requireGrant(first, activeAssignment("same"), "same");
    await requireGrant(second, activeAssignment("same"), "same");
    await expect(second.getRoleAssignment("same")).resolves.toMatchObject({
      assignment: { status: "active" },
    });
    await expect(
      first.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toHaveLength(1);
  });
});

describe("audited revoke", () => {
  it("preserves grant evidence and derives revocation from the stored record", async () => {
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
    if (result.status !== "revoked") throw new Error("expected revoked");
    const revoked: RevokedRoleAssignment = result.record.assignment;
    expect(revoked).toMatchObject({
      id: assignment.id,
      principalId: assignment.principalId,
      role: assignment.role,
      scope: organizationScope,
      grantedBy: assignment.grantedBy,
      grantedAtEpochMs: assignment.grantedAtEpochMs,
      revokedBy: revoker,
      reason: "complete",
    });
  });

  it("replays an exact completed revocation as unchanged", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(adapter, activeAssignment("replay"));
    const command = {
      assignmentId: "replay",
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "revoke_replay",
    } as const;
    const first = await adapter.revokeRoleAssignmentWithAudit(command);
    const second = await adapter.revokeRoleAssignmentWithAudit(command);
    expect(first.status).toBe("revoked");
    expect(second).toMatchObject({
      status: "unchanged",
      auditRecord: { sequence: 2, event: { id: "revoke_replay" } },
    });
    await expect(
      adapter.listRoleAssignmentAuditEvents("replay"),
    ).resolves.toHaveLength(2);
  });

  it("refuses a different operation against a revoked lifecycle", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(adapter, activeAssignment("revoked"));
    const command = {
      assignmentId: "revoked",
      expectedConcurrencyToken: granted.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "revoke_event",
    } as const;
    expect((await adapter.revokeRoleAssignmentWithAudit(command)).status).toBe(
      "revoked",
    );
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...command,
        revokedAtEpochMs: command.revokedAtEpochMs + 1,
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...command,
        revokedBy: { kind: "system", systemId: "competitor" },
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...command,
        auditEventId: "other_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    await expect(
      adapter.listRoleAssignmentAuditEvents("revoked"),
    ).resolves.toHaveLength(2);
  });

  it("rejects a stale token against an active record", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("stale"));
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: "stale",
        expectedConcurrencyToken: "not-the-token",
        revokedBy: revoker,
        revokedAtEpochMs: 1_700_000_000_001,
        auditEventId: "stale_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
    await expect(adapter.getRoleAssignment("stale")).resolves.toMatchObject({
      assignment: { status: "active" },
    });
  });

  it("rejects revocation earlier than its grant", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(adapter, activeAssignment("ordered"));
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: "ordered",
        expectedConcurrencyToken: granted.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: 1_699_999_999_999,
        auditEventId: "early_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    await expect(
      adapter.listRoleAssignmentAuditEvents("ordered"),
    ).resolves.toHaveLength(1);
  });

  it("returns not_found for an absent exact ID", async () => {
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
  });

  it("prevents a delayed old-ID revoke from affecting a fresh regrant", async () => {
    const adapter = createInMemoryStorageAdapter();
    const old = await requireGrant(adapter, activeAssignment("old"));
    await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: "old",
      expectedConcurrencyToken: old.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: 1_700_000_000_001,
      auditEventId: "old_revoke",
    });
    await requireGrant(
      adapter,
      activeAssignment("fresh", { grantedAtEpochMs: 1_700_000_000_002 }),
    );

    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: "old",
        expectedConcurrencyToken: old.record.concurrencyToken,
        revokedBy: { kind: "system", systemId: "late-command" },
        revokedAtEpochMs: 1_700_000_000_003,
        auditEventId: "late_event",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
    await expect(
      adapter.listActiveRoleAssignments("principal_alpha", applicationScope),
    ).resolves.toMatchObject([{ id: "fresh" }]);
  });

  it("returns one winner for competing revocations of one record", async () => {
    const adapter = createInMemoryStorageAdapter();
    const granted = await requireGrant(adapter, activeAssignment("competing"));
    const results = await Promise.all([
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: "competing",
        expectedConcurrencyToken: granted.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: 1_700_000_000_001,
        auditEventId: "competing-a",
      }),
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: "competing",
        expectedConcurrencyToken: granted.record.concurrencyToken,
        revokedBy: { kind: "system", systemId: "other" },
        revokedAtEpochMs: 1_700_000_000_001,
        auditEventId: "competing-b",
      }),
    ]);
    expect(results.filter(({ status }) => status === "revoked")).toHaveLength(
      1,
    );
    expect(results.filter(({ status }) => status === "conflict")).toHaveLength(
      1,
    );
    await expect(
      adapter.listRoleAssignmentAuditEvents("competing"),
    ).resolves.toHaveLength(2);
  });

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
      await expect(
        adapter.revokeRoleAssignmentWithAudit({
          assignmentId: "invalid",
          expectedConcurrencyToken: granted.record.concurrencyToken,
          revokedBy: revoker,
          revokedAtEpochMs: timestamp,
          auditEventId: "invalid_revoke",
        }),
      ).rejects.toThrow("non-negative safe integer");
      expect(
        (await adapter.getRoleAssignment("invalid"))?.assignment.status,
      ).toBe("active");
    },
  );
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
      {
        principalId: "principal_alpha",
        roles: ["provider|subject", "unknown-role"],
      },
      { version: "storage-contract", roles: { support: ["support.read"] } },
    );
    expect(context.permissions).toEqual([]);
    expect(context).not.toHaveProperty("assignmentId");
    expect(context).not.toHaveProperty("scope");
    expect(context).not.toHaveProperty("audit");
    expect(context).not.toHaveProperty("issuer");
    expect(context).not.toHaveProperty("subject");
  });

  it("projects only role names from a complete active selection", async () => {
    const adapter = createInMemoryStorageAdapter();
    await requireGrant(adapter, activeAssignment("support"));
    await requireGrant(adapter, activeAssignment("admin", { role: "admin" }));

    const active = await adapter.listActiveRoleAssignments(
      "principal_alpha",
      applicationScope,
    );
    const context = resolveAccess(
      {
        principalId: "principal_alpha",
        roles: [...active].map(({ role }) => role),
      },
      {
        version: "storage-contract",
        roles: { support: ["support.read"], admin: ["admin.write"] },
      },
    );
    expect([...context.permissions].sort()).toEqual([
      "admin.write",
      "support.read",
    ]);
    expect(context).not.toHaveProperty("assignmentId");
  });
});
