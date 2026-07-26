import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  TableClient,
  TableEntity,
  TableTransactionResponse,
  TransactionAction,
} from "@azure/data-tables";
import type {
  ActiveRoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import type {
  AuditedRoleAssignmentMutationStore,
  PrincipalLookupStore,
  RoleAssignmentAuditReader,
  RoleAssignmentReader,
} from "@pegma/authorization-storage";

import {
  createAzureTableIdentityLinkEntity,
  createAzureTableStorageAdapter,
  type AzureTableClient,
  type AzureTableStorageAdapter,
} from "./index.js";

class FakeTableClient {
  readonly rows = new Map<string, Record<string, unknown>>();
  nextEtag = 1;
  throwAfterCommit = false;
  failActionIndex: number | undefined;
  forcedGetError:
    | (Error & {
        readonly statusCode: number;
        readonly details?: { readonly errorCode: string };
      })
    | undefined;
  afterYield:
    | ((row: Readonly<Record<string, unknown>>) => Promise<void> | void)
    | undefined;
  listYieldCount = 0;

  private key(partitionKey: string, rowKey: string): string {
    return `${partitionKey}\u0000${rowKey}`;
  }

  private copy(value: Record<string, unknown>): Record<string, unknown> {
    return structuredClone(value);
  }

  put(entity: TableEntity): void {
    this.rows.set(
      this.key(entity.partitionKey, entity.rowKey),
      this.copy({ ...entity, etag: `"${this.nextEtag++}"` }),
    );
  }

  async getEntity<T extends object>(
    partitionKey: string,
    rowKey: string,
  ): Promise<T> {
    if (this.forcedGetError !== undefined) {
      throw this.forcedGetError;
    }
    const row = this.rows.get(this.key(partitionKey, rowKey));
    if (row === undefined) {
      throw Object.assign(new Error("not found"), {
        statusCode: 404,
        details: { errorCode: "EntityNotFound" },
      });
    }
    return this.copy(row) as T;
  }

  listEntities<T extends object>(options?: {
    readonly queryOptions?: { readonly filter?: string };
  }): AsyncIterable<T> {
    const filter = options?.queryOptions?.filter ?? "";
    const quoted = [...filter.matchAll(/'(.*?)'/g)].map((match) =>
      (match[1] ?? "").replaceAll("''", "'"),
    );
    const [partitionKey, lower, upper] = quoted;
    const rows = [...this.rows.values()]
      .filter(
        (row) =>
          row.partitionKey === partitionKey &&
          typeof row.rowKey === "string" &&
          row.rowKey >= (lower ?? "") &&
          row.rowKey < (upper ?? "\uffff"),
      )
      .sort((left, right) =>
        String(left.rowKey).localeCompare(String(right.rowKey)),
      )
      .map((row) => this.copy(row) as T);
    const self = this;
    return {
      async *[Symbol.asyncIterator]() {
        for (const row of rows) {
          self.listYieldCount += 1;
          yield row;
          const afterYield = self.afterYield;
          if (afterYield !== undefined) {
            self.afterYield = undefined;
            await afterYield(row as Readonly<Record<string, unknown>>);
          }
        }
      },
    };
  }

  async submitTransaction(
    actions: TransactionAction[],
  ): Promise<TableTransactionResponse> {
    const next = new Map(
      [...this.rows.entries()].map(([key, value]) => [key, this.copy(value)]),
    );
    const subResponses: Array<{ status: number; etag?: string }> = [];
    for (const [actionIndex, action] of actions.entries()) {
      if (actionIndex === this.failActionIndex) {
        this.failActionIndex = undefined;
        throw Object.assign(new Error("injected transaction failure"), {
          statusCode: 500,
        });
      }
      const [operation, entity] = action;
      const key = this.key(entity.partitionKey, entity.rowKey);
      const current = next.get(key);
      if (operation === "create") {
        if (current !== undefined) {
          throw Object.assign(new Error("conflict"), { statusCode: 409 });
        }
        const etag = `"${this.nextEtag++}"`;
        next.set(key, this.copy({ ...entity, etag }));
        subResponses.push({ status: 201, etag });
      } else if (operation === "update") {
        const options = action[3];
        if (current === undefined || current.etag !== options?.etag) {
          throw Object.assign(new Error("precondition failed"), {
            statusCode: 412,
          });
        }
        const etag = `"${this.nextEtag++}"`;
        next.set(key, this.copy({ ...entity, etag }));
        subResponses.push({ status: 204, etag });
      } else {
        if (current === undefined) {
          throw Object.assign(new Error("not found"), { statusCode: 404 });
        }
        next.delete(key);
        subResponses.push({ status: 204 });
      }
    }
    this.rows.clear();
    for (const [key, value] of next) {
      this.rows.set(key, value);
    }
    if (this.throwAfterCommit) {
      this.throwAfterCommit = false;
      throw Object.assign(new Error("response lost"), { code: "ECONNRESET" });
    }
    return {
      status: 202,
      subResponses,
      getResponseForEntity: (rowKey) =>
        subResponses[
          actions.findIndex(([, entity]) => entity.rowKey === rowKey)
        ],
    };
  }

  asClient(): AzureTableClient {
    return this as unknown as AzureTableClient;
  }
}

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

const makeAdapter = (
  client = new FakeTableClient(),
  applicationId = "application_alpha",
) => ({
  client,
  adapter: createAzureTableStorageAdapter({
    tableClient: client.asClient(),
    applicationId,
  }),
});

const setSelectionFenceCount = (
  client: FakeTableClient,
  activeCount: number,
): void => {
  const fence = [...client.rows.entries()].find(
    ([, row]) => row.entityKind === "selection_fence",
  );
  if (fence === undefined) {
    throw new Error("expected selection fence row");
  }
  client.rows.set(fence[0], {
    ...fence[1],
    activeCount,
  });
};

const requireGrant = async (
  adapter: AzureTableStorageAdapter,
  assignment: ActiveRoleAssignment,
  auditEventId = `grant:${assignment.id}`,
) => {
  const result = await adapter.grantRoleAssignmentWithAudit({
    assignment,
    auditEventId,
  });
  if (result.status !== "granted") {
    throw new Error(`expected granted, received ${result.status}`);
  }
  return result;
};

describe("createAzureTableStorageAdapter", () => {
  it("exposes only readers and safe combined mutations", () => {
    const { adapter } = makeAdapter();
    expectTypeOf(adapter).toMatchTypeOf<PrincipalLookupStore>();
    expectTypeOf(adapter).toMatchTypeOf<RoleAssignmentReader>();
    expectTypeOf(adapter).toMatchTypeOf<RoleAssignmentAuditReader>();
    expectTypeOf(adapter).toMatchTypeOf<AuditedRoleAssignmentMutationStore>();
    expectTypeOf<TableClient>().toMatchTypeOf<AzureTableClient>();
    expect(Object.isFrozen(adapter)).toBe(true);
    expect("createRoleAssignment" in adapter).toBe(false);
    expect("revokeRoleAssignment" in adapter).toBe(false);
    expect("appendRoleAssignmentAuditEvent" in adapter).toBe(false);
  });

  it("resolves exact hostile identity tuples in the bound application only", async () => {
    const client = new FakeTableClient();
    const alpha = makeAdapter(client, "app/#/alpha");
    const beta = makeAdapter(client, "app/#/beta");
    client.put(
      createAzureTableIdentityLinkEntity("app/#/alpha", {
        key: {
          issuer: "https://issuer.example/a|b\u0000?",
          subject: "__proto__/\\#?",
        },
        principalId: "principal_alpha",
      }),
    );

    await expect(
      alpha.adapter.resolvePrincipalId({
        issuer: "https://issuer.example/a|b\u0000?",
        subject: "__proto__/\\#?",
      }),
    ).resolves.toBe("principal_alpha");
    await expect(
      alpha.adapter.resolvePrincipalId({
        issuer: "https://issuer.example/a|b\u0000?",
        subject: "__proto__/\\#?x",
      }),
    ).resolves.toBeNull();
    await expect(
      beta.adapter.resolvePrincipalId({
        issuer: "https://issuer.example/a|b\u0000?",
        subject: "__proto__/\\#?",
      }),
    ).resolves.toBeNull();
  });

  it("treats only entity-level 404 errors as definitive absence", async () => {
    const { client, adapter } = makeAdapter();
    client.forcedGetError = Object.assign(new Error("Azurite entity missing"), {
      statusCode: 404,
      details: { errorCode: "ResourceNotFound" },
    });
    await expect(
      adapter.resolvePrincipalId({ issuer: "issuer", subject: "subject" }),
    ).resolves.toBeNull();

    client.forcedGetError = Object.assign(new Error("table missing"), {
      statusCode: 404,
      details: { errorCode: "TableNotFound" },
    });
    await expect(
      adapter.resolvePrincipalId({ issuer: "issuer", subject: "subject" }),
    ).rejects.toThrow("table missing");

    client.forcedGetError = Object.assign(new Error("service unavailable"), {
      statusCode: 503,
    });
    await expect(adapter.getRoleAssignment("assignment")).rejects.toThrow(
      "service unavailable",
    );
  });

  it("atomically grants, reads, audits, and revokes frozen detached records", async () => {
    const { adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_alpha", {
      scope: organizationScope,
    });
    const grant = await requireGrant(adapter, assignment);
    expect(grant.record.assignment).toEqual(assignment);
    expect(grant.auditRecord.sequence).toBe(1);
    expect(Object.isFrozen(grant.record.assignment)).toBe(true);
    expect(Object.isFrozen(grant.record.assignment.scope)).toBe(true);

    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        organizationScope,
      ),
    ).resolves.toEqual([assignment]);
    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        applicationScope,
      ),
    ).resolves.toEqual([]);

    const revoke = await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: assignment.id,
      expectedConcurrencyToken: grant.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: assignment.grantedAtEpochMs + 1,
      reason: "rotation",
      auditEventId: "revoke:assignment_alpha",
    });
    expect(revoke.status).toBe("revoked");
    if (revoke.status !== "revoked") {
      throw new Error("expected revoked");
    }
    expect(revoke.record.concurrencyToken).not.toBe(
      grant.record.concurrencyToken,
    );
    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        organizationScope,
      ),
    ).resolves.toEqual([]);
    await expect(
      adapter.listRoleAssignmentAuditEvents(assignment.id),
    ).resolves.toMatchObject([
      { sequence: 1, event: { kind: "granted" } },
      { sequence: 2, event: { kind: "revoked" } },
    ]);
  });

  it("returns exact grant and revoke replays without reactivation", async () => {
    const { adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_replay");
    const grant = await requireGrant(adapter, assignment, "event_grant");
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: "event_grant",
      }),
    ).resolves.toMatchObject({ status: "unchanged" });
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: "different_grant_event",
      }),
    ).resolves.toEqual({
      status: "conflict",
      reason: "lifecycle_position",
    });

    const command = {
      assignmentId: assignment.id,
      expectedConcurrencyToken: grant.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: assignment.grantedAtEpochMs + 1,
      auditEventId: "event_revoke",
    } as const;
    await expect(
      adapter.revokeRoleAssignmentWithAudit(command),
    ).resolves.toMatchObject({ status: "revoked" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit(command),
    ).resolves.toMatchObject({ status: "unchanged" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...command,
        expectedConcurrencyToken: `${grant.record.concurrencyToken}x`,
      }),
    ).resolves.toEqual({
      status: "conflict",
      reason: "concurrency",
    });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        ...command,
        auditEventId: "different_revoke_event",
      }),
    ).resolves.toEqual({
      status: "conflict",
      reason: "lifecycle_position",
    });
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: "event_grant",
      }),
    ).resolves.toMatchObject({ status: "unchanged" });
    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        assignment.scope,
      ),
    ).resolves.toEqual([]);
  });

  it("enforces assignment, active-tuple, event, lifecycle, and token conflicts", async () => {
    const { adapter } = makeAdapter();
    const first = activeAssignment("assignment_one");
    const grant = await requireGrant(adapter, first, "event_one");

    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment: activeAssignment("assignment_one", { role: "admin" }),
        auditEventId: "event_other",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "assignment_id" });
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment: activeAssignment("assignment_two"),
        auditEventId: "event_two",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "active_tuple" });
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment: activeAssignment("assignment_three", { role: "admin" }),
        auditEventId: "event_one",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "event_id" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: first.id,
        expectedConcurrencyToken: "*",
        revokedBy: revoker,
        revokedAtEpochMs: first.grantedAtEpochMs + 1,
        auditEventId: "event_revoke",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: first.id,
        expectedConcurrencyToken: 42 as unknown as string,
        revokedBy: revoker,
        revokedAtEpochMs: first.grantedAtEpochMs + 1,
        auditEventId: "event_revoke",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: first.id,
        expectedConcurrencyToken: `${grant.record.concurrencyToken}x`,
        revokedBy: revoker,
        revokedAtEpochMs: first.grantedAtEpochMs + 1,
        auditEventId: "event_revoke",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "concurrency" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: first.id,
        expectedConcurrencyToken: grant.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: first.grantedAtEpochMs - 1,
        auditEventId: "event_revoke",
      }),
    ).resolves.toEqual({ status: "conflict", reason: "lifecycle" });
  });

  it("leaves no partial rows when a transaction action fails", async () => {
    const { client, adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_rollback");
    client.failActionIndex = 3;
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: "event_rollback",
      }),
    ).rejects.toThrow("injected transaction failure");
    await expect(adapter.getRoleAssignment(assignment.id)).resolves.toBeNull();
    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        assignment.scope,
      ),
    ).resolves.toEqual([]);
    await expect(
      adapter.listRoleAssignmentAuditEvents(assignment.id),
    ).resolves.toEqual([]);
  });

  it("reconciles a committed transaction whose response is lost", async () => {
    const { client, adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_ambiguous");
    client.throwAfterCommit = true;
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: "event_ambiguous_grant",
      }),
    ).resolves.toMatchObject({ status: "unchanged" });

    const current = await adapter.getRoleAssignment(assignment.id);
    if (current === null) {
      throw new Error("missing committed assignment");
    }
    client.throwAfterCommit = true;
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: assignment.id,
        expectedConcurrencyToken: current.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: assignment.grantedAtEpochMs + 1,
        auditEventId: "event_ambiguous_revoke",
      }),
    ).resolves.toMatchObject({ status: "unchanged" });
  });

  it("retains a tuple tombstone and safely permits a fresh-ID regrant", async () => {
    const { adapter } = makeAdapter();
    const oldAssignment = activeAssignment("assignment_old");
    const oldGrant = await requireGrant(adapter, oldAssignment);
    await adapter.revokeRoleAssignmentWithAudit({
      assignmentId: oldAssignment.id,
      expectedConcurrencyToken: oldGrant.record.concurrencyToken,
      revokedBy: revoker,
      revokedAtEpochMs: oldAssignment.grantedAtEpochMs + 1,
      auditEventId: "revoke:assignment_old",
    });

    const fresh = activeAssignment("assignment_fresh", {
      grantedAtEpochMs: oldAssignment.grantedAtEpochMs + 2,
    });
    const freshGrant = await requireGrant(adapter, fresh);
    await expect(
      adapter.listActiveRoleAssignments(fresh.principalId, fresh.scope),
    ).resolves.toEqual([fresh]);
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: oldAssignment.id,
        expectedConcurrencyToken: oldGrant.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: oldAssignment.grantedAtEpochMs + 1,
        auditEventId: "revoke:assignment_old",
      }),
    ).resolves.toMatchObject({ status: "unchanged" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: fresh.id,
        expectedConcurrencyToken: freshGrant.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: fresh.grantedAtEpochMs + 1,
        auditEventId: "revoke:assignment_fresh",
      }),
    ).resolves.toMatchObject({ status: "revoked" });
    await expect(
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: oldAssignment.id,
        expectedConcurrencyToken: oldGrant.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: oldAssignment.grantedAtEpochMs + 1,
        auditEventId: "revoke:assignment_old",
      }),
    ).resolves.toMatchObject({ status: "unchanged" });
  });

  it("fully consumes large active-selection result sets", async () => {
    const { client, adapter } = makeAdapter();
    const assignments = Array.from({ length: 101 }, (_, index) =>
      activeAssignment(`assignment_${index}`, { role: `role_${index}` }),
    );
    for (const assignment of assignments) {
      await requireGrant(adapter, assignment);
    }
    client.listYieldCount = 0;
    const active = await adapter.listActiveRoleAssignments(
      "principal_alpha",
      applicationScope,
    );
    expect(active).toHaveLength(assignments.length);
    expect(client.listYieldCount).toBe(assignments.length);
  });

  it("retries a paged-style read when its selection fence changes", async () => {
    const { client, adapter } = makeAdapter();
    const first = activeAssignment("fence_first", { role: "role_first" });
    const second = activeAssignment("fence_second", { role: "role_second" });
    await requireGrant(adapter, first);
    await requireGrant(adapter, second);

    let revokedId = "";
    const replacement = activeAssignment("fence_replacement", {
      role: "role_replacement",
    });
    client.afterYield = async (row) => {
      const encoded = row.assignmentJson;
      if (typeof encoded !== "string") {
        throw new Error("expected selection assignment");
      }
      const yielded = JSON.parse(encoded) as ActiveRoleAssignment;
      revokedId = yielded.id;
      const current = await adapter.getRoleAssignment(yielded.id);
      if (current === null) {
        throw new Error("expected yielded assignment");
      }
      const revoke = await adapter.revokeRoleAssignmentWithAudit({
        assignmentId: yielded.id,
        expectedConcurrencyToken: current.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: yielded.grantedAtEpochMs + 1,
        auditEventId: `fence-revoke:${yielded.id}`,
      });
      if (revoke.status !== "revoked") {
        throw new Error("expected interleaved revocation");
      }
      await requireGrant(adapter, replacement);
    };

    const active = await adapter.listActiveRoleAssignments(
      first.principalId,
      first.scope,
    );
    expect(revokedId).not.toBe("");
    expect(active.map((assignment) => assignment.id)).not.toContain(revokedId);
    expect(active.map((assignment) => assignment.id)).toContain(replacement.id);
    expect(active).toHaveLength(2);
  });

  it("retries a grant when its active-tuple snapshot is concurrently retired", async () => {
    const { client, adapter } = makeAdapter();
    const first = activeAssignment("tuple_overlap_first");
    const firstGrant = await requireGrant(adapter, first);
    const replacement = activeAssignment("tuple_overlap_replacement", {
      grantedAtEpochMs: first.grantedAtEpochMs + 2,
    });
    client.afterYield = async () => {
      const revoke = await adapter.revokeRoleAssignmentWithAudit({
        assignmentId: first.id,
        expectedConcurrencyToken: firstGrant.record.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: first.grantedAtEpochMs + 1,
        auditEventId: "tuple_overlap_revoke",
      });
      if (revoke.status !== "revoked") {
        throw new Error("expected overlapping revocation");
      }
    };

    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment: replacement,
        auditEventId: "tuple_overlap_replacement_grant",
      }),
    ).resolves.toMatchObject({
      status: "granted",
      record: { assignment: replacement },
    });
  });

  it("fails closed when a hashed identity row contains different exact values", async () => {
    const { client, adapter } = makeAdapter();
    const entity = createAzureTableIdentityLinkEntity("application_alpha", {
      key: { issuer: "issuer", subject: "subject" },
      principalId: "principal_alpha",
    });
    client.put({ ...entity, issuer: "different-issuer" });
    await expect(
      adapter.resolvePrincipalId({ issuer: "issuer", subject: "subject" }),
    ).rejects.toThrow(/corrupt/i);
  });

  it("fails closed when an active selection loses its tuple guard", async () => {
    const { client, adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_corrupt");
    await requireGrant(adapter, assignment);
    const tuple = [...client.rows.entries()].find(
      ([, row]) => row.entityKind === "active_tuple",
    );
    if (tuple === undefined) {
      throw new Error("expected tuple row");
    }
    client.rows.delete(tuple[0]);
    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        assignment.scope,
      ),
    ).rejects.toThrow(/corrupt/i);
  });

  it("fails closed when an active assignment loses its selection row", async () => {
    const { client, adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_selection_corrupt");
    await requireGrant(adapter, assignment);
    const selection = [...client.rows.entries()].find(
      ([, row]) => row.entityKind === "active_selection",
    );
    if (selection === undefined) {
      throw new Error("expected selection row");
    }
    client.rows.delete(selection[0]);
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: `grant:${assignment.id}`,
      }),
    ).rejects.toThrow(/corrupt/i);
    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        assignment.scope,
      ),
    ).rejects.toThrow(/corrupt/i);
  });

  it.each([
    { operation: "grant", activeCount: 0 },
    { operation: "grant", activeCount: 2 },
    { operation: "revoke", activeCount: 0 },
    { operation: "revoke", activeCount: 2 },
  ] as const)(
    "rejects a $operation when the selection fence count is $activeCount",
    async ({ operation, activeCount }) => {
      const { client, adapter } = makeAdapter();
      const assignment = activeAssignment(
        `assignment_${operation}_${activeCount}`,
      );
      const grant = await requireGrant(adapter, assignment);
      setSelectionFenceCount(client, activeCount);

      if (operation === "grant") {
        await expect(
          adapter.grantRoleAssignmentWithAudit({
            assignment: activeAssignment(
              `assignment_${operation}_${activeCount}_next`,
              { role: "admin" },
            ),
            auditEventId: `event_${operation}_${activeCount}_next`,
          }),
        ).rejects.toThrow(/corrupt/i);
      } else {
        await expect(
          adapter.revokeRoleAssignmentWithAudit({
            assignmentId: assignment.id,
            expectedConcurrencyToken: grant.record.concurrencyToken,
            revokedBy: revoker,
            revokedAtEpochMs: assignment.grantedAtEpochMs + 1,
            auditEventId: `event_${operation}_${activeCount}`,
          }),
        ).rejects.toThrow(/corrupt/i);
      }
    },
  );

  it("fails closed instead of treating an orphan active tuple as a conflict", async () => {
    const { client, adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_orphan_tuple");
    await requireGrant(adapter, assignment);
    for (const [key, row] of client.rows) {
      if (row.entityKind !== "active_tuple") {
        client.rows.delete(key);
      }
    }

    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment: activeAssignment("assignment_orphan_tuple_next"),
        auditEventId: "event_orphan_tuple_next",
      }),
    ).rejects.toThrow(/corrupt/i);
  });

  it("fails closed when an active assignment loses its grant audit", async () => {
    const { client, adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_audit_corrupt");
    await requireGrant(adapter, assignment);
    const audit = [...client.rows.entries()].find(
      ([, row]) => row.entityKind === "role_audit" && row.sequence === 1,
    );
    if (audit === undefined) {
      throw new Error("expected grant audit");
    }
    client.rows.delete(audit[0]);
    await expect(
      adapter.listActiveRoleAssignments(
        assignment.principalId,
        assignment.scope,
      ),
    ).rejects.toThrow(/corrupt/i);
  });

  it("fails closed when an event guard no longer matches its hashed ID", async () => {
    const { client, adapter } = makeAdapter();
    const assignment = activeAssignment("assignment_event_corrupt");
    await requireGrant(adapter, assignment, "event_corrupt");
    const guard = [...client.rows.entries()].find(
      ([, row]) => row.entityKind === "audit_event_guard",
    );
    if (guard === undefined) {
      throw new Error("expected event guard");
    }
    client.rows.set(guard[0], {
      ...guard[1],
      auditEventId: "different_event",
    });
    await expect(
      adapter.grantRoleAssignmentWithAudit({
        assignment: activeAssignment("another_assignment", { role: "admin" }),
        auditEventId: "event_corrupt",
      }),
    ).rejects.toThrow(/corrupt/i);
  });

  it("isolates identical IDs across application partitions", async () => {
    const client = new FakeTableClient();
    const alpha = makeAdapter(client, "application_alpha").adapter;
    const beta = makeAdapter(client, "application_beta").adapter;
    const assignment = activeAssignment("same_assignment");
    await requireGrant(alpha, assignment, "same_event");
    await requireGrant(beta, assignment, "same_event");
    await expect(alpha.getRoleAssignment(assignment.id)).resolves.toMatchObject(
      { assignment },
    );
    await expect(beta.getRoleAssignment(assignment.id)).resolves.toMatchObject({
      assignment,
    });
  });

  it("makes concurrent same-tuple grants single-winner", async () => {
    const { adapter } = makeAdapter();
    const [left, right] = await Promise.all([
      adapter.grantRoleAssignmentWithAudit({
        assignment: activeAssignment("race_left"),
        auditEventId: "race_event_left",
      }),
      adapter.grantRoleAssignmentWithAudit({
        assignment: activeAssignment("race_right"),
        auditEventId: "race_event_right",
      }),
    ]);
    expect([left.status, right.status].sort()).toEqual(["conflict", "granted"]);
  });

  it("classifies concurrent same-record commands with different event IDs", async () => {
    const { adapter } = makeAdapter();
    const assignment = activeAssignment("same_record_race");
    const grants = await Promise.all([
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: "grant_race_left",
      }),
      adapter.grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: "grant_race_right",
      }),
    ]);
    expect(grants.map((result) => result.status).sort()).toEqual([
      "conflict",
      "granted",
    ]);
    expect(grants.find((result) => result.status === "conflict")).toMatchObject(
      { reason: "lifecycle_position" },
    );

    const current = await adapter.getRoleAssignment(assignment.id);
    if (current === null) {
      throw new Error("expected assignment");
    }
    const revocations = await Promise.all([
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: assignment.id,
        expectedConcurrencyToken: current.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: assignment.grantedAtEpochMs + 1,
        auditEventId: "revoke_race_left",
      }),
      adapter.revokeRoleAssignmentWithAudit({
        assignmentId: assignment.id,
        expectedConcurrencyToken: current.concurrencyToken,
        revokedBy: revoker,
        revokedAtEpochMs: assignment.grantedAtEpochMs + 1,
        auditEventId: "revoke_race_right",
      }),
    ]);
    expect(revocations.map((result) => result.status).sort()).toEqual([
      "conflict",
      "revoked",
    ]);
    expect(
      revocations.find((result) => result.status === "conflict"),
    ).toMatchObject({ reason: "lifecycle_position" });
  });
});
