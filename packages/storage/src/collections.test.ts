import { describe, expect, it } from "vitest";

import type { ActiveRoleAssignment } from "@pegma/authorization-contracts";
import {
  createMemoryStore,
  defineCollection,
  StorageError,
  type CollectionDefinition,
  type CollectionStore,
  type EntityKey,
  type Store,
  type StoredRecord,
  type StoredValue,
} from "@pegma/storage-core";

import {
  assignmentPointers,
  assignmentRecordId,
  auditRecordId,
  authorizationRecords,
  GRANT_SEQUENCE,
  identityLinkKey,
  identityLinks,
  pointerKey,
  recordPartition,
  REVOKE_SEQUENCE,
  roleHolderPartition,
  roleHolders,
  tupleRecordId,
  type AuthorizationRecord,
  type RecordLocation,
  type StoredAssignment,
  type StoredAssignmentPointer,
  type StoredAudit,
  type StoredIdentityLink,
  type StoredRoleHolder,
  type StoredTuple,
} from "./collections.js";
import { createRoleStore, storedRecordsEqual } from "./role-store.js";

const APPLICATION_ID = "application_one";
const ASSIGNMENT_ID = "assignment_one";
const PRINCIPAL_ID = "principal_one";
const ROLE = "support";
const GRANT_EVENT_ID = "grant_one";
const applicationScope = { kind: "application" } as const;
const location: RecordLocation = {
  applicationId: APPLICATION_ID,
  principalId: PRINCIPAL_ID,
  scope: applicationScope,
};
const assignment: ActiveRoleAssignment = {
  id: ASSIGNMENT_ID,
  principalId: PRINCIPAL_ID,
  role: ROLE,
  scope: applicationScope,
  grantedBy: { kind: "principal", principalId: "principal_admin" },
  grantedAtEpochMs: 1_700_000_000_000,
  status: "active",
};
const storedAssignment: StoredAssignment = {
  kind: "assignment",
  ...location,
  assignment,
  grantEventId: GRANT_EVENT_ID,
  revokeEventId: null,
};
const pointer: StoredAssignmentPointer = {
  ...location,
  assignmentId: ASSIGNMENT_ID,
  role: ROLE,
};

const replaceFields = (
  record: StoredRecord,
  replacements: Readonly<Record<string, StoredValue>>,
): StoredRecord => ({ ...record, ...replacements });

const omitField = (record: StoredRecord, field: string): StoredRecord => {
  const copy: Record<string, StoredValue> = { ...record };
  delete copy[field];
  return copy;
};

const putRaw = async (
  store: Store,
  name: string,
  key: EntityKey,
  record: StoredRecord,
): Promise<void> => {
  const collection = store.collection(
    defineCollection<StoredRecord>({
      name,
      key: () => key,
      codec: {
        encode: (value) => value,
        decode: (value) => value,
      },
    }),
  );
  await collection.put(record);
};

const putPointer = (store: Store): Promise<void> =>
  putRaw(
    store,
    assignmentPointers.name,
    pointerKey(APPLICATION_ID, ASSIGNMENT_ID),
    assignmentPointers.codec.encode(pointer),
  );

const putAssignment = (
  store: Store,
  record = authorizationRecords.codec.encode(storedAssignment),
): Promise<void> =>
  putRaw(
    store,
    authorizationRecords.name,
    {
      partition: recordPartition(location),
      id: assignmentRecordId(ASSIGNMENT_ID),
    },
    record,
  );

const wrapAuthorizationRecords = (
  store: Store,
  wrap: (
    collection: CollectionStore<AuthorizationRecord>,
  ) => CollectionStore<AuthorizationRecord>,
): Store => ({
  collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
    const collection = store.collection(definition);
    if (definition.name !== authorizationRecords.name) {
      return collection;
    }
    return wrap(
      collection as unknown as CollectionStore<AuthorizationRecord>,
    ) as unknown as CollectionStore<T>;
  },
});

const requireGrant = async (store: Store) => {
  const adapter = createRoleStore(store, APPLICATION_ID);
  const result = await adapter.grantRoleAssignmentWithAudit({
    assignment,
    auditEventId: GRANT_EVENT_ID,
  });
  if (result.status !== "granted") {
    throw new Error(`expected granted, received ${result.status}`);
  }
  return adapter;
};

describe("storage collection codecs", () => {
  const activeRecord = authorizationRecords.codec.encode(storedAssignment);

  it("round-trips exact active and revoked assignment records", () => {
    expect(authorizationRecords.codec.decode(activeRecord)).toEqual(
      storedAssignment,
    );

    const revoked: StoredAssignment = {
      ...storedAssignment,
      assignment: {
        ...assignment,
        status: "revoked",
        revokedBy: { kind: "system", systemId: "role-administration" },
        revokedAtEpochMs: assignment.grantedAtEpochMs + 1,
        reason: "routine cleanup",
      },
      revokeEventId: "revoke_one",
    };
    expect(
      authorizationRecords.codec.decode(
        authorizationRecords.codec.encode(revoked),
      ),
    ).toEqual(revoked);
  });

  it.each([
    ["unknown status", replaceFields(activeRecord, { status: "pending" })],
    ["missing field", omitField(activeRecord, "role")],
    ["extra field", replaceFields(activeRecord, { extra: "value" })],
    [
      "wrong field type",
      replaceFields(activeRecord, { grantedAtEpochMs: "1700000000000" }),
    ],
    ["unknown scope", replaceFields(activeRecord, { scopeKind: "tenant" })],
    [
      "unknown actor",
      replaceFields(activeRecord, { grantedByKind: "operator" }),
    ],
  ])("rejects an assignment record with %s", (_label, record) => {
    expect(() => authorizationRecords.codec.decode(record)).toThrow(
      StorageError,
    );
  });

  it("rejects accessor-backed fields", () => {
    const record = { ...activeRecord };
    Object.defineProperty(record, "role", {
      enumerable: true,
      get: () => ROLE,
    });
    expect(() =>
      authorizationRecords.codec.decode(record as StoredRecord),
    ).toThrow(StorageError);
  });

  it("treats symbol-bearing stored records as unequal", () => {
    const extra = Symbol("extra");
    const clean = { field: "value" } as StoredRecord;
    const withSymbol = {
      field: "value",
      [extra]: "extra",
    } as unknown as StoredRecord;

    expect(storedRecordsEqual(clean, withSymbol)).toBe(false);
    expect(storedRecordsEqual(withSymbol, clean)).toBe(false);
    expect(storedRecordsEqual(withSymbol, withSymbol)).toBe(false);
  });

  it("rejects unknown record kinds and lifecycle positions", () => {
    const tuple: StoredTuple = {
      kind: "tuple",
      ...location,
      role: ROLE,
      activeAssignmentId: ASSIGNMENT_ID,
    };
    expect(() =>
      authorizationRecords.codec.decode(
        replaceFields(authorizationRecords.codec.encode(tuple), {
          kind: "other",
        }),
      ),
    ).toThrow(StorageError);

    const lifecyclePosition: StoredAudit = {
      kind: "audit",
      ...location,
      assignmentId: ASSIGNMENT_ID,
      sequence: GRANT_SEQUENCE,
      eventId: GRANT_EVENT_ID,
    };
    expect(() =>
      authorizationRecords.codec.decode(
        replaceFields(authorizationRecords.codec.encode(lifecyclePosition), {
          sequence: 3,
        }),
      ),
    ).toThrow(StorageError);
  });

  it.each([
    [
      "assignment pointer",
      () =>
        assignmentPointers.codec.decode(
          replaceFields(assignmentPointers.codec.encode(pointer), {
            role: 42,
          }),
        ),
    ],
    [
      "role holder",
      () =>
        roleHolders.codec.decode(
          omitField(
            roleHolders.codec.encode({
              ...pointer,
            }),
            "principalId",
          ),
        ),
    ],
    [
      "identity link",
      () =>
        identityLinks.codec.decode({
          applicationId: APPLICATION_ID,
          issuer: "issuer",
          subject: "subject",
          principalId: 42,
        }),
    ],
  ])("rejects a malformed %s record", (_label, decode) => {
    expect(decode).toThrow(StorageError);
  });
});

describe("storage record bindings", () => {
  it.each([
    ["application", { applicationId: "application_two" }],
    ["assignment", { assignmentId: "assignment_two" }],
  ] as const)(
    "rejects a pointer with a mismatched %s",
    async (_label, change) => {
      const store = createMemoryStore();
      await putRaw(
        store,
        assignmentPointers.name,
        pointerKey(APPLICATION_ID, ASSIGNMENT_ID),
        replaceFields(assignmentPointers.codec.encode(pointer), change),
      );
      await expect(
        createRoleStore(store, APPLICATION_ID).getRoleAssignment(ASSIGNMENT_ID),
      ).rejects.toBeInstanceOf(StorageError);
    },
  );

  it("rejects an assignment row stored under a different physical id", async () => {
    const store = createMemoryStore();
    await putRaw(
      store,
      authorizationRecords.name,
      {
        partition: recordPartition(location),
        id: assignmentRecordId("assignment_two"),
      },
      authorizationRecords.codec.encode(storedAssignment),
    );
    await expect(
      createRoleStore(store, APPLICATION_ID).listRoleAssignments(
        PRINCIPAL_ID,
        applicationScope,
      ),
    ).rejects.toThrow("changed during read; retry");
  });

  it("reports a retry when a listed row changes before confirmation", async () => {
    const base = createMemoryStore();
    await putAssignment(base);
    let listed = false;
    const store = wrapAuthorizationRecords(base, (collection) => ({
      ...collection,
      async list(partition) {
        const found = await collection.list(partition);
        listed = true;
        return found;
      },
      async get(key) {
        return listed ? null : collection.get(key);
      },
    }));

    await expect(
      createRoleStore(store, APPLICATION_ID).listRoleAssignments(
        PRINCIPAL_ID,
        applicationScope,
      ),
    ).rejects.toThrow("changed during read; retry");
  });

  it("confirms principal listing rows in bounded batches", async () => {
    const base = createMemoryStore();
    const writer = createRoleStore(base, APPLICATION_ID);
    for (let index = 0; index < 17; index += 1) {
      const next = {
        ...assignment,
        id: `assignment_${String(index)}`,
        role: `role_${String(index)}`,
      };
      const result = await writer.grantRoleAssignmentWithAudit({
        assignment: next,
        auditEventId: `grant_${String(index)}`,
      });
      expect(result.status).toBe("granted");
    }

    let active = 0;
    let maximum = 0;
    let calls = 0;
    const store = wrapAuthorizationRecords(base, (collection) => ({
      ...collection,
      async get(key) {
        active += 1;
        calls += 1;
        maximum = Math.max(maximum, active);
        await Promise.resolve();
        try {
          return await collection.get(key);
        } finally {
          active -= 1;
        }
      },
    }));

    await expect(
      createRoleStore(store, APPLICATION_ID).listRoleAssignments(
        PRINCIPAL_ID,
        applicationScope,
      ),
    ).resolves.toHaveLength(17);
    expect(calls).toBe(51);
    expect(maximum).toBe(16);
  });

  it.each([
    ["application", { applicationId: "application_two" }],
    ["principal", { principalId: "principal_two" }],
    [
      "scope",
      { scopeKind: "organization", organizationId: "organization_two" },
    ],
    ["assignment", { assignmentId: "assignment_two" }],
    ["role", { role: "viewer" }],
  ] as const)(
    "rejects an assignment row with a mismatched %s binding",
    async (_label, change) => {
      const store = createMemoryStore();
      await putPointer(store);
      await putAssignment(
        store,
        replaceFields(
          authorizationRecords.codec.encode(storedAssignment),
          change,
        ),
      );
      await expect(
        createRoleStore(store, APPLICATION_ID).getRoleAssignment(ASSIGNMENT_ID),
      ).rejects.toBeInstanceOf(StorageError);
    },
  );

  it("rejects a role-holder row stored under a different physical id", async () => {
    const store = createMemoryStore();
    const adapter = await requireGrant(store);
    const correctKey = {
      partition: roleHolderPartition(APPLICATION_ID, ROLE, applicationScope),
      id: ASSIGNMENT_ID,
    };
    const holderRows = store.collection(
      defineCollection<StoredRecord>({
        name: roleHolders.name,
        key: () => correctKey,
        codec: {
          encode: (value) => value,
          decode: (value) => value,
        },
      }),
    );
    const existing = await holderRows.get(correctKey);
    if (existing === null) {
      throw new Error("expected a role-holder row");
    }
    await holderRows.delete(correctKey);
    await putRaw(
      store,
      roleHolders.name,
      { ...correctKey, id: "assignment_two" },
      existing,
    );
    await expect(
      adapter.listActiveRoleAssignmentsByRole(ROLE, applicationScope),
    ).rejects.toBeInstanceOf(StorageError);
  });

  it("rejects an assignment pointer stored under a different physical id", async () => {
    const store = createMemoryStore();
    await putRaw(
      store,
      assignmentPointers.name,
      {
        partition: APPLICATION_ID,
        id: "assignment_two",
      },
      assignmentPointers.codec.encode(pointer),
    );
    await expect(
      createRoleStore(store, APPLICATION_ID).rebuildRoleHolderIndex(),
    ).rejects.toBeInstanceOf(StorageError);
  });

  it.each([
    ["application", { applicationId: "application_two" }],
    ["principal", { principalId: "principal_two" }],
    [
      "scope",
      { scopeKind: "organization", organizationId: "organization_two" },
    ],
  ] as const)(
    "rejects a partition row with a mismatched %s binding",
    async (_label, change) => {
      const store = createMemoryStore();
      await putAssignment(
        store,
        replaceFields(
          authorizationRecords.codec.encode(storedAssignment),
          change,
        ),
      );
      await expect(
        createRoleStore(store, APPLICATION_ID).listRoleAssignments(
          PRINCIPAL_ID,
          applicationScope,
        ),
      ).rejects.toThrow("corrupt record");
    },
  );

  it("rejects a tuple whose role disagrees with its requested key", async () => {
    const store = createMemoryStore();
    const tuple: StoredTuple = {
      kind: "tuple",
      ...location,
      role: "viewer",
      activeAssignmentId: null,
    };
    await putRaw(
      store,
      authorizationRecords.name,
      {
        partition: recordPartition(location),
        id: tupleRecordId(ROLE),
      },
      authorizationRecords.codec.encode(tuple),
    );
    await expect(
      createRoleStore(store, APPLICATION_ID).grantRoleAssignmentWithAudit({
        assignment,
        auditEventId: GRANT_EVENT_ID,
      }),
    ).rejects.toBeInstanceOf(StorageError);
  });

  it.each([
    ["application", { applicationId: "application_two" }],
    ["principal", { principalId: "principal_two" }],
    [
      "scope",
      { scopeKind: "organization", organizationId: "organization_two" },
    ],
    ["role", { role: "viewer" }],
    ["assignment", { assignmentId: "assignment_two" }],
  ] as const)(
    "rejects a role-holder row with a mismatched %s binding",
    async (_label, change) => {
      const store = createMemoryStore();
      const adapter = await requireGrant(store);
      const holder: StoredRoleHolder = {
        ...location,
        assignmentId: ASSIGNMENT_ID,
        role: ROLE,
      };
      await putRaw(
        store,
        roleHolders.name,
        {
          partition: roleHolderPartition(
            APPLICATION_ID,
            ROLE,
            applicationScope,
          ),
          id: ASSIGNMENT_ID,
        },
        replaceFields(roleHolders.codec.encode(holder), change),
      );
      await expect(
        adapter.listActiveRoleAssignmentsByRole(ROLE, applicationScope),
      ).rejects.toBeInstanceOf(StorageError);
    },
  );

  it.each([
    ["application", { applicationId: "application_two" }],
    ["issuer", { issuer: "issuer_two" }],
    ["subject", { subject: "subject_two" }],
  ] as const)(
    "rejects an identity row with a mismatched %s binding",
    async (_label, change) => {
      const store = createMemoryStore();
      const stored: StoredIdentityLink = {
        applicationId: APPLICATION_ID,
        link: {
          key: { issuer: "issuer_one", subject: "subject_one" },
          principalId: PRINCIPAL_ID,
        },
      };
      await putRaw(
        store,
        identityLinks.name,
        identityLinkKey(APPLICATION_ID, "issuer_one", "subject_one"),
        replaceFields(identityLinks.codec.encode(stored), change),
      );
      await expect(
        createRoleStore(store, APPLICATION_ID).resolvePrincipalId({
          issuer: "issuer_one",
          subject: "subject_one",
        }),
      ).rejects.toBeInstanceOf(StorageError);
    },
  );

  it.each([
    ["assignment", { assignmentId: "assignment_two" }],
    ["sequence", { sequence: REVOKE_SEQUENCE }],
    ["event", { eventId: "grant_two" }],
  ] as const)(
    "rejects a lifecycle row with a mismatched %s binding",
    async (_label, change) => {
      const store = createMemoryStore();
      const adapter = await requireGrant(store);
      const lifecyclePosition: StoredAudit = {
        kind: "audit",
        ...location,
        assignmentId: ASSIGNMENT_ID,
        sequence: GRANT_SEQUENCE,
        eventId: GRANT_EVENT_ID,
      };
      await putRaw(
        store,
        authorizationRecords.name,
        {
          partition: recordPartition(location),
          id: auditRecordId(ASSIGNMENT_ID, GRANT_SEQUENCE),
        },
        replaceFields(
          authorizationRecords.codec.encode(lifecyclePosition),
          change,
        ),
      );
      await expect(
        adapter.listRoleAssignmentAuditEvents(ASSIGNMENT_ID),
      ).rejects.toBeInstanceOf(StorageError);
    },
  );

  it("rejects an unexpected revoke position on an active assignment", async () => {
    const store = createMemoryStore();
    const adapter = await requireGrant(store);
    const lifecyclePosition: StoredAudit = {
      kind: "audit",
      ...location,
      assignmentId: ASSIGNMENT_ID,
      sequence: REVOKE_SEQUENCE,
      eventId: "revoke_one",
    };
    await putRaw(
      store,
      authorizationRecords.name,
      {
        partition: recordPartition(location),
        id: auditRecordId(ASSIGNMENT_ID, REVOKE_SEQUENCE),
      },
      authorizationRecords.codec.encode(lifecyclePosition),
    );
    await expect(
      adapter.listRoleAssignmentAuditEvents(ASSIGNMENT_ID),
    ).rejects.toBeInstanceOf(StorageError);
  });

  it("rejects lifecycle positions without their assignment row", async () => {
    const store = createMemoryStore();
    await putPointer(store);
    const lifecyclePosition: StoredAudit = {
      kind: "audit",
      ...location,
      assignmentId: ASSIGNMENT_ID,
      sequence: GRANT_SEQUENCE,
      eventId: GRANT_EVENT_ID,
    };
    await putRaw(
      store,
      authorizationRecords.name,
      {
        partition: recordPartition(location),
        id: auditRecordId(ASSIGNMENT_ID, GRANT_SEQUENCE),
      },
      authorizationRecords.codec.encode(lifecyclePosition),
    );

    await expect(
      createRoleStore(store, APPLICATION_ID).listRoleAssignmentAuditEvents(
        ASSIGNMENT_ID,
      ),
    ).rejects.toBeInstanceOf(StorageError);
  });

  it("rejects a miskeyed lifecycle position without its assignment row", async () => {
    const store = createMemoryStore();
    await putPointer(store);
    const lifecyclePosition: StoredAudit = {
      kind: "audit",
      ...location,
      assignmentId: ASSIGNMENT_ID,
      sequence: GRANT_SEQUENCE,
      eventId: GRANT_EVENT_ID,
    };
    await putRaw(
      store,
      authorizationRecords.name,
      {
        partition: recordPartition(location),
        id: auditRecordId("assignment_two", GRANT_SEQUENCE),
      },
      authorizationRecords.codec.encode(lifecyclePosition),
    );

    await expect(
      createRoleStore(store, APPLICATION_ID).listRoleAssignmentAuditEvents(
        ASSIGNMENT_ID,
      ),
    ).rejects.toBeInstanceOf(StorageError);
  });
});
