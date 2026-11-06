import type {
  ActiveRoleAssignment,
  IdentityLink,
  IdentityLinkKey,
  PrincipalId,
  RevokedRoleAssignment,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentId,
  RoleAssignmentScope,
  RoleName,
} from "@pegma/authorization-contracts";
import {
  createMemoryStore,
  StorageError,
  type Store,
  type StoredRecord,
  type TransactionAction,
} from "@pegma/storage-core";

import {
  assignmentPointers,
  assignmentRecordId,
  auditRecordId,
  authorizationRecords,
  GRANT_SEQUENCE,
  identityLinkKey,
  identityLinks as identityLinkCollection,
  pointerKey,
  pointerPartition,
  recordPartition,
  REVOKE_SEQUENCE,
  roleHolderPartition,
  roleHolders,
  tupleRecordId,
  type ApplicationId,
  type AuthorizationRecord,
  type RecordLocation,
  type StoredAssignment,
  type StoredAssignmentPointer,
  type StoredAudit,
  type StoredRoleHolder,
  type StoredTuple,
} from "./collections.js";
import type {
  AuditedRevokeRoleAssignmentCommand,
  AuditedRevokeRoleAssignmentResult,
  GrantRoleAssignmentCommand,
  GrantRoleAssignmentResult,
  InMemoryStorageAdapter,
  InMemoryStorageAdapterOptions,
  LinkIdentityResult,
  RebuildRoleHolderIndexResult,
  SequencedRoleAssignmentAuditEvent,
  VersionedRoleAssignment,
} from "./index.js";

const snapshotScope = (scope: RoleAssignmentScope): RoleAssignmentScope => {
  if (scope.kind === "application") {
    return Object.freeze({ kind: "application" });
  }
  if (scope.kind === "organization") {
    return Object.freeze({
      kind: "organization",
      organizationId: scope.organizationId,
    });
  }
  throw new TypeError("role assignment scope must be explicit");
};

const snapshotActor = (actor: RoleAssignmentActor): RoleAssignmentActor => {
  if (actor.kind === "principal") {
    return Object.freeze({
      kind: "principal",
      principalId: actor.principalId,
    });
  }
  if (actor.kind === "system") {
    return Object.freeze({ kind: "system", systemId: actor.systemId });
  }
  throw new TypeError("role assignment actor must be explicit");
};

const snapshotIdentityLink = (link: IdentityLink): IdentityLink =>
  Object.freeze({
    key: Object.freeze({
      issuer: link.key.issuer,
      subject: link.key.subject,
    }),
    principalId: link.principalId,
  });

const requireLifecycleTimestamp = (value: number, field: string): number => {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new RangeError(`${field} must be a non-negative safe integer`);
  }
  return value;
};

const snapshotActive = (
  assignment: ActiveRoleAssignment,
): ActiveRoleAssignment => {
  if (assignment.status !== "active") {
    throw new TypeError("a grant requires an active role assignment");
  }
  return Object.freeze({
    id: assignment.id,
    principalId: assignment.principalId,
    role: assignment.role,
    scope: snapshotScope(assignment.scope),
    grantedBy: snapshotActor(assignment.grantedBy),
    grantedAtEpochMs: requireLifecycleTimestamp(
      assignment.grantedAtEpochMs,
      "grantedAtEpochMs",
    ),
    status: "active",
  });
};

/** The active grant evidence a revoked record still carries. */
const activeForm = (assignment: RoleAssignment): ActiveRoleAssignment =>
  Object.freeze({
    id: assignment.id,
    principalId: assignment.principalId,
    role: assignment.role,
    scope: snapshotScope(assignment.scope),
    grantedBy: snapshotActor(assignment.grantedBy),
    grantedAtEpochMs: assignment.grantedAtEpochMs,
    status: "active",
  });

const freezeAssignment = <Assignment extends RoleAssignment>(
  assignment: Assignment,
): Assignment => {
  Object.freeze(assignment.scope);
  Object.freeze(assignment.grantedBy);
  if (assignment.status === "revoked") {
    Object.freeze(assignment.revokedBy);
  }
  return Object.freeze(assignment);
};

const freezeVersioned = <Assignment extends RoleAssignment>(
  record: VersionedRoleAssignment<Assignment>,
): VersionedRoleAssignment<Assignment> => {
  freezeAssignment(record.assignment);
  return Object.freeze(record);
};

const freezeAuditRecord = (
  record: SequencedRoleAssignmentAuditEvent,
): SequencedRoleAssignmentAuditEvent => {
  freezeAssignment(record.event.assignment);
  Object.freeze(record.event);
  return Object.freeze(record);
};

/** Authoritative point reads issued concurrently by one by-role read. */
const HOLDER_VERIFY_BATCH = 16;

const byGrantThenId = (left: RoleAssignment, right: RoleAssignment): number =>
  left.grantedAtEpochMs !== right.grantedAtEpochMs
    ? left.grantedAtEpochMs - right.grantedAtEpochMs
    : left.id < right.id
      ? -1
      : left.id > right.id
        ? 1
        : 0;

const scopesEqual = (
  left: RoleAssignmentScope,
  right: RoleAssignmentScope,
): boolean =>
  left.kind === "application"
    ? right.kind === "application"
    : right.kind === "organization" &&
      left.organizationId === right.organizationId;

/**
 * Whether an existing pointer describes something other than this grant.
 *
 * A pointer is immutable and an assignment id is single-use, so a pointer that
 * is already present must describe exactly the grant being attempted. Anything
 * else means the id is already spoken for: either by a live assignment in a
 * different partition, or by an earlier attempt that was refused after its
 * pointer had been written. Both cases must be refused, because `locate` can
 * only ever resolve an id through its first pointer — a second lifecycle under
 * one id would be active yet unreadable and unrevocable by that id.
 */
const pointsElsewhere = (
  pointer: StoredAssignmentPointer,
  location: RecordLocation,
  role: RoleName,
): boolean =>
  pointer.applicationId !== location.applicationId ||
  pointer.principalId !== location.principalId ||
  !scopesEqual(pointer.scope, location.scope) ||
  pointer.role !== role;

const actorsEqual = (
  left: RoleAssignmentActor,
  right: RoleAssignmentActor,
): boolean =>
  left.kind === "principal"
    ? right.kind === "principal" && left.principalId === right.principalId
    : right.kind === "system" && left.systemId === right.systemId;

const revocationsEqual = (
  assignment: RevokedRoleAssignment,
  command: AuditedRevokeRoleAssignmentCommand,
): boolean =>
  actorsEqual(assignment.revokedBy, command.revokedBy) &&
  assignment.revokedAtEpochMs === command.revokedAtEpochMs &&
  assignment.reason === command.reason;

const conflict = <Reason extends string>(
  reason: Reason,
): Readonly<{ readonly status: "conflict"; readonly reason: Reason }> =>
  Object.freeze({ status: "conflict", reason });

const snapshotRevokeCommand = (
  command: AuditedRevokeRoleAssignmentCommand,
): AuditedRevokeRoleAssignmentCommand =>
  Object.freeze({
    assignmentId: command.assignmentId,
    expectedConcurrencyToken: command.expectedConcurrencyToken,
    revokedBy: snapshotActor(command.revokedBy),
    revokedAtEpochMs: requireLifecycleTimestamp(
      command.revokedAtEpochMs,
      "revokedAtEpochMs",
    ),
    ...(command.reason === undefined ? {} : { reason: command.reason }),
    auditEventId: command.auditEventId,
  });

const corrupt = (detail: string): StorageError =>
  new StorageError(`authorization storage holds a corrupt record: ${detail}`);

const storedRecordsEqual = (
  left: StoredRecord,
  right: StoredRecord,
): boolean => {
  const leftFields = Object.keys(left);
  const rightFields = Object.keys(right);
  return (
    leftFields.length === rightFields.length &&
    leftFields.every(
      (field) => Object.hasOwn(right, field) && left[field] === right[field],
    )
  );
};

const requireLocation = (
  actual: RecordLocation,
  expected: RecordLocation,
  detail: string,
): void => {
  if (
    actual.applicationId !== expected.applicationId ||
    actual.principalId !== expected.principalId ||
    !scopesEqual(actual.scope, expected.scope)
  ) {
    throw corrupt(`${detail} disagrees with its requested partition`);
  }
};

const requirePointerKey = (
  pointer: StoredAssignmentPointer,
  applicationId: ApplicationId,
  assignmentId: RoleAssignmentId,
): StoredAssignmentPointer => {
  if (
    pointer.applicationId !== applicationId ||
    pointer.assignmentId !== assignmentId
  ) {
    throw corrupt(`${assignmentId} has a pointer that disagrees with its key`);
  }
  return pointer;
};

const requireHolderKey = (
  holder: StoredRoleHolder,
  expected: StoredRoleHolder,
): StoredRoleHolder => {
  requireLocation(holder, expected, `${expected.assignmentId} holder row`);
  if (
    holder.assignmentId !== expected.assignmentId ||
    holder.role !== expected.role
  ) {
    throw corrupt(
      `${expected.assignmentId} has a holder row that disagrees with its key`,
    );
  }
  return holder;
};

const requireAssignment = (
  record: AuthorizationRecord | undefined,
  location: RecordLocation,
  assignmentId: RoleAssignmentId,
  role: RoleName,
): StoredAssignment => {
  if (record === undefined || record.kind !== "assignment") {
    throw corrupt(`${assignmentId} is not an assignment record`);
  }
  requireLocation(record, location, `${assignmentId} assignment`);
  if (
    record.assignment.id !== assignmentId ||
    record.assignment.principalId !== location.principalId ||
    !scopesEqual(record.assignment.scope, location.scope) ||
    record.assignment.role !== role
  ) {
    throw corrupt(`${assignmentId} disagrees with its requested key`);
  }
  return record;
};

const requireTuple = (
  record: AuthorizationRecord | undefined,
  location: RecordLocation,
  role: RoleName,
): StoredTuple => {
  if (record === undefined || record.kind !== "tuple") {
    throw corrupt(`the guard for ${role} is not a tuple record`);
  }
  requireLocation(record, location, `${role} guard`);
  if (record.role !== role) {
    throw corrupt(`the guard for ${role} disagrees with its requested key`);
  }
  return record;
};

const requireLifecyclePosition = (
  record: AuthorizationRecord | null,
  location: RecordLocation,
  assignmentId: RoleAssignmentId,
  sequence: number,
  eventId: string,
): StoredAudit => {
  if (record === null || record.kind !== "audit") {
    throw corrupt(
      `${assignmentId} is missing lifecycle position ${String(sequence)}`,
    );
  }
  requireLocation(
    record,
    location,
    `${assignmentId} lifecycle position ${String(sequence)}`,
  );
  if (
    record.assignmentId !== assignmentId ||
    record.sequence !== sequence ||
    record.eventId !== eventId
  ) {
    throw corrupt(
      `${assignmentId} lifecycle position ${String(sequence)} disagrees with its requested key`,
    );
  }
  return record;
};

const grantAuditRecord = (
  stored: StoredAssignment,
): SequencedRoleAssignmentAuditEvent => ({
  sequence: GRANT_SEQUENCE,
  event: {
    id: stored.grantEventId,
    kind: "granted",
    assignment: activeForm(stored.assignment),
  },
});

const revokeAuditRecord = (
  stored: StoredAssignment,
): SequencedRoleAssignmentAuditEvent => {
  if (stored.assignment.status !== "revoked" || stored.revokeEventId === null) {
    throw corrupt(`${stored.assignment.id} has a revoke event without one`);
  }
  return {
    sequence: REVOKE_SEQUENCE,
    event: {
      id: stored.revokeEventId,
      kind: "revoked",
      assignment: stored.assignment,
    },
  };
};

/**
 * Binds the authorization collections to one backend and one host application.
 *
 * The returned object is the safe combined surface: exact reads plus audited
 * grant and revoke. It deliberately has no raw role or audit write, so every
 * mutation preserves the combined lifecycle-and-audit invariant.
 *
 * Durability, cross-process transactions, and restart recovery are properties
 * of the `Store` that is passed in, not of this binding.
 */
export const createRoleStore = (
  store: Store,
  applicationId: ApplicationId,
): InMemoryStorageAdapter => {
  const records = store.collection(authorizationRecords);
  const pointers = store.collection(assignmentPointers);
  const links = store.collection(identityLinkCollection);
  const holders = store.collection(roleHolders);

  const confirmRecordListing = async (
    partition: string,
    found: readonly AuthorizationRecord[],
  ): Promise<void> => {
    const ids = new Set<string>();
    for (const record of found) {
      const key = authorizationRecords.key(record);
      if (key.partition !== partition || ids.has(key.id)) {
        throw corrupt("an authorization row disagrees with its physical key");
      }
      ids.add(key.id);
      const confirmed = await records.get(key);
      if (
        confirmed === null ||
        !storedRecordsEqual(
          authorizationRecords.codec.encode(record),
          authorizationRecords.codec.encode(confirmed),
        )
      ) {
        throw corrupt("an authorization row disagrees with its physical key");
      }
    }
  };

  const confirmHolderListing = async (
    partition: string,
    found: readonly StoredRoleHolder[],
  ): Promise<void> => {
    const ids = new Set<string>();
    for (const holder of found) {
      const key = roleHolders.key(holder);
      if (key.partition !== partition || ids.has(key.id)) {
        throw corrupt("a role-holder row disagrees with its physical key");
      }
      ids.add(key.id);
      const confirmed = await holders.get(key);
      if (
        confirmed === null ||
        !storedRecordsEqual(
          roleHolders.codec.encode(holder),
          roleHolders.codec.encode(confirmed),
        )
      ) {
        throw corrupt("a role-holder row disagrees with its physical key");
      }
    }
  };

  const confirmPointerListing = async (
    partition: string,
    found: readonly StoredAssignmentPointer[],
  ): Promise<void> => {
    const ids = new Set<string>();
    for (const pointer of found) {
      const key = assignmentPointers.key(pointer);
      if (key.partition !== partition || ids.has(key.id)) {
        throw corrupt("an assignment pointer disagrees with its physical key");
      }
      ids.add(key.id);
      const confirmed = await pointers.get(key);
      if (
        confirmed === null ||
        !storedRecordsEqual(
          assignmentPointers.codec.encode(pointer),
          assignmentPointers.codec.encode(confirmed),
        )
      ) {
        throw corrupt("an assignment pointer disagrees with its physical key");
      }
    }
  };

  const locate = async (
    assignmentId: RoleAssignmentId,
  ): Promise<StoredAssignmentPointer | null> => {
    const pointer = await pointers.get(pointerKey(applicationId, assignmentId));
    if (pointer === null) {
      return null;
    }
    return requirePointerKey(pointer, applicationId, assignmentId);
  };

  const readAssignment = async (
    location: RecordLocation,
    assignmentId: RoleAssignmentId,
    role: RoleName,
  ): Promise<{
    readonly stored: StoredAssignment;
    readonly version: string;
  } | null> => {
    const versioned = await records.getVersioned({
      partition: recordPartition(location),
      id: assignmentRecordId(assignmentId),
    });
    return versioned === null
      ? null
      : {
          stored: requireAssignment(
            versioned.value,
            location,
            assignmentId,
            role,
          ),
          version: versioned.version,
        };
  };

  const adapter: InMemoryStorageAdapter = {
    async resolvePrincipalId(
      key: IdentityLinkKey,
    ): Promise<PrincipalId | null> {
      const stored = await links.get(
        identityLinkKey(applicationId, key.issuer, key.subject),
      );
      if (stored === null) {
        return null;
      }
      if (
        stored.applicationId !== applicationId ||
        stored.link.key.issuer !== key.issuer ||
        stored.link.key.subject !== key.subject
      ) {
        throw corrupt("an identity link disagrees with its requested key");
      }
      return stored.link.principalId;
    },

    async linkIdentity(link: IdentityLink): Promise<LinkIdentityResult> {
      const snapshot = snapshotIdentityLink(link);
      const result = await links.insertIfAbsent({
        applicationId,
        link: snapshot,
      });
      const stored = result.value.link;
      if (
        result.value.applicationId !== applicationId ||
        stored.key.issuer !== snapshot.key.issuer ||
        stored.key.subject !== snapshot.key.subject
      ) {
        // Key encoding is injective, so a stored tuple can differ from the
        // written one only if the record itself is damaged.
        throw corrupt("an identity link disagrees with its key tuple");
      }
      if (stored.principalId !== snapshot.principalId) {
        return conflict("principal");
      }
      return Object.freeze({
        status: result.inserted ? "linked" : "unchanged",
        link: snapshotIdentityLink(stored),
      });
    },

    async getRoleAssignment(
      assignmentId: RoleAssignmentId,
    ): Promise<VersionedRoleAssignment | null> {
      const location = await locate(assignmentId);
      if (location === null) {
        return null;
      }
      const current = await readAssignment(
        location,
        assignmentId,
        location.role,
      );
      return current === null
        ? null
        : freezeVersioned({
            assignment: current.stored.assignment,
            concurrencyToken: current.version,
          });
    },

    async listActiveRoleAssignments(
      principalId: PrincipalId,
      scope: RoleAssignmentScope,
    ): Promise<readonly ActiveRoleAssignment[]> {
      const exact = snapshotScope(scope);
      const partition = recordPartition({
        applicationId,
        principalId,
        scope: exact,
      });
      const found = await records.list(partition);
      await confirmRecordListing(partition, found);
      const expected = { applicationId, principalId, scope: exact };
      for (const record of found) {
        requireLocation(record, expected, "authorization record");
      }
      return Object.freeze(
        found
          .filter(
            (record): record is StoredAssignment =>
              record.kind === "assignment" &&
              record.assignment.status === "active",
          )
          .map(({ assignment }) =>
            freezeAssignment(assignment as ActiveRoleAssignment),
          ),
      );
    },

    async listRoleAssignments(
      principalId: PrincipalId,
      scope: RoleAssignmentScope,
    ): Promise<readonly RoleAssignment[]> {
      const exact = snapshotScope(scope);
      const partition = recordPartition({
        applicationId,
        principalId,
        scope: exact,
      });
      const found = await records.list(partition);
      await confirmRecordListing(partition, found);
      const expected = { applicationId, principalId, scope: exact };
      for (const record of found) {
        requireLocation(record, expected, "authorization record");
      }
      return Object.freeze(
        found
          .filter(
            (record): record is StoredAssignment =>
              record.kind === "assignment",
          )
          .map(({ assignment }) => assignment)
          .sort(byGrantThenId)
          .map((assignment) => freezeAssignment(assignment)),
      );
    },

    async listActiveRoleAssignmentsByRole(
      role: RoleName,
      scope: RoleAssignmentScope,
    ): Promise<readonly ActiveRoleAssignment[]> {
      const exact = snapshotScope(scope);
      const partition = roleHolderPartition(applicationId, role, exact);
      const candidates = await holders.list(partition);
      await confirmHolderListing(partition, candidates);
      const verify = async (
        candidate: (typeof candidates)[number],
      ): Promise<ActiveRoleAssignment | null> => {
        if (
          candidate.applicationId !== applicationId ||
          candidate.role !== role ||
          !scopesEqual(candidate.scope, exact)
        ) {
          throw corrupt(`a ${role} holder row disagrees with its partition`);
        }
        const pointer = await locate(candidate.assignmentId);
        if (pointer === null) {
          throw corrupt(
            `${candidate.assignmentId} has a holder row without a pointer`,
          );
        }
        requireLocation(
          candidate,
          pointer,
          `${candidate.assignmentId} holder row`,
        );
        if (candidate.role !== pointer.role) {
          throw corrupt(
            `${candidate.assignmentId} holder row disagrees with its pointer`,
          );
        }
        // Rows are candidates only. A row whose grant was refused has no
        // lifecycle behind it and reads as nothing.
        const current = await readAssignment(
          pointer,
          candidate.assignmentId,
          pointer.role,
        );
        if (current === null) {
          return null;
        }
        const assignment = current.stored.assignment;
        if (
          assignment.principalId !== candidate.principalId ||
          assignment.role !== role ||
          !scopesEqual(assignment.scope, exact)
        ) {
          throw corrupt(
            `${candidate.assignmentId} disagrees with its holder row`,
          );
        }
        return assignment.status === "active" ? assignment : null;
      };
      // Bounded fan-out: the partition keeps every historical row, so verify
      // in fixed-size batches rather than one unbounded burst of point reads.
      const verified: (ActiveRoleAssignment | null)[] = [];
      for (
        let start = 0;
        start < candidates.length;
        start += HOLDER_VERIFY_BATCH
      ) {
        verified.push(
          ...(await Promise.all(
            candidates.slice(start, start + HOLDER_VERIFY_BATCH).map(verify),
          )),
        );
      }
      return Object.freeze(
        verified
          .filter(
            (assignment): assignment is ActiveRoleAssignment =>
              assignment !== null,
          )
          .sort(byGrantThenId)
          .map((assignment) => freezeAssignment(assignment)),
      );
    },

    async rebuildRoleHolderIndex(): Promise<RebuildRoleHolderIndexResult> {
      // Every assignment ever granted has a pointer, and pointers already
      // carry the location and role a holder row needs.
      const partition = pointerPartition(applicationId);
      const known = await pointers.list(partition);
      await confirmPointerListing(partition, known);
      let recorded = 0;
      for (const pointer of known) {
        if (pointer.applicationId !== applicationId) {
          throw corrupt(`${pointer.assignmentId} points outside its namespace`);
        }
        if (
          (await readAssignment(
            pointer,
            pointer.assignmentId,
            pointer.role,
          )) === null
        ) {
          continue;
        }
        const expectedHolder: StoredRoleHolder = {
          applicationId,
          principalId: pointer.principalId,
          scope: pointer.scope,
          assignmentId: pointer.assignmentId,
          role: pointer.role,
        };
        const written = await holders.insertIfAbsent(expectedHolder);
        requireHolderKey(written.value, expectedHolder);
        if (written.inserted) {
          recorded += 1;
        }
      }
      return Object.freeze({ recorded });
    },

    async listRoleAssignmentAuditEvents(
      assignmentId: RoleAssignmentId,
    ): Promise<readonly SequencedRoleAssignmentAuditEvent[]> {
      const location = await locate(assignmentId);
      if (location === null) {
        return Object.freeze([]);
      }
      const current = await readAssignment(
        location,
        assignmentId,
        location.role,
      );
      if (current === null) {
        return Object.freeze([]);
      }
      const partition = recordPartition(location);
      const grantPosition = requireLifecyclePosition(
        await records.get({
          partition,
          id: auditRecordId(assignmentId, GRANT_SEQUENCE),
        }),
        location,
        assignmentId,
        GRANT_SEQUENCE,
        current.stored.grantEventId,
      );
      const grantRecord = freezeAuditRecord(grantAuditRecord(current.stored));
      if (grantPosition.sequence !== grantRecord.sequence) {
        throw corrupt(`${assignmentId} has an invalid grant position`);
      }
      const revokePosition = await records.get({
        partition,
        id: auditRecordId(assignmentId, REVOKE_SEQUENCE),
      });
      if (current.stored.assignment.status === "active") {
        if (revokePosition !== null) {
          throw corrupt(`${assignmentId} has a revoke position while active`);
        }
        return Object.freeze([grantRecord]);
      }
      if (current.stored.revokeEventId === null) {
        throw corrupt(`${assignmentId} is revoked without a revoke event id`);
      }
      requireLifecyclePosition(
        revokePosition,
        location,
        assignmentId,
        REVOKE_SEQUENCE,
        current.stored.revokeEventId,
      );
      return Object.freeze([
        grantRecord,
        freezeAuditRecord(revokeAuditRecord(current.stored)),
      ]);
    },

    async grantRoleAssignmentWithAudit(
      input: GrantRoleAssignmentCommand,
    ): Promise<GrantRoleAssignmentResult> {
      const assignment = snapshotActive(input.assignment);
      const auditEventId = input.auditEventId;
      const location: RecordLocation = {
        applicationId,
        principalId: assignment.principalId,
        scope: assignment.scope,
      };
      const partition = recordPartition(location);

      // Immutable, so it can be written before the lifecycle it points at. A
      // pointer with nothing behind it reads as definitive absence.
      //
      // The insert result is what enforces the port's unique-assignment-ID
      // guarantee: the per-partition tuple guard below cannot see an id that
      // was already used in a different partition.
      const pointer = await pointers.insertIfAbsent({
        ...location,
        assignmentId: assignment.id,
        role: assignment.role,
      });
      requirePointerKey(pointer.value, applicationId, assignment.id);
      if (
        !pointer.inserted &&
        pointsElsewhere(pointer.value, location, assignment.role)
      ) {
        return conflict("assignment_id");
      }

      // Written before the grant, never deleted: the by-role index may
      // over-report a refused grant but can never miss a stored one.
      const expectedHolder: StoredRoleHolder = {
        ...location,
        assignmentId: assignment.id,
        role: assignment.role,
      };
      const holder = await holders.insertIfAbsent(expectedHolder);
      requireHolderKey(holder.value, expectedHolder);

      const guard = await records.getVersioned({
        partition,
        id: tupleRecordId(assignment.role),
      });
      const occupant =
        guard === null
          ? null
          : requireTuple(guard.value, location, assignment.role)
              .activeAssignmentId;
      if (occupant !== null && occupant !== assignment.id) {
        return conflict("active_tuple");
      }

      const unchanged = (found: {
        readonly stored: StoredAssignment;
        readonly version: string;
      }): GrantRoleAssignmentResult =>
        Object.freeze({
          status: "unchanged",
          record: freezeVersioned({
            assignment: found.stored.assignment,
            concurrencyToken: found.version,
          }),
          auditRecord: freezeAuditRecord(grantAuditRecord(found.stored)),
        });

      const existing = await readAssignment(
        location,
        assignment.id,
        assignment.role,
      );
      if (existing !== null) {
        // The lifecycle already exists. An exact replay is unchanged and never
        // reactivates a revoked record; a different event ID for the same ID is
        // a different operation.
        return existing.stored.grantEventId === auditEventId
          ? unchanged(existing)
          : conflict("event_id");
      }

      const claimed: StoredTuple = {
        kind: "tuple",
        ...location,
        role: assignment.role,
        activeAssignmentId: assignment.id,
      };
      const actions: readonly TransactionAction<AuthorizationRecord>[] = [
        {
          action: "insert",
          value: {
            kind: "assignment",
            ...location,
            assignment,
            grantEventId: auditEventId,
            revokeEventId: null,
          },
        },
        guard === null
          ? { action: "insert", value: claimed }
          : {
              action: "putIfUnchanged",
              value: claimed,
              version: guard.version,
            },
        {
          action: "insert",
          value: {
            kind: "audit",
            ...location,
            assignmentId: assignment.id,
            sequence: GRANT_SEQUENCE,
            eventId: auditEventId,
          },
        },
      ];

      const outcome = await records.transact(partition, actions);
      if (!outcome.committed) {
        if (outcome.reason !== "exists") {
          // The tuple guard moved or vanished under us, so someone else holds
          // it now.
          return conflict("active_tuple");
        }
        // A refused insert means a competing writer reached this partition
        // first. Which precondition it refused is best-effort information, so
        // decide from the state that actually landed rather than from the
        // rejection.
        const landed = await readAssignment(
          location,
          assignment.id,
          assignment.role,
        );
        if (landed === null) {
          return conflict("active_tuple");
        }
        return landed.stored.grantEventId === auditEventId
          ? unchanged(landed)
          : conflict("assignment_id");
      }

      const written = await readAssignment(
        location,
        assignment.id,
        assignment.role,
      );
      if (written === null) {
        throw corrupt(`${assignment.id} vanished after a committed grant`);
      }
      return Object.freeze({
        status: "granted",
        record: freezeVersioned({
          assignment: written.stored.assignment as ActiveRoleAssignment,
          concurrencyToken: written.version,
        }),
        auditRecord: freezeAuditRecord(grantAuditRecord(written.stored)),
      });
    },

    async revokeRoleAssignmentWithAudit(
      input: AuditedRevokeRoleAssignmentCommand,
    ): Promise<AuditedRevokeRoleAssignmentResult> {
      const command = snapshotRevokeCommand(input);
      const location = await locate(command.assignmentId);
      if (location === null) {
        return Object.freeze({ status: "not_found" });
      }
      const partition = recordPartition(location);
      const existing = await readAssignment(
        location,
        command.assignmentId,
        location.role,
      );
      if (existing === null) {
        return Object.freeze({ status: "not_found" });
      }

      const current = existing.stored.assignment;
      if (current.status === "revoked") {
        if (
          existing.stored.revokeEventId !== command.auditEventId ||
          !revocationsEqual(current, command)
        ) {
          return conflict("lifecycle");
        }
        return Object.freeze({
          status: "unchanged",
          record: freezeVersioned({
            assignment: current,
            concurrencyToken: existing.version,
          }),
          auditRecord: freezeAuditRecord(revokeAuditRecord(existing.stored)),
        });
      }
      if (existing.version !== command.expectedConcurrencyToken) {
        return conflict("concurrency");
      }
      if (command.revokedAtEpochMs < current.grantedAtEpochMs) {
        return conflict("lifecycle");
      }

      const guard = await records.getVersioned({
        partition,
        id: tupleRecordId(current.role),
      });
      if (guard === null) {
        throw corrupt(
          `${current.role} has an active assignment without a guard`,
        );
      }
      const held = requireTuple(guard.value, location, current.role);

      const revoked: RevokedRoleAssignment = {
        ...current,
        status: "revoked",
        revokedBy: command.revokedBy,
        revokedAtEpochMs: command.revokedAtEpochMs,
        ...(command.reason === undefined ? {} : { reason: command.reason }),
      };
      const actions: readonly TransactionAction<AuthorizationRecord>[] = [
        {
          action: "putIfUnchanged",
          value: {
            kind: "assignment",
            ...location,
            assignment: revoked,
            grantEventId: existing.stored.grantEventId,
            revokeEventId: command.auditEventId,
          },
          version: existing.version,
        },
        {
          action: "putIfUnchanged",
          value: {
            ...held,
            activeAssignmentId:
              held.activeAssignmentId === command.assignmentId
                ? null
                : held.activeAssignmentId,
          },
          version: guard.version,
        },
        {
          action: "insert",
          value: {
            kind: "audit",
            ...location,
            assignmentId: command.assignmentId,
            sequence: REVOKE_SEQUENCE,
            eventId: command.auditEventId,
          },
        },
      ];

      const outcome = await records.transact(partition, actions);
      if (!outcome.committed) {
        return conflict(
          outcome.reason === "changed"
            ? "concurrency"
            : outcome.reason === "exists"
              ? "event_id"
              : "lifecycle",
        );
      }

      const written = await readAssignment(
        location,
        command.assignmentId,
        location.role,
      );
      if (written === null) {
        throw corrupt(
          `${command.assignmentId} vanished after a committed revoke`,
        );
      }
      return Object.freeze({
        status: "revoked",
        record: freezeVersioned({
          assignment: written.stored.assignment as RevokedRoleAssignment,
          concurrencyToken: written.version,
        }),
        auditRecord: freezeAuditRecord(revokeAuditRecord(written.stored)),
      });
    },
  };

  return Object.freeze(adapter);
};

/** The single application namespace an in-memory instance is bound to. */
const IN_MEMORY_APPLICATION_ID = "default";

const snapshotIdentityLinks = (
  options: InMemoryStorageAdapterOptions,
): readonly IdentityLink[] => {
  const seeds = options.identityLinks ?? [];
  const claimed = new Map<string, Map<string, PrincipalId>>();
  return Object.freeze(
    Array.from(seeds, (seed) => {
      const link = Object.freeze({
        key: Object.freeze({
          issuer: seed.key.issuer,
          subject: seed.key.subject,
        }),
        principalId: seed.principalId,
      });
      const subjects =
        claimed.get(link.key.issuer) ?? new Map<string, PrincipalId>();
      const existing = subjects.get(link.key.subject);
      if (existing !== undefined && existing !== link.principalId) {
        throw new Error(
          "one exact identity-link key cannot seed multiple principals",
        );
      }
      subjects.set(link.key.subject, link.principalId);
      claimed.set(link.key.issuer, subjects);
      return link;
    }),
  );
};

/**
 * Creates an isolated, ephemeral reference adapter for one host application.
 *
 * It is the storage-core memory store behind {@link createRoleStore}, so it
 * enforces the same key, transaction, and optimistic-concurrency rules a
 * durable backend does. It is not durable and not a cross-process transaction.
 */
export const createInMemoryStorageAdapter = (
  options: InMemoryStorageAdapterOptions = {},
): InMemoryStorageAdapter => {
  // Seeds are copied before anything asynchronous starts, so a caller mutating
  // its own array afterwards cannot change what this instance resolves.
  const seeds = snapshotIdentityLinks(options);
  const store = createMemoryStore();
  const adapter = createRoleStore(store, IN_MEMORY_APPLICATION_ID);
  const links = store.collection(identityLinkCollection);
  const seeded = Promise.all(
    seeds.map((link) =>
      links.insertIfAbsent({
        applicationId: IN_MEMORY_APPLICATION_ID,
        link,
      }),
    ),
  );

  return Object.freeze({
    ...adapter,
    async resolvePrincipalId(
      key: IdentityLinkKey,
    ): Promise<PrincipalId | null> {
      await seeded;
      return adapter.resolvePrincipalId(key);
    },
    async linkIdentity(link: IdentityLink): Promise<LinkIdentityResult> {
      await seeded;
      return adapter.linkIdentity(link);
    },
  });
};
