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
  type TransactionAction,
} from "@pegma/storage-core";

import {
  assignmentPointers,
  assignmentRecordId,
  authorizationRecords,
  GRANT_SEQUENCE,
  identityLinkKey,
  identityLinks as identityLinkCollection,
  pointerKey,
  recordPartition,
  REVOKE_SEQUENCE,
  tupleRecordId,
  type ApplicationId,
  type AuthorizationRecord,
  type RecordLocation,
  type StoredAssignment,
  type StoredAssignmentPointer,
  type StoredAudit,
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

const requireAssignment = (
  record: AuthorizationRecord | undefined,
  assignmentId: RoleAssignmentId,
): StoredAssignment => {
  if (record === undefined || record.kind !== "assignment") {
    throw corrupt(`${assignmentId} is not an assignment record`);
  }
  return record;
};

const requireTuple = (
  record: AuthorizationRecord | undefined,
  role: string,
): StoredTuple => {
  if (record === undefined || record.kind !== "tuple") {
    throw corrupt(`the guard for ${role} is not a tuple record`);
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

  const locate = async (
    assignmentId: RoleAssignmentId,
  ): Promise<RecordLocation | null> => {
    const pointer = await pointers.get(pointerKey(applicationId, assignmentId));
    if (pointer === null || pointer.assignmentId !== assignmentId) {
      return null;
    }
    return pointer;
  };

  const readAssignment = async (
    location: RecordLocation,
    assignmentId: RoleAssignmentId,
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
          stored: requireAssignment(versioned.value, assignmentId),
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
      if (
        stored === null ||
        stored.link.key.issuer !== key.issuer ||
        stored.link.key.subject !== key.subject
      ) {
        return null;
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
      const current = await readAssignment(location, assignmentId);
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
      const partition = recordPartition({
        applicationId,
        principalId,
        scope: snapshotScope(scope),
      });
      const found = await records.list(partition);
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
      const partition = recordPartition({
        applicationId,
        principalId,
        scope: snapshotScope(scope),
      });
      const found = await records.list(partition);
      return Object.freeze(
        found
          .filter(
            (record): record is StoredAssignment =>
              record.kind === "assignment",
          )
          .map(({ assignment }) => assignment)
          .sort((left, right) =>
            left.grantedAtEpochMs !== right.grantedAtEpochMs
              ? left.grantedAtEpochMs - right.grantedAtEpochMs
              : left.id < right.id
                ? -1
                : left.id > right.id
                  ? 1
                  : 0,
          )
          .map((assignment) => freezeAssignment(assignment)),
      );
    },

    async listRoleAssignmentAuditEvents(
      assignmentId: RoleAssignmentId,
    ): Promise<readonly SequencedRoleAssignmentAuditEvent[]> {
      const location = await locate(assignmentId);
      if (location === null) {
        return Object.freeze([]);
      }
      const found = await records.list(recordPartition(location));
      const positions = found
        .filter(
          (record): record is StoredAudit =>
            record.kind === "audit" && record.assignmentId === assignmentId,
        )
        .map(({ sequence }) => sequence)
        .sort((left, right) => left - right);
      if (positions.length === 0) {
        return Object.freeze([]);
      }

      const stored = requireAssignment(
        found.find(
          (record) =>
            record.kind === "assignment" &&
            record.assignment.id === assignmentId,
        ),
        assignmentId,
      );
      return Object.freeze(
        positions.map((sequence) =>
          freezeAuditRecord(
            sequence === REVOKE_SEQUENCE
              ? revokeAuditRecord(stored)
              : grantAuditRecord(stored),
          ),
        ),
      );
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
      if (
        !pointer.inserted &&
        pointsElsewhere(pointer.value, location, assignment.role)
      ) {
        return conflict("assignment_id");
      }

      const guard = await records.getVersioned({
        partition,
        id: tupleRecordId(assignment.role),
      });
      const occupant =
        guard === null
          ? null
          : requireTuple(guard.value, assignment.role).activeAssignmentId;
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

      const existing = await readAssignment(location, assignment.id);
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
        const landed = await readAssignment(location, assignment.id);
        if (landed === null) {
          return conflict("active_tuple");
        }
        return landed.stored.grantEventId === auditEventId
          ? unchanged(landed)
          : conflict("assignment_id");
      }

      const written = await readAssignment(location, assignment.id);
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
      const existing = await readAssignment(location, command.assignmentId);
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
      const held = requireTuple(guard.value, current.role);

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

      const written = await readAssignment(location, command.assignmentId);
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
