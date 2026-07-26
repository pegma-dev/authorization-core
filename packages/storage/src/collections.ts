import type {
  IdentityLink,
  PrincipalId,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentId,
  RoleAssignmentScope,
  RoleName,
} from "@pegma/authorization-contracts";
import {
  defineCollection,
  type EntityKey,
  type StoredRecord,
} from "@pegma/storage-core";

/**
 * Characters that may not appear raw in a storage key.
 *
 * `|` is the separator this module composes keys with, and the others are
 * rejected outright by common key-value backends. Escaping rather than hashing
 * keeps keys readable and, more importantly, keeps the mapping injective: two
 * distinct roles can never collide onto one record, which under this layout
 * would be an authorization fault rather than a storage one.
 */
const KEY_ESCAPES = /[%|/\\#?\u0000-\u001F\u007F-\u009F]/g;

function encodeSegment(value: string): string {
  // `%` is escaped by the same rule, and because it is listed first in the
  // class it can never be produced by escaping something else. The encoding is
  // therefore reversible even though nothing here needs to reverse it.
  return value.replace(
    KEY_ESCAPES,
    (character) =>
      `%${character.charCodeAt(0).toString(16).padStart(2, "0").toUpperCase()}`,
  );
}

function joinSegments(segments: readonly string[]): string {
  return segments.map(encodeSegment).join("|");
}

/** Stable tag for an exact scope, used as part of a partition key. */
export function scopeTag(scope: RoleAssignmentScope): string {
  return scope.kind === "application"
    ? "application"
    : `organization|${encodeSegment(scope.organizationId)}`;
}

/**
 * The application this store's records belong to.
 *
 * Every key begins with it, so one storage account can serve several
 * applications without their assignments being visible to each other.
 */
export type ApplicationId = string;

/** Per-assignment audit sequence for the grant event. */
export const GRANT_SEQUENCE = 1;

/** Per-assignment audit sequence for the revocation event. */
export const REVOKE_SEQUENCE = 2;

/**
 * The exact application, principal, and scope one record belongs to.
 *
 * These three fields are the partition. Every kind of record carries them
 * because the collection derives a record's location from the record itself.
 */
export interface RecordLocation {
  readonly applicationId: ApplicationId;
  readonly principalId: PrincipalId;
  readonly scope: RoleAssignmentScope;
}

/**
 * One role assignment, flattened for storage.
 *
 * This is the authoritative lifecycle record. `grantEventId` and
 * `revokeEventId` are the caller-selected audit event IDs; the audit payloads
 * themselves are derived from this record rather than stored a second time, so
 * history can never disagree with the lifecycle it describes.
 */
export interface StoredAssignment extends RecordLocation {
  readonly kind: "assignment";
  readonly assignment: RoleAssignment;
  /** Caller-supplied id of the audit event that recorded the grant. */
  readonly grantEventId: string;
  /** Caller-supplied id of the audit event that recorded the revocation. */
  readonly revokeEventId: string | null;
}

/**
 * The uniqueness guard for one exact `(principalId, role, scope)` tuple.
 *
 * It holds the assignment currently occupying the tuple, or `null` once that
 * assignment is revoked. Retiring rather than deleting is deliberate: a
 * transaction offers no version-conditional delete, so a tombstone is how a
 * conditional removal is expressed.
 */
export interface StoredTuple extends RecordLocation {
  readonly kind: "tuple";
  readonly role: RoleName;
  readonly activeAssignmentId: RoleAssignmentId | null;
}

/**
 * One position in an assignment's two-event history.
 *
 * Only the sequence and the event ID are kept. The event payload is the
 * lifecycle evidence on the assignment record, so an audit row cannot drift
 * from the assignment it belongs to.
 */
export interface StoredAudit extends RecordLocation {
  readonly kind: "audit";
  readonly assignmentId: RoleAssignmentId;
  readonly sequence: number;
  readonly eventId: string;
}

/**
 * Everything one principal-and-scope partition holds.
 *
 * Assignment, tuple guard, and audit positions share a partition so that an
 * audited grant or revoke is one transaction, which is the only guarantee
 * every backend worth targeting actually offers.
 */
export type AuthorizationRecord = StoredAssignment | StoredTuple | StoredAudit;

/** Partition holding every record for one principal in one exact scope. */
export function recordPartition(location: RecordLocation): string {
  return `${joinSegments([location.applicationId, location.principalId])}|${scopeTag(location.scope)}`;
}

/** Record id of the authoritative lifecycle record for one assignment. */
export function assignmentRecordId(assignmentId: RoleAssignmentId): string {
  return `assignment|${encodeSegment(assignmentId)}`;
}

/** Record id of the uniqueness guard for one role in a partition. */
export function tupleRecordId(role: RoleName): string {
  return `tuple|${encodeSegment(role)}`;
}

/** Record id of one audit position for one assignment. */
export function auditRecordId(
  assignmentId: RoleAssignmentId,
  sequence: number,
): string {
  return `audit|${encodeSegment(assignmentId)}|${String(sequence).padStart(4, "0")}`;
}

function encodeActor(
  actor: RoleAssignmentActor,
  prefix: string,
): Record<string, string | null> {
  return {
    [`${prefix}Kind`]: actor.kind,
    [`${prefix}PrincipalId`]:
      actor.kind === "principal" ? actor.principalId : null,
    [`${prefix}SystemId`]: actor.kind === "system" ? actor.systemId : null,
  };
}

function decodeActor(
  record: StoredRecord,
  prefix: string,
): RoleAssignmentActor {
  return record[`${prefix}Kind`] === "system"
    ? { kind: "system", systemId: String(record[`${prefix}SystemId`]) }
    : {
        kind: "principal",
        principalId: String(record[`${prefix}PrincipalId`]),
      };
}

function encodeLocation(location: RecordLocation): StoredRecord {
  return {
    applicationId: location.applicationId,
    principalId: location.principalId,
    scopeKind: location.scope.kind,
    organizationId:
      location.scope.kind === "organization"
        ? location.scope.organizationId
        : null,
  };
}

function decodeScope(record: StoredRecord): RoleAssignmentScope {
  return record["scopeKind"] === "organization"
    ? { kind: "organization", organizationId: String(record["organizationId"]) }
    : { kind: "application" };
}

function decodeLocation(record: StoredRecord): RecordLocation {
  return {
    applicationId: String(record["applicationId"]),
    principalId: String(record["principalId"]),
    scope: decodeScope(record),
  };
}

function encodeAssignment(stored: StoredAssignment): StoredRecord {
  const { assignment } = stored;
  const revoked = assignment.status === "revoked" ? assignment : null;
  return {
    kind: "assignment",
    ...encodeLocation(stored),
    assignmentId: assignment.id,
    role: assignment.role,
    status: assignment.status,
    grantedAtEpochMs: assignment.grantedAtEpochMs,
    ...encodeActor(assignment.grantedBy, "grantedBy"),
    revokedAtEpochMs: revoked?.revokedAtEpochMs ?? null,
    ...(revoked === null
      ? {
          revokedByKind: null,
          revokedByPrincipalId: null,
          revokedBySystemId: null,
        }
      : encodeActor(revoked.revokedBy, "revokedBy")),
    reason: revoked?.reason ?? null,
    grantEventId: stored.grantEventId,
    revokeEventId: stored.revokeEventId,
  };
}

function decodeAssignment(record: StoredRecord): StoredAssignment {
  const location = decodeLocation(record);
  const grant = {
    id: String(record["assignmentId"]),
    principalId: location.principalId,
    role: String(record["role"]),
    scope: location.scope,
    grantedBy: decodeActor(record, "grantedBy"),
    grantedAtEpochMs: Number(record["grantedAtEpochMs"]),
  };

  const reason = record["reason"];
  const assignment: RoleAssignment =
    record["status"] === "revoked"
      ? {
          ...grant,
          status: "revoked",
          revokedBy: decodeActor(record, "revokedBy"),
          revokedAtEpochMs: Number(record["revokedAtEpochMs"]),
          ...(reason == null ? {} : { reason: String(reason) }),
        }
      : { ...grant, status: "active" };

  const revokeEventId = record["revokeEventId"];
  return {
    kind: "assignment",
    ...location,
    assignment,
    grantEventId: String(record["grantEventId"]),
    revokeEventId: revokeEventId == null ? null : String(revokeEventId),
  };
}

/**
 * Everything one host application keeps about one principal and scope.
 *
 * The record id says which kind a row is, and the codec switches on it. Three
 * kinds in one collection is what lets a lifecycle change and its derived audit
 * event settle in a single-partition transaction.
 */
export const authorizationRecords = defineCollection<AuthorizationRecord>({
  name: "authorization_records",
  key: (record) => ({
    partition: recordPartition(record),
    id:
      record.kind === "assignment"
        ? assignmentRecordId(record.assignment.id)
        : record.kind === "tuple"
          ? tupleRecordId(record.role)
          : auditRecordId(record.assignmentId, record.sequence),
  }),
  codec: {
    encode: (record) => {
      if (record.kind === "assignment") {
        return encodeAssignment(record);
      }
      if (record.kind === "tuple") {
        return {
          kind: "tuple",
          ...encodeLocation(record),
          role: record.role,
          activeAssignmentId: record.activeAssignmentId,
        };
      }
      return {
        kind: "audit",
        ...encodeLocation(record),
        assignmentId: record.assignmentId,
        sequence: record.sequence,
        eventId: record.eventId,
      };
    },
    decode: (record) => {
      if (record["kind"] === "assignment") {
        return decodeAssignment(record);
      }
      if (record["kind"] === "tuple") {
        const activeAssignmentId = record["activeAssignmentId"];
        return {
          kind: "tuple",
          ...decodeLocation(record),
          role: String(record["role"]),
          activeAssignmentId:
            activeAssignmentId == null ? null : String(activeAssignmentId),
        };
      }
      return {
        kind: "audit",
        ...decodeLocation(record),
        assignmentId: String(record["assignmentId"]),
        sequence: Number(record["sequence"]),
        eventId: String(record["eventId"]),
      };
    },
  },
});

/**
 * Where an assignment id lives.
 *
 * Records are partitioned by principal and scope so that selection is a single
 * partition read, which leaves lookup by assignment id without a partition to
 * search. This collection supplies it.
 *
 * A pointer is immutable: an assignment's location is fixed at grant and an id
 * is never reused, so this record can be written before the assignment without
 * a transaction. A pointer that resolves to nothing reads as absence, which
 * the port already treats as definitive.
 */
export interface StoredAssignmentPointer extends RecordLocation {
  readonly assignmentId: RoleAssignmentId;
  readonly role: RoleName;
}

export const assignmentPointers = defineCollection<StoredAssignmentPointer>({
  name: "authorization_assignment_pointers",
  key: (pointer) => pointerKey(pointer.applicationId, pointer.assignmentId),
  codec: {
    encode: (pointer) => ({
      ...encodeLocation(pointer),
      assignmentId: pointer.assignmentId,
      role: pointer.role,
    }),
    decode: (record) => ({
      ...decodeLocation(record),
      assignmentId: String(record["assignmentId"]),
      role: String(record["role"]),
    }),
  },
});

/** Key of the pointer for one exact assignment id. */
export function pointerKey(
  applicationId: ApplicationId,
  assignmentId: RoleAssignmentId,
): EntityKey {
  return {
    partition: encodeSegment(applicationId),
    id: encodeSegment(assignmentId),
  };
}

/**
 * Provider identity linked to a host principal.
 *
 * Issuer and subject are compared as an exact case-sensitive tuple, so they are
 * stored raw as well as encoded into the key: a reader must be able to confirm
 * the match rather than trust that two distinct tuples did not encode alike.
 */
export interface StoredIdentityLink {
  readonly applicationId: ApplicationId;
  readonly link: IdentityLink;
}

export const identityLinks = defineCollection<StoredIdentityLink>({
  name: "authorization_identity_links",
  key: (stored) =>
    identityLinkKey(
      stored.applicationId,
      stored.link.key.issuer,
      stored.link.key.subject,
    ),
  codec: {
    encode: (stored) => ({
      applicationId: stored.applicationId,
      issuer: stored.link.key.issuer,
      subject: stored.link.key.subject,
      principalId: stored.link.principalId,
    }),
    decode: (record) => ({
      applicationId: String(record["applicationId"]),
      link: {
        key: {
          issuer: String(record["issuer"]),
          subject: String(record["subject"]),
        },
        principalId: String(record["principalId"]),
      },
    }),
  },
});

/** Key of the identity link for one exact issuer-and-subject tuple. */
export function identityLinkKey(
  applicationId: ApplicationId,
  issuer: string,
  subject: string,
): EntityKey {
  return {
    partition: encodeSegment(applicationId),
    id: joinSegments([issuer, subject]),
  };
}
