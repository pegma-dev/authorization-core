import type {
  ActiveRoleAssignment,
  IdentityLink,
  PrincipalId,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentId,
  RoleAssignmentScope,
  RoleName,
} from "@pegma/authorization-contracts";
import { defineCollection, type EntityKey } from "@pegma/storage-core";

/**
 * Characters that may not appear raw in a storage key.
 *
 * `|` is the separator this module composes keys with, and the others are
 * rejected outright by Azure Table Storage. Escaping rather than hashing keeps
 * keys readable and, more importantly, keeps the mapping injective: two
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

/**
 * One role assignment, flattened for storage.
 *
 * The audit trail is carried here rather than in its own collection. An
 * assignment's history is exactly two events, granted and revoked, and both
 * are already derivable from these fields. Keeping them on the record is what
 * lets a grant or a revoke be a single write, which is the only way to be
 * atomic without a transaction the port does not offer.
 */
export interface StoredRoleAssignment {
  readonly applicationId: ApplicationId;
  readonly assignment: RoleAssignment;
  /** Caller-supplied id of the audit event that recorded the grant. */
  readonly grantEventId: string;
  /** Caller-supplied id of the audit event that recorded the revocation. */
  readonly revokeEventId: string | null;
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
  record: Readonly<Record<string, unknown>>,
  prefix: string,
): RoleAssignmentActor {
  return record[`${prefix}Kind`] === "system"
    ? { kind: "system", systemId: String(record[`${prefix}SystemId`]) }
    : {
        kind: "principal",
        principalId: String(record[`${prefix}PrincipalId`]),
      };
}

/**
 * Role assignments, partitioned by the exact pair the reader selects on.
 *
 * The record id is the role, which makes "at most one assignment per
 * principal, role, and scope" a property of the key rather than a rule some
 * companion row has to enforce. Selecting a principal's active roles for a
 * scope is then one partition read of the authoritative records, with no
 * derived index that could drift from them.
 */
export const roleAssignments = defineCollection<StoredRoleAssignment>({
  name: "authorization_role_assignments",
  key: (stored) => assignmentKey(stored.applicationId, stored.assignment),
  codec: {
    encode: (stored) => {
      const { assignment } = stored;
      const revoked = assignment.status === "revoked" ? assignment : null;
      return {
        applicationId: stored.applicationId,
        assignmentId: assignment.id,
        principalId: assignment.principalId,
        role: assignment.role,
        scopeKind: assignment.scope.kind,
        organizationId:
          assignment.scope.kind === "organization"
            ? assignment.scope.organizationId
            : null,
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
    },
    decode: (record) => {
      const scope: RoleAssignmentScope =
        record["scopeKind"] === "organization"
          ? {
              kind: "organization",
              organizationId: String(record["organizationId"]),
            }
          : { kind: "application" };

      const grant = {
        id: String(record["assignmentId"]),
        principalId: String(record["principalId"]),
        role: String(record["role"]),
        scope,
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
        applicationId: String(record["applicationId"]),
        assignment,
        grantEventId: String(record["grantEventId"]),
        revokeEventId: revokeEventId == null ? null : String(revokeEventId),
      };
    },
  },
});

/** Partition holding every assignment for one principal in one exact scope. */
export function assignmentPartition(
  applicationId: ApplicationId,
  principalId: PrincipalId,
  scope: RoleAssignmentScope,
): string {
  return `${joinSegments([applicationId, principalId])}|${scopeTag(scope)}`;
}

export function assignmentKey(
  applicationId: ApplicationId,
  assignment: Pick<ActiveRoleAssignment, "principalId" | "role" | "scope">,
): EntityKey {
  return {
    partition: assignmentPartition(
      applicationId,
      assignment.principalId,
      assignment.scope,
    ),
    id: encodeSegment(assignment.role),
  };
}

/**
 * Where an assignment id lives.
 *
 * Assignments are keyed by principal, scope, and role so that selection is a
 * single partition read, which leaves lookup by assignment id without a
 * partition to search. This collection supplies it.
 *
 * A pointer is immutable: an assignment's location is fixed at grant and an id
 * is never reused, so this record can be written before the assignment without
 * a transaction. A pointer that resolves to nothing reads as absence, which
 * the port already treats as definitive.
 */
export interface StoredAssignmentPointer {
  readonly applicationId: ApplicationId;
  readonly assignmentId: RoleAssignmentId;
  readonly principalId: PrincipalId;
  readonly scope: RoleAssignmentScope;
  readonly role: RoleName;
}

export const assignmentPointers = defineCollection<StoredAssignmentPointer>({
  name: "authorization_assignment_pointers",
  key: (pointer) => ({
    partition: encodeSegment(pointer.applicationId),
    id: encodeSegment(pointer.assignmentId),
  }),
  codec: {
    encode: (pointer) => ({
      applicationId: pointer.applicationId,
      assignmentId: pointer.assignmentId,
      principalId: pointer.principalId,
      role: pointer.role,
      scopeKind: pointer.scope.kind,
      organizationId:
        pointer.scope.kind === "organization"
          ? pointer.scope.organizationId
          : null,
    }),
    decode: (record) => ({
      applicationId: String(record["applicationId"]),
      assignmentId: String(record["assignmentId"]),
      principalId: String(record["principalId"]),
      role: String(record["role"]),
      scope:
        record["scopeKind"] === "organization"
          ? {
              kind: "organization",
              organizationId: String(record["organizationId"]),
            }
          : { kind: "application" },
    }),
  },
});

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
  key: (stored) => ({
    partition: encodeSegment(stored.applicationId),
    id: joinSegments([stored.link.key.issuer, stored.link.key.subject]),
  }),
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
