import type {
  ActiveRoleAssignment,
  IdentityLink,
  IdentityLinkKey,
  RevokedRoleAssignment,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import type {
  RoleAssignmentAuditEvent,
  SequencedRoleAssignmentAuditEvent,
  VersionedRoleAssignment,
} from "@pegma/authorization-storage";

export type StoredEntity = Readonly<Record<string, unknown>> & {
  readonly etag?: string;
  readonly partitionKey?: string;
  readonly rowKey?: string;
};

const fail = (message: string): never => {
  throw new Error(`Azure Table Storage data is corrupt: ${message}`);
};

const objectValue = (
  value: unknown,
  field: string,
): Record<string, unknown> => {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return fail(`${field} must be an object`);
  }
  return value as Record<string, unknown>;
};

const stringValue = (value: unknown, field: string): string => {
  if (typeof value !== "string") {
    return fail(`${field} must be a string`);
  }
  return value;
};

const timestampValue = (value: unknown, field: string): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    return fail(`${field} must be a non-negative safe integer`);
  }
  return value;
};

const exactKeys = (
  value: Record<string, unknown>,
  expected: readonly string[],
  field: string,
): void => {
  const keys = Object.keys(value).sort();
  const sortedExpected = [...expected].sort();
  if (
    keys.length !== sortedExpected.length ||
    keys.some((key, index) => key !== sortedExpected[index])
  ) {
    fail(`${field} has unexpected fields`);
  }
};

export const snapshotScope = (value: unknown): RoleAssignmentScope => {
  const scope = objectValue(value, "scope");
  if (scope.kind === "application") {
    exactKeys(scope, ["kind"], "scope");
    return Object.freeze({ kind: "application" });
  }
  if (scope.kind === "organization") {
    exactKeys(scope, ["kind", "organizationId"], "scope");
    return Object.freeze({
      kind: "organization",
      organizationId: stringValue(scope.organizationId, "scope.organizationId"),
    });
  }
  return fail("scope.kind is invalid");
};

export const snapshotActor = (value: unknown): RoleAssignmentActor => {
  const actor = objectValue(value, "actor");
  if (actor.kind === "principal") {
    exactKeys(actor, ["kind", "principalId"], "actor");
    return Object.freeze({
      kind: "principal",
      principalId: stringValue(actor.principalId, "actor.principalId"),
    });
  }
  if (actor.kind === "system") {
    exactKeys(actor, ["kind", "systemId"], "actor");
    return Object.freeze({
      kind: "system",
      systemId: stringValue(actor.systemId, "actor.systemId"),
    });
  }
  return fail("actor.kind is invalid");
};

export const snapshotActive = (value: unknown): ActiveRoleAssignment => {
  const assignment = objectValue(value, "assignment");
  exactKeys(
    assignment,
    [
      "id",
      "principalId",
      "role",
      "scope",
      "grantedBy",
      "grantedAtEpochMs",
      "status",
    ],
    "active assignment",
  );
  if (assignment.status !== "active") {
    return fail("grant requires an active assignment");
  }
  return Object.freeze({
    id: stringValue(assignment.id, "assignment.id"),
    principalId: stringValue(assignment.principalId, "assignment.principalId"),
    role: stringValue(assignment.role, "assignment.role"),
    scope: snapshotScope(assignment.scope),
    grantedBy: snapshotActor(assignment.grantedBy),
    grantedAtEpochMs: timestampValue(
      assignment.grantedAtEpochMs,
      "assignment.grantedAtEpochMs",
    ),
    status: "active",
  });
};

export const snapshotRevoked = (value: unknown): RevokedRoleAssignment => {
  const assignment = objectValue(value, "assignment");
  const expected = [
    "id",
    "principalId",
    "role",
    "scope",
    "grantedBy",
    "grantedAtEpochMs",
    "status",
    "revokedBy",
    "revokedAtEpochMs",
    ...(assignment.reason === undefined ? [] : ["reason"]),
  ];
  exactKeys(assignment, expected, "revoked assignment");
  if (assignment.status !== "revoked") {
    return fail("revoked assignment status is invalid");
  }
  const grantedAtEpochMs = timestampValue(
    assignment.grantedAtEpochMs,
    "assignment.grantedAtEpochMs",
  );
  const revokedAtEpochMs = timestampValue(
    assignment.revokedAtEpochMs,
    "assignment.revokedAtEpochMs",
  );
  if (revokedAtEpochMs < grantedAtEpochMs) {
    return fail("revocation precedes grant");
  }
  return Object.freeze({
    id: stringValue(assignment.id, "assignment.id"),
    principalId: stringValue(assignment.principalId, "assignment.principalId"),
    role: stringValue(assignment.role, "assignment.role"),
    scope: snapshotScope(assignment.scope),
    grantedBy: snapshotActor(assignment.grantedBy),
    grantedAtEpochMs,
    status: "revoked",
    revokedBy: snapshotActor(assignment.revokedBy),
    revokedAtEpochMs,
    ...(assignment.reason === undefined
      ? {}
      : { reason: stringValue(assignment.reason, "assignment.reason") }),
  });
};

export const snapshotAssignment = (value: unknown): RoleAssignment => {
  const assignment = objectValue(value, "assignment");
  return assignment.status === "active"
    ? snapshotActive(assignment)
    : snapshotRevoked(assignment);
};

export const encodeAssignment = (assignment: RoleAssignment): string =>
  JSON.stringify(assignment);

export const decodeAssignment = (json: unknown): RoleAssignment => {
  const encoded = stringValue(json, "assignmentJson");
  try {
    return snapshotAssignment(JSON.parse(encoded) as unknown);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith("Azure Table Storage data is corrupt:")
    ) {
      throw error;
    }
    return fail("assignmentJson is not valid JSON");
  }
};

export const scopesEqual = (
  left: RoleAssignmentScope,
  right: RoleAssignmentScope,
): boolean =>
  left.kind === "application"
    ? right.kind === "application"
    : right.kind === "organization" &&
      left.organizationId === right.organizationId;

export const actorsEqual = (
  left: RoleAssignmentActor,
  right: RoleAssignmentActor,
): boolean =>
  left.kind === "principal"
    ? right.kind === "principal" && left.principalId === right.principalId
    : right.kind === "system" && left.systemId === right.systemId;

export const grantsEqual = (
  left: RoleAssignment,
  right: ActiveRoleAssignment,
): boolean =>
  left.id === right.id &&
  left.principalId === right.principalId &&
  left.role === right.role &&
  scopesEqual(left.scope, right.scope) &&
  actorsEqual(left.grantedBy, right.grantedBy) &&
  left.grantedAtEpochMs === right.grantedAtEpochMs;

export const assignmentsEqual = (
  left: RoleAssignment,
  right: RoleAssignment,
): boolean => {
  if (
    !grantsEqual(left, {
      id: right.id,
      principalId: right.principalId,
      role: right.role,
      scope: right.scope,
      grantedBy: right.grantedBy,
      grantedAtEpochMs: right.grantedAtEpochMs,
      status: "active",
    }) ||
    left.status !== right.status
  ) {
    return false;
  }
  return left.status === "active"
    ? true
    : right.status === "revoked" &&
        actorsEqual(left.revokedBy, right.revokedBy) &&
        left.revokedAtEpochMs === right.revokedAtEpochMs &&
        left.reason === right.reason;
};

export const snapshotVersioned = <Assignment extends RoleAssignment>(
  assignment: Assignment,
  concurrencyToken: string,
): VersionedRoleAssignment<Assignment> =>
  Object.freeze({
    assignment: snapshotAssignment(assignment) as Assignment,
    concurrencyToken,
  });

export const snapshotEvent = (
  event: RoleAssignmentAuditEvent,
): RoleAssignmentAuditEvent =>
  Object.freeze(
    event.kind === "granted"
      ? {
          id: event.id,
          kind: "granted",
          assignment: snapshotActive(event.assignment),
        }
      : {
          id: event.id,
          kind: "revoked",
          assignment: snapshotRevoked(event.assignment),
        },
  );

export const snapshotAuditRecord = (
  record: SequencedRoleAssignmentAuditEvent,
): SequencedRoleAssignmentAuditEvent =>
  Object.freeze({
    sequence: record.sequence,
    event: snapshotEvent(record.event),
  });

export const snapshotIdentityLink = (value: unknown): IdentityLink => {
  const link = objectValue(value, "identity link");
  exactKeys(link, ["key", "principalId"], "identity link");
  const key = objectValue(link.key, "identity link key");
  exactKeys(key, ["issuer", "subject"], "identity link key");
  return Object.freeze({
    key: Object.freeze({
      issuer: stringValue(key.issuer, "identity issuer"),
      subject: stringValue(key.subject, "identity subject"),
    }),
    principalId: stringValue(link.principalId, "identity principalId"),
  });
};

export const identityKeysEqual = (
  left: IdentityLinkKey,
  right: IdentityLinkKey,
): boolean => left.issuer === right.issuer && left.subject === right.subject;

export const assertBaseEntity = (
  entity: StoredEntity,
  expected: Readonly<{
    partitionKey: string;
    rowKey: string;
    applicationId: string;
    entityKind: string;
  }>,
): void => {
  if (
    entity.partitionKey !== expected.partitionKey ||
    entity.rowKey !== expected.rowKey ||
    entity.schemaVersion !== 1 ||
    entity.applicationId !== expected.applicationId ||
    entity.entityKind !== expected.entityKind
  ) {
    fail(`${expected.entityKind} row binding is invalid`);
  }
};

export const requireEtag = (entity: StoredEntity): string => {
  if (
    typeof entity.etag !== "string" ||
    entity.etag.length === 0 ||
    entity.etag === "*"
  ) {
    return fail("entity ETag is missing or unsafe");
  }
  return entity.etag;
};

export const requireStringProperty = (
  entity: StoredEntity,
  property: string,
): string => stringValue(entity[property], property);

export const requireIntegerProperty = (
  entity: StoredEntity,
  property: string,
): number => timestampValue(entity[property], property);

export const corrupt = fail;
