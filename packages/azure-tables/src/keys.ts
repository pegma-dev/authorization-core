import { createHash } from "node:crypto";

import type {
  RoleAssignment,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";

const updateString = (
  hash: ReturnType<typeof createHash>,
  value: string,
): void => {
  const length = Buffer.allocUnsafe(4);
  length.writeUInt32BE(value.length);
  hash.update(length);

  const codeUnits = Buffer.allocUnsafe(value.length * 2);
  for (let index = 0; index < value.length; index += 1) {
    codeUnits.writeUInt16BE(value.charCodeAt(index), index * 2);
  }
  hash.update(codeUnits);
};

export const digest = (domain: string, values: readonly string[]): string => {
  const hash = createHash("sha256");
  updateString(hash, domain);
  for (const value of values) {
    updateString(hash, value);
  }
  return hash.digest("hex");
};

export const scopeValues = (scope: RoleAssignmentScope): readonly string[] =>
  scope.kind === "application"
    ? ["application"]
    : ["organization", scope.organizationId];

export const applicationPartitionKey = (applicationId: string): string =>
  `app:${digest("application", [applicationId])}`;

export const identityRowKey = (issuer: string, subject: string): string =>
  `i:${digest("identity", [issuer, subject])}`;

export const assignmentRowKey = (assignmentId: string): string =>
  `a:${digest("assignment", [assignmentId])}`;

export const tupleRowKey = (
  assignment: Pick<RoleAssignment, "principalId" | "role" | "scope">,
): string =>
  `t:${digest("active-tuple", [
    assignment.principalId,
    assignment.role,
    ...scopeValues(assignment.scope),
  ])}`;

export const selectionPrefix = (
  principalId: string,
  scope: RoleAssignmentScope,
): string => `s:${digest("selection", [principalId, ...scopeValues(scope)])}:`;

export const selectionRowKey = (
  assignment: Pick<RoleAssignment, "id" | "principalId" | "scope">,
): string =>
  `${selectionPrefix(assignment.principalId, assignment.scope)}${digest(
    "selection-assignment",
    [assignment.id],
  )}`;

export const selectionFenceRowKey = (
  principalId: string,
  scope: RoleAssignmentScope,
): string =>
  `f:${digest("selection-fence", [principalId, ...scopeValues(scope)])}`;

export const auditPrefix = (assignmentId: string): string =>
  `h:${digest("audit-assignment", [assignmentId])}:`;

export const auditRowKey = (assignmentId: string, sequence: 1 | 2): string =>
  `${auditPrefix(assignmentId)}${sequence.toString().padStart(4, "0")}`;

export const eventRowKey = (eventId: string): string =>
  `e:${digest("audit-event", [eventId])}`;

/** Exclusive bound for prefixes whose suffix is lowercase hexadecimal. */
export const prefixUpperBound = (prefix: string): string => `${prefix}g`;
