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
} from "@pegma/authorization-contracts";

import type {
  AuditedRevokeRoleAssignmentCommand,
  AuditedRevokeRoleAssignmentResult,
  GrantRoleAssignmentCommand,
  GrantRoleAssignmentResult,
  InMemoryStorageAdapter,
  InMemoryStorageAdapterOptions,
  RoleAssignmentAuditEvent,
  RoleAssignmentAuditEventId,
  RoleAssignmentConcurrencyToken,
  SequencedRoleAssignmentAuditEvent,
  VersionedRoleAssignment,
} from "./index.js";

interface State {
  readonly assignments: ReadonlyMap<RoleAssignmentId, VersionedRoleAssignment>;
  readonly auditByAssignment: ReadonlyMap<
    RoleAssignmentId,
    readonly SequencedRoleAssignmentAuditEvent[]
  >;
  readonly auditByEventId: ReadonlyMap<
    RoleAssignmentAuditEventId,
    SequencedRoleAssignmentAuditEvent
  >;
  readonly revocationReplayTokens: ReadonlyMap<
    RoleAssignmentId,
    RoleAssignmentConcurrencyToken
  >;
  readonly nextToken: number;
}

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

const snapshotRevoked = (
  assignment: RevokedRoleAssignment,
): RevokedRoleAssignment => {
  const grantedAtEpochMs = requireLifecycleTimestamp(
    assignment.grantedAtEpochMs,
    "grantedAtEpochMs",
  );
  const revokedAtEpochMs = requireLifecycleTimestamp(
    assignment.revokedAtEpochMs,
    "revokedAtEpochMs",
  );
  if (revokedAtEpochMs < grantedAtEpochMs) {
    throw new RangeError(
      "revokedAtEpochMs must be greater than or equal to grantedAtEpochMs",
    );
  }
  return Object.freeze({
    id: assignment.id,
    principalId: assignment.principalId,
    role: assignment.role,
    scope: snapshotScope(assignment.scope),
    grantedBy: snapshotActor(assignment.grantedBy),
    grantedAtEpochMs,
    status: "revoked",
    revokedBy: snapshotActor(assignment.revokedBy),
    revokedAtEpochMs,
    ...(assignment.reason === undefined ? {} : { reason: assignment.reason }),
  });
};

const snapshotAssignment = (assignment: RoleAssignment): RoleAssignment =>
  assignment.status === "active"
    ? snapshotActive(assignment)
    : snapshotRevoked(assignment);

const snapshotVersioned = <Assignment extends RoleAssignment>(
  record: VersionedRoleAssignment<Assignment>,
): VersionedRoleAssignment<Assignment> =>
  Object.freeze({
    assignment: snapshotAssignment(record.assignment) as Assignment,
    concurrencyToken: record.concurrencyToken,
  });

const snapshotEvent = (
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

const snapshotAuditRecord = (
  record: SequencedRoleAssignmentAuditEvent,
): SequencedRoleAssignmentAuditEvent =>
  Object.freeze({
    sequence: record.sequence,
    event: snapshotEvent(record.event),
  });

const scopesEqual = (
  left: RoleAssignmentScope,
  right: RoleAssignmentScope,
): boolean =>
  left.kind === "application"
    ? right.kind === "application"
    : right.kind === "organization" &&
      left.organizationId === right.organizationId;

const actorsEqual = (
  left: RoleAssignmentActor,
  right: RoleAssignmentActor,
): boolean =>
  left.kind === "principal"
    ? right.kind === "principal" && left.principalId === right.principalId
    : right.kind === "system" && left.systemId === right.systemId;

const grantsEqual = (
  left: RoleAssignment,
  right: ActiveRoleAssignment,
): boolean =>
  left.id === right.id &&
  left.principalId === right.principalId &&
  left.role === right.role &&
  scopesEqual(left.scope, right.scope) &&
  actorsEqual(left.grantedBy, right.grantedBy) &&
  left.grantedAtEpochMs === right.grantedAtEpochMs;

const revocationsEqual = (
  assignment: RevokedRoleAssignment,
  command: AuditedRevokeRoleAssignmentCommand,
): boolean =>
  actorsEqual(assignment.revokedBy, command.revokedBy) &&
  assignment.revokedAtEpochMs === command.revokedAtEpochMs &&
  assignment.reason === command.reason;

const assignmentsEqual = (
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

const eventsEqual = (
  left: RoleAssignmentAuditEvent,
  right: RoleAssignmentAuditEvent,
): boolean =>
  left.id === right.id &&
  left.kind === right.kind &&
  assignmentsEqual(left.assignment, right.assignment);

const freezeGrantResult = <
  Result extends Exclude<
    GrantRoleAssignmentResult,
    { readonly status: "conflict" }
  >,
>(
  result: Result,
): Result =>
  Object.freeze({
    status: result.status,
    record: snapshotVersioned(result.record),
    auditRecord: snapshotAuditRecord(result.auditRecord),
  }) as Result;

const freezeRevokeResult = (
  result: Exclude<
    AuditedRevokeRoleAssignmentResult,
    { readonly status: "not_found" | "conflict" }
  >,
): AuditedRevokeRoleAssignmentResult =>
  Object.freeze({
    status: result.status,
    record: snapshotVersioned(result.record),
    auditRecord: snapshotAuditRecord(result.auditRecord),
  });

const conflict = <Reason extends string>(
  reason: Reason,
): Readonly<{ readonly status: "conflict"; readonly reason: Reason }> =>
  Object.freeze({ status: "conflict", reason });

const snapshotGrantCommand = (
  command: GrantRoleAssignmentCommand,
): GrantRoleAssignmentCommand =>
  Object.freeze({
    assignment: snapshotActive(command.assignment),
    auditEventId: command.auditEventId,
  });

const snapshotRevokeCommand = (
  command: AuditedRevokeRoleAssignmentCommand,
): AuditedRevokeRoleAssignmentCommand => {
  const revokedAtEpochMs = requireLifecycleTimestamp(
    command.revokedAtEpochMs,
    "revokedAtEpochMs",
  );
  return Object.freeze({
    assignmentId: command.assignmentId,
    expectedConcurrencyToken: command.expectedConcurrencyToken,
    revokedBy: snapshotActor(command.revokedBy),
    revokedAtEpochMs,
    ...(command.reason === undefined ? {} : { reason: command.reason }),
    auditEventId: command.auditEventId,
  });
};

const snapshotIdentityLinks = (
  options: InMemoryStorageAdapterOptions,
): readonly IdentityLink[] => {
  const links = options.identityLinks ?? [];
  return Object.freeze(
    Array.from(links, (link) =>
      Object.freeze({
        key: Object.freeze({
          issuer: link.key.issuer,
          subject: link.key.subject,
        }),
        principalId: link.principalId,
      }),
    ),
  );
};

/**
 * Creates an isolated, ephemeral reference adapter for one host application.
 *
 * Mutations synchronously prepare copy-on-write state and publish it with one
 * in-process commit before their returned promise settles. This is not a
 * durable or cross-process transaction.
 */
export const createInMemoryStorageAdapter = (
  options: InMemoryStorageAdapterOptions = {},
): InMemoryStorageAdapter => {
  const identityLinks = snapshotIdentityLinks(options);
  const identities = new Map<string, Map<string, PrincipalId>>();
  for (const link of identityLinks) {
    const subjects =
      identities.get(link.key.issuer) ?? new Map<string, PrincipalId>();
    const existing = subjects.get(link.key.subject);
    if (existing !== undefined && existing !== link.principalId) {
      throw new Error(
        "one exact identity-link key cannot seed multiple principals",
      );
    }
    subjects.set(link.key.subject, link.principalId);
    identities.set(link.key.issuer, subjects);
  }

  let state: State = {
    assignments: new Map(),
    auditByAssignment: new Map(),
    auditByEventId: new Map(),
    revocationReplayTokens: new Map(),
    nextToken: 1,
  };

  const adapter: InMemoryStorageAdapter = {
    resolvePrincipalId(key: IdentityLinkKey): Promise<PrincipalId | null> {
      const issuer = key.issuer;
      const subject = key.subject;
      return Promise.resolve(identities.get(issuer)?.get(subject) ?? null);
    },

    getRoleAssignment(
      assignmentId: RoleAssignmentId,
    ): Promise<VersionedRoleAssignment | null> {
      const exactId = assignmentId;
      const record = state.assignments.get(exactId);
      return Promise.resolve(
        record === undefined ? null : snapshotVersioned(record),
      );
    },

    listActiveRoleAssignments(
      principalId: PrincipalId,
      scope: RoleAssignmentScope,
    ): Promise<readonly ActiveRoleAssignment[]> {
      const exactPrincipalId = principalId;
      const exactScope = snapshotScope(scope);
      const records = [...state.assignments.values()]
        .map(({ assignment }) => assignment)
        .filter(
          (assignment): assignment is ActiveRoleAssignment =>
            assignment.status === "active" &&
            assignment.principalId === exactPrincipalId &&
            scopesEqual(assignment.scope, exactScope),
        )
        .map(snapshotActive);
      return Promise.resolve(Object.freeze(records));
    },

    listRoleAssignmentAuditEvents(
      assignmentId: RoleAssignmentId,
    ): Promise<readonly SequencedRoleAssignmentAuditEvent[]> {
      const exactId = assignmentId;
      const history = state.auditByAssignment.get(exactId) ?? [];
      return Promise.resolve(Object.freeze(history.map(snapshotAuditRecord)));
    },

    grantRoleAssignmentWithAudit(
      input: GrantRoleAssignmentCommand,
    ): Promise<GrantRoleAssignmentResult> {
      const command = snapshotGrantCommand(input);
      const assignment = command.assignment;
      const existing = state.assignments.get(assignment.id);

      if (
        existing !== undefined &&
        !grantsEqual(existing.assignment, assignment)
      ) {
        return Promise.resolve(conflict("assignment_id"));
      }
      if (
        existing === undefined &&
        [...state.assignments.values()].some(
          ({ assignment: candidate }) =>
            candidate.status === "active" &&
            candidate.principalId === assignment.principalId &&
            candidate.role === assignment.role &&
            scopesEqual(candidate.scope, assignment.scope),
        )
      ) {
        return Promise.resolve(conflict("active_tuple"));
      }

      const derivedEvent: RoleAssignmentAuditEvent = Object.freeze({
        id: command.auditEventId,
        kind: "granted",
        assignment,
      });
      const existingEvent = state.auditByEventId.get(command.auditEventId);
      if (existingEvent !== undefined) {
        if (
          existing !== undefined &&
          existingEvent.sequence === 1 &&
          eventsEqual(existingEvent.event, derivedEvent)
        ) {
          return Promise.resolve(
            freezeGrantResult({
              status: "unchanged",
              record: existing,
              auditRecord: existingEvent,
            }),
          );
        }
        return Promise.resolve(conflict("event_id"));
      }
      if (
        existing !== undefined ||
        (state.auditByAssignment.get(assignment.id)?.length ?? 0) !== 0
      ) {
        return Promise.resolve(conflict("lifecycle_position"));
      }

      const record: VersionedRoleAssignment<ActiveRoleAssignment> =
        Object.freeze({
          assignment,
          concurrencyToken: `version_${state.nextToken}`,
        });
      const auditRecord: SequencedRoleAssignmentAuditEvent = Object.freeze({
        sequence: 1,
        event: derivedEvent,
      });
      const assignments = new Map(state.assignments);
      assignments.set(assignment.id, record);
      const auditByAssignment = new Map(state.auditByAssignment);
      auditByAssignment.set(assignment.id, Object.freeze([auditRecord]));
      const auditByEventId = new Map(state.auditByEventId);
      auditByEventId.set(command.auditEventId, auditRecord);
      state = {
        assignments,
        auditByAssignment,
        auditByEventId,
        revocationReplayTokens: state.revocationReplayTokens,
        nextToken: state.nextToken + 1,
      };
      return Promise.resolve(
        freezeGrantResult({
          status: "granted",
          record,
          auditRecord,
        }),
      );
    },

    revokeRoleAssignmentWithAudit(
      input: AuditedRevokeRoleAssignmentCommand,
    ): Promise<AuditedRevokeRoleAssignmentResult> {
      const command = snapshotRevokeCommand(input);
      const existing = state.assignments.get(command.assignmentId);
      if (existing === undefined) {
        return Promise.resolve(Object.freeze({ status: "not_found" }));
      }
      if (existing.assignment.status === "revoked") {
        if (!revocationsEqual(existing.assignment, command)) {
          return Promise.resolve(conflict("lifecycle"));
        }
        if (
          state.revocationReplayTokens.get(command.assignmentId) !==
          command.expectedConcurrencyToken
        ) {
          return Promise.resolve(conflict("concurrency"));
        }
        const derivedEvent: RoleAssignmentAuditEvent = Object.freeze({
          id: command.auditEventId,
          kind: "revoked",
          assignment: existing.assignment,
        });
        const existingEvent = state.auditByEventId.get(command.auditEventId);
        if (existingEvent !== undefined) {
          if (
            existingEvent.sequence === 2 &&
            eventsEqual(existingEvent.event, derivedEvent)
          ) {
            return Promise.resolve(
              freezeRevokeResult({
                status: "unchanged",
                record:
                  existing as VersionedRoleAssignment<RevokedRoleAssignment>,
                auditRecord: existingEvent,
              }),
            );
          }
          return Promise.resolve(conflict("event_id"));
        }
        return Promise.resolve(conflict("lifecycle_position"));
      }
      if (existing.concurrencyToken !== command.expectedConcurrencyToken) {
        return Promise.resolve(conflict("concurrency"));
      }
      if (command.revokedAtEpochMs < existing.assignment.grantedAtEpochMs) {
        return Promise.resolve(conflict("lifecycle"));
      }

      const revoked: RevokedRoleAssignment = Object.freeze({
        ...existing.assignment,
        status: "revoked",
        revokedBy: command.revokedBy,
        revokedAtEpochMs: command.revokedAtEpochMs,
        ...(command.reason === undefined ? {} : { reason: command.reason }),
      });
      const derivedEvent: RoleAssignmentAuditEvent = Object.freeze({
        id: command.auditEventId,
        kind: "revoked",
        assignment: revoked,
      });
      const existingEvent = state.auditByEventId.get(command.auditEventId);
      if (existingEvent !== undefined) {
        return Promise.resolve(conflict("event_id"));
      }
      const history = state.auditByAssignment.get(command.assignmentId) ?? [];
      if (
        history.length !== 1 ||
        history[0]?.sequence !== 1 ||
        history[0].event.kind !== "granted" ||
        !grantsEqual(revoked, history[0].event.assignment)
      ) {
        return Promise.resolve(conflict("lifecycle_position"));
      }

      const record: VersionedRoleAssignment<RevokedRoleAssignment> =
        Object.freeze({
          assignment: revoked,
          concurrencyToken: `version_${state.nextToken}`,
        });
      const auditRecord: SequencedRoleAssignmentAuditEvent = Object.freeze({
        sequence: 2,
        event: derivedEvent,
      });
      const assignments = new Map(state.assignments);
      assignments.set(command.assignmentId, record);
      const auditByAssignment = new Map(state.auditByAssignment);
      auditByAssignment.set(
        command.assignmentId,
        Object.freeze([...history, auditRecord]),
      );
      const auditByEventId = new Map(state.auditByEventId);
      auditByEventId.set(command.auditEventId, auditRecord);
      const revocationReplayTokens = new Map(state.revocationReplayTokens);
      revocationReplayTokens.set(
        command.assignmentId,
        command.expectedConcurrencyToken,
      );
      state = {
        assignments,
        auditByAssignment,
        auditByEventId,
        revocationReplayTokens,
        nextToken: state.nextToken + 1,
      };
      return Promise.resolve(
        freezeRevokeResult({
          status: "revoked",
          record,
          auditRecord,
        }),
      );
    },
  };

  return Object.freeze(adapter);
};
