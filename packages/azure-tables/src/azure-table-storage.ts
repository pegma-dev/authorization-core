import { randomUUID } from "node:crypto";

import {
  odata,
  type TableClient,
  type TableEntity,
  type TransactionAction,
} from "@azure/data-tables";
import type {
  ActiveRoleAssignment,
  IdentityLink,
  IdentityLinkKey,
  PrincipalId,
  RevokedRoleAssignment,
  RoleAssignment,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import type {
  AuditedRevokeRoleAssignmentCommand,
  AuditedRevokeRoleAssignmentResult,
  GrantRoleAssignmentCommand,
  GrantRoleAssignmentResult,
  RoleAssignmentAuditEvent,
  SequencedRoleAssignmentAuditEvent,
  VersionedRoleAssignment,
} from "@pegma/authorization-storage";

import {
  actorsEqual,
  assertBaseEntity,
  assignmentsEqual,
  corrupt,
  decodeAssignment,
  encodeAssignment,
  grantsEqual,
  identityKeysEqual,
  requireEtag,
  requireIntegerProperty,
  requireStringProperty,
  scopesEqual,
  snapshotActive,
  snapshotActor,
  snapshotAssignment,
  snapshotAuditRecord,
  snapshotIdentityLink,
  snapshotRevoked,
  snapshotScope,
  snapshotVersioned,
  type StoredEntity,
} from "./codec.js";
import {
  applicationPartitionKey,
  assignmentRowKey,
  auditPrefix,
  auditRowKey,
  eventRowKey,
  identityRowKey,
  prefixUpperBound,
  selectionPrefix,
  selectionFenceRowKey,
  selectionRowKey,
  tupleRowKey,
} from "./keys.js";
import type {
  AzureTableStorageAdapter,
  AzureTableStorageAdapterOptions,
} from "./index.js";

type AzureTableClient = Pick<
  TableClient,
  "getEntity" | "listEntities" | "submitTransaction"
>;

const storageErrorCode = (error: unknown): string | undefined => {
  if (typeof error !== "object" || error === null) {
    return undefined;
  }
  const candidate = error as {
    readonly code?: unknown;
    readonly details?: { readonly errorCode?: unknown };
    readonly response?: {
      readonly headers?: { readonly get?: (name: string) => unknown };
    };
  };
  if (typeof candidate.code === "string") {
    return candidate.code;
  }
  if (typeof candidate.details?.errorCode === "string") {
    return candidate.details.errorCode;
  }
  const header = candidate.response?.headers?.get?.("x-ms-error-code");
  return typeof header === "string" ? header : undefined;
};

const isEntityNotFound = (error: unknown): boolean => {
  if (
    typeof error !== "object" ||
    error === null ||
    !("statusCode" in error) ||
    (error as { readonly statusCode?: unknown }).statusCode !== 404
  ) {
    return false;
  }
  const code = storageErrorCode(error);
  return code === "EntityNotFound" || code === "ResourceNotFound";
};

const getEntityOrNull = async (
  client: AzureTableClient,
  partitionKey: string,
  rowKey: string,
): Promise<StoredEntity | null> => {
  try {
    return (await client.getEntity<Record<string, unknown>>(
      partitionKey,
      rowKey,
    )) as StoredEntity;
  } catch (error) {
    if (isEntityNotFound(error)) {
      return null;
    }
    throw error;
  }
};

const baseEntity = (
  partitionKey: string,
  rowKey: string,
  applicationId: string,
  entityKind: string,
): TableEntity => ({
  partitionKey,
  rowKey,
  schemaVersion: 1,
  applicationId,
  entityKind,
});

const assignmentEntity = (
  partitionKey: string,
  applicationId: string,
  assignment: RoleAssignment,
  replayToken?: string,
): TableEntity => ({
  ...baseEntity(
    partitionKey,
    assignmentRowKey(assignment.id),
    applicationId,
    "assignment",
  ),
  assignmentId: assignment.id,
  assignmentJson: encodeAssignment(assignment),
  lifecycleStatus: assignment.status,
  ...(replayToken === undefined ? {} : { revocationReplayToken: replayToken }),
});

const tupleEntity = (
  partitionKey: string,
  applicationId: string,
  assignment: RoleAssignment,
): TableEntity => ({
  ...baseEntity(
    partitionKey,
    tupleRowKey(assignment),
    applicationId,
    "active_tuple",
  ),
  tupleState: assignment.status === "active" ? "active" : "retired",
  assignmentId: assignment.id,
  assignmentJson: encodeAssignment(assignment),
});

const selectionEntity = (
  partitionKey: string,
  applicationId: string,
  assignment: ActiveRoleAssignment,
): TableEntity => ({
  ...baseEntity(
    partitionKey,
    selectionRowKey(assignment),
    applicationId,
    "active_selection",
  ),
  assignmentId: assignment.id,
  assignmentJson: encodeAssignment(assignment),
});

const selectionFenceEntity = (
  partitionKey: string,
  applicationId: string,
  principalId: string,
  scope: RoleAssignmentScope,
  activeCount: number,
): TableEntity => ({
  ...baseEntity(
    partitionKey,
    selectionFenceRowKey(principalId, scope),
    applicationId,
    "selection_fence",
  ),
  principalId,
  scopeJson: JSON.stringify(scope),
  activeCount,
  revisionId: randomUUID(),
});

const auditEntity = (
  partitionKey: string,
  applicationId: string,
  event: RoleAssignmentAuditEvent,
  sequence: 1 | 2,
): TableEntity => ({
  ...baseEntity(
    partitionKey,
    auditRowKey(event.assignment.id, sequence),
    applicationId,
    "role_audit",
  ),
  assignmentId: event.assignment.id,
  auditEventId: event.id,
  eventKind: event.kind,
  sequence,
  assignmentJson: encodeAssignment(event.assignment),
});

const eventEntity = (
  partitionKey: string,
  applicationId: string,
  event: RoleAssignmentAuditEvent,
  sequence: 1 | 2,
): TableEntity => ({
  ...baseEntity(
    partitionKey,
    eventRowKey(event.id),
    applicationId,
    "audit_event_guard",
  ),
  auditEventId: event.id,
  assignmentId: event.assignment.id,
  eventKind: event.kind,
  sequence,
  auditRowKey: auditRowKey(event.assignment.id, sequence),
});

const decodeAssignmentEntity = (
  entity: StoredEntity,
  partitionKey: string,
  applicationId: string,
  expectedAssignmentId?: string,
): VersionedRoleAssignment => {
  const assignment = decodeAssignment(entity.assignmentJson);
  const rowKey = assignmentRowKey(assignment.id);
  assertBaseEntity(entity, {
    partitionKey,
    rowKey,
    applicationId,
    entityKind: "assignment",
  });
  if (
    requireStringProperty(entity, "assignmentId") !== assignment.id ||
    entity.lifecycleStatus !== assignment.status ||
    (expectedAssignmentId !== undefined &&
      assignment.id !== expectedAssignmentId)
  ) {
    corrupt("assignment source binding is invalid");
  }
  if (
    assignment.status === "active" &&
    entity.revocationReplayToken !== undefined
  ) {
    corrupt("active assignment contains a revocation replay token");
  }
  if (
    assignment.status === "revoked" &&
    (typeof entity.revocationReplayToken !== "string" ||
      entity.revocationReplayToken.length === 0 ||
      entity.revocationReplayToken === "*")
  ) {
    corrupt("revoked assignment replay token is invalid");
  }
  return snapshotVersioned(assignment, requireEtag(entity));
};

interface DecodedTuple {
  readonly state: "active" | "retired";
  readonly assignment: RoleAssignment;
  readonly etag: string;
}

const decodeTupleEntity = (
  entity: StoredEntity,
  partitionKey: string,
  applicationId: string,
  expected: Pick<RoleAssignment, "principalId" | "role" | "scope">,
): DecodedTuple => {
  const assignment = decodeAssignment(entity.assignmentJson);
  assertBaseEntity(entity, {
    partitionKey,
    rowKey: tupleRowKey(assignment),
    applicationId,
    entityKind: "active_tuple",
  });
  if (
    assignment.principalId !== expected.principalId ||
    assignment.role !== expected.role ||
    !scopesEqual(assignment.scope, expected.scope) ||
    requireStringProperty(entity, "assignmentId") !== assignment.id
  ) {
    corrupt("active tuple source binding is invalid");
  }
  const state = entity.tupleState;
  if (
    (state !== "active" && state !== "retired") ||
    (state === "active") !== (assignment.status === "active")
  ) {
    corrupt("active tuple lifecycle state is invalid");
  }
  return Object.freeze({
    state: state as "active" | "retired",
    assignment,
    etag: requireEtag(entity),
  });
};

const decodeSelectionEntity = (
  entity: StoredEntity,
  partitionKey: string,
  applicationId: string,
  principalId: string,
  scope: RoleAssignmentScope,
): ActiveRoleAssignment => {
  const assignment = decodeAssignment(entity.assignmentJson);
  if (assignment.status !== "active") {
    corrupt("active selection contains a revoked assignment");
  }
  assertBaseEntity(entity, {
    partitionKey,
    rowKey: selectionRowKey(assignment),
    applicationId,
    entityKind: "active_selection",
  });
  requireEtag(entity);
  if (
    assignment.principalId !== principalId ||
    !scopesEqual(assignment.scope, scope) ||
    requireStringProperty(entity, "assignmentId") !== assignment.id
  ) {
    corrupt("active selection source binding is invalid");
  }
  return snapshotActive(assignment);
};

interface DecodedSelectionFence {
  readonly activeCount: number;
  readonly etag: string;
  readonly principalId: string;
  readonly scope: RoleAssignmentScope;
}

const decodeSelectionFenceEntity = (
  entity: StoredEntity,
  partitionKey: string,
  applicationId: string,
  expectedPrincipalId: string,
  expectedScope: RoleAssignmentScope,
): DecodedSelectionFence => {
  const principalId = requireStringProperty(entity, "principalId");
  const encodedScope = requireStringProperty(entity, "scopeJson");
  let scope: RoleAssignmentScope;
  try {
    scope = snapshotScope(JSON.parse(encodedScope) as unknown);
  } catch (error) {
    if (
      error instanceof Error &&
      error.message.startsWith("Azure Table Storage data is corrupt:")
    ) {
      throw error;
    }
    return corrupt("selection fence scope is not valid JSON");
  }
  assertBaseEntity(entity, {
    partitionKey,
    rowKey: selectionFenceRowKey(principalId, scope),
    applicationId,
    entityKind: "selection_fence",
  });
  requireStringProperty(entity, "revisionId");
  const activeCount = requireIntegerProperty(entity, "activeCount");
  if (
    principalId !== expectedPrincipalId ||
    !scopesEqual(scope, expectedScope)
  ) {
    corrupt("selection fence source binding is invalid");
  }
  return Object.freeze({
    activeCount,
    etag: requireEtag(entity),
    principalId,
    scope,
  });
};

const decodeAuditEntity = (
  entity: StoredEntity,
  partitionKey: string,
  applicationId: string,
  expectedAssignmentId: string,
): SequencedRoleAssignmentAuditEvent => {
  const sequence = requireIntegerProperty(entity, "sequence");
  if (sequence !== 1 && sequence !== 2) {
    corrupt("audit sequence must be one or two");
  }
  const assignment = decodeAssignment(entity.assignmentJson);
  const kind = entity.eventKind;
  if (
    assignment.id !== expectedAssignmentId ||
    requireStringProperty(entity, "assignmentId") !== assignment.id ||
    (sequence === 1 &&
      (kind !== "granted" || assignment.status !== "active")) ||
    (sequence === 2 && (kind !== "revoked" || assignment.status !== "revoked"))
  ) {
    corrupt("audit lifecycle position is invalid");
  }
  assertBaseEntity(entity, {
    partitionKey,
    rowKey: auditRowKey(assignment.id, sequence as 1 | 2),
    applicationId,
    entityKind: "role_audit",
  });
  requireEtag(entity);
  return snapshotAuditRecord({
    sequence: sequence as 1 | 2,
    event: {
      id: requireStringProperty(entity, "auditEventId"),
      kind,
      assignment,
    } as RoleAssignmentAuditEvent,
  });
};

const assertEventGuard = (
  entity: StoredEntity,
  partitionKey: string,
  applicationId: string,
  record: SequencedRoleAssignmentAuditEvent,
): void => {
  const event = record.event;
  assertBaseEntity(entity, {
    partitionKey,
    rowKey: eventRowKey(event.id),
    applicationId,
    entityKind: "audit_event_guard",
  });
  requireEtag(entity);
  if (
    entity.auditEventId !== event.id ||
    entity.assignmentId !== event.assignment.id ||
    entity.eventKind !== event.kind ||
    entity.sequence !== record.sequence ||
    entity.auditRowKey !==
      auditRowKey(event.assignment.id, record.sequence as 1 | 2)
  ) {
    corrupt("audit event guard binding is invalid");
  }
};

const auditRecordsEqual = (
  left: SequencedRoleAssignmentAuditEvent,
  right: SequencedRoleAssignmentAuditEvent,
): boolean =>
  left.sequence === right.sequence &&
  left.event.id === right.event.id &&
  left.event.kind === right.event.kind &&
  assignmentsEqual(left.event.assignment, right.event.assignment);

const makeGrantAudit = (
  assignment: ActiveRoleAssignment,
  eventId: string,
): SequencedRoleAssignmentAuditEvent =>
  snapshotAuditRecord({
    sequence: 1,
    event: { id: eventId, kind: "granted", assignment },
  });

const makeRevokeAudit = (
  assignment: RevokedRoleAssignment,
  eventId: string,
): SequencedRoleAssignmentAuditEvent =>
  snapshotAuditRecord({
    sequence: 2,
    event: { id: eventId, kind: "revoked", assignment },
  });

const readAssignment = async (
  client: AzureTableClient,
  partitionKey: string,
  applicationId: string,
  assignmentId: string,
): Promise<VersionedRoleAssignment | null> => {
  const entity = await getEntityOrNull(
    client,
    partitionKey,
    assignmentRowKey(assignmentId),
  );
  return entity === null
    ? null
    : decodeAssignmentEntity(entity, partitionKey, applicationId, assignmentId);
};

const readSelectionFence = async (
  client: AzureTableClient,
  partitionKey: string,
  applicationId: string,
  principalId: string,
  scope: RoleAssignmentScope,
): Promise<DecodedSelectionFence | null> => {
  const entity = await getEntityOrNull(
    client,
    partitionKey,
    selectionFenceRowKey(principalId, scope),
  );
  return entity === null
    ? null
    : decodeSelectionFenceEntity(
        entity,
        partitionKey,
        applicationId,
        principalId,
        scope,
      );
};

const sameFence = (
  left: DecodedSelectionFence | null,
  right: DecodedSelectionFence | null,
): boolean =>
  left === null ? right === null : right !== null && left.etag === right.etag;

const isCorruptDataError = (error: unknown): boolean =>
  error instanceof Error &&
  error.message.startsWith("Azure Table Storage data is corrupt:");

const readAuditAt = async (
  client: AzureTableClient,
  partitionKey: string,
  applicationId: string,
  assignmentId: string,
  sequence: 1 | 2,
): Promise<SequencedRoleAssignmentAuditEvent | null> => {
  const entity = await getEntityOrNull(
    client,
    partitionKey,
    auditRowKey(assignmentId, sequence),
  );
  return entity === null
    ? null
    : decodeAuditEntity(entity, partitionKey, applicationId, assignmentId);
};

const verifyExistingEventId = async (
  client: AzureTableClient,
  partitionKey: string,
  applicationId: string,
  entity: StoredEntity,
  expectedEventId: string,
): Promise<void> => {
  const actualEventId = requireStringProperty(entity, "auditEventId");
  assertBaseEntity(entity, {
    partitionKey,
    rowKey: eventRowKey(actualEventId),
    applicationId,
    entityKind: "audit_event_guard",
  });
  requireEtag(entity);
  if (actualEventId !== expectedEventId) {
    corrupt("audit event digest collision");
  }
  const assignmentId = requireStringProperty(entity, "assignmentId");
  const sequence = requireIntegerProperty(entity, "sequence");
  if (sequence !== 1 && sequence !== 2) {
    corrupt("audit event guard sequence is invalid");
  }
  const record = await readAuditAt(
    client,
    partitionKey,
    applicationId,
    assignmentId,
    sequence as 1 | 2,
  );
  if (record === null) {
    corrupt("audit event guard has no audit record");
  }
  assertEventGuard(entity, partitionKey, applicationId, record!);
};

const verifyAuditGuard = async (
  client: AzureTableClient,
  partitionKey: string,
  applicationId: string,
  record: SequencedRoleAssignmentAuditEvent,
): Promise<void> => {
  const guard = await getEntityOrNull(
    client,
    partitionKey,
    eventRowKey(record.event.id),
  );
  if (guard === null) {
    corrupt("audit event guard is missing");
  }
  assertEventGuard(guard!, partitionKey, applicationId, record);
};

const getStatusCode = (error: unknown): number | undefined =>
  typeof error === "object" &&
  error !== null &&
  "statusCode" in error &&
  typeof (error as { readonly statusCode?: unknown }).statusCode === "number"
    ? (error as { readonly statusCode: number }).statusCode
    : undefined;

const safeExpectedToken = (value: unknown): value is string =>
  typeof value === "string" && value.length > 0 && value !== "*";

export const createAzureTableIdentityLinkEntity = (
  applicationId: string,
  identityLink: IdentityLink,
): TableEntity => {
  if (applicationId.length === 0) {
    throw new TypeError("applicationId must not be empty");
  }
  const link = snapshotIdentityLink(identityLink);
  const partitionKey = applicationPartitionKey(applicationId);
  return {
    ...baseEntity(
      partitionKey,
      identityRowKey(link.key.issuer, link.key.subject),
      applicationId,
      "identity_link",
    ),
    issuer: link.key.issuer,
    subject: link.key.subject,
    principalId: link.principalId,
  };
};

export const createAzureTableStorageAdapter = (
  options: AzureTableStorageAdapterOptions,
): AzureTableStorageAdapter => {
  if (options.applicationId.length === 0) {
    throw new TypeError("applicationId must not be empty");
  }
  const client = options.tableClient;
  const applicationId = options.applicationId;
  const partitionKey = applicationPartitionKey(applicationId);

  const resolvePrincipalId = async (
    keyInput: IdentityLinkKey,
  ): Promise<PrincipalId | null> => {
    const key = Object.freeze({
      issuer: keyInput.issuer,
      subject: keyInput.subject,
    });
    const rowKey = identityRowKey(key.issuer, key.subject);
    const entity = await getEntityOrNull(client, partitionKey, rowKey);
    if (entity === null) {
      return null;
    }
    assertBaseEntity(entity, {
      partitionKey,
      rowKey,
      applicationId,
      entityKind: "identity_link",
    });
    requireEtag(entity);
    const link = snapshotIdentityLink({
      key: {
        issuer: entity.issuer,
        subject: entity.subject,
      },
      principalId: entity.principalId,
    });
    if (!identityKeysEqual(link.key, key)) {
      corrupt("identity-link digest collision");
    }
    return link.principalId;
  };

  const listActiveRoleAssignments = async (
    principalIdInput: string,
    scopeInput: RoleAssignmentScope,
  ): Promise<readonly ActiveRoleAssignment[]> => {
    const principalId = principalIdInput;
    const scope = snapshotScope(scopeInput);
    const selectionKeyPrefix = selectionPrefix(principalId, scope);
    const selectionFilter = odata`PartitionKey eq ${partitionKey} and RowKey ge ${selectionKeyPrefix} and RowKey lt ${prefixUpperBound(
      selectionKeyPrefix,
    )}`;

    for (let attempt = 0; attempt < 3; attempt += 1) {
      const before = await readSelectionFence(
        client,
        partitionKey,
        applicationId,
        principalId,
        scope,
      );
      try {
        const assignments = new Map<string, ActiveRoleAssignment>();
        const seenTuples = new Set<string>();
        for await (const entity of client.listEntities<Record<string, unknown>>(
          {
            queryOptions: { filter: selectionFilter },
          },
        )) {
          const selection = decodeSelectionEntity(
            entity as StoredEntity,
            partitionKey,
            applicationId,
            principalId,
            scope,
          );
          if (assignments.has(selection.id)) {
            corrupt("active selection index contains a duplicate");
          }
          const authoritative = await readAssignment(
            client,
            partitionKey,
            applicationId,
            selection.id,
          );
          if (
            authoritative === null ||
            authoritative.assignment.status !== "active" ||
            !assignmentsEqual(authoritative.assignment, selection)
          ) {
            corrupt("active selection has no authoritative assignment");
          }
          const tupleKey = tupleRowKey(selection);
          if (seenTuples.has(tupleKey)) {
            corrupt("active selections contain a duplicate tuple");
          }
          const tupleSource = await getEntityOrNull(
            client,
            partitionKey,
            tupleKey,
          );
          if (tupleSource === null) {
            corrupt("active selection tuple guard is missing");
          }
          const tuple = decodeTupleEntity(
            tupleSource!,
            partitionKey,
            applicationId,
            selection,
          );
          if (
            tuple.state !== "active" ||
            !assignmentsEqual(tuple.assignment, selection)
          ) {
            corrupt("active selection tuple guard is inconsistent");
          }
          const grantAudit = await readAuditAt(
            client,
            partitionKey,
            applicationId,
            selection.id,
            1,
          );
          if (
            grantAudit === null ||
            grantAudit.event.kind !== "granted" ||
            !grantsEqual(selection, grantAudit.event.assignment)
          ) {
            corrupt("active selection grant audit is incomplete");
          }
          await verifyAuditGuard(
            client,
            partitionKey,
            applicationId,
            grantAudit!,
          );
          assignments.set(selection.id, snapshotActive(selection));
          seenTuples.add(tupleKey);
        }
        if (assignments.size !== (before?.activeCount ?? 0)) {
          corrupt("active assignment selection row is missing");
        }

        const after = await readSelectionFence(
          client,
          partitionKey,
          applicationId,
          principalId,
          scope,
        );
        if (!sameFence(before, after)) {
          continue;
        }
        return Object.freeze([...assignments.values()]);
      } catch (error) {
        if (!isCorruptDataError(error)) {
          throw error;
        }
        const after = await readSelectionFence(
          client,
          partitionKey,
          applicationId,
          principalId,
          scope,
        );
        if (!sameFence(before, after)) {
          continue;
        }
        throw error;
      }
    }
    throw new Error(
      "Azure Table Storage active-role selection changed too frequently",
    );
  };

  const listRoleAssignmentAuditEvents = async (
    assignmentId: string,
  ): Promise<readonly SequencedRoleAssignmentAuditEvent[]> => {
    const prefix = auditPrefix(assignmentId);
    const filter = odata`PartitionKey eq ${partitionKey} and RowKey ge ${prefix} and RowKey lt ${prefixUpperBound(
      prefix,
    )}`;
    const records: SequencedRoleAssignmentAuditEvent[] = [];
    for await (const entity of client.listEntities<Record<string, unknown>>({
      queryOptions: { filter },
    })) {
      records.push(
        decodeAuditEntity(
          entity as StoredEntity,
          partitionKey,
          applicationId,
          assignmentId,
        ),
      );
    }
    records.sort((left, right) => left.sequence - right.sequence);
    if (
      records.length > 2 ||
      records.some((record, index) => record.sequence !== index + 1)
    ) {
      corrupt("audit history is not a complete lifecycle prefix");
    }

    const assignment = await readAssignment(
      client,
      partitionKey,
      applicationId,
      assignmentId,
    );
    if (records.length === 0) {
      if (assignment !== null) {
        corrupt("assignment has no audit history");
      }
      return Object.freeze([]);
    }
    if (assignment === null) {
      corrupt("audit history has no assignment");
    }
    const authoritative = assignment!;
    const expectedCount = authoritative.assignment.status === "active" ? 1 : 2;
    if (
      records.length !== expectedCount ||
      !grantsEqual(
        authoritative.assignment,
        records[0]?.event.assignment as ActiveRoleAssignment,
      ) ||
      (expectedCount === 2 &&
        !assignmentsEqual(
          authoritative.assignment,
          records[1]?.event.assignment as RoleAssignment,
        ))
    ) {
      corrupt("audit history does not match assignment lifecycle");
    }
    for (const record of records) {
      await verifyAuditGuard(client, partitionKey, applicationId, record);
    }
    return Object.freeze(records.map(snapshotAuditRecord));
  };

  const assignmentChangedSince = async (
    record: VersionedRoleAssignment,
  ): Promise<boolean> => {
    const current = await readAssignment(
      client,
      partitionKey,
      applicationId,
      record.assignment.id,
    );
    if (current === null) {
      corrupt("authoritative assignment disappeared");
    }
    return (
      current!.concurrencyToken !== record.concurrencyToken ||
      !assignmentsEqual(current!.assignment, record.assignment)
    );
  };

  const verifyLifecycleIntegrity = async (
    record: VersionedRoleAssignment,
  ): Promise<void> => {
    const assignment = record.assignment;
    const history = await listRoleAssignmentAuditEvents(assignment.id);
    if (
      history.length !== (assignment.status === "active" ? 1 : 2) ||
      history[0]?.event.kind !== "granted" ||
      !grantsEqual(assignment, history[0].event.assignment) ||
      (assignment.status === "revoked" &&
        (history[1]?.event.kind !== "revoked" ||
          !assignmentsEqual(assignment, history[1].event.assignment)))
    ) {
      corrupt("assignment lifecycle audit is incomplete");
    }

    const fence = await readSelectionFence(
      client,
      partitionKey,
      applicationId,
      assignment.principalId,
      assignment.scope,
    );
    if (fence === null) {
      corrupt("assignment selection fence is missing");
    }

    const tupleSource = await getEntityOrNull(
      client,
      partitionKey,
      tupleRowKey(assignment),
    );
    if (tupleSource === null) {
      corrupt("assignment tuple guard is missing");
    }
    const tuple = decodeTupleEntity(
      tupleSource!,
      partitionKey,
      applicationId,
      assignment,
    );

    const selectionSource = await getEntityOrNull(
      client,
      partitionKey,
      selectionRowKey(assignment),
    );
    if (assignment.status === "active") {
      if (
        fence!.activeCount < 1 ||
        tuple.state !== "active" ||
        !assignmentsEqual(tuple.assignment, assignment) ||
        selectionSource === null
      ) {
        corrupt("active assignment derivatives are incomplete");
      }
      const selection = decodeSelectionEntity(
        selectionSource!,
        partitionKey,
        applicationId,
        assignment.principalId,
        assignment.scope,
      );
      if (!assignmentsEqual(selection, assignment)) {
        corrupt("active assignment selection is inconsistent");
      }
    } else {
      if (selectionSource !== null) {
        corrupt("revoked assignment retains an active selection");
      }
      const tupleRecord = await readAssignment(
        client,
        partitionKey,
        applicationId,
        tuple.assignment.id,
      );
      if (
        tupleRecord === null ||
        !assignmentsEqual(tupleRecord.assignment, tuple.assignment)
      ) {
        corrupt("tuple guard has no authoritative assignment");
      }
      const tupleHistory = await listRoleAssignmentAuditEvents(
        tuple.assignment.id,
      );
      if (
        tupleHistory.length !== (tuple.assignment.status === "active" ? 1 : 2)
      ) {
        corrupt("tuple guard assignment audit is incomplete");
      }
      const currentSelection = await getEntityOrNull(
        client,
        partitionKey,
        selectionRowKey(tuple.assignment),
      );
      if (
        (tuple.state === "active" && currentSelection === null) ||
        (tuple.state === "retired" && currentSelection !== null) ||
        (tuple.state === "active" && fence!.activeCount < 1)
      ) {
        corrupt("tuple guard selection state is inconsistent");
      }
      if (currentSelection !== null) {
        const decoded = decodeSelectionEntity(
          currentSelection,
          partitionKey,
          applicationId,
          tuple.assignment.principalId,
          tuple.assignment.scope,
        );
        if (!assignmentsEqual(decoded, tuple.assignment)) {
          corrupt("tuple guard active selection is inconsistent");
        }
      }
    }

    const activeAssignments = await listActiveRoleAssignments(
      assignment.principalId,
      assignment.scope,
    );
    const matchingAssignment = activeAssignments.find(
      (candidate) => candidate.id === assignment.id,
    );
    if (
      (assignment.status === "active" &&
        (matchingAssignment === undefined ||
          !assignmentsEqual(matchingAssignment, assignment))) ||
      (assignment.status === "revoked" && matchingAssignment !== undefined)
    ) {
      corrupt("assignment selection snapshot is inconsistent");
    }
  };

  const getRoleAssignment = async (
    assignmentId: string,
  ): Promise<VersionedRoleAssignment | null> => {
    const record = await readAssignment(
      client,
      partitionKey,
      applicationId,
      assignmentId,
    );
    if (record !== null) {
      await verifyLifecycleIntegrity(record);
    }
    return record;
  };

  const grantRoleAssignmentWithAudit = async (
    commandInput: GrantRoleAssignmentCommand,
  ): Promise<GrantRoleAssignmentResult> => {
    const assignment = snapshotActive(commandInput.assignment);
    const auditEventId = commandInput.auditEventId;
    if (typeof auditEventId !== "string") {
      throw new TypeError("auditEventId must be a string");
    }
    const expectedAudit = makeGrantAudit(assignment, auditEventId);

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const existing = await readAssignment(
        client,
        partitionKey,
        applicationId,
        assignment.id,
      );
      if (existing !== null) {
        if (!grantsEqual(existing.assignment, assignment)) {
          return Object.freeze({
            status: "conflict",
            reason: "assignment_id",
          });
        }
        const storedAudit = await readAuditAt(
          client,
          partitionKey,
          applicationId,
          assignment.id,
          1,
        );
        if (storedAudit === null) {
          corrupt("replayed assignment is missing its grant audit");
        }
        const suppliedEvent = await getEntityOrNull(
          client,
          partitionKey,
          eventRowKey(auditEventId),
        );
        if (storedAudit!.event.id !== auditEventId) {
          if (suppliedEvent !== null) {
            await verifyExistingEventId(
              client,
              partitionKey,
              applicationId,
              suppliedEvent,
              auditEventId,
            );
          }
          return Object.freeze({
            status: "conflict",
            reason: suppliedEvent === null ? "lifecycle_position" : "event_id",
          });
        }
        if (
          suppliedEvent === null ||
          !auditRecordsEqual(storedAudit!, expectedAudit)
        ) {
          corrupt("replayed assignment grant audit is incomplete");
        }
        assertEventGuard(
          suppliedEvent!,
          partitionKey,
          applicationId,
          storedAudit!,
        );
        await verifyLifecycleIntegrity(existing);
        return Object.freeze({
          status: "unchanged",
          record: existing,
          auditRecord: storedAudit!,
        });
      }

      const tupleKey = tupleRowKey(assignment);
      const storedTupleEntity = await getEntityOrNull(
        client,
        partitionKey,
        tupleKey,
      );
      const storedTuple =
        storedTupleEntity === null
          ? null
          : decodeTupleEntity(
              storedTupleEntity,
              partitionKey,
              applicationId,
              assignment,
            );
      const stableSelection = await listActiveRoleAssignments(
        assignment.principalId,
        assignment.scope,
      );
      if (storedTuple?.state === "retired") {
        const retiredAssignment = await readAssignment(
          client,
          partitionKey,
          applicationId,
          storedTuple.assignment.id,
        );
        if (
          retiredAssignment === null ||
          retiredAssignment.assignment.status !== "revoked" ||
          !assignmentsEqual(
            retiredAssignment.assignment,
            storedTuple.assignment,
          )
        ) {
          corrupt("active tuple tombstone has no revoked assignment");
        }
        const retiredHistory = await listRoleAssignmentAuditEvents(
          storedTuple.assignment.id,
        );
        if (retiredHistory.length !== 2) {
          corrupt("active tuple tombstone has incomplete audit history");
        }
      }

      const selectionKey = selectionRowKey(assignment);
      const existingSelection = await getEntityOrNull(
        client,
        partitionKey,
        selectionKey,
      );

      const existingEvent = await getEntityOrNull(
        client,
        partitionKey,
        eventRowKey(auditEventId),
      );
      const existingAudit = await getEntityOrNull(
        client,
        partitionKey,
        auditRowKey(assignment.id, 1),
      );
      const fence = await readSelectionFence(
        client,
        partitionKey,
        applicationId,
        assignment.principalId,
        assignment.scope,
      );
      const refreshed = await readAssignment(
        client,
        partitionKey,
        applicationId,
        assignment.id,
      );
      if (refreshed !== null) {
        continue;
      }
      if (storedTuple?.state === "active") {
        const tupleAssignment = stableSelection.find(
          (candidate) => candidate.id === storedTuple.assignment.id,
        );
        if (
          tupleAssignment !== undefined &&
          !assignmentsEqual(tupleAssignment, storedTuple.assignment)
        ) {
          corrupt("active tuple guard references a different assignment");
        }
        if (tupleAssignment !== undefined) {
          return Object.freeze({
            status: "conflict",
            reason: "active_tuple",
          });
        }
        const currentTupleSource = await getEntityOrNull(
          client,
          partitionKey,
          tupleKey,
        );
        if (currentTupleSource === null) {
          corrupt("active tuple guard disappeared");
        }
        const currentTuple = decodeTupleEntity(
          currentTupleSource!,
          partitionKey,
          applicationId,
          assignment,
        );
        if (
          currentTuple.etag !== storedTuple.etag ||
          currentTuple.state !== storedTuple.state ||
          !assignmentsEqual(currentTuple.assignment, storedTuple.assignment)
        ) {
          continue;
        }
        corrupt("active tuple guard has no complete active assignment");
      }
      if (existingSelection !== null) {
        corrupt("orphan active selection blocks grant");
      }
      if (existingEvent !== null) {
        await verifyExistingEventId(
          client,
          partitionKey,
          applicationId,
          existingEvent,
          auditEventId,
        );
        return Object.freeze({ status: "conflict", reason: "event_id" });
      }
      if (existingAudit !== null) {
        return Object.freeze({
          status: "conflict",
          reason: "lifecycle_position",
        });
      }

      const event: RoleAssignmentAuditEvent = {
        id: auditEventId,
        kind: "granted",
        assignment,
      };
      const actions: TransactionAction[] = [
        ["create", assignmentEntity(partitionKey, applicationId, assignment)],
        storedTuple === null
          ? ["create", tupleEntity(partitionKey, applicationId, assignment)]
          : [
              "update",
              tupleEntity(partitionKey, applicationId, assignment),
              "Replace",
              { etag: storedTuple.etag },
            ],
        ["create", selectionEntity(partitionKey, applicationId, assignment)],
        fence === null
          ? [
              "create",
              selectionFenceEntity(
                partitionKey,
                applicationId,
                assignment.principalId,
                assignment.scope,
                1,
              ),
            ]
          : [
              "update",
              selectionFenceEntity(
                partitionKey,
                applicationId,
                assignment.principalId,
                assignment.scope,
                fence.activeCount + 1,
              ),
              "Replace",
              { etag: fence.etag },
            ],
        ["create", auditEntity(partitionKey, applicationId, event, 1)],
        ["create", eventEntity(partitionKey, applicationId, event, 1)],
      ];

      try {
        await client.submitTransaction(actions);
      } catch (error) {
        const after = await readAssignment(
          client,
          partitionKey,
          applicationId,
          assignment.id,
        );
        if (after !== null) {
          if (!grantsEqual(after.assignment, assignment)) {
            return Object.freeze({
              status: "conflict",
              reason: "assignment_id",
            });
          }
          const storedAudit = await readAuditAt(
            client,
            partitionKey,
            applicationId,
            assignment.id,
            1,
          );
          if (storedAudit === null) {
            corrupt("grant response was ambiguous and state is incomplete");
          }
          if (!auditRecordsEqual(storedAudit!, expectedAudit)) {
            await verifyAuditGuard(
              client,
              partitionKey,
              applicationId,
              storedAudit!,
            );
            const suppliedEvent = await getEntityOrNull(
              client,
              partitionKey,
              eventRowKey(auditEventId),
            );
            if (suppliedEvent !== null) {
              await verifyExistingEventId(
                client,
                partitionKey,
                applicationId,
                suppliedEvent,
                auditEventId,
              );
            }
            return Object.freeze({
              status: "conflict",
              reason:
                suppliedEvent === null ? "lifecycle_position" : "event_id",
            });
          }
          await verifyAuditGuard(
            client,
            partitionKey,
            applicationId,
            storedAudit!,
          );
          await verifyLifecycleIntegrity(after);
          return Object.freeze({
            status: "unchanged",
            record: after,
            auditRecord: storedAudit!,
          });
        }
        const statusCode = getStatusCode(error);
        if ((statusCode === 409 || statusCode === 412) && attempt === 0) {
          continue;
        }
        throw error;
      }

      const created = await readAssignment(
        client,
        partitionKey,
        applicationId,
        assignment.id,
      );
      const auditRecord = await readAuditAt(
        client,
        partitionKey,
        applicationId,
        assignment.id,
        1,
      );
      if (
        created === null ||
        created.assignment.status !== "active" ||
        !assignmentsEqual(created.assignment, assignment) ||
        auditRecord === null ||
        !auditRecordsEqual(auditRecord, expectedAudit)
      ) {
        corrupt("committed grant is incomplete");
      }
      await verifyAuditGuard(client, partitionKey, applicationId, auditRecord!);
      await verifyLifecycleIntegrity(created!);
      return Object.freeze({
        status: "granted",
        record: created as VersionedRoleAssignment<ActiveRoleAssignment>,
        auditRecord: auditRecord!,
      });
    }
    throw new Error("Azure Table Storage grant could not be settled");
  };

  const revokeRoleAssignmentWithAudit = async (
    commandInput: AuditedRevokeRoleAssignmentCommand,
  ): Promise<AuditedRevokeRoleAssignmentResult> => {
    const command = Object.freeze({
      assignmentId: commandInput.assignmentId,
      expectedConcurrencyToken: commandInput.expectedConcurrencyToken,
      revokedBy: snapshotActor(commandInput.revokedBy),
      revokedAtEpochMs: commandInput.revokedAtEpochMs,
      ...(commandInput.reason === undefined
        ? {}
        : { reason: commandInput.reason }),
      auditEventId: commandInput.auditEventId,
    });
    if (
      !safeExpectedToken(command.expectedConcurrencyToken) ||
      typeof command.auditEventId !== "string"
    ) {
      return Object.freeze({ status: "conflict", reason: "concurrency" });
    }

    for (let attempt = 0; attempt < 2; attempt += 1) {
      const existing = await readAssignment(
        client,
        partitionKey,
        applicationId,
        command.assignmentId,
      );
      if (existing === null) {
        return Object.freeze({ status: "not_found" });
      }
      if (existing.assignment.status === "revoked") {
        const raw = await getEntityOrNull(
          client,
          partitionKey,
          assignmentRowKey(command.assignmentId),
        );
        if (raw === null) {
          corrupt("revoked assignment disappeared during replay");
        }
        const replayToken = requireStringProperty(
          raw!,
          "revocationReplayToken",
        );
        const exactEvidence =
          actorsEqual(existing.assignment.revokedBy, command.revokedBy) &&
          existing.assignment.revokedAtEpochMs === command.revokedAtEpochMs &&
          existing.assignment.reason === command.reason;
        if (!exactEvidence) {
          return Object.freeze({ status: "conflict", reason: "lifecycle" });
        }
        if (replayToken !== command.expectedConcurrencyToken) {
          return Object.freeze({ status: "conflict", reason: "concurrency" });
        }
        const auditRecord = await readAuditAt(
          client,
          partitionKey,
          applicationId,
          command.assignmentId,
          2,
        );
        if (auditRecord === null) {
          corrupt("replayed revocation is missing its audit");
        }
        const expectedAudit = makeRevokeAudit(
          existing.assignment,
          command.auditEventId,
        );
        const suppliedEvent = await getEntityOrNull(
          client,
          partitionKey,
          eventRowKey(command.auditEventId),
        );
        if (auditRecord!.event.id !== command.auditEventId) {
          if (suppliedEvent !== null) {
            await verifyExistingEventId(
              client,
              partitionKey,
              applicationId,
              suppliedEvent,
              command.auditEventId,
            );
          }
          return Object.freeze({
            status: "conflict",
            reason: suppliedEvent === null ? "lifecycle_position" : "event_id",
          });
        }
        if (
          suppliedEvent === null ||
          !auditRecordsEqual(auditRecord!, expectedAudit)
        ) {
          corrupt("replayed revocation audit is incomplete");
        }
        assertEventGuard(
          suppliedEvent!,
          partitionKey,
          applicationId,
          auditRecord!,
        );
        await verifyLifecycleIntegrity(existing);
        return Object.freeze({
          status: "unchanged",
          record: existing as VersionedRoleAssignment<RevokedRoleAssignment>,
          auditRecord: auditRecord!,
        });
      }
      if (existing.concurrencyToken !== command.expectedConcurrencyToken) {
        return Object.freeze({ status: "conflict", reason: "concurrency" });
      }
      if (command.revokedAtEpochMs < existing.assignment.grantedAtEpochMs) {
        return Object.freeze({ status: "conflict", reason: "lifecycle" });
      }

      const revoked = snapshotRevoked({
        ...existing.assignment,
        status: "revoked",
        revokedBy: command.revokedBy,
        revokedAtEpochMs: command.revokedAtEpochMs,
        ...(command.reason === undefined ? {} : { reason: command.reason }),
      });
      const expectedAudit = makeRevokeAudit(revoked, command.auditEventId);
      const grantAudit = await readAuditAt(
        client,
        partitionKey,
        applicationId,
        command.assignmentId,
        1,
      );
      if (
        grantAudit === null ||
        grantAudit.event.kind !== "granted" ||
        !grantsEqual(existing.assignment, grantAudit.event.assignment)
      ) {
        corrupt("active assignment grant audit is incomplete");
      }
      await verifyAuditGuard(client, partitionKey, applicationId, grantAudit!);
      const tupleKey = tupleRowKey(existing.assignment);
      const tupleSource = await getEntityOrNull(client, partitionKey, tupleKey);
      if (tupleSource === null) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        corrupt("active assignment tuple guard is missing");
      }
      const tuple = decodeTupleEntity(
        tupleSource!,
        partitionKey,
        applicationId,
        existing.assignment,
      );
      if (
        tuple.state !== "active" ||
        !assignmentsEqual(tuple.assignment, existing.assignment)
      ) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        corrupt("active assignment tuple guard is inconsistent");
      }
      const selectionKey = selectionRowKey(existing.assignment);
      const selectionSource = await getEntityOrNull(
        client,
        partitionKey,
        selectionKey,
      );
      if (selectionSource === null) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        corrupt("active assignment selection row is missing");
      }
      const selection = decodeSelectionEntity(
        selectionSource!,
        partitionKey,
        applicationId,
        existing.assignment.principalId,
        existing.assignment.scope,
      );
      if (!assignmentsEqual(selection, existing.assignment)) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        corrupt("active assignment selection row is inconsistent");
      }
      const stableSelection = await listActiveRoleAssignments(
        existing.assignment.principalId,
        existing.assignment.scope,
      );
      const stableAssignment = stableSelection.find(
        (candidate) => candidate.id === existing.assignment.id,
      );
      if (
        stableAssignment === undefined ||
        !assignmentsEqual(stableAssignment, existing.assignment)
      ) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        corrupt("active assignment selection snapshot is inconsistent");
      }
      const fence = await readSelectionFence(
        client,
        partitionKey,
        applicationId,
        existing.assignment.principalId,
        existing.assignment.scope,
      );
      if (fence === null) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        corrupt("active assignment selection fence is missing");
      }
      if (fence!.activeCount < 1) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        corrupt("active assignment selection count is invalid");
      }

      const eventSource = await getEntityOrNull(
        client,
        partitionKey,
        eventRowKey(command.auditEventId),
      );
      if (eventSource !== null) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        await verifyExistingEventId(
          client,
          partitionKey,
          applicationId,
          eventSource,
          command.auditEventId,
        );
        return Object.freeze({ status: "conflict", reason: "event_id" });
      }
      const auditSource = await getEntityOrNull(
        client,
        partitionKey,
        auditRowKey(command.assignmentId, 2),
      );
      if (auditSource !== null) {
        if (await assignmentChangedSince(existing)) {
          continue;
        }
        return Object.freeze({
          status: "conflict",
          reason: "lifecycle_position",
        });
      }

      const event: RoleAssignmentAuditEvent = {
        id: command.auditEventId,
        kind: "revoked",
        assignment: revoked,
      };
      const actions: TransactionAction[] = [
        [
          "update",
          assignmentEntity(
            partitionKey,
            applicationId,
            revoked,
            existing.concurrencyToken,
          ),
          "Replace",
          { etag: existing.concurrencyToken },
        ],
        [
          "update",
          tupleEntity(partitionKey, applicationId, revoked),
          "Replace",
          { etag: tuple.etag },
        ],
        [
          "delete",
          baseEntity(
            partitionKey,
            selectionKey,
            applicationId,
            "active_selection",
          ),
        ],
        [
          "update",
          selectionFenceEntity(
            partitionKey,
            applicationId,
            existing.assignment.principalId,
            existing.assignment.scope,
            fence!.activeCount - 1,
          ),
          "Replace",
          { etag: fence!.etag },
        ],
        ["create", auditEntity(partitionKey, applicationId, event, 2)],
        ["create", eventEntity(partitionKey, applicationId, event, 2)],
      ];

      try {
        await client.submitTransaction(actions);
      } catch (error) {
        const after = await readAssignment(
          client,
          partitionKey,
          applicationId,
          command.assignmentId,
        );
        if (after?.assignment.status === "revoked") {
          const raw = await getEntityOrNull(
            client,
            partitionKey,
            assignmentRowKey(command.assignmentId),
          );
          if (
            raw !== null &&
            raw.revocationReplayToken === command.expectedConcurrencyToken &&
            actorsEqual(after.assignment.revokedBy, command.revokedBy) &&
            after.assignment.revokedAtEpochMs === command.revokedAtEpochMs &&
            after.assignment.reason === command.reason
          ) {
            const auditRecord = await readAuditAt(
              client,
              partitionKey,
              applicationId,
              command.assignmentId,
              2,
            );
            if (auditRecord === null) {
              corrupt(
                "revocation response was ambiguous and state is incomplete",
              );
            }
            if (!auditRecordsEqual(auditRecord!, expectedAudit)) {
              await verifyAuditGuard(
                client,
                partitionKey,
                applicationId,
                auditRecord!,
              );
              const suppliedEvent = await getEntityOrNull(
                client,
                partitionKey,
                eventRowKey(command.auditEventId),
              );
              if (suppliedEvent !== null) {
                await verifyExistingEventId(
                  client,
                  partitionKey,
                  applicationId,
                  suppliedEvent,
                  command.auditEventId,
                );
              }
              return Object.freeze({
                status: "conflict",
                reason:
                  suppliedEvent === null ? "lifecycle_position" : "event_id",
              });
            }
            await verifyAuditGuard(
              client,
              partitionKey,
              applicationId,
              auditRecord!,
            );
            await verifyLifecycleIntegrity(after);
            return Object.freeze({
              status: "unchanged",
              record: after as VersionedRoleAssignment<RevokedRoleAssignment>,
              auditRecord: auditRecord!,
            });
          }
          return Object.freeze({ status: "conflict", reason: "lifecycle" });
        }
        if (
          after !== null &&
          after.concurrencyToken !== command.expectedConcurrencyToken
        ) {
          return Object.freeze({ status: "conflict", reason: "concurrency" });
        }
        const statusCode = getStatusCode(error);
        if ((statusCode === 409 || statusCode === 412) && attempt === 0) {
          continue;
        }
        throw error;
      }

      const completed = await readAssignment(
        client,
        partitionKey,
        applicationId,
        command.assignmentId,
      );
      const auditRecord = await readAuditAt(
        client,
        partitionKey,
        applicationId,
        command.assignmentId,
        2,
      );
      if (
        completed?.assignment.status !== "revoked" ||
        !assignmentsEqual(completed.assignment, revoked) ||
        auditRecord === null ||
        !auditRecordsEqual(auditRecord, expectedAudit)
      ) {
        corrupt("committed revocation is incomplete");
      }
      await verifyAuditGuard(client, partitionKey, applicationId, auditRecord!);
      await verifyLifecycleIntegrity(completed!);
      return Object.freeze({
        status: "revoked",
        record: completed as VersionedRoleAssignment<RevokedRoleAssignment>,
        auditRecord: auditRecord!,
      });
    }
    throw new Error("Azure Table Storage revocation could not be settled");
  };

  return Object.freeze({
    resolvePrincipalId,
    getRoleAssignment,
    listActiveRoleAssignments,
    listRoleAssignmentAuditEvents,
    grantRoleAssignmentWithAudit,
    revokeRoleAssignmentWithAudit,
  });
};
