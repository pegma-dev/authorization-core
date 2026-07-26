import type {
  ActiveRoleAssignment,
  IdentityAdapter,
  IdentityLink,
  IdentityLinkKey,
  PrincipalId,
  RevokedRoleAssignment,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentId,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";

/**
 * Exact, read-only identity-link lookup.
 *
 * One instance or namespace belongs to one host application. Shared backends
 * bind that application partition at construction.
 *
 * `null` means the link is definitively absent. Implementations reject for
 * operational failures, incomplete reads, and corrupt records.
 */
export interface PrincipalLookupStore extends IdentityAdapter<IdentityLinkKey> {}

/** Opaque record-scoped optimistic-concurrency token. */
export type RoleAssignmentConcurrencyToken = string;

/** One immutable lifecycle record and its current concurrency token. */
export interface VersionedRoleAssignment<
  Assignment extends RoleAssignment = RoleAssignment,
> {
  readonly assignment: Assignment;
  readonly concurrencyToken: RoleAssignmentConcurrencyToken;
}

/** Read-only role-assignment persistence shared by stores and safe adapters. */
export interface RoleAssignmentReader {
  /** Exact-ID lifecycle read; `null` means definitive absence. */
  readonly getRoleAssignment: (
    assignmentId: RoleAssignmentId,
  ) => Promise<VersionedRoleAssignment | null>;

  /**
   * Complete exact-principal and exact-scope active selection.
   *
   * An empty array means definitive emptiness. Implementations reject partial,
   * operationally failed, or corrupt results.
   */
  readonly listActiveRoleAssignments: (
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ) => Promise<readonly ActiveRoleAssignment[]>;
}

/** Result of atomically attempting to create one active assignment. */
export type CreateRoleAssignmentResult =
  | Readonly<{
      readonly status: "created";
      readonly record: VersionedRoleAssignment<ActiveRoleAssignment>;
    }>
  | Readonly<{
      readonly status: "unchanged";
      readonly record: VersionedRoleAssignment;
    }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason: "assignment_id" | "active_tuple";
    }>;

/**
 * Conditional, exact-ID revocation command.
 *
 * The expected token belongs only to the specified assignment record.
 */
export interface RevokeRoleAssignmentCommand {
  readonly assignmentId: RoleAssignmentId;
  readonly expectedConcurrencyToken: RoleAssignmentConcurrencyToken;
  readonly revokedBy: RoleAssignmentActor;
  readonly revokedAtEpochMs: number;
  readonly reason?: string;
}

/** Result of attempting one exact-ID conditional revocation. */
export type RevokeRoleAssignmentResult =
  | Readonly<{
      readonly status: "revoked" | "unchanged";
      readonly record: VersionedRoleAssignment<RevokedRoleAssignment>;
    }>
  | Readonly<{ readonly status: "not_found" }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason: "concurrency" | "lifecycle";
    }>;

/**
 * Provider-neutral role-assignment persistence.
 *
 * A store instance or namespace belongs to exactly one host application.
 * Shared backends bind that application partition when constructing the store;
 * application identity is deliberately absent from every query.
 */
export interface RoleAssignmentStore extends RoleAssignmentReader {
  /**
   * Atomically creates one active record while enforcing unique assignment ID
   * and one active exact `(principalId, role, scope)` tuple.
   */
  readonly createRoleAssignment: (
    assignment: ActiveRoleAssignment,
  ) => Promise<CreateRoleAssignmentResult>;

  /**
   * Conditionally and irreversibly revokes exactly one assignment ID.
   *
   * Implementations preserve grant evidence, advance the record token, and
   * treat an exact replay of completed revocation evidence as unchanged.
   */
  readonly revokeRoleAssignment: (
    command: RevokeRoleAssignmentCommand,
  ) => Promise<RevokeRoleAssignmentResult>;
}

/** Opaque, exact event identifier selected by the host. */
export type RoleAssignmentAuditEventId = string;

/** Role-lifecycle-specific append-only audit event. */
export type RoleAssignmentAuditEvent =
  | Readonly<{
      readonly id: RoleAssignmentAuditEventId;
      readonly kind: "granted";
      readonly assignment: ActiveRoleAssignment;
    }>
  | Readonly<{
      readonly id: RoleAssignmentAuditEventId;
      readonly kind: "revoked";
      readonly assignment: RevokedRoleAssignment;
    }>;

/** Audit event with its store-assigned per-assignment sequence. */
export interface SequencedRoleAssignmentAuditEvent {
  readonly sequence: number;
  readonly event: RoleAssignmentAuditEvent;
}

/** Read-only append-only role-audit history. */
export interface RoleAssignmentAuditReader {
  /**
   * Complete per-assignment history in strictly increasing sequence order.
   *
   * An empty array means definitive absence. Implementations reject partial,
   * operationally failed, or corrupt results.
   */
  readonly listRoleAssignmentAuditEvents: (
    assignmentId: RoleAssignmentId,
  ) => Promise<readonly SequencedRoleAssignmentAuditEvent[]>;
}

/** Result of appending one lifecycle event. */
export type AppendRoleAssignmentAuditEventResult =
  | Readonly<{
      readonly status: "appended" | "unchanged";
      readonly record: SequencedRoleAssignmentAuditEvent;
    }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason: "event_id" | "lifecycle_position";
    }>;

/**
 * Append-only role lifecycle audit port.
 *
 * Like the role-assignment port, one instance or namespace belongs to one host
 * application, with any shared-backend partition bound at construction.
 *
 * Sequence values are positive safe integers assigned independently for each
 * assignment and listed in strictly increasing order. This port makes no
 * global gapless-order, update/delete, retention, signing, or tamper-evidence
 * promise.
 */
export interface RoleAssignmentAuditStore extends RoleAssignmentAuditReader {
  readonly appendRoleAssignmentAuditEvent: (
    event: RoleAssignmentAuditEvent,
  ) => Promise<AppendRoleAssignmentAuditEventResult>;
}

/** Atomically grants one role and appends its derived audit event. */
export interface GrantRoleAssignmentCommand {
  readonly assignment: ActiveRoleAssignment;
  readonly auditEventId: RoleAssignmentAuditEventId;
}

/** Result of one atomic audited grant attempt. */
export type GrantRoleAssignmentResult =
  | Readonly<{
      readonly status: "granted";
      readonly record: VersionedRoleAssignment<ActiveRoleAssignment>;
      readonly auditRecord: SequencedRoleAssignmentAuditEvent;
    }>
  | Readonly<{
      readonly status: "unchanged";
      readonly record: VersionedRoleAssignment;
      readonly auditRecord: SequencedRoleAssignmentAuditEvent;
    }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason:
        "assignment_id" | "active_tuple" | "event_id" | "lifecycle_position";
    }>;

/** Atomically revokes one role and appends its derived audit event. */
export interface AuditedRevokeRoleAssignmentCommand extends RevokeRoleAssignmentCommand {
  readonly auditEventId: RoleAssignmentAuditEventId;
}

/** Result of one atomic audited revoke attempt. */
export type AuditedRevokeRoleAssignmentResult =
  | Readonly<{
      readonly status: "revoked" | "unchanged";
      readonly record: VersionedRoleAssignment<RevokedRoleAssignment>;
      readonly auditRecord: SequencedRoleAssignmentAuditEvent;
    }>
  | Readonly<{ readonly status: "not_found" }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason:
        "concurrency" | "lifecycle" | "event_id" | "lifecycle_position";
    }>;

/**
 * Safe combined role-and-audit mutation boundary.
 *
 * Implementations decide role-side conflicts before audit-side conflicts.
 * Audit payloads are derived from the role lifecycle; callers supply only an
 * exact event ID. An unchanged revoke replay must present the same
 * pre-revocation concurrency token as the completed operation.
 */
export interface AuditedRoleAssignmentMutationStore {
  readonly grantRoleAssignmentWithAudit: (
    command: GrantRoleAssignmentCommand,
  ) => Promise<GrantRoleAssignmentResult>;
  readonly revokeRoleAssignmentWithAudit: (
    command: AuditedRevokeRoleAssignmentCommand,
  ) => Promise<AuditedRevokeRoleAssignmentResult>;
}

/** Optional read-only identity-link seeds for one in-memory instance. */
export interface InMemoryStorageAdapterOptions {
  readonly identityLinks?: readonly IdentityLink[];
}

/**
 * Ephemeral single-process reference adapter.
 *
 * Its public surface intentionally omits the raw role and audit write ports so
 * every mutation preserves the combined lifecycle-and-audit invariant.
 */
export interface InMemoryStorageAdapter
  extends
    PrincipalLookupStore,
    RoleAssignmentReader,
    RoleAssignmentAuditReader,
    AuditedRoleAssignmentMutationStore {}

export { createInMemoryStorageAdapter } from "./in-memory.js";
