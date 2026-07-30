<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-storage

Generated from the public declaration entry point `packages/storage/dist/index.d.ts`. Internal modules are intentionally excluded.

## AppendRoleAssignmentAuditEventResult

**Kind:** type

Result of appending one lifecycle event.

```ts
export type AppendRoleAssignmentAuditEventResult =
  | Readonly<{
      readonly status: "appended" | "unchanged";
      readonly record: SequencedRoleAssignmentAuditEvent;
    }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason: "event_id" | "lifecycle_position";
    }>;
```

## AuditedRevokeRoleAssignmentCommand

**Kind:** interface

Atomically revokes one role and appends its derived audit event.

```ts
export interface AuditedRevokeRoleAssignmentCommand extends RevokeRoleAssignmentCommand {
  readonly auditEventId: RoleAssignmentAuditEventId;
}
```

## AuditedRevokeRoleAssignmentResult

**Kind:** type

Result of one atomic audited revoke attempt.

```ts
export type AuditedRevokeRoleAssignmentResult =
  | Readonly<{
      readonly status: "revoked" | "unchanged";
      readonly record: VersionedRoleAssignment<RevokedRoleAssignment>;
      readonly auditRecord: SequencedRoleAssignmentAuditEvent;
    }>
  | Readonly<{
      readonly status: "not_found";
    }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason:
        "concurrency" | "lifecycle" | "event_id" | "lifecycle_position";
    }>;
```

## AuditedRoleAssignmentMutationStore

**Kind:** interface

Safe combined role-and-audit mutation boundary.

Implementations decide role-side conflicts before audit-side conflicts.
Audit payloads are derived from the role lifecycle; callers supply only an
exact event ID. An unchanged revoke replay matches the completed event ID
and revocation evidence; the opaque pre-revocation token is not retained.

An unchanged grant replay attests to the assignment ID, its principal, scope,
and role, and the grant event ID — not to the whole command. A replay whose
principal, scope, or role differs is a reused assignment ID and conflicts;
one that differs only in `grantedBy` or `grantedAtEpochMs` is unchanged, and
the returned record is the stored assignment rather than the command's, so a
caller always reads back what is actually persisted.

```ts
export interface AuditedRoleAssignmentMutationStore {
  readonly grantRoleAssignmentWithAudit: (
    command: GrantRoleAssignmentCommand,
  ) => Promise<GrantRoleAssignmentResult>;
  readonly revokeRoleAssignmentWithAudit: (
    command: AuditedRevokeRoleAssignmentCommand,
  ) => Promise<AuditedRevokeRoleAssignmentResult>;
}
```

## createInMemoryStorageAdapter

**Kind:** const

Creates an isolated, ephemeral reference adapter for one host application.

It is the storage-core memory store behind {@link createRoleStore}, so it
enforces the same key, transaction, and optimistic-concurrency rules a
durable backend does. It is not durable and not a cross-process transaction.

```ts
export declare const createInMemoryStorageAdapter: (
  options?: InMemoryStorageAdapterOptions,
) => InMemoryStorageAdapter;
```

## CreateRoleAssignmentResult

**Kind:** type

Result of atomically attempting to create one active assignment.

```ts
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
```

## createRoleStore

**Kind:** const

Binds the authorization collections to one backend and one host application.

The returned object is the safe combined surface: exact reads plus audited
grant and revoke. It deliberately has no raw role or audit write, so every
mutation preserves the combined lifecycle-and-audit invariant.

Durability, cross-process transactions, and restart recovery are properties
of the `Store` that is passed in, not of this binding.

```ts
export declare const createRoleStore: (
  store: Store,
  applicationId: ApplicationId,
) => InMemoryStorageAdapter;
```

## GrantRoleAssignmentCommand

**Kind:** interface

Atomically grants one role and appends its derived audit event.

```ts
export interface GrantRoleAssignmentCommand {
  readonly assignment: ActiveRoleAssignment;
  readonly auditEventId: RoleAssignmentAuditEventId;
}
```

## GrantRoleAssignmentResult

**Kind:** type

Result of one atomic audited grant attempt.

```ts
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
```

## InMemoryStorageAdapter

**Kind:** interface

Ephemeral single-process reference adapter.

Its public surface intentionally omits the raw role and audit write ports so
every mutation preserves the combined lifecycle-and-audit invariant.

```ts
export interface InMemoryStorageAdapter
  extends
    PrincipalLookupStore,
    RoleAssignmentReader,
    RoleAssignmentAuditReader,
    AuditedRoleAssignmentMutationStore {}
```

## InMemoryStorageAdapterOptions

**Kind:** interface

Optional read-only identity-link seeds for one in-memory instance.

```ts
export interface InMemoryStorageAdapterOptions {
  readonly identityLinks?: readonly IdentityLink[];
}
```

## PrincipalLookupStore

**Kind:** interface

Exact, read-only identity-link lookup.

One instance or namespace belongs to one host application. Shared backends
bind that application partition at construction.

`null` means the link is definitively absent. Implementations reject for
operational failures, incomplete reads, and corrupt records.

```ts
export interface PrincipalLookupStore extends IdentityAdapter<IdentityLinkKey> {}
```

## RevokeRoleAssignmentCommand

**Kind:** interface

Conditional, exact-ID revocation command.

The expected token belongs only to the specified assignment record.

```ts
export interface RevokeRoleAssignmentCommand {
  readonly assignmentId: RoleAssignmentId;
  readonly expectedConcurrencyToken: RoleAssignmentConcurrencyToken;
  readonly revokedBy: RoleAssignmentActor;
  readonly revokedAtEpochMs: number;
  readonly reason?: string;
}
```

## RevokeRoleAssignmentResult

**Kind:** type

Result of attempting one exact-ID conditional revocation.

```ts
export type RevokeRoleAssignmentResult =
  | Readonly<{
      readonly status: "revoked" | "unchanged";
      readonly record: VersionedRoleAssignment<RevokedRoleAssignment>;
    }>
  | Readonly<{
      readonly status: "not_found";
    }>
  | Readonly<{
      readonly status: "conflict";
      readonly reason: "concurrency" | "lifecycle";
    }>;
```

## RoleAssignmentAuditEvent

**Kind:** type

Role-lifecycle-specific append-only audit event.

```ts
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
```

## RoleAssignmentAuditEventId

**Kind:** type

Opaque, exact event identifier selected by the host.

```ts
export type RoleAssignmentAuditEventId = string;
```

## RoleAssignmentAuditReader

**Kind:** interface

Read-only append-only role-audit history.

```ts
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
```

## RoleAssignmentAuditStore

**Kind:** interface

Append-only role lifecycle audit port.

Like the role-assignment port, one instance or namespace belongs to one host
application, with any shared-backend partition bound at construction.

Sequence values are positive safe integers assigned independently for each
assignment and listed in strictly increasing order. This port makes no
global gapless-order, update/delete, retention, signing, or tamper-evidence
promise.

```ts
export interface RoleAssignmentAuditStore extends RoleAssignmentAuditReader {
  readonly appendRoleAssignmentAuditEvent: (
    event: RoleAssignmentAuditEvent,
  ) => Promise<AppendRoleAssignmentAuditEventResult>;
}
```

## RoleAssignmentConcurrencyToken

**Kind:** type

Opaque record-scoped optimistic-concurrency token.

```ts
export type RoleAssignmentConcurrencyToken = string;
```

## RoleAssignmentReader

**Kind:** interface

Read-only role-assignment persistence shared by stores and safe adapters.

```ts
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
```

## RoleAssignmentStore

**Kind:** interface

Provider-neutral role-assignment persistence.

A store instance or namespace belongs to exactly one host application.
Shared backends bind that application partition when constructing the store;
application identity is deliberately absent from every query.

```ts
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
```

## SequencedRoleAssignmentAuditEvent

**Kind:** interface

Audit event with its store-assigned per-assignment sequence.

```ts
export interface SequencedRoleAssignmentAuditEvent {
  readonly sequence: number;
  readonly event: RoleAssignmentAuditEvent;
}
```

## VersionedRoleAssignment

**Kind:** interface

One immutable lifecycle record and its current concurrency token.

```ts
export interface VersionedRoleAssignment<
  Assignment extends RoleAssignment = RoleAssignment,
> {
  readonly assignment: Assignment;
  readonly concurrencyToken: RoleAssignmentConcurrencyToken;
}
```
