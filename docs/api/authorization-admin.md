<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-admin

Generated from the public declaration entry point `packages/admin/dist/index.d.ts`. Internal modules are intentionally excluded.

## AdministeredAssignment

**Kind:** interface

One active assignment with its management label.

```ts
export interface AdministeredAssignment {
  readonly assignment: ActiveRoleAssignment;
  readonly managedBy: ManagedBy;
}
```

## assignmentManagedBy

**Kind:** function

Management label for one assignment under one policy. Grants by humans
are human-managed; grants by system actors are locked unless the actor
is one-time (the seed and guard-compensation actors always are).

```ts
export declare function assignmentManagedBy(
  assignment: Pick<ActiveRoleAssignment, "grantedBy">,
  policy: RoleManagementPolicy,
): ManagedBy;
```

## AssignRoleCommand

**Kind:** interface

Command for an audited operator grant.

```ts
export interface AssignRoleCommand {
  readonly principalId: PrincipalId;
  readonly role: RoleName;
  readonly scope: RoleAssignmentScope;
  readonly actor: RoleAssignmentActor;
}
```

## AssignRoleResult

**Kind:** type

Result of one audited operator grant.

```ts
export type AssignRoleResult =
  | Readonly<{
      readonly status: "assigned";
      readonly record: VersionedRoleAssignment<ActiveRoleAssignment>;
    }>
  | Readonly<{
      readonly status: "duplicate";
    }>
  | Readonly<{
      readonly status: "conflict";
    }>;
```

## createRoleAdministration

**Kind:** function

Creates the administration service over host-owned ports.

```ts
export declare function createRoleAdministration(
  options: RoleAdministrationOptions,
): RoleAdministration;
```

## ensureSeededAssignment

**Kind:** function

Seed one role for one principal, once per principal AND ROLE, ever: any
existing assignment record for that role — active or revoked, whatever
its provenance — is durable already-seeded evidence, so a deliberate
revocation is never resurrected by a lingering seed input. The ceremony
in `docs/ADMINISTRATOR_BOOTSTRAP.md` decides whether and for whom to
call this; the helper is a pure function over the ports.

`conflict` means the manifest is CONTRADICTORY — its assignment id is
already claimed by a different lifecycle — and the principal may still
hold nothing: the ceremony must fail closed, not report convergence.
(A concurrent duplicate run converges through the store's `unchanged`
replay, never through a conflict.)

```ts
export declare function ensureSeededAssignment(
  options: EnsureSeededAssignmentOptions,
): Promise<"granted" | "already" | "conflict">;
```

## EnsureSeededAssignmentOptions

**Kind:** interface

Options for {@link ensureSeededAssignment}.

```ts
export interface EnsureSeededAssignmentOptions {
  readonly store: RoleAdministrationStore;
  /** When provided, the superset row is recorded before the grant. */
  readonly holderIndex?: RoleHolderIndex;
  readonly principalId: PrincipalId;
  readonly role: RoleName;
  readonly scope: RoleAssignmentScope;
  /**
   * Fresh opaque assignment id from the host's ceremony manifest, retained
   * there for retries. NOT derived from the principal or role
   * (`docs/ROLE_ASSIGNMENTS.md`); an exact replay is the store's ordinary
   * `unchanged`, and the history check below converges even a lost
   * manifest.
   */
  readonly assignmentId: string;
  /** Audit event id, equally fresh and manifest-retained. */
  readonly auditEventId: string;
  readonly systemId?: string;
  readonly now?: () => number;
}
```

## GUARD_COMPENSATION_SYSTEM_ID

**Kind:** const

System actor written by the guard's post-revoke compensation grant.

```ts
export declare const GUARD_COMPENSATION_SYSTEM_ID = "last-administrator-guard";
```

## ManagedBy

**Kind:** type

Who may edit an assignment through the administration surface.

```ts
export type ManagedBy = "system" | "human";
```

## RevokeRoleCommand

**Kind:** interface

Command for an audited operator revocation.

```ts
export interface RevokeRoleCommand {
  readonly assignmentId: string;
  readonly actor: RoleAssignmentActor;
  readonly reason?: string;
}
```

## RevokeRoleResult

**Kind:** type

Result of one audited operator revocation.

`compensated` reports that the post-revoke re-verification found no
active administrator remaining (a concurrent revoke on another instance
won its race) and the guard wrote a compensation grant restoring the
revoked principal. See "What the guard does NOT promise" in
`docs/ADMINISTRATION.md` for the honest limits of this treatment.

```ts
export type RevokeRoleResult =
  | Readonly<{
      readonly status: "revoked";
      readonly compensated: boolean;
    }>
  | Readonly<{
      readonly status: "not_found";
    }>
  | Readonly<{
      readonly status: "already_revoked";
    }>
  | Readonly<{
      readonly status: "system_managed";
    }>
  | Readonly<{
      readonly status: "last_administrator";
    }>
  | Readonly<{
      readonly status: "conflict";
    }>;
```

## RoleAdministration

**Kind:** interface

The administration service. One instance per application; host-gated.

```ts
export interface RoleAdministration {
  readonly viewGrants: (
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ) => Promise<readonly AdministeredAssignment[]>;
  readonly listHistory: (
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ) => Promise<readonly RoleAdministrationEvent[]>;
  readonly assignRole: (
    command: AssignRoleCommand,
  ) => Promise<AssignRoleResult>;
  readonly revokeRole: (
    command: RevokeRoleCommand,
  ) => Promise<RevokeRoleResult>;
  readonly anotherActiveHolderExists: (
    role: RoleName,
    scope: RoleAssignmentScope,
    excludingPrincipalId: PrincipalId | "",
  ) => Promise<boolean>;
}
```

## RoleAdministrationEvent

**Kind:** interface

One rendered lifecycle event for the per-principal history view.

```ts
export interface RoleAdministrationEvent {
  readonly assignmentId: string;
  readonly role: RoleName;
  readonly kind: "granted" | "revoked";
  readonly actor: RoleAssignmentActor;
  readonly atEpochMs: number;
  readonly reason?: string;
}
```

## RoleAdministrationOptions

**Kind:** interface

Constructor options for {@link createRoleAdministration}.

```ts
export interface RoleAdministrationOptions {
  readonly store: RoleAdministrationStore;
  readonly holderIndex: RoleHolderIndex;
  readonly policy: RoleManagementPolicy;
  /** Epoch-milliseconds clock; injectable for deterministic tests. */
  readonly now?: () => number;
  /** Fresh opaque id source for grants and audit events. */
  readonly generateId?: () => string;
}
```

## RoleAdministrationStore

**Kind:** interface

The store surface the service needs: reads plus audited mutations.

```ts
export interface RoleAdministrationStore
  extends RoleAssignmentReader, AuditedRoleAssignmentMutationStore {}
```

## RoleHolderIndex

**Kind:** interface

The host-provided by-role index (`docs/STORAGE.md` recipe): rows are
written BEFORE grants, never deleted, and verified against the
authoritative store on every read. The index may over-report; it must
never under-report a grant that exists.

```ts
export interface RoleHolderIndex {
  readonly record: (row: RoleHolderIndexRow) => Promise<void>;
  readonly listByRole: (
    role: RoleName,
  ) => Promise<readonly RoleHolderIndexRow[]>;
}
```

## RoleHolderIndexRow

**Kind:** interface

One superset row in the host's by-role holder index.

```ts
export interface RoleHolderIndexRow {
  readonly principalId: PrincipalId;
  readonly assignmentId: string;
  readonly role: RoleName;
}
```

## RoleManagementPolicy

**Kind:** interface

Explicit management policy. Assignments granted by system actors are
locked (`managedBy: "system"`) unless the actor is declared ONE-TIME
here: a one-time actor writes once and never touches the assignment
again, so the record is human-managed like any operator grant. The seed
and guard-compensation actors are one-time by definition and are always
included.

```ts
export interface RoleManagementPolicy {
  /** The role the last-administrator guard protects. */
  readonly administratorRole: RoleName;
  /** Additional host-declared one-time system actor ids. */
  readonly oneTimeSystemActors?: ReadonlySet<string>;
}
```

## SEED_SYSTEM_ID

**Kind:** const

Default system actor for `ensureSeededAssignment`.

```ts
export declare const SEED_SYSTEM_ID = "bootstrap";
```
