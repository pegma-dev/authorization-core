<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-contracts

Generated from the public declaration entry point `packages/contracts/dist/index.d.ts`. Internal modules are intentionally excluded.

## AccessContext

**Kind:** interface

Immutable authorization facts resolved for one principal and policy.

```ts
export interface AccessContext {
  readonly principalId: PrincipalId;
  readonly policyVersion: string;
  readonly roles: readonly RoleName[];
  readonly entitlements: readonly EntitlementName[];
  readonly permissions: readonly PermissionName[];
}
```

## AccessDecision

**Kind:** interface

Auditable result of checking one permission against an access context.

```ts
export interface AccessDecision {
  readonly allowed: boolean;
  readonly permission: PermissionName;
  readonly reason: AccessDecisionReason;
}
```

## AccessDecisionReason

**Kind:** type

```ts
export type AccessDecisionReason = "granted" | "not_granted";
```

## AccessPolicy

**Kind:** interface

Application-owned mapping from roles and entitlements to permissions.

Unknown names are intentionally harmless: they appear in the resulting
context for observability but grant no permissions.

```ts
export interface AccessPolicy {
  readonly version: string;
  readonly defaults?: readonly PermissionName[];
  readonly roles?: Readonly<Record<RoleName, readonly PermissionName[]>>;
  readonly entitlements?: Readonly<
    Record<EntitlementName, readonly PermissionName[]>
  >;
}
```

## AccessResolution

**Kind:** interface

Immutable access context together with opt-in resolution diagnostics.

```ts
export interface AccessResolution {
  readonly context: AccessContext;
  readonly diagnostics: AccessResolutionDiagnostics;
}
```

## AccessResolutionDiagnostics

**Kind:** interface

Unknown subject facts observed while resolving one access context.

```ts
export interface AccessResolutionDiagnostics {
  readonly unknownRoles: readonly RoleName[];
  readonly unknownEntitlements: readonly EntitlementName[];
}
```

## AccessSubject

**Kind:** interface

Trusted, already-resolved facts about the principal requesting access.

Identity, billing, and persistence adapters are responsible for producing
these facts from verified server-side sources.

```ts
export interface AccessSubject {
  readonly principalId: PrincipalId;
  readonly roles?: readonly RoleName[];
  readonly entitlements?: readonly EntitlementName[];
}
```

## ActiveRoleAssignment

**Kind:** interface

A role assignment currently eligible for exact-scope selection.

```ts
export interface ActiveRoleAssignment extends RoleAssignmentGrant {
  readonly status: "active";
}
```

## EntitlementAdapter

**Kind:** interface

Loads currently active host entitlement names for one stable principal.

Input is principal-keyed request context, not transient provider facts.
Webhook-derived state is loaded request-time from trusted host persistence.
Missing, stale, future, corrupt, and operationally unavailable state rejects
without last-known-good fallback. Output is a detached, frozen, sorted,
duplicate-free list of exact host entitlement names. Roles, permissions,
provider lifecycle statuses, and persistence mechanics remain outside this
contract.

```ts
export interface EntitlementAdapter<
  Input extends EntitlementRequest = EntitlementRequest,
> {
  readonly resolveEntitlements: (
    input: Input,
  ) => Promise<readonly EntitlementName[]>;
}
```

## EntitlementName

**Kind:** type

A named commercial or otherwise externally sourced grant.

```ts
export type EntitlementName = string;
```

## EntitlementRequest

**Kind:** interface

Principal-keyed request for active entitlements from trusted host state.

```ts
export interface EntitlementRequest {
  readonly principalId: PrincipalId;
}
```

## IdentityAdapter

**Kind:** interface

Resolves verified, provider-namespaced identity evidence to a stable
host-owned principal.

Input must include an exact issuer-and-subject key and may carry additional
adapter-owned, verified evidence. A returned principal ID is never a raw
provider subject or email address. `null` means the host has no linked
principal; operational failures reject.

```ts
export interface IdentityAdapter<
  Input extends IdentityLinkKey = IdentityLinkKey,
> {
  readonly resolvePrincipalId: (input: Input) => Promise<PrincipalId | null>;
}
```

## IdentityLink

**Kind:** interface

One issuer-namespaced provider identity linked to a host-owned principal.

```ts
export interface IdentityLink {
  readonly key: IdentityLinkKey;
  readonly principalId: PrincipalId;
}
```

## IdentityLinkKey

**Kind:** interface

Provider identity key compared as an exact, case-sensitive tuple.

Neither component is normalized. Each issuer-and-subject pair may link to at
most one principal, while one host-owned principal may have multiple keys.

```ts
export interface IdentityLinkKey {
  readonly issuer: string;
  readonly subject: string;
}
```

## OrganizationId

**Kind:** type

Stable, host-owned identifier for an organization.

```ts
export type OrganizationId = string;
```

## PermissionName

**Kind:** type

An application action that can be allowed or denied.

```ts
export type PermissionName = string;
```

## PrincipalId

**Kind:** type

Stable identifier assigned by the host application.

Provider identifiers and email addresses should be linked to a principal,
not used in place of one.

```ts
export type PrincipalId = string;
```

## RevokedRoleAssignment

**Kind:** interface

A permanently revoked role assignment with its original grant evidence.

`reason`, when present, is immutable host-authored administrative context.
It is not interpreted for authorization and should not contain provider
identifiers, email addresses, credentials, or other sensitive data.

```ts
export interface RevokedRoleAssignment extends RoleAssignmentGrant {
  readonly status: "revoked";
  readonly revokedBy: RoleAssignmentActor;
  readonly revokedAtEpochMs: number;
  readonly reason?: string;
}
```

## RoleAssignment

**Kind:** type

Complete immutable lifecycle state for one role assignment ID.

```ts
export type RoleAssignment = ActiveRoleAssignment | RevokedRoleAssignment;
```

## RoleAssignmentActor

**Kind:** type

Host-authenticated actor responsible for a role lifecycle change.

Principal actors use the same host-owned PrincipalId as authorization.
System actors use a host-owned identifier for the trusted job or service.

```ts
export type RoleAssignmentActor =
  | Readonly<{
      readonly kind: "principal";
      readonly principalId: PrincipalId;
    }>
  | Readonly<{
      readonly kind: "system";
      readonly systemId: string;
    }>;
```

## RoleAssignmentGrant

**Kind:** interface

Immutable evidence common to the active and revoked lifecycle states.

```ts
export interface RoleAssignmentGrant {
  readonly id: RoleAssignmentId;
  readonly principalId: PrincipalId;
  readonly role: RoleName;
  readonly scope: RoleAssignmentScope;
  readonly grantedBy: RoleAssignmentActor;
  readonly grantedAtEpochMs: number;
}
```

## RoleAssignmentId

**Kind:** type

Opaque, immutable identifier for one role-assignment lifecycle.

Hosts generate a new exact, case-sensitive value for every grant. Revoking
and later regranting the same role creates a new assignment ID.

```ts
export type RoleAssignmentId = string;
```

## RoleAssignmentScope

**Kind:** type

Exact authorization scope for one role assignment.

Organization scope is selected from the target resource by the host; it is
not inferred from identity-provider claims or carried by AccessContext.

```ts
export type RoleAssignmentScope =
  | Readonly<{
      readonly kind: "application";
    }>
  | Readonly<{
      readonly kind: "organization";
      readonly organizationId: OrganizationId;
    }>;
```

## RoleName

**Kind:** type

A named responsibility assigned by the host application.

```ts
export type RoleName = string;
```
