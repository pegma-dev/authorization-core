# @pegma/authorization-core

Generated from the public declaration entry point `packages/core/dist/index.d.ts`. Internal modules are intentionally excluded.

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

## decideAccess

**Kind:** function

Produce an explicit, log-friendly decision for one permission check.

```ts
export declare function decideAccess(
  context: AccessContext,
  permission: PermissionName,
): AccessDecision;
```

## EntitlementName

**Kind:** type

A named commercial or otherwise externally sourced grant.

```ts
export type EntitlementName = string;
```

## hasPermission

**Kind:** function

Return true when an access context explicitly includes a permission.

```ts
export declare function hasPermission(
  context: AccessContext,
  permission: PermissionName,
): boolean;
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

## resolveAccess

**Kind:** function

Resolve trusted principal facts through an application-owned policy.

Unknown roles and entitlements are retained for observability but do not
grant permissions. The resolver does not support wildcard permissions.

```ts
export declare function resolveAccess(
  subject: AccessSubject,
  policy: AccessPolicy,
): AccessContext;
```

## resolveAccessWithDiagnostics

**Kind:** function

Resolve access and report unknown subject facts without changing grants.

Diagnostics are informational and have no effect on the returned context.

```ts
export declare function resolveAccessWithDiagnostics(
  subject: AccessSubject,
  policy: AccessPolicy,
): AccessResolution;
```

## RoleName

**Kind:** type

A named responsibility assigned by the host application.

```ts
export type RoleName = string;
```

## serializeAccessContext

**Kind:** function

Serialize one access context to a stable, compact JSON snapshot.

The snapshot is unauthenticated and must not be trusted as client input or
used in place of a signed access grant.

```ts
export declare function serializeAccessContext(context: AccessContext): string;
```
