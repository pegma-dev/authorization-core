/**
 * Stable identifier assigned by the host application.
 *
 * Provider identifiers and email addresses should be linked to a principal,
 * not used in place of one.
 */
export type PrincipalId = string;

/**
 * Provider identity key compared as an exact, case-sensitive tuple.
 *
 * Neither component is normalized. Each issuer-and-subject pair may link to at
 * most one principal, while one host-owned principal may have multiple keys.
 */
export interface IdentityLinkKey {
  readonly issuer: string;
  readonly subject: string;
}

/** One issuer-namespaced provider identity linked to a host-owned principal. */
export interface IdentityLink {
  readonly key: IdentityLinkKey;
  readonly principalId: PrincipalId;
}

/** A named responsibility assigned by the host application. */
export type RoleName = string;

/**
 * Opaque, immutable identifier for one role-assignment lifecycle.
 *
 * Hosts generate a new exact, case-sensitive value for every grant. Revoking
 * and later regranting the same role creates a new assignment ID.
 */
export type RoleAssignmentId = string;

/** Stable, host-owned identifier for an organization. */
export type OrganizationId = string;

/**
 * Exact authorization scope for one role assignment.
 *
 * Organization scope is selected from the target resource by the host; it is
 * not inferred from identity-provider claims or carried by AccessContext.
 */
export type RoleAssignmentScope =
  | Readonly<{ readonly kind: "application" }>
  | Readonly<{
      readonly kind: "organization";
      readonly organizationId: OrganizationId;
    }>;

/**
 * Host-authenticated actor responsible for a role lifecycle change.
 *
 * Principal actors use the same host-owned PrincipalId as authorization.
 * System actors use a host-owned identifier for the trusted job or service.
 */
export type RoleAssignmentActor =
  | Readonly<{
      readonly kind: "principal";
      readonly principalId: PrincipalId;
    }>
  | Readonly<{
      readonly kind: "system";
      readonly systemId: string;
    }>;

/** Immutable evidence common to the active and revoked lifecycle states. */
export interface RoleAssignmentGrant {
  readonly id: RoleAssignmentId;
  readonly principalId: PrincipalId;
  readonly role: RoleName;
  readonly scope: RoleAssignmentScope;
  readonly grantedBy: RoleAssignmentActor;
  readonly grantedAtEpochMs: number;
}

/** A role assignment currently eligible for exact-scope selection. */
export interface ActiveRoleAssignment extends RoleAssignmentGrant {
  readonly status: "active";
}

/**
 * A permanently revoked role assignment with its original grant evidence.
 *
 * `reason`, when present, is immutable host-authored administrative context.
 * It is not interpreted for authorization and should not contain provider
 * identifiers, email addresses, credentials, or other sensitive data.
 */
export interface RevokedRoleAssignment extends RoleAssignmentGrant {
  readonly status: "revoked";
  readonly revokedBy: RoleAssignmentActor;
  readonly revokedAtEpochMs: number;
  readonly reason?: string;
}

/** Complete immutable lifecycle state for one role assignment ID. */
export type RoleAssignment = ActiveRoleAssignment | RevokedRoleAssignment;

/** A named commercial or otherwise externally sourced grant. */
export type EntitlementName = string;

/** An application action that can be allowed or denied. */
export type PermissionName = string;

/**
 * Resolves verified, provider-namespaced identity evidence to a stable
 * host-owned principal.
 *
 * Input must include an exact issuer-and-subject key and may carry additional
 * adapter-owned, verified evidence. A returned principal ID is never a raw
 * provider subject or email address. `null` means the host has no linked
 * principal; operational failures reject.
 */
export interface IdentityAdapter<
  Input extends IdentityLinkKey = IdentityLinkKey,
> {
  readonly resolvePrincipalId: (input: Input) => Promise<PrincipalId | null>;
}

/** Principal-keyed request for active entitlements from trusted host state. */
export interface EntitlementRequest {
  readonly principalId: PrincipalId;
}

/**
 * Loads currently active host entitlement names for one stable principal.
 *
 * Input is principal-keyed request context, not transient provider facts.
 * Webhook-derived state is loaded request-time from trusted host persistence.
 * Output contains entitlements only: roles, permissions, provider lifecycle
 * statuses, and persistence mechanics remain outside this contract.
 */
export interface EntitlementAdapter<
  Input extends EntitlementRequest = EntitlementRequest,
> {
  readonly resolveEntitlements: (
    input: Input,
  ) => Promise<readonly EntitlementName[]>;
}

/**
 * Trusted, already-resolved facts about the principal requesting access.
 *
 * Identity, billing, and persistence adapters are responsible for producing
 * these facts from verified server-side sources.
 */
export interface AccessSubject {
  readonly principalId: PrincipalId;
  readonly roles?: readonly RoleName[];
  readonly entitlements?: readonly EntitlementName[];
}

/**
 * Application-owned mapping from roles and entitlements to permissions.
 *
 * Unknown names are intentionally harmless: they appear in the resulting
 * context for observability but grant no permissions.
 */
export interface AccessPolicy {
  readonly version: string;
  readonly defaults?: readonly PermissionName[];
  readonly roles?: Readonly<Record<RoleName, readonly PermissionName[]>>;
  readonly entitlements?: Readonly<
    Record<EntitlementName, readonly PermissionName[]>
  >;
}

/** Immutable authorization facts resolved for one principal and policy. */
export interface AccessContext {
  readonly principalId: PrincipalId;
  readonly policyVersion: string;
  readonly roles: readonly RoleName[];
  readonly entitlements: readonly EntitlementName[];
  readonly permissions: readonly PermissionName[];
}

/** Unknown subject facts observed while resolving one access context. */
export interface AccessResolutionDiagnostics {
  readonly unknownRoles: readonly RoleName[];
  readonly unknownEntitlements: readonly EntitlementName[];
}

/** Immutable access context together with opt-in resolution diagnostics. */
export interface AccessResolution {
  readonly context: AccessContext;
  readonly diagnostics: AccessResolutionDiagnostics;
}

export type AccessDecisionReason = "granted" | "not_granted";

/** Auditable result of checking one permission against an access context. */
export interface AccessDecision {
  readonly allowed: boolean;
  readonly permission: PermissionName;
  readonly reason: AccessDecisionReason;
}
