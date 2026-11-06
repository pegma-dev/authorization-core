import type {
  AccessContext,
  AccessDecision,
  AccessPolicy,
  AccessResolution,
  AccessResolutionDiagnostics,
  AccessSubject,
  PermissionName,
} from "@pegma/authorization-contracts";

export type {
  AccessContext,
  AccessDecision,
  AccessPolicy,
  AccessResolution,
  AccessResolutionDiagnostics,
  AccessSubject,
  EntitlementName,
  PermissionName,
  PrincipalId,
  RoleName,
} from "@pegma/authorization-contracts";

function requireName(value: string, field: string): void {
  if (value.trim().length === 0) {
    throw new TypeError(`${field} must not be empty`);
  }
}

function ownDataValue(
  value: object,
  field: string,
  label: string = field,
): unknown {
  if (!Object.hasOwn(value, field)) {
    throw new TypeError(`${label} must be an own data property`);
  }

  const descriptor = Object.getOwnPropertyDescriptor(value, field);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`${label} must be an own data property`);
  }

  return descriptor.value;
}

function optionalOwnDataValue(
  value: object,
  field: string,
  label: string = field,
): unknown {
  if (!Object.hasOwn(value, field)) {
    return undefined;
  }

  const descriptor = Object.getOwnPropertyDescriptor(value, field);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`${label} must be an own data property`);
  }

  return descriptor.value;
}

function requiredString(
  value: object,
  field: string,
  label: string = field,
): string {
  const candidate = ownDataValue(value, field, label);
  if (typeof candidate !== "string") {
    throw new TypeError(`${label} must be a string`);
  }

  requireName(candidate, label);
  return candidate;
}

function copyStringArrayValue(candidate: unknown, label: string): string[] {
  if (!Array.isArray(candidate)) {
    throw new TypeError(`${label} must be an array of strings`);
  }

  const copy: string[] = [];
  for (let index = 0; index < candidate.length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(candidate, index);
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      typeof descriptor.value !== "string"
    ) {
      throw new TypeError(`${label} must be a dense array of strings`);
    }

    copy.push(descriptor.value);
  }

  return copy;
}

function copyStringArray(value: object, field: string): string[] {
  return copyStringArrayValue(ownDataValue(value, field), field);
}

function copyOptionalStringArray(
  value: object,
  field: string,
  label: string,
): string[] {
  const candidate = optionalOwnDataValue(value, field, label);
  return candidate === undefined ? [] : copyStringArrayValue(candidate, label);
}

function serializeJsonString(value: string): string {
  const serialized = JSON.stringify(value);
  if (serialized === undefined) {
    throw new TypeError("string could not be serialized");
  }

  return serialized;
}

function serializeJsonStringArray(values: readonly string[]): string {
  return `[${values.map(serializeJsonString).join(",")}]`;
}

function uniqueSorted(values: readonly string[]): readonly string[] {
  return Object.freeze([...new Set(values)].sort());
}

function ownPermissions(
  assignments: Readonly<Record<string, readonly PermissionName[]>> | undefined,
  name: string,
  label: string,
): readonly PermissionName[] | undefined {
  if (assignments === undefined || !Object.hasOwn(assignments, name)) {
    return undefined;
  }

  const descriptor = Object.getOwnPropertyDescriptor(assignments, name);
  if (descriptor === undefined || !("value" in descriptor)) {
    throw new TypeError(`${label}.${name} must be an own data property`);
  }

  if (descriptor.value === undefined) {
    return [];
  }

  return copyStringArrayValue(descriptor.value, `${label}.${name}`);
}

function optionalPermissionMap(
  policy: AccessPolicy,
  field: "roles" | "entitlements",
): Readonly<Record<string, readonly PermissionName[]>> | undefined {
  const label = `policy.${field}`;
  const candidate = optionalOwnDataValue(policy, field, label);
  if (candidate === undefined) {
    return undefined;
  }
  if (typeof candidate !== "object" || candidate === null) {
    throw new TypeError(`${label} must be an object`);
  }

  return candidate as Readonly<Record<string, readonly PermissionName[]>>;
}

function resolveAccessInternal(
  subject: AccessSubject,
  policy: AccessPolicy,
): AccessResolution {
  const principalId = requiredString(subject, "principalId");
  const policyVersion = requiredString(policy, "version", "policy.version");
  const roles = uniqueSorted(
    copyOptionalStringArray(subject, "roles", "roles"),
  );
  const entitlements = uniqueSorted(
    copyOptionalStringArray(subject, "entitlements", "entitlements"),
  );
  const defaults = copyOptionalStringArray(
    policy,
    "defaults",
    "policy.defaults",
  );
  const roleAssignments = optionalPermissionMap(policy, "roles");
  const entitlementAssignments = optionalPermissionMap(policy, "entitlements");

  const granted = new Set<PermissionName>(defaults);
  const unknownRoles: string[] = [];
  const unknownEntitlements: string[] = [];

  for (const role of roles) {
    const permissions = ownPermissions(roleAssignments, role, "policy.roles");
    if (permissions === undefined) {
      unknownRoles.push(role);
      continue;
    }

    for (const permission of permissions) {
      granted.add(permission);
    }
  }

  for (const entitlement of entitlements) {
    const permissions = ownPermissions(
      entitlementAssignments,
      entitlement,
      "policy.entitlements",
    );
    if (permissions === undefined) {
      unknownEntitlements.push(entitlement);
      continue;
    }

    for (const permission of permissions) {
      granted.add(permission);
    }
  }

  const context = Object.freeze({
    principalId,
    policyVersion,
    roles,
    entitlements,
    permissions: uniqueSorted([...granted]),
  });
  const diagnostics = Object.freeze({
    unknownRoles: Object.freeze(unknownRoles),
    unknownEntitlements: Object.freeze(unknownEntitlements),
  });

  return Object.freeze({ context, diagnostics });
}

/**
 * Resolve trusted principal facts through an application-owned policy.
 *
 * Unknown roles and entitlements are retained for observability but do not
 * grant permissions. The resolver does not support wildcard permissions.
 */
export function resolveAccess(
  subject: AccessSubject,
  policy: AccessPolicy,
): AccessContext {
  return resolveAccessInternal(subject, policy).context;
}

/**
 * Resolve access and report unknown subject facts without changing grants.
 *
 * Diagnostics are informational and have no effect on the returned context.
 */
export function resolveAccessWithDiagnostics(
  subject: AccessSubject,
  policy: AccessPolicy,
): AccessResolution {
  return resolveAccessInternal(subject, policy);
}

/**
 * Serialize one access context to a stable, compact JSON snapshot.
 *
 * The snapshot is unauthenticated and must not be trusted as client input or
 * used in place of a signed access grant.
 */
export function serializeAccessContext(context: AccessContext): string {
  if (typeof context !== "object" || context === null) {
    throw new TypeError("context must be an object");
  }

  const principalId = requiredString(context, "principalId");
  const policyVersion = requiredString(context, "policyVersion");
  const roles = copyStringArray(context, "roles");
  const entitlements = copyStringArray(context, "entitlements");
  const permissions = copyStringArray(context, "permissions");

  return (
    `{"principalId":${serializeJsonString(principalId)},` +
    `"policyVersion":${serializeJsonString(policyVersion)},` +
    `"roles":${serializeJsonStringArray(roles)},` +
    `"entitlements":${serializeJsonStringArray(entitlements)},` +
    `"permissions":${serializeJsonStringArray(permissions)}}`
  );
}

/** Return true when an access context explicitly includes a permission. */
export function hasPermission(
  context: AccessContext,
  permission: PermissionName,
): boolean {
  requireName(permission, "permission");
  return context.permissions.includes(permission);
}

/** Produce an explicit, log-friendly decision for one permission check. */
export function decideAccess(
  context: AccessContext,
  permission: PermissionName,
): AccessDecision {
  const allowed = hasPermission(context, permission);

  return Object.freeze({
    allowed,
    permission,
    reason: allowed ? "granted" : "not_granted",
  });
}
