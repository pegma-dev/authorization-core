import type {
  AccessPolicy,
  EntitlementName,
  PermissionName,
  RoleName,
} from "@pegma/authorization-contracts";

export const POLICY_SCHEMA_VERSION = 1 as const;
export const MAX_POLICY_VERSION_LENGTH = 128;
export const MAX_PERMISSION_NAME_LENGTH = 255;
export const MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH = 255;

/**
 * Policy versions are opaque, case-sensitive host revision tokens. Authorization Core
 * compares them only for exact equality and assigns no ordering semantics.
 */
export const POLICY_VERSION_PATTERN_SOURCE =
  "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";

/**
 * Permission names are dot-separated lowercase ASCII segments. A segment
 * begins with a letter and may contain alphanumeric groups separated by one
 * hyphen or underscore.
 */
export const PERMISSION_NAME_PATTERN_SOURCE =
  "^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*)*$";

const ASCII_CONTROL_PATTERN = /[\u0000-\u001f\u007f]/;
const POLICY_VERSION_PATTERN = new RegExp(POLICY_VERSION_PATTERN_SOURCE);
const PERMISSION_NAME_PATTERN = new RegExp(PERMISSION_NAME_PATTERN_SOURCE);
const POLICY_FIELDS = new Set([
  "schemaVersion",
  "version",
  "defaults",
  "roles",
  "entitlements",
]);

/** The first serialized, JSON-compatible Authorization Core policy document. */
export interface PolicyDocumentV1 extends AccessPolicy {
  readonly schemaVersion: typeof POLICY_SCHEMA_VERSION;
}

export type PolicyDiagnosticCode =
  | "invalid_structure"
  | "invalid_type"
  | "missing_field"
  | "unknown_field"
  | "unsupported_schema_version"
  | "invalid_policy_version"
  | "empty_name"
  | "invalid_name"
  | "malformed_permission"
  | "duplicate_grant";

/** One deterministic policy validation failure at an RFC 6901 JSON Pointer. */
export interface PolicyDiagnostic {
  readonly code: PolicyDiagnosticCode;
  readonly path: string;
  readonly message: string;
  readonly relatedPath?: string;
}

export type PolicyValidationResult =
  | {
      readonly valid: true;
      readonly policy: PolicyDocumentV1;
    }
  | {
      readonly valid: false;
      readonly diagnostics: readonly PolicyDiagnostic[];
    };

/** Error thrown by {@link parsePolicy} when validation fails. */
export class PolicyValidationError extends TypeError {
  readonly diagnostics: readonly PolicyDiagnostic[];

  constructor(diagnostics: readonly PolicyDiagnostic[]) {
    super(
      `Policy validation failed with ${diagnostics.length} diagnostic${
        diagnostics.length === 1 ? "" : "s"
      }`,
    );
    this.name = "PolicyValidationError";
    this.diagnostics = diagnostics;
  }
}

type MutableDiagnostic = {
  code: PolicyDiagnosticCode;
  path: string;
  message: string;
  relatedPath?: string;
};

type SafePermissionMap = Readonly<Record<string, readonly PermissionName[]>>;

function pointer(parent: string, token: string | number): string {
  const escaped = String(token).replaceAll("~", "~0").replaceAll("/", "~1");
  return `${parent}/${escaped}`;
}

function invalidResult(
  diagnostics: readonly MutableDiagnostic[],
): PolicyValidationResult {
  const frozen = Object.freeze(
    diagnostics.map(
      (diagnostic) => Object.freeze({ ...diagnostic }) as PolicyDiagnostic,
    ),
  );
  return Object.freeze({ valid: false, diagnostics: frozen });
}

function plainRecordIssue(value: object): string | undefined {
  if (
    Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Object.prototype
  ) {
    return "Expected an ordinary JSON object.";
  }

  if (Object.getOwnPropertySymbols(value).length > 0) {
    return "JSON objects must not contain symbol properties.";
  }

  for (const descriptor of Object.values(
    Object.getOwnPropertyDescriptors(value),
  )) {
    if (!("value" in descriptor) || !descriptor.enumerable) {
      return "JSON object properties must be enumerable data properties.";
    }
  }

  return undefined;
}

function arrayIssue(value: readonly unknown[]): string | undefined {
  if (Object.getPrototypeOf(value) !== Array.prototype) {
    return "Expected an ordinary JSON array.";
  }

  if (Object.getOwnPropertySymbols(value).length > 0) {
    return "JSON arrays must not contain symbol properties.";
  }

  const descriptors = Object.getOwnPropertyDescriptors(value);
  for (const key of Object.keys(descriptors)) {
    if (key === "length") {
      continue;
    }

    const index = Number(key);
    const isCanonicalIndex =
      /^(0|[1-9][0-9]*)$/.test(key) &&
      Number.isSafeInteger(index) &&
      index >= 0 &&
      index < value.length;
    const descriptor = descriptors[key];
    if (
      !isCanonicalIndex ||
      descriptor === undefined ||
      !("value" in descriptor) ||
      !descriptor.enumerable
    ) {
      return "JSON arrays must contain only enumerable indexed data properties.";
    }
  }

  for (let index = 0; index < value.length; index += 1) {
    if (!Object.hasOwn(value, index)) {
      return "JSON arrays must not be sparse.";
    }
  }

  return undefined;
}

function ownValue(
  record: Readonly<Record<string, unknown>>,
  key: string,
): unknown {
  return Object.getOwnPropertyDescriptor(record, key)?.value;
}

function validateHostName(
  name: string,
  path: string,
  kind: "role" | "entitlement",
  diagnostics: MutableDiagnostic[],
): void {
  let codePointLength = 0;
  for (const _codePoint of name) {
    codePointLength += 1;
    if (codePointLength > MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH) {
      break;
    }
  }

  if (codePointLength === 0) {
    diagnostics.push({
      code: "empty_name",
      path,
      message: `${kind} names must not be empty.`,
    });
    return;
  }

  if (
    name.trim() !== name ||
    ASCII_CONTROL_PATTERN.test(name) ||
    codePointLength > MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH
  ) {
    diagnostics.push({
      code: "invalid_name",
      path,
      message: `${kind} names must have no surrounding whitespace or ASCII control characters and be at most 255 Unicode code points.`,
    });
  }
}

function validatePermission(
  value: string,
  path: string,
  diagnostics: MutableDiagnostic[],
): void {
  if (value.length === 0 || value.trim().length === 0) {
    diagnostics.push({
      code: "empty_name",
      path,
      message: "Permission names must not be empty.",
    });
    return;
  }

  if (
    value.length > MAX_PERMISSION_NAME_LENGTH ||
    !PERMISSION_NAME_PATTERN.test(value)
  ) {
    diagnostics.push({
      code: "malformed_permission",
      path,
      message:
        "Permission names must be 1-255 characters of dot-separated lowercase ASCII segments.",
    });
  }
}

function validateGrantList(
  value: unknown,
  path: string,
  diagnostics: MutableDiagnostic[],
): readonly PermissionName[] | undefined {
  if (!Array.isArray(value)) {
    diagnostics.push({
      code: "invalid_type",
      path,
      message: "Expected an array of permission names.",
    });
    return undefined;
  }

  const issue = arrayIssue(value);
  if (issue !== undefined) {
    diagnostics.push({
      code: "invalid_structure",
      path,
      message: issue,
    });
    return undefined;
  }

  const permissions: PermissionName[] = [];
  const firstPaths = new Map<string, string>();
  for (let index = 0; index < value.length; index += 1) {
    const itemPath = pointer(path, index);
    const item = value[index];
    if (typeof item !== "string") {
      diagnostics.push({
        code: "invalid_type",
        path: itemPath,
        message: "Permission names must be strings.",
      });
      continue;
    }

    validatePermission(item, itemPath, diagnostics);
    const relatedPath = firstPaths.get(item);
    if (relatedPath !== undefined) {
      diagnostics.push({
        code: "duplicate_grant",
        path: itemPath,
        relatedPath,
        message: "A grant list must not contain duplicate permissions.",
      });
    } else {
      firstPaths.set(item, itemPath);
    }
    permissions.push(item);
  }

  return Object.freeze([...permissions]);
}

function validatePermissionMap(
  value: unknown,
  path: string,
  kind: "role" | "entitlement",
  diagnostics: MutableDiagnostic[],
): SafePermissionMap | undefined {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    diagnostics.push({
      code: "invalid_type",
      path,
      message: `Expected an object mapping ${kind} names to permission arrays.`,
    });
    return undefined;
  }

  const issue = plainRecordIssue(value);
  if (issue !== undefined) {
    diagnostics.push({
      code: "invalid_structure",
      path,
      message: issue,
    });
    return undefined;
  }

  const record = value as Readonly<Record<string, unknown>>;
  const result: Record<string, readonly PermissionName[]> = Object.create(null);
  for (const name of Object.keys(record).sort()) {
    const namePath = pointer(path, name);
    validateHostName(name, namePath, kind, diagnostics);
    const permissions = validateGrantList(
      ownValue(record, name),
      namePath,
      diagnostics,
    );
    if (permissions !== undefined) {
      result[name] = permissions;
    }
  }

  return Object.freeze(result);
}

function validatePolicyInternal(input: unknown): PolicyValidationResult {
  const diagnostics: MutableDiagnostic[] = [];
  if (typeof input !== "object" || input === null || Array.isArray(input)) {
    return invalidResult([
      {
        code: "invalid_type",
        path: "",
        message: "Expected a policy document object.",
      },
    ]);
  }

  const rootIssue = plainRecordIssue(input);
  if (rootIssue !== undefined) {
    return invalidResult([
      {
        code: "invalid_structure",
        path: "",
        message: rootIssue,
      },
    ]);
  }

  const record = input as Readonly<Record<string, unknown>>;
  for (const field of Object.keys(record)
    .filter((field) => !POLICY_FIELDS.has(field))
    .sort()) {
    diagnostics.push({
      code: "unknown_field",
      path: pointer("", field),
      message: "PolicyDocumentV1 does not allow this field.",
    });
  }

  if (!Object.hasOwn(record, "schemaVersion")) {
    diagnostics.push({
      code: "missing_field",
      path: "/schemaVersion",
      message: "schemaVersion is required.",
    });
  } else {
    const schemaVersion = ownValue(record, "schemaVersion");
    if (typeof schemaVersion !== "number") {
      diagnostics.push({
        code: "invalid_type",
        path: "/schemaVersion",
        message: "schemaVersion must be the number 1.",
      });
    } else if (schemaVersion !== POLICY_SCHEMA_VERSION) {
      diagnostics.push({
        code: "unsupported_schema_version",
        path: "/schemaVersion",
        message: "Only policy schema version 1 is supported.",
      });
    }
  }

  let version: string | undefined;
  if (!Object.hasOwn(record, "version")) {
    diagnostics.push({
      code: "missing_field",
      path: "/version",
      message: "version is required.",
    });
  } else {
    const value = ownValue(record, "version");
    if (typeof value !== "string") {
      diagnostics.push({
        code: "invalid_type",
        path: "/version",
        message: "version must be a string.",
      });
    } else if (!POLICY_VERSION_PATTERN.test(value)) {
      diagnostics.push({
        code: "invalid_policy_version",
        path: "/version",
        message:
          "version must be a 1-128 character opaque ASCII revision token.",
      });
    } else {
      version = value;
    }
  }

  let defaults: readonly PermissionName[] | undefined;
  if (Object.hasOwn(record, "defaults")) {
    defaults = validateGrantList(
      ownValue(record, "defaults"),
      "/defaults",
      diagnostics,
    );
  }

  let roles: SafePermissionMap | undefined;
  if (Object.hasOwn(record, "roles")) {
    roles = validatePermissionMap(
      ownValue(record, "roles"),
      "/roles",
      "role",
      diagnostics,
    );
  }

  let entitlements: SafePermissionMap | undefined;
  if (Object.hasOwn(record, "entitlements")) {
    entitlements = validatePermissionMap(
      ownValue(record, "entitlements"),
      "/entitlements",
      "entitlement",
      diagnostics,
    );
  }

  if (diagnostics.length > 0 || version === undefined) {
    return invalidResult(diagnostics);
  }

  const policy: {
    schemaVersion: typeof POLICY_SCHEMA_VERSION;
    version: string;
    defaults?: readonly PermissionName[];
    roles?: Readonly<Record<RoleName, readonly PermissionName[]>>;
    entitlements?: Readonly<Record<EntitlementName, readonly PermissionName[]>>;
  } = {
    schemaVersion: POLICY_SCHEMA_VERSION,
    version,
  };
  if (defaults !== undefined) {
    policy.defaults = defaults;
  }
  if (roles !== undefined) {
    policy.roles = roles;
  }
  if (entitlements !== undefined) {
    policy.entitlements = entitlements;
  }

  return Object.freeze({
    valid: true,
    policy: Object.freeze(policy),
  });
}

/**
 * Validate an already parsed policy value without returning a partial policy.
 *
 * The input must have the same ordinary data-property shape produced by
 * JSON.parse. Unexpected proxies or reflective failures are reported as an
 * invalid structure rather than escaping the fail-closed boundary.
 */
export function validatePolicy(input: unknown): PolicyValidationResult {
  try {
    return validatePolicyInternal(input);
  } catch {
    return invalidResult([
      {
        code: "invalid_structure",
        path: "",
        message: "The policy input could not be inspected safely.",
      },
    ]);
  }
}

/**
 * Parse a previously JSON-decoded value into a validated immutable V1 policy.
 *
 * @throws {PolicyValidationError} when any validation diagnostic is present.
 */
export function parsePolicy(input: unknown): PolicyDocumentV1 {
  const result = validatePolicy(input);
  if (!result.valid) {
    throw new PolicyValidationError(result.diagnostics);
  }
  return result.policy;
}
