# @pegma/authorization-policy

Generated from the public declaration entry point `packages/policy/dist/index.d.ts`. Internal modules are intentionally excluded.

## MAX_PERMISSION_NAME_LENGTH

**Kind:** const

```ts
export declare const MAX_PERMISSION_NAME_LENGTH = 255;
```

## MAX_POLICY_VERSION_LENGTH

**Kind:** const

```ts
export declare const MAX_POLICY_VERSION_LENGTH = 128;
```

## MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH

**Kind:** const

```ts
export declare const MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH = 255;
```

## parsePolicy

**Kind:** function

Parse a previously JSON-decoded value into a validated immutable V1 policy.

@throws {PolicyValidationError} when any validation diagnostic is present.

```ts
export declare function parsePolicy(input: unknown): PolicyDocumentV1;
```

## PERMISSION_NAME_PATTERN_SOURCE

**Kind:** const

Permission names are dot-separated lowercase ASCII segments. A segment
begins with a letter and may contain alphanumeric groups separated by one
hyphen or underscore.

```ts
export declare const PERMISSION_NAME_PATTERN_SOURCE =
  "^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*(?:\\.[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*)*$";
```

## POLICY_SCHEMA_VERSION

**Kind:** const

```ts
export declare const POLICY_SCHEMA_VERSION: 1;
```

## POLICY_VERSION_PATTERN_SOURCE

**Kind:** const

Policy versions are opaque, case-sensitive host revision tokens. Authorization Core
compares them only for exact equality and assigns no ordering semantics.

```ts
export declare const POLICY_VERSION_PATTERN_SOURCE =
  "^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$";
```

## PolicyDiagnostic

**Kind:** interface

One deterministic policy validation failure at an RFC 6901 JSON Pointer.

```ts
export interface PolicyDiagnostic {
  readonly code: PolicyDiagnosticCode;
  readonly path: string;
  readonly message: string;
  readonly relatedPath?: string;
}
```

## PolicyDiagnosticCode

**Kind:** type

```ts
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
```

## PolicyDocumentV1

**Kind:** interface

The first serialized, JSON-compatible Authorization Core policy document.

```ts
export interface PolicyDocumentV1 extends AccessPolicy {
  readonly schemaVersion: typeof POLICY_SCHEMA_VERSION;
}
```

## PolicyValidationError

**Kind:** class

Error thrown by {@link parsePolicy} when validation fails.

```ts
export declare class PolicyValidationError extends TypeError {
  readonly diagnostics: readonly PolicyDiagnostic[];
  constructor(diagnostics: readonly PolicyDiagnostic[]);
}
```

## PolicyValidationResult

**Kind:** type

```ts
export type PolicyValidationResult =
  | {
      readonly valid: true;
      readonly policy: PolicyDocumentV1;
    }
  | {
      readonly valid: false;
      readonly diagnostics: readonly PolicyDiagnostic[];
    };
```

## validatePolicy

**Kind:** function

Validate an already parsed policy value without returning a partial policy.

The input must have the same ordinary data-property shape produced by
JSON.parse. Unexpected proxies or reflective failures are reported as an
invalid structure rather than escaping the fail-closed boundary.

```ts
export declare function validatePolicy(input: unknown): PolicyValidationResult;
```
