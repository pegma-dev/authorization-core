<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-tokens

Generated from the public declaration entry point `packages/tokens/dist/index.d.ts`. Internal modules are intentionally excluded.

## AcceptedAccessGrantPolicy

**Kind:** interface

```ts
export interface AcceptedAccessGrantPolicy {
  readonly version: string;
  readonly digest: string;
}
```

## ACCESS_GRANT_ALGORITHM

**Kind:** const

```ts
export declare const ACCESS_GRANT_ALGORITHM: "ES256";
```

## ACCESS_GRANT_PROFILE_VERSION

**Kind:** const

```ts
export declare const ACCESS_GRANT_PROFILE_VERSION: 1;
```

## ACCESS_GRANT_TYPE

**Kind:** const

```ts
export declare const ACCESS_GRANT_TYPE: "pegma-access-grant+jwt";
```

## AccessGrantError

**Kind:** class

```ts
export declare class AccessGrantError extends Error {
  constructor(
    message?: string,
    options?: {
      cause?: unknown;
    },
  );
}
```

## AccessGrantIssuer

**Kind:** interface

```ts
export interface AccessGrantIssuer<ReadRequest> {
  readSourceAuthorization(
    request: ReadRequest,
  ): Promise<AuthoritativeSourceAuthorizationRead>;
  bindSourceAuthorization(
    read: AuthoritativeSourceAuthorizationRead,
  ): SourceAuthorizationCapability;
  issue(input: IssueAccessGrantInput): Promise<string>;
}
```

## AccessGrantIssuerConfiguration

**Kind:** interface

```ts
export interface AccessGrantIssuerConfiguration<ReadRequest> {
  readonly issuer: string;
  readonly applicationId: string;
  readonly kid: string;
  readonly signingKey: CryptoKey;
  readonly audiences: Readonly<Record<string, readonly string[]>>;
  readonly acceptedPolicies: readonly AcceptedAccessGrantPolicy[];
  readonly sourceReader: (
    request: ReadRequest,
  ) => SourceAuthorizationSnapshot | Promise<SourceAuthorizationSnapshot>;
}
```

## AccessGrantJtiReservation

**Kind:** interface

One issuer-owned identifier permanently reserved before signing.

```ts
export interface AccessGrantJtiReservation {
  readonly issuer: string;
  readonly applicationId: string;
  readonly jti: string;
}
```

## accessGrantJtiReservationKey

**Kind:** function

```ts
export declare function accessGrantJtiReservationKey(
  issuer: string,
  applicationId: string,
  jti: string,
): EntityKey;
```

## accessGrantJtiReservations

**Kind:** const

Declared issuer-side identifier reservation collection.

```ts
export declare const accessGrantJtiReservations: import("@pegma/storage-core").CollectionDefinition<AccessGrantJtiReservation>;
```

## AccessGrantJwks

**Kind:** interface

```ts
export interface AccessGrantJwks {
  readonly keys: readonly AccessGrantPublicJwk[];
}
```

## AccessGrantPublicJwk

**Kind:** interface

```ts
export interface AccessGrantPublicJwk {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
  readonly use: "sig";
  readonly alg: typeof ACCESS_GRANT_ALGORITHM;
  readonly kid: string;
}
```

## AccessGrantPublicKey

**Kind:** interface

```ts
export interface AccessGrantPublicKey {
  readonly kid: string;
  readonly key: CryptoKey;
}
```

## accessGrantReplayKey

**Kind:** function

```ts
export declare function accessGrantReplayKey(
  issuer: string,
  applicationId: string,
  audience: string,
  jti: string,
): EntityKey;
```

## AccessGrantReplayRecord

**Kind:** interface

One exact V1 grant consumption. Records may safely be retained indefinitely.

```ts
export interface AccessGrantReplayRecord {
  readonly issuer: string;
  readonly applicationId: string;
  readonly audience: string;
  readonly jti: string;
  /** The record must remain present through this NumericDate second. */
  readonly retainThrough: number;
}
```

## accessGrantReplays

**Kind:** const

Declared replay collection. The host supplies the Store implementation.

```ts
export declare const accessGrantReplays: import("@pegma/storage-core").CollectionDefinition<AccessGrantReplayRecord>;
```

## AccessGrantSourceScope

**Kind:** type

```ts
export type AccessGrantSourceScope =
  | Readonly<{
      readonly kind: "application";
    }>
  | Readonly<{
      readonly kind: "organization";
      readonly organizationId: string;
    }>;
```

## AccessGrantVerifier

**Kind:** interface

```ts
export interface AccessGrantVerifier {
  /**
   * Verify every V1 invariant and atomically consume the grant before return.
   *
   * There is intentionally no verify-only public operation.
   */
  verifyAndConsume(compact: string): Promise<VerifiedAccessGrant>;
}
```

## AccessGrantVerifierConfiguration

**Kind:** interface

```ts
export interface AccessGrantVerifierConfiguration {
  readonly issuer: string;
  readonly applicationId: string;
  readonly audience: string;
  readonly allowedPermissions: readonly string[];
  readonly acceptedPolicies: readonly AcceptedAccessGrantPolicy[];
  readonly jwksUrl: string;
  readonly jwksCacheAgeMs: number;
}
```

## AuthoritativeSourceAuthorizationRead

**Kind:** class

Opaque evidence returned only by an issuer's trusted source reader.

```ts
export declare class AuthoritativeSourceAuthorizationRead {}
```

## createAccessGrantIssuer

**Kind:** function

Create a production issuer with process-owned clocks and CSPRNG.

```ts
export declare function createAccessGrantIssuer<ReadRequest>(
  configuration: AccessGrantIssuerConfiguration<ReadRequest>,
  store: Store,
): AccessGrantIssuer<ReadRequest>;
```

## createAccessGrantJwks

**Kind:** function

Project host-owned public CryptoKeys into the exact V1 JWKS surface.

Private keys are rejected before export and only the seven public profile
members are copied into the returned document.

```ts
export declare function createAccessGrantJwks(
  entries: readonly AccessGrantPublicKey[],
): Promise<AccessGrantJwks>;
```

## createAccessGrantVerifier

**Kind:** function

Create a production verifier using a host-supplied storage-core Store.

```ts
export declare function createAccessGrantVerifier(
  configuration: AccessGrantVerifierConfiguration,
  store: Store,
): AccessGrantVerifier;
```

## IssueAccessGrantInput

**Kind:** interface

```ts
export interface IssueAccessGrantInput {
  readonly audience: string;
  readonly requestedPermissions: readonly string[];
  readonly source: SourceAuthorizationCapability;
}
```

## MAX_ACCESS_GRANT_LIFETIME_SECONDS

**Kind:** const

```ts
export declare const MAX_ACCESS_GRANT_LIFETIME_SECONDS = 30;
```

## MAX_JWKS_CACHE_AGE_MS

**Kind:** const

```ts
export declare const MAX_JWKS_CACHE_AGE_MS = 60000;
```

## MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS

**Kind:** const

```ts
export declare const MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS = 5;
```

## MAX_SOURCE_AUTHORIZATION_LIFETIME_MS

**Kind:** const

```ts
export declare const MAX_SOURCE_AUTHORIZATION_LIFETIME_MS = 60000;
```

## parseAccessGrantJwks

**Kind:** function

Parse and fully validate one exact V1 public JWKS document.

```ts
export declare function parseAccessGrantJwks(
  input: string | Uint8Array,
): Promise<AccessGrantJwks>;
```

## SourceAuthorizationCapability

**Kind:** class

Opaque, issuer-local source authorization accepted by issue().

```ts
export declare class SourceAuthorizationCapability {}
```

## SourceAuthorizationSnapshot

**Kind:** interface

```ts
export interface SourceAuthorizationSnapshot {
  readonly applicationId: string;
  readonly context: AccessContext;
  readonly policyDigest: string;
  readonly scope: AccessGrantSourceScope;
  /**
   * Absolute cache/read lifetime beginning at the sample immediately before
   * this snapshot's authoritative source reader was called.
   */
  readonly maximumLifetimeMs: number;
}
```

## UNKNOWN_KID_REFRESH_INTERVAL_MS

**Kind:** const

```ts
export declare const UNKNOWN_KID_REFRESH_INTERVAL_MS = 5000;
```

## VerifiedAccessGrant

**Kind:** interface

```ts
export interface VerifiedAccessGrant {
  readonly issuer: string;
  readonly applicationId: string;
  readonly audience: string;
  readonly principalId: string;
  readonly expiresAt: number;
  readonly issuedAt: number;
  readonly jti: string;
  readonly profileVersion: typeof ACCESS_GRANT_PROFILE_VERSION;
  readonly policyVersion: string;
  readonly policyDigest: string;
  readonly permissions: readonly string[];
}
```
