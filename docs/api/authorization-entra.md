<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-entra

Generated from the public declaration entry point `packages/entra/dist/index.d.ts`. Internal modules are intentionally excluded.

## EntraIssuerObjectIdClaims

**Kind:** interface

Minimal Entra claims accepted after the host has verified the token that
supplied them. `oid` is the tenant-scoped stable object id; `sub` is
pairwise per app registration and is deliberately not accepted.

```ts
export interface EntraIssuerObjectIdClaims {
  readonly iss: string;
  readonly oid: string;
}
```

## identityLinkKeyFromVerifiedEntraClaims

**Kind:** const

Projects already-verified Entra issuer and object-id claims into an identity
link key.

This function does not decode or verify tokens. It preserves both nonblank
claim values exactly, accepts only the v2 issuer profile, and rejects
malformed claim containers. Pairwise `sub` is never read.

```ts
export declare const identityLinkKeyFromVerifiedEntraClaims: (
  claims: EntraIssuerObjectIdClaims,
) => IdentityLinkKey;
```
