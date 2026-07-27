# @pegma/authorization-auth0

Generated from the public declaration entry point `packages/auth0/dist/index.d.ts`. Internal modules are intentionally excluded.

## Auth0IssuerSubjectClaims

**Kind:** interface

Minimal Auth0 claims accepted after the host has verified the token or
session that supplied them.

```ts
export interface Auth0IssuerSubjectClaims {
  readonly iss: string;
  readonly sub: string;
}
```

## identityLinkKeyFromVerifiedAuth0Claims

**Kind:** const

Projects already-verified Auth0 issuer and subject claims into an identity
link key.

This function does not decode or verify tokens. It preserves both nonblank
claim values exactly and rejects malformed claim containers.

```ts
export declare const identityLinkKeyFromVerifiedAuth0Claims: (
  claims: Auth0IssuerSubjectClaims,
) => IdentityLinkKey;
```
