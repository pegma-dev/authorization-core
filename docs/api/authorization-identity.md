<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-identity

Generated from the public declaration entry point `packages/identity-link/dist/index.d.ts`. Internal modules are intentionally excluded.

## identityLinkKeyFromVerifiedIdentityClaims

**Kind:** function

Projects already-verified first-party identity claims into an authorization
identity-link key.

This function does not authenticate a session or resolve a principal. It
accepts only the exact verified-claims shape and deliberately omits contact
data and verification evidence from its frozen result. Descriptor validation
does not execute ordinary-object getters; portable JavaScript reflection may
execute proxy traps, so trusted callers should pass a plain claims snapshot.

```ts
export declare function identityLinkKeyFromVerifiedIdentityClaims(
  claims: VerifiedIdentityClaims,
): IdentityLinkKey;
```

## VerifiedIdentityClaims

**Kind:** interface

The verified first-party identity claims projected by this adapter.

This structural contract matches `@pegma/identity` without making either
package depend on the other. Email remains identity-side contact evidence
and never enters an authorization link key.

```ts
export interface VerifiedIdentityClaims {
  readonly issuer: string;
  readonly subject: PrincipalId;
  readonly emailVerified: true;
}
```
