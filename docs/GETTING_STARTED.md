# Getting started

Authorization Core is an embedded server-side library. It turns trusted,
host-owned identity, billing, and role facts into explicit permissions; it does
not replace authentication, billing lifecycle handling, persistence, or
resource relationship checks.

The runnable [reference API](../examples/reference-api/README.md) is the
shortest complete example. From a clean clone:

```sh
npm ci
npm run example
```

## Integration sequence

1. Validate the application-owned policy with `parsePolicy` during trusted
   server startup. Invalid policy stops boot. Define exact permissions using
   the [policy reference](POLICY.md) and
   [permission naming guide](PERMISSIONS.md). Deterministically serialize the
   reviewed policy/deployment inputs, hash those exact bytes, and parse that
   same snapshot so a content change cannot retain its accepted digest.
2. Verify the identity-provider token or session using the provider's supported
   verifier. Only then project the exact issuer and subject. The Auth0 adapter
   is a [post-verification projection](AUTH0.md), not a JWT verifier.
3. Resolve that exact identity-link key to a stable host `principalId`.
   `null` means unlinked; operational failure rejects. See
   [Identity linking](IDENTITY_LINKING.md).
4. Load fresh persisted billing state through the principal-keyed Stripe
   adapter. The host verifies webhooks, owns lifecycle decisions and durable
   persistence, and chooses the maximum age. See [Stripe](STRIPE.md).
5. Derive scope from the authoritative target, validate current membership,
   and read application plus exact-organization active assignments explicitly.
   Pass role names only into the resolver. See [Scoping](SCOPING.md),
   [Role assignments](ROLE_ASSIGNMENTS.md), and [Storage](STORAGE.md).
6. Call `resolveAccess` with the exact principal, trusted role names, and fresh
   entitlement names. Unknown names grant nothing.
7. At the server route, call `decideAccess` for the exact permission and still
   enforce ownership, membership, assignment, and target-version checks.
8. A `/access/me` response may display a filtered access snapshot, but neither
   that response nor `serializeAccessContext` is authoritative client input.
9. Mutate roles only through `grantRoleAssignmentWithAudit` and
   `revokeRoleAssignmentWithAudit`. Authenticate an exact host actor outside
   the command body, authorize that principal for application-scoped
   `roles.manage`, and bind the same principal to the audit mutation. Use a
   durable `Store` in production and follow the
   [revocation cache bound](ROLE_REVOCATION.md).
10. For an independently deployed module, issue a narrow application-scoped
    grant, publish public-only JWKS, and require `verifyAndConsume` before the
    protected action. V1 rejects organization-scoped sources. See
    [Access grants](ACCESS_GRANTS.md).

## Failure behavior

Unverified or unlinked identity, missing or stale billing state, incomplete role
reads, invalid policy, failed membership checks, expired cache state, storage
outages, invalid grants, and replay-store failure all fail closed. Never
replace one of those conditions with empty trusted facts or stale
last-known-good authorization.

Before production, work through the [integration security model](SECURITY_MODEL.md).
Custom providers should follow [Adapter authoring](ADAPTER_AUTHORING.md).
Existing applications can use the staged [migration guide](MIGRATION.md).
Every documented public export is in the generated
[API reference](api/README.md).
