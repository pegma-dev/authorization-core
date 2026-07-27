# Migrating direct role and plan checks

Migrate incrementally, but never make `legacyAllow || newAllow` a permanent
authorization rule. That construction preserves whichever path is broader and
can hide a broken trusted-fact translation.

## Staged migration

1. Inventory every direct plan, price, provider-role, staff-role, and
   browser-visible claim check. Record the protected action and any ownership
   or organization relationship it assumes.
2. Define stable application permissions for those actions using the
   [permission guide](PERMISSIONS.md). Keep resource IDs, provider IDs, plans,
   and roles out of permission names.
3. Establish exact host principals and identity links using
   [Identity linking](IDENTITY_LINKING.md). Email and provider subject alone are
   not migration keys.
4. Translate commercial state into entitlements from fresh persisted facts.
   For Stripe, preserve existing lifecycle policy and follow the
   [Stripe integration boundary](STRIPE.md).
5. Move staff responsibility into audited
   [role assignments](ROLE_ASSIGNMENTS.md), preserving an explicit application
   or target-derived organization scope.
6. Validate a versioned policy at startup. Add every new grant deliberately and
   include matching allow and deny tests.
7. In observation-only shadow mode, resolve Authorization Core decisions and
   compare them with legacy outcomes without granting from the new result.
   Log structured differences without tokens, provider facts, emails, or
   private keys. Investigate every access-expanding mismatch.
8. Switch one trusted server route at a time to the exact permission decision,
   retaining its independent ownership, membership, and resource checks.
9. Preserve the [60-second role bound and stale-fill fence](ROLE_REVOCATION.md)
   in any cache. Invalidate cached denials on grants and cached allows on
   revocations.
10. Remove the corresponding legacy check, provider vocabulary, and shadow log
    only after tests and production evidence agree. Keep rollback at the policy
    or deployment level; do not reactivate a less restrictive check in the
    request path.

For organizations and multiple applications, follow [Scoping](SCOPING.md).
For protected services, migrate only application-scoped permissions into the
V1 [access-grant profile](ACCESS_GRANTS.md). Review the complete
[security model](SECURITY_MODEL.md) before declaring the old boundary removed.
