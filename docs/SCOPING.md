# Application and organization scoping

Authorization Core deliberately keeps `AccessSubject` and `AccessContext`
principal-only. Scope is trusted host state that surrounds resolution and the
final resource decision.

## Application isolation

One role store, identity-link namespace, token issuer configuration, policy
snapshot and digest, and cache-key family belong to one exact host application.
`createRoleStore(store, applicationId)` binds the application at construction;
request callers do not select it. A shared backend creates separate bound store
instances. This is embedded application storage, not a cross-application
control plane.

Never reuse a context, cache entry, signing issuer, replay namespace, or audit
writer across applications merely because their principals or permission names
look alike. Token issuers and verifiers compare the provider-neutral
`application_id` exactly.

## Organization-targeted authorization

For an operation on a resource:

1. Load the authoritative target.
2. Derive its exact host organization ID.
3. Validate the principal's current membership for that organization.
4. Read application-scoped active assignments explicitly.
5. Read active assignments for that exact organization scope explicitly.
6. Resolve only the selected role names and fresh entitlements.
7. Decide the exact permission.
8. Recheck the target's organization, ownership, assignment, and other
   relationships before the action.

The organization is never accepted from an access context, assignment,
browser-selected claim, or permission name. A role assignment is not membership
evidence. A context resolved for organization A cannot authorize a target in
organization B.

Cache keys bind the exact application, principal, tagged scope, policy version
and digest, and final resource inputs. Application-scope changes invalidate all
organization variants for the principal; organization changes invalidate that
exact scope. See [Role assignments](ROLE_ASSIGNMENTS.md),
[Storage](STORAGE.md), and [Fast role revocation](ROLE_REVOCATION.md).

## Service grants

The V1 [access-grant profile](ACCESS_GRANTS.md) has no organization claim.
Issuance accepts only `{ kind: "application" }` source authorization and rejects
organization-scoped sources. Do not relabel a target-derived context as
application-scoped or remove organization roles after resolution and assume
the remainder is proven safe. Perform a fresh authoritative application-scope
read and resolution for the issuer.

A future organization-confinement profile would need separately versioned,
target-derived issuer evidence and exact verifier target binding. It would
still not replace membership or resource checks.
