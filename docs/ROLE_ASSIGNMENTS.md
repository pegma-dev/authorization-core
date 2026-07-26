# Role assignments

Role assignments are host-owned records that connect one stable principal to
one application role in one exact scope. They are privileged authorization
facts, not identity-provider claims, billing-provider attributes, or policy.

`@pegma/authorization-contracts` defines the immutable record shape. It deliberately
does not define mutation services, runtime parsers, or cache behavior.
`@pegma/authorization-storage` separately defines persistence ports for this lifecycle
and its role-specific audit events, and implements them over a
`@pegma/storage-core` `Store`; the in-memory store is the ephemeral reference
backend. The public surface exposes only safe mutations that atomically update
the role and its derived audit history. See [the storage guide](STORAGE.md) for
read, concurrency, application-partition, and atomicity semantics.

## Record model

Every assignment contains immutable grant evidence:

- `id`: an opaque, exact, case-sensitive `RoleAssignmentId`;
- `principalId`: the exact host-owned principal receiving the role;
- `role`: the exact application-owned `RoleName`;
- `scope`: either application-wide or one exact organization;
- `grantedBy`: the trusted host actor responsible for the grant; and
- `grantedAtEpochMs`: the host-recorded grant time.

An active record has `status: "active"`. A revoked record has
`status: "revoked"` plus `revokedBy` and `revokedAtEpochMs`. Revocation
preserves every original grant field.

`reason` is optional administrative context on a revoked record. When a host
uses it, the value is immutable and is never interpreted for authorization.
Keep it short and suitable for access-controlled operational records. Do not
put provider identifiers, email addresses, credentials, tokens, or unnecessary
personal information in it.

The actor union is explicit:

- `{ kind: "principal", principalId }` identifies a host-authenticated
  principal; and
- `{ kind: "system", systemId }` identifies a trusted host job or service.

Both identifiers are host-owned and compared exactly. Provider subjects,
emails, display names, and unverified claims are not actors.

## Scope and selection

Application scope is `{ kind: "application" }`. Organization scope is
`{ kind: "organization", organizationId }`, where `organizationId` is the exact
host-owned organization identifier.

The trusted host derives scope from the resource or operation being
authorized. For an organization target, it loads and validates host-owned
membership for that exact organization, then selects active assignments whose
`principalId` and scope match exactly. Application roles and roles for the
selected organization may be composed explicitly. Roles from another
organization must never be reused.

Organization membership remains outside this record and outside Authorization Core's
`AccessSubject` and `AccessContext`. An organization-scoped assignment is not
membership evidence, and a resolved access context is not proof that the
target resource belongs to that organization. The host must preserve the
target-to-scope binding through any cache and the final resource decision.

After exact selection, the host passes only the selected role names to
`AccessSubject.roles`. Assignment IDs, scopes, actors, and lifecycle metadata
never enter `AccessSubject` or `AccessContext`. Unknown role names remain
observable but grant no permission unless application policy explicitly maps
them.

## Lifecycle invariants

Hosts and future storage adapters must preserve these rules:

1. Generate a fresh opaque assignment ID for each grant. Do not encode,
   derive, sort, or authorize from an ID's contents.
2. Allow at most one active assignment for an exact
   `(principalId, role, scope)` tuple.
3. Treat recreation of the same assignment ID with identical immutable grant
   fields as idempotent. Reject the same ID with conflicting fields, and reject
   a different ID that would create a second active exact tuple.
4. Revoke conditionally by the expected exact assignment ID. Revocation is
   irreversible; an already revoked record never becomes active again.
5. Regranting the same principal, role, and scope creates a new assignment ID.
   A delayed revoke for the old ID must fail and must not affect the regrant.
6. Preserve original grant evidence after revocation. The storage package's
   append-only audit contract records the completed active and revoked states.
7. Generate lifecycle times on the trusted host. `grantedAtEpochMs` and
   `revokedAtEpochMs` are non-negative JavaScript safe integers, and
   `revokedAtEpochMs` must be greater than or equal to `grantedAtEpochMs`.
   Client clocks and provider event times are not authoritative lifecycle
   times.

The contracts contain no assignment-expiry semantics. Removing a role requires
explicit revocation. Role-derived authorization caches have a separate hard
60,000 millisecond absolute lifetime measured from before the authoritative
read, with a 5,000 millisecond invalidation-delivery target. See
[Fast role revocation and cache bounds](ROLE_REVOCATION.md).

## Administrator bootstrap

The first application administrator is created through a separate
out-of-band, operator-controlled host ceremony. It targets an independently
verified pre-existing exact host principal, uses explicit application scope,
and calls the safe combined audited grant on durable storage. Signup, login,
email, provider identifiers or roles, invitations, browser input, and
first-user rules never choose the target.

The host preserves one immutable retry manifest and arms a durable one-shot CAS
gate for its exact digest and deployment binding. Tuple uniqueness alone does
not prevent different principals from each receiving the administrator role,
and these ports cannot prove global first- or only-administrator exclusivity.
See [Administrator bootstrap](ADMINISTRATOR_BOOTSTRAP.md) for the normative
procedure, verification, credential removal, delegation, and break-glass
rules.

## Example

```ts
import type { RoleAssignment } from "@pegma/authorization-contracts";

const assignment: RoleAssignment = {
  id: "ra_01J5YQ4M7QJ3F6K9P2D8C1V0BX",
  principalId: "account_123",
  role: "support",
  scope: {
    kind: "organization",
    organizationId: "organization_alpha",
  },
  grantedBy: {
    kind: "principal",
    principalId: "account_admin",
  },
  grantedAtEpochMs: 1_700_000_000_000,
  status: "active",
};
```

The example ID format is illustrative only. Applications may use any
collision-resistant host-generated opaque string and must not depend on the
example prefix or length.

## Deliberate exclusions

This model does not add a parser, general runtime validator, identity mutation,
actor authorization, cache implementation, bootstrap endpoint or coordinator, role
hierarchy, role expiry, provider identifier, email field, or policy behavior.
It also does not change core resolution or add organization scope to access
subjects or contexts. The bootstrap guide composes existing public ports but
adds no runtime API. Its contract fixture and the in-memory adapter are
single-process and non-durable; neither is evidence of production bootstrap or
audit durability.
