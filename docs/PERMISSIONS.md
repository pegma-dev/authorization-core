# Permission naming and compatibility

Permissions are application-owned names for actions that server-side code may
authorize. Authorization Core validates permission syntax and performs exact membership
checks, but it does not assign global meaning to any segment.

This guide covers application-level vocabulary and safe evolution. The
[policy guide](POLICY.md#permission-names) is the normative reference for the
V1 parser's grammar and length limits.

## Trust boundary

Authorize permissions, not identity-provider claims, billing product names,
prices, roles, or entitlements. A trusted host translates verified identity,
billing state, and application-owned role assignments into an access subject;
Authorization Core then resolves that subject through application-owned policy.

Permission checks belong on the trusted server. Browser-provided permissions,
roles, entitlements, and serialized access contexts are never authoritative.

The V1 permission grammar is enforced by `@pegma/authorization-policy` when a host
validates its policy. `PermissionName` is a TypeScript string alias, not a
validated or branded runtime value, and Core does not revalidate the full
grammar on every permission check. Hosts should load policy through
`parsePolicy` or `validatePolicy` at startup rather than constructing an
unchecked `AccessPolicy`.

## Recommended vocabulary

Prefer names that read from a stable application domain toward a concrete
action:

```text
[domain.]resource.action[.qualifier]
```

Examples:

```text
account.read.own
support.queue.read
support.ticket.reply.any
billing.invoice.download.own
```

This layout is a convention, not an additional parser rule. Single-segment
permissions and other valid segment counts remain syntactically legal.
Applications own the vocabulary and may choose a different consistent layout.

Use stable application concepts:

- name the resource and action the API actually protects;
- use a domain prefix when it prevents collisions between modules;
- keep action words consistent, such as `read`, `create`, `update`, `delete`,
  `reply`, or `manage`;
- add a qualifier only when server code gives it a precise meaning;
- mint a new name when the protected capability changes materially.

Do not encode provider subjects, email addresses, tenant or organization IDs,
principal IDs, Stripe price IDs, environment names, or other instance data in
a permission. Do not use a plan or role as the action, such as `plan.pro` or
`role.admin`. Plans and purchases belong in entitlements; staff responsibility
belongs in roles.

Permission names can appear in diagnostics, logs, and access-context snapshots.
Treat them as non-secret identifiers, but avoid names that reveal customer
data, credentials, or unnecessary details about unreleased features.

## Exact-name behavior

Permission matching is exact and case-sensitive. Authorization Core does not provide:

- wildcard or prefix grants;
- hierarchical inheritance between dot-separated segments;
- aliases or automatic rename handling;
- normalization of case, separators, or Unicode;
- implicit parent permissions;
- explicit deny rules.

For example, `support.ticket.read.any` does not imply
`support.ticket.read.own`, and `support.ticket.*` is not a valid V1 permission.
A syntactically valid typo is a different host-owned permission; there is no
global registry that can infer the intended name.

Resolution is additive. Defaults and every exactly matched role or entitlement
grant are combined, deduplicated, and sorted. Unknown role or entitlement names
grant nothing beyond declared defaults. Role and entitlement identifiers are
opaque, exact, case-sensitive host values in independent namespaces; they do
not use the permission-name grammar.

## Qualifiers and resource checks

Qualifiers such as `own` and `any` are useful only when the host defines and
enforces them consistently.

`support.ticket.read.own` can establish that a principal may attempt to read an
owned ticket. It does not establish that a particular ticket is owned by that
principal. The host must still load the resource and check its ownership,
organization, assignment, or other relationship before returning it.

Core `AccessSubject` and `AccessContext` values are intentionally
principal-only and do not model tenant or organization scope. Organization
membership and active or requested organization scope are trusted host facts.
For an organization-targeted operation, the host must first load or identify
the exact authorization target, derive its organization scope, validate the
principal's membership in that scope, and select only role assignments
applicable to that same scope before resolution. The host must carry the
target-scope binding outside the principal-only access context through the
final decision. Any cached result must be keyed by that exact scope and must
not be reused for another organization.

Role-derived caches also bind the host application namespace, exact principal,
policy version, and immutable policy content or deployment digest. They expire
at the 60,000 millisecond absolute deadline measured from before the first
authoritative role read; cache layers in the same monotonic clock domain never
restart that deadline. A cached final decision additionally binds its exact
permission and every resource, relationship, and target-version input. See
[Fast role revocation and cache bounds](ROLE_REVOCATION.md).

Never combine permissions resolved from scoped roles for organization A with a
separate membership or resource check for organization B. Do not encode a
specific tenant or organization into a permission name as a substitute for
target-bound role selection or for a resource or relationship check.

An `AccessContext` is never proof of organization membership, resource
ownership, assignment, or another relationship. The server remains
authoritative: it must load the requested resource and enforce those
relationships before returning or mutating it.

The Phase 4 V1 signed access-grant profile has no organization-confinement
claim and cannot use permissions derived from organization-scoped role
assignments. Any future confinement design requires a separately versioned
profile with authoritative target-derived issuer facts and exact verifier
binding; it is not inherited from, supplied by, or implied by the core access
context.

## Compatibility of permission and policy changes

Classify a change by its authorization effect, not by whether the JSON remains
valid.

| Change                                                      | Compatibility effect                                                               | Required handling                                                                                                                                                        |
| ----------------------------------------------------------- | ---------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| Define a new name in application code or documentation      | Inert until policy grants it and server code checks it                             | Define its semantics before use; add allow and deny tests when it becomes active                                                                                         |
| Add a permission to a role or entitlement                   | Potentially access-expanding for principals with that fact                         | Check for overlap with existing sources, review the trusted source of the fact, change the policy revision, and add allow and deny tests                                 |
| Add or broaden a default                                    | Access-expanding for principals that do not already receive the permission         | Treat as the highest-risk grant change because defaults apply regardless of matched facts; change the policy revision and test unknown and minimally privileged subjects |
| Remove a grant                                              | Potentially access-narrowing when no other matched source grants the permission    | Check effective overlap, coordinate dependent services, change the policy revision, and test the intended denial                                                         |
| Rename a permission                                         | Breaking remove-plus-add operation                                                 | Use a staged dual-name migration; Authorization Core has no aliases                                                                                                      |
| Reinterpret an existing permission                          | Breaking even when the string is unchanged                                         | Mint a new permission and migrate explicitly                                                                                                                             |
| Rename a role or entitlement                                | Old subject facts become unknown and grant only defaults or other matching sources | Update the trusted producer and policy in a coordinated rollout; monitor unknown-name diagnostics                                                                        |
| Move a grant between a role and an entitlement              | Changes the trust and business boundary even if current output looks equal         | Review as an authorization change and update tests and the policy revision                                                                                               |
| Reorder maps or grant lists                                 | No resolver-output change                                                          | No compatibility action beyond normal validation                                                                                                                         |
| Grant the same permission from multiple independent sources | Allowed and deduplicated                                                           | Keep each source intentional; removing one source may leave access through another                                                                                       |

The V1 parser rejects a duplicate permission within one grant list. The same
permission may appear in defaults and in multiple role or entitlement lists.
Core also deduplicates resolved output. A host that bypasses policy validation
does not receive the parser's duplicate-list guarantee.

## Safe permission rename

Authorization Core does not negotiate permission versions or resolve aliases. Rename a
permission with an overlap period:

1. Add the new permission to every applicable grant list while retaining the
   old permission.
2. Deploy the updated policy to every context producer. Invalidate cached
   contexts from the prior revision, or keep the next step compatible until
   their maximum lifetime has elapsed.
3. Deploy server consumers with a narrow temporary check that accepts either
   the old or new permission whenever stale contexts can still arrive. A host
   that has invalidated every old context may switch directly to the new name.
4. Confirm that every supported producer emits the new permission and no
   supported consumer requires the old permission.
5. Remove the old permission from policy.
6. Remove the temporary consumer fallback after no old context remains valid.

Use a distinct policy revision token for each stage that changes grants.
Independently deployed services must coordinate the rollout themselves; an
access context does not automatically reject a stale policy revision.

If a transition temporarily checks either name, keep that compatibility logic
narrow and remove it after migration. Do not introduce a permanent wildcard,
prefix match, or generic alias layer.

## Three separate versions

Authorization Core uses separate version concepts:

- `schemaVersion` identifies the serialized policy shape. V1 accepts only the
  number `1` and fails closed on other shapes or unknown fields.
- Policy `version` is an opaque, case-sensitive host revision token preserved
  as `AccessContext.policyVersion`. Change it whenever permission-granting
  behavior changes. It has no semantic-version, date, ordering, negotiation,
  cache-invalidation, or stale-context enforcement behavior.
- Package versions describe the npm APIs. They do not order policy revisions or
  alter a policy document's schema.

The packages remain unpublished `0.x` software, so public API stability and a
formal deprecation policy are not promised yet. Hosts should still make
permission vocabulary changes explicit and staged because application data and
independently deployed consumers can outlive a package upgrade.

## Change checklist

Before shipping a permission change:

1. Confirm that policy is validated once on the trusted server startup path.
2. Describe the action and any qualifier in application terms.
3. Verify that identity, billing, role, and resource-ownership checks remain at
   their correct host boundaries.
4. Classify whether the change expands, narrows, renames, or reinterprets
   access.
5. Add matching allow and deny tests for every permission-granting change.
6. Assign a new opaque policy revision token when grant behavior changes.
7. Coordinate producers and consumers when a name or trusted fact changes.
8. Monitor unknown role and entitlement diagnostics during migrations.
9. Review whether returned snapshots or logs should filter role and permission
   names.

Keep permission names boring, exact, and stable. Their value is that an
application can audit one explicit action without depending on which identity
provider, billing product, or staff-role implementation produced it.

See [Scoping](SCOPING.md) for multi-application and target-derived organization
selection, [Migration](MIGRATION.md) for replacing direct checks, and the
[integration security model](SECURITY_MODEL.md) for deployment review.
