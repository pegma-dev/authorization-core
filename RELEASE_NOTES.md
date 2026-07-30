# Authorization Core 0.4.0

Authorization Core 0.4.0 first advertises `@pegma/authorization-admin`, the
tenth package: the HTTP-neutral audited role-administration service both
reference hosts previously duplicated (design and contract in
`docs/ADMINISTRATION.md`).

The service owns the grants view with an explicit management policy
(ongoing system actors lock; declared one-time actors stay human-managed),
audited assign with the holder-index write-before-grant discipline, audited
revoke with the last-administrator guard — in-process serialization, typed
refusal, post-commit re-verification, and an honest compensation outcome,
with exact-scope holder matching so an organization-scoped administrator
never masks the loss of the last application-scoped one — per-principal
lifecycle history over `listRoleAssignments`, and `ensureSeededAssignment`,
the once-per-principal-and-role seed whose already-seeded signal is
lifecycle history and whose conflicts fail closed. Hosts keep the HTTP
envelope, UI, principal lookup, rate limiting, and the authorization of the
service's own callers.

The version advances to `0.4.0` because the workspace gains a public
package; there are no behavioral changes to the nine existing packages. The
root, all ten public package manifests, every exact internal Authorization
dependency, and the lockfile advance together to `0.4.0`. All ten packages
require Node.js 22 or newer and remain MIT licensed.

# Authorization Core 0.3.0

Authorization Core 0.3.0 delivers the storage surface additions from the first
reference-consumer feedback cycle (issues #23 and #24, filed from the
retiregolden.org integration), together with documentation for the
webhook-ledger Stripe composition (issue #25).

`@pegma/authorization-storage` gains two public operations:

- `IdentityLinkStore.linkIdentity` is the previously missing public write path
  for durable identity links. It atomically claims one exact, case-sensitive
  issuer-and-subject tuple for one host principal: the first write is
  `linked`, an identical replay is `unchanged`, and a claimed tuple written
  with a different principal is a fail-closed `conflict` that leaves the
  existing edge untouched. Concurrent writes for one free tuple settle on
  exactly one winner, and successful results read back the stored link.
- `RoleAssignmentReader.listRoleAssignments(principalId, scope)` returns the
  complete lifecycle history for one exact principal and scope — active and
  revoked assignments alike, with grant and revocation evidence intact —
  ordered by grant time and then assignment ID.

Documentation gains the translator-plus-host-lifecycle composition as the
first-class `@pegma/authorization-stripe` path for webhook-maintained ledgers,
including the fail-closed pipeline-health bound and per-object event
supersession that composition obligates, plus the superset-with-verification
index recipe for by-role selection and last-administrator guards and the
write-ahead audit protocol for identity-link writes.

The version advances to `0.3.0` (rather than a patch) because
`RoleAssignmentReader` gains a required method: hosts that implement the
storage ports themselves must add `listRoleAssignments`, which is a breaking
port change under `0.x` semver. Hosts that only consume the provided adapters
are unaffected; there are no behavioral changes to any existing operation.

The root, all nine public package manifests, every exact internal Authorization
dependency, and the lockfile advance together to `0.3.0`. All nine packages
require Node.js 22 or newer and remain MIT licensed.
