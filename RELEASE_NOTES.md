# Authorization Core 0.1.3

Authorization Core 0.1.3 resolves the findings of the 2026-07-29 security
review. There are no public API or type changes; every change either refuses
input that should always have been refused, or bounds work that was previously
unbounded.

The one substantive fix is in `@pegma/authorization-storage`. An audited grant
wrote its assignment-ID pointer and discarded the result, so the port's
documented unique-assignment-ID guarantee was not actually enforced: the tuple
guard is per principal-and-scope partition and cannot see an ID already spent in
another partition. Reusing one assignment ID across two principals therefore
committed a second active assignment that `getRoleAssignment` and
`revokeRoleAssignmentWithAudit` could not reach, because both resolve an ID
through its first pointer only — an active grant that could not be revoked by
its own ID. `grantRoleAssignmentWithAudit` now inspects the insert result and
returns `conflict("assignment_id")` when an existing pointer's application,
principal, scope, or role differs from the grant being attempted. A pointer is
durable even when the grant that wrote it was refused, so an assignment ID is
single-use across failed attempts as well; retrying a refused grant unchanged
still succeeds.

This release also:

- bounds the production JWKS fetcher in `@pegma/authorization-tokens` with a
  5 second deadline and a 64 KiB streamed response cap, so a hung or oversized
  endpoint can no longer stall every verifier sharing that cache;
- rejects a compact access grant larger than 8 KiB before any segment split,
  base64url decode, or strict-JSON walk, and holds the issuer to the same bound
  so it cannot mint a grant its own verifier would refuse for size;
- documents at the port exactly what an unchanged grant replay attests to; and
- caps the request body the reference example reads, answering an oversized
  administrative command with 413 rather than buffering it.

Three review findings were disputed rather than fixed, because each proposed
change would have removed a deliberate, tested guarantee without closing a
demonstrated exploit path: arbitrary-identifier safety at the storage lifecycle
boundary, verbatim preservation of third-party claims in the Auth0 adapter, and
the published test-construction subpath. `docs/securityscan.md` records the
reasoning for each.

The root, all eight public package manifests, every exact internal Authorization
dependency, and the lockfile advance together to `0.1.3`. All eight packages
require Node.js 22 or newer and remain MIT licensed.
