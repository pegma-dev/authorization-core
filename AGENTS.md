# Working in this repository

Read this before changing anything. It is short on purpose.

## What this is part of

Authorization Core is one component of **Pegma**, a family of MIT-licensed
packages that a host application composes: identity and permissions here,
persistence in `@pegma/storage-core`, shared contracts in `@pegma/spine`, a
support desk and other components to follow. They publish under the `@pegma`
scope, one repository per component.

The governing principle, which every rule below follows from:

> **Optimize for a fresh agent context window.** How much must be read to make
> a correct change, and how does the change prove itself correct? Minimize the
> first, mechanize the second.

That is why contracts are typed and narrow, why conformance suites exist, why
wiring is explicit rather than discovered, and why the code is deliberately
ordinary. Novel structure is harder for both people and models to read.

## Hard rules

**Never build persistence in this repository.** Declare collections against
`@pegma/storage-core` and take a `Store` from the host. This repo already grew
its own storage layer and an Azure adapter once; both were deleted on
2026-07-26 and replaced by declared collections. If storage cannot express
something you need, that is a gap to fix in `storage-core` with conformance
cases, not to work around here. The same applies to anything a sibling package
already owns.

**Do not create a package before its implementation begins.** An empty adapter
package makes a compatibility promise while supplying nothing.

**Keep public contracts provider-neutral.** No Auth0, Stripe, Azure, or
RetireGolden types in `@pegma/authorization-contracts`. Providers are adapters.

**Do not weaken a documented guarantee to make an implementation easier.**
Regrant, ABA-safety, append-only audit, and one active assignment per
principal/role/scope are load-bearing. A design that quietly breaks one is
wrong even when it is smaller. If a guarantee genuinely should change, change
the documentation deliberately and say so in the pull request.

**Never write literal control characters into source.** Write them as escape
sequences such as backslash-u-0000 through backslash-u-001F in regular
expressions, and verify the bytes after any tool-assisted edit. Tooling has
silently turned those escapes into actual control characters more than once in
this codebase, producing a regex that reads correctly and matches the wrong
thing.

## Workflow

Work on a `claude/*` branch and open a pull request; `main` is protected by CI.
The gate is `npm run format:check`, `npm run check`, `npm test` — all three must
pass, and CI runs them on Node 22 and 24.

Publishing is trusted-publisher only: no tokens exist. A release starts with a
protected signed annotated `vX.Y.Z` tag, followed by
`gh release create vX.Y.Z --verify-tag`; this runs the same gate and publishes
the synchronized workspace package set with provenance attestations. A
brand-new package cannot use trusted publishing for its first version. Follow
`docs/RELEASING.md`: publish the exact prepared `0.0.0` tarballs once under the
non-default `bootstrap` dist-tag, configure every package's trusted publisher,
then make the next synchronized `0.1.x` version its first advertised OIDC
release.

The one-time `0.0.0` package-name bootstrap is published under the non-default
`bootstrap` dist-tag, and trusted publishing is configured. The signed
`v0.1.0` GitHub release published all seven `0.1.0` packages through OIDC with
provenance on 2026-07-27.

`@pegma/authorization-identity` is the eighth package. Its signed
`authorization-identity-v0.0.0` source tag targets merged commit
`afdf3f168d355629b2721512c246c1a18fd54c9d`; complete its package-only name
reservation and trusted-publisher setup before creating the synchronized
`v0.1.1` release that first advertises it.

## Where things stand

Foundation and Phases 1 through 5 are complete, including signed access grants,
the reference integration, public documentation, and the first advertised
release. Phase 6 is integration feedback and contract stabilization; do not
expand the shared API speculatively.

Three things about the storage migration are worth knowing before you touch the
lifecycle code, all deliberate:

- An unchanged revoke replay no longer verifies the pre-revocation concurrency
  token. Storage versions are opaque and the previous one is not retained, so
  it matches on event id and revocation evidence. The port docstring still
  describes the older rule.
- `lifecycle_position` and application-wide `event_id` conflict reasons are
  unreachable. Audit positions derive from the assignment record, and an
  application-wide event index would need a second partition and would leave
  the transaction boundary.
- `listActiveRoleAssignments` is a non-snapshot read of the authoritative
  records. The host cache generation fence in `docs/ROLE_REVOCATION.md` is
  therefore load-bearing rather than an extra safeguard.

## Reading order

`docs/PROJECT_PLAN.md` is the source of truth for scope, phases, and decisions
already made. Then the document for whatever you are touching:
`docs/POLICY.md`, `docs/ROLE_ASSIGNMENTS.md`, `docs/ROLE_REVOCATION.md`,
`docs/STORAGE.md`, `docs/AUTH0.md`, `docs/STRIPE.md`,
`docs/ADMINISTRATOR_BOOTSTRAP.md`.

Siblings: [storage-core](https://github.com/pegma-dev/storage-core),
[spine](https://github.com/pegma-dev/spine), and the organization profile at
[github.com/pegma-dev](https://github.com/pegma-dev).
