# Authorization Core Project Plan

## Status

**Stage:** Phase 5 pre-release integration and release bootstrap complete;
first publication pending (Foundation and Phases 1–4 complete; Phase 5
documentation, API reference, runnable example, and verified package-release
path complete; `0.x`, public API unstable and unpublished)

**Initial reference application:** RetireGolden

**License:** MIT

**Naming:** This project was developed as EntitleKit under the `@entitlekit`
scope through Phase 3. On 2026-07-26 it moved into the Pegma component
ecosystem as Authorization Core, publishing under `@pegma`. The git history
begins at that move, and nothing was ever published under the former name.

**Storage:** `@pegma/authorization-storage` declares its collections against
`@pegma/storage-core`. The bespoke persistence layer and the
`@pegma/authorization-azure-tables` package that predated the shared storage
port were removed on 2026-07-26; a durable deployment now supplies a `Store`
rather than another adapter package here.

Authorization Core will begin as an embedded TypeScript library. A separately deployed
authorization service may be added after multiple applications need a shared
runtime, but it is not part of the initial scope.

## Vision

Authorization Core gives SaaS applications a small, auditable boundary between:

- identity providers that authenticate people;
- billing providers that describe purchases;
- application-owned staff or organizational roles; and
- APIs that must authorize specific actions.

An application should be able to change identity, billing, or storage providers
without rewriting its permission model. An open-source module such as a support
desk should be able to consume the same access contract without understanding
the host application's subscription plans.

## Problem statement

Modern SaaS products commonly assemble identity and billing from hosted
providers. Those providers expose different identifiers, lifecycle events, and
authorization features. Applications often respond by spreading checks such as
`plan === "pro"` or `role === "admin"` throughout route handlers and user
interfaces.

That approach creates several problems:

- commercial plans become coupled to individual features;
- staff roles and paid access are conflated;
- vendor-specific identifiers leak into otherwise reusable modules;
- permission behavior becomes difficult to audit and test;
- changing a provider requires changes across the application;
- browser-visible claims are accidentally treated as authoritative.

Authorization Core centralizes the translation from trusted facts to explicit
permissions while leaving identity verification, billing, and application data
ownership with the systems designed for them.

## Core model

### Principal

A principal is the stable, application-owned identifier for a person or service.
OIDC subjects, billing customer IDs, and email addresses are linked attributes,
not principal IDs.

### Role

A role represents an assigned responsibility, such as support agent or
administrator. Roles come from trusted application storage and map to explicit
permissions through policy.

### Entitlement

An entitlement represents a commercial or externally sourced grant, such as a
paid product feature. Billing adapters translate provider state into active
entitlements. The core does not interpret vendor subscription states.
Adapters are responsible for collapsing temporal billing states such as
trials, grace periods, and payment failures into a single active-or-absent
decision; the core deliberately has no expiry semantics.

### Permission

A permission names an application action, such as
`support.ticket.reply.any`. Application APIs authorize permissions rather than
roles, plans, prices, or providers.

### Policy

A policy is an application-owned, versioned mapping from roles and entitlements
to permissions. The first version is intentionally additive: matching grants
are combined, unknown names grant nothing, and there are no wildcards or
explicit deny rules.

A policy may also declare default permissions that every resolved principal
receives regardless of roles or entitlements. Defaults are an explicit grant
surface and require the same review as role and entitlement grants.

### Access context

An access context is the immutable result of resolving trusted principal facts
through one policy version:

```json
{
  "principalId": "f8ea9308-1bdb-49b0-89a9-eef2af28eb6b",
  "policyVersion": "2026-07-01",
  "roles": ["support"],
  "entitlements": ["plan.pro"],
  "permissions": [
    "account.read.own",
    "support.queue.read",
    "support.ticket.create",
    "support.ticket.reply.any"
  ]
}
```

Resource ownership and relationship checks remain the application's
responsibility. For example, `support.ticket.read.own` permits an application to
perform an ownership check; it does not prove that a particular ticket belongs
to the principal.

## Trust boundaries

```text
Untrusted or independently trusted systems
  OIDC tokens       Billing webhooks       Browser requests
       │                   │                       │
       ▼                   ▼                       │
 Provider verification and lifecycle handling     │
       │                   │                       │
       ▼                   ▼                       │
 Verified identity   Trusted billing state         │
       │                   │                       │
       ▼                   ▼                       │
 Identity port       Entitlement port              │
       │                   │                       │
       └────── host-owned facts ────┐              │
                                    ▼              │
 Application role store ─────> Authorization Core  │
                                    │              │
                                    ▼              │
                             Access context        │
                                    │              │
                                    ▼              ▼
                             Server authorization checks
```

Provider integrations establish trust before invoking the narrow adapter ports.
The identity port links verified, issuer-namespaced evidence to a host principal,
while the entitlement port translates trusted billing state into host
entitlement names. The core is a deterministic policy resolver and must not
fetch provider data or accept browser claims as authoritative.

## Scope

### In scope

- Provider-neutral TypeScript contracts
- Deterministic role and entitlement resolution
- Explicit access decisions
- Policy validation and versioning
- Adapter interfaces and conformance tests
- Auth0 identity integration
- Stripe entitlement integration
- Pluggable persistence for role assignments and audit records
- Optional short-lived signed access grants for service boundaries
- Documentation and reference integrations

### Non-goals for the initial releases

- Replacing an identity provider
- Processing payments
- A full Zanzibar-style relationship authorization engine
- A general-purpose policy language
- Frontend-only authorization
- Storing arbitrary user profiles
- Treating email as identity
- Shipping a hosted multi-tenant control plane
- Offline commercial licensing semantics

Offline product licenses may reuse Authorization Core contracts in the future, but their
longer validity and revocation model should not be mixed with online staff
authorization.

## Package architecture

The repository will stay a monorepo while the public contracts mature.

| Package                          | Responsibility                               | Earliest phase |
| -------------------------------- | -------------------------------------------- | -------------- |
| `@pegma/authorization-contracts` | Shared domain and adapter contracts          | Foundation     |
| `@pegma/authorization-core`      | Pure resolution and access decisions         | Foundation     |
| `@pegma/authorization-policy`    | Policy parsing, validation, and diagnostics  | Phase 1        |
| `@pegma/authorization-auth0`     | Verified Auth0 `iss`/`sub` to identity key   | Phase 2        |
| `@pegma/authorization-stripe`    | Stripe state to active entitlements          | Phase 2        |
| `@pegma/authorization-storage`   | Persistence ports over `@pegma/storage-core` | Phase 3        |
| `@pegma/authorization-tokens`    | Short-lived signed access grants and JWKS    | Phase 4        |

Packages should be created only when implementation begins. Empty adapter
packages make compatibility promises without supplying value.

Two further identity adapters are decided but deliberately unimplemented,
each with its own decision record and gates: `@pegma/authorization-entra`
([docs/ENTRA_ADAPTER.md](ENTRA_ADAPTER.md) — after Phase 5, on a real
consumer) and `@pegma/authorization-identity`
([docs/IDENTITY_ADAPTER.md](IDENTITY_ADAPTER.md) — after Phase 5 and after
`@pegma/identity` exists to emit claims). Both keep the auth0 package's
pure-projection shape; neither starts before its gates open.

Other providers should be implementable outside this repository by depending
on public contracts and running a published conformance suite.

## Delivery phases

### Foundation — repository and resolver

**Goal:** Establish project boundaries and make the smallest useful behavior
executable.

- [x] MIT license
- [x] TypeScript workspace
- [x] Provider-neutral contracts
- [x] Deterministic additive resolver
- [x] Explicit access decisions
- [x] Allow and deny tests
- [x] CI, dependency updates, and security scanning
- [x] Contribution and vulnerability-reporting guidance
- [x] Validate terminology and API shape in RetireGolden

**Exit criterion:** RetireGolden can model a test account with both a paid
entitlement and a staff role without adding product-specific behavior to the
core.

**Validation (2026-07-24):** The reference fixture maps RetireGolden's internal
account UUID to `principalId`; the provider subject remains a linked identifier,
not the principal. RetireGolden translates its already-resolved active tier to
an entitlement such as `plan.advisor` and supplies trusted staff roles
separately. Stripe lifecycle and price-ID mapping, the permission policy, and
the signed offline desktop-license contract remain RetireGolden-owned behavior.

### Phase 1 — policy hardening

**Goal:** Make configuration errors visible and policy evolution safe.

- [x] Define a versioned JSON-compatible policy schema, including the semantics
      of policy version strings that compatibility rules depend on.
- [x] Define the permission-name grammar, then validate empty names, duplicate
      grants, and malformed permission names against it.
- [x] Validate policy at startup so hosts fail closed at boot instead of relying
      on resolution-time errors.
- [x] Decide how diagnostics for unknown names are surfaced, then report unknown
      roles and entitlements without granting access.
- [x] Add stable JSON serialization for access contexts.
- [x] Add property-based tests for determinism and deny-by-default behavior.
- [x] Document broader permission naming and compatibility rules.

**Implemented boundary (2026-07-24):** `@pegma/authorization-policy` validates strict V1
JSON-compatible policy documents and returns a detached immutable policy or
structured diagnostics. Schema compatibility uses `schemaVersion`; the
application-owned `version` remains an opaque exact-match revision. Hosts can
call the throwing parser during startup to fail closed before the resolver is
reachable. Core's opt-in `resolveAccessWithDiagnostics` API reports canonical
unknown subject roles and entitlements alongside an unchanged access context.
These runtime diagnostics are frozen informational output: they do not grant
permissions, fail startup, or log automatically.
Property-based resolver tests now exercise deterministic canonical output,
equivalent input ordering, deny-by-default behavior, and prototype-sensitive
keys. Core's `serializeAccessContext` API emits a stable compact five-field
snapshot without reinterpreting the resolver's canonical arrays. Serialized
contexts are unauthenticated display or storage data, not authoritative client
input or signed access grants. The
[permission guide](PERMISSIONS.md) now separates parser-enforced syntax from
host-owned vocabulary, exact-match behavior, authorization boundaries, change
compatibility, and staged migrations.

**Exit criterion:** A host application can validate policy during startup and
fail closed on invalid configuration.

### Phase 2 — identity and billing adapters

**Goal:** Prove provider neutrality using real Auth0 and Stripe integration.

- [x] Define narrow identity and entitlement adapter ports.
- [x] Define the identity-linking model: how an issuer-namespaced subject resolves
      to a principal, whether a principal may hold multiple linked subjects, and
      what unlinking and account merging mean.
- [x] Add Auth0 issuer-and-subject translation without making Auth0 IDs
      principal IDs.
- [x] Add Stripe price/product-feature translation into active entitlements.
- [x] Require webhook-derived state to be persisted by the host.
- [x] Enforce a staleness bound on webhook-derived entitlement state through the
      adapter contract, with reconciliation guidance and contract tests, so a
      missed webhook cannot silently extend paid access.
- [x] Decide whether organization scope belongs in the core access context,
      using RetireGolden as the deciding case before the Phase 4 token profile
      is frozen.
- [x] Add contract tests using provider fixtures.
- [x] Keep provider SDK types out of core contracts.

**Implemented boundary (2026-07-25):** `@pegma/authorization-contracts` now exposes
generic async identity and entitlement ports. Adapter-owned identity evidence
resolves to a host-owned principal ID or `null`; a principal-keyed entitlement
request resolves currently active host entitlement names from trusted persisted
state. Provider SDK objects, provider status semantics, roles, and permissions
remain outside these narrow contracts. Identity keys are exact, case-sensitive
issuer-and-subject tuples:
each key links to zero or one host principal, and a principal may hold multiple
keys. Unlink removes one edge; a directional merge atomically transfers every
source edge to a surviving principal and retires the losing principal. The host
owns verification, authorization, auditing, conflict handling, related-data
migration, and session/cache invalidation for those lifecycle operations.
Runtime identity mutation APIs and persistence implementations remain deferred.
`@pegma/authorization-auth0` now performs one defensive post-verification projection:
own nonblank string `iss` and `sub` claims become a fresh frozen identity-link
key without normalization or fallback claims. It does not decode or verify
tokens, depend on an Auth0 SDK, resolve links, or return a principal. Hosts
retain verification and lookup ownership, including exact custom-domain issuer
configuration and the distinction between an absent link and an operational
failure.
`@pegma/authorization-stripe` now compiles a validated, detached host allowlist from
exact Stripe Entitlements Feature IDs and Price IDs into active host
entitlements. Each call selects authoritative feature mode or explicit price
fallback mode; the namespaces are never combined. Unknown valid IDs grant
nothing, malformed input throws without partial output, and successful output
is canonical and immutable. The package accepts no Stripe SDK or raw provider
objects and owns no webhook, lifecycle, customer-binding, persistence writer,
reconciliation scheduler, policy, role, or permission behavior.
The shared entitlement request is now principal-keyed. The official Stripe
adapter loads state through a host-supplied persistence reader once per
resolution, validates the returned principal binding, host-recorded
`refreshedAtEpochMs`, and fact shape, then applies the existing translator.
Construction requires a positive safe-integer maximum state age; state at the
exact bound is accepted, while the adapter rejects stale, future-dated,
malformed, and operationally unavailable state without a cache or
last-known-good fallback. This
contract is a semantic durability obligation: Authorization Core supplies no storage
backend, writer, webhook processing, or reconciliation scheduler. Hosts choose
and document the bound and advance the confirmation time only after a webhook
or reconciliation path successfully reconfirms complete Stripe state.
RetireGolden already reads its persisted account/Price-tier ledger, but this
does not claim a live Authorization Core integration.

**Organization-scope decision (2026-07-25):** Core `AccessSubject` and
`AccessContext` remain principal-only and unchanged. Organization membership
and active or requested organization scope are host-owned trusted facts. A host
with organizations derives scope from the exact authorization target,
validates membership, and selects the applicable role assignments for that
same scope before resolution. Because the access context carries no scope, the
host preserves that target-scope binding through cache lookup and the final
resource decision; it never applies permissions resolved for one organization
to a target in another. Server-side resource and relationship checks remain
authoritative: an access context is never proof of organization membership,
resource ownership, assignment, or another relationship. Tenant and
organization IDs are instance data and do not belong in permission names. A
Phase 4 subsequently kept organization confinement out of V1 entirely:
application-scoped grants cannot include permissions derived from
organization-scoped assignments. Any future confinement design remains a
separately versioned profile with explicit issuer and verification semantics;
it is not inherited from the core context.

The RetireGolden evidence supports that boundary without claiming a live
Authorization Core integration. Its current commercial model has one principal,
account, subscription, and seat. Advisor client plans remain local application
records, and there is no organization-membership model from which to derive a
reusable core scope contract.

**Provider-fixture contract boundary (2026-07-25):** A root-level contract test
now composes sanitized, dated Auth0 access-token-profile and organization-claim
fixtures through exact identity linking, a host-owned principal, fully paged
Stripe active-entitlement projection, host persistence, the Stripe adapter,
and core resolution. A separate Price fixture exercises explicit host-selected
fallback mode. The tests prove that provider subjects, permissions, roles,
organization claims, customer and entitlement identifiers, Feature and Price
identifiers, lookup keys, and raw provider objects do not enter the final
access context. They also deny unlinked identities and unmapped Stripe
identifiers, and distinguish complete reconciliation time from webhook event
time and the limited webhook summary. The fixtures are synthetic shapes
captured from official provider documentation, not SDK compatibility tests,
live API recordings, token verification tests, webhook processing, lifecycle
policy, durable storage, or evidence of a deployed RetireGolden integration.

**Exit criterion:** RetireGolden can replace direct plan checks with Authorization Core
permissions while retaining its existing Auth0 session and Stripe ledger.

### Phase 3 — role assignments, storage, and audit

**Goal:** Support application-owned staff roles safely.

- [x] Specify role assignment lifecycle, scope, grantor, and revocation fields.
- [x] Define storage ports for principal lookup, role assignment, and append-only
      audit events.
- [x] Provide an in-memory reference adapter.
- [x] Implement those ports once against `@pegma/storage-core`, so the backend
      is the host's choice.
- [x] Add an administrator bootstrap procedure that does not depend on signup
      claims.
- [x] Define fast role-revocation behavior and cache limits with concrete numeric
      bounds.

**Role-assignment model decision (2026-07-25):** The public contracts define an
opaque assignment ID, an exact principal and role, an explicit application or
exact-organization scope, and an explicit principal or system actor. Active and
revoked states form a discriminated immutable union; revocation preserves grant
evidence, is irreversible, and a regrant requires a new ID. Hosts permit one
active exact principal/role/scope tuple, revoke conditionally by exact ID, and
use non-negative safe-integer host timestamps with revocation no earlier than
grant. Scope is derived from the exact target and organization membership
remains host-owned. Assignment IDs, actors, scopes, and lifecycle metadata do
not enter `AccessSubject` or `AccessContext`; only exactly selected role names
do, and unknown roles remain deny-by-default. See
[the normative role-assignment model](ROLE_ASSIGNMENTS.md). General runtime
validation, durable persistence, cache behavior, and bootstrap were delivered
as separate Phase 3 slices.

**Fast role-revocation and cache-bound decision (2026-07-26):** Any
role-derived authorization cache has a hard 60,000 millisecond lifetime,
measured with trusted monotonic elapsed time immediately before the first
authoritative role read and preserved through every derived cache layer.
Entries are expired at the exact deadline. Hosts target invalidation delivery
within 5,000 milliseconds after a durable audited grant or revoke, while the
absolute deadline remains the safety bound when delivery is lost. Exact
structured keys bind application, principal, tagged scope, policy version, and
immutable policy content or deployment digest. The application namespace is
created inseparably with its authoritative reader and private storage
namespace, policy digests are recomputed from immutable snapshots, caller
inputs are snapshotted, returned records are immutable, and raw monotonic
deadlines never cross process clock domains. Exact opaque tokens bind facts to
one clock instance, and an anomaly permanently retires that shared domain
across caches and composed decisions. Final decision keys also bind permission
and every resource or relationship input. Composed facts require exact matching
application, principal, tagged scope, policy, and clock-domain identities.
Application-scope changes fan out across organization contexts, grants
invalidate denials, and per-key generations prevent pre-change reads from
publishing stale results. Expiry, read failure, partial or corrupt data,
invalid or regressing clock state, and generation changes fail closed with no
stale fallback. Composed authorization inherits the earliest input deadline. This
documentation-and-contract-test slice adds no runtime cache API, storage port,
provider behavior, or field to principal-only `AccessSubject` or
`AccessContext`. See
[Fast role revocation and cache bounds](ROLE_REVOCATION.md).

**Storage-port boundary (2026-07-25):** `@pegma/authorization-storage` is a types-first
package depending only on `@pegma/authorization-contracts`. It defines exact read-only
identity lookup compatible with `IdentityAdapter`, complete exact-principal and
mandatory exact-scope active role selection, exact-ID lifecycle reads with
opaque record-scoped concurrency tokens, atomic idempotent create, and
conditional irreversible exact-ID revoke. `null` and empty arrays mean
definitive absence; operational, partial, and corrupt reads reject. Identical
create replay never reactivates a revoked lifecycle, concurrent distinct IDs
for one active tuple are single-winner, and delayed old-ID revocation cannot
affect a fresh regrant.

The separate append-only audit port carries only complete granted and revoked
role-assignment states. It provides opaque event IDs, exact replay semantics,
and positive safe-integer sequence values ordered independently per assignment;
it makes no global gapless-order or tamper-evidence claim. One store instance or
namespace belongs to one host application. Shared backends bind the
application partition at construction, never from caller query input.

Role mutation and audit append remain separate low-level port calls and do not
guarantee an atomic audited operation.

**Storage-core boundary (2026-07-26):** `@pegma/authorization-storage` declares
three collections against a `@pegma/storage-core` `Store` and binds them to one
host application with `createRoleStore`. Assignment, tuple guard, and audit
positions share one partition per principal and scope, so each audited grant or
revoke settles in one single-partition transaction — the guarantee every
backend worth targeting actually offers. A separate immutable pointer
collection resolves an assignment ID to its partition, and a pointer that
resolves to nothing reads as definitive absence. Audit payloads are derived
from the assignment record rather than stored again, so history cannot disagree
with the lifecycle it describes.

The public factory surface exposes exact read-only identity, role, and audit
operations plus combined audited grant and revoke commands; it deliberately
does not expose the raw role or audit writes. Caller-selected exact audit event
IDs are the only audit input. Exact replay is idempotent, a revoked lifecycle
cannot be reactivated, and a refused transaction is re-read rather than trusted
to name which precondition it refused. Lifecycle timestamps are validated as
non-negative safe integers with revocation no earlier than grant, but this is
not a general runtime parser.

`listActiveRoleAssignments` is a non-snapshot read of the authoritative
assignment records: there is no derived selection index and therefore nothing
that can drift, but a partition listing that begins before a revocation may
still observe the assignment as active. The host's cache generation fence
([Fast role revocation and cache bounds](ROLE_REVOCATION.md)) is therefore
load-bearing rather than belt-and-braces — without it an in-flight read can
refill a cache after eviction.

`createInMemoryStorageAdapter` is that same implementation over the storage-core
memory store, so tests and examples exercise the production code path. It is
ephemeral, non-durable, single-process, and not a production audit store;
durability, restart recovery, and cross-process coordination are properties of
the `Store` a deployment supplies. This slice removed the bespoke persistence
layer and the Azure Table Storage package, and added no identity mutation,
organization membership, bootstrap, cache limit, provider, core, or policy
behavior. See [the storage guide](STORAGE.md).

**Administrator-bootstrap decision (2026-07-25):** Bootstrap is a short-lived,
out-of-band, operator-only host deployment ceremony, never a signup, login,
invitation, browser, first-user, or provider-role flow. An operator
independently verifies a pre-existing authoritative host principal and
preserves one access-controlled immutable application-scoped retry manifest
with fresh opaque assignment, grant-audit, and reserved failure-revoke audit
IDs, a host timestamp, trusted system actor, required permission, exact policy
version or digest, and exact deployment fingerprints.

The host supplies a durable one-shot CAS gate that is disabled by default and
armed for exactly the reviewed manifest digest and environment, storage, and
application binding. The coordinator calls only the combined audited grant on
durable production storage while holding one unique fenced `executing` claim.
Concurrent contenders cannot reach storage; stale-claim recovery first removes
old mutation authority and verifies quiescence. Exact retries reconcile the
same lifecycle. Definitive conflicts, revoked replay, and contradictory durable
readback consume the gate into non-authorizing `failure_cleanup_pending`;
indeterminate outcomes that might have committed retain the fenced claim for
exact reconciliation. Failure cleanup durably resumes exact grant
reconciliation or audited revocation under a separate fenced cleanup-only claim
that cannot grant or mutate another lifecycle, plus bootstrap-authority and
temporary-credential removal, and enters terminal `failed` only after all are
verified. Different manifests and other invalid inputs fail closed. Success
requires exact active assignment, sequence-one audit, active-selection, and
fresh authoritative principal and manifest-bound current-policy readback before
the gate durably enters `cleanup_pending`.
That state forbids further role mutation and idempotently resumes
bootstrap-authority and temporary-credential removal after crashes. The gate
becomes terminally `completed` only after cleanup is verified.

The current ports cannot prove zero other administrators or enforce global
first- or only-administrator exclusivity; tuple uniqueness is narrower. The host
must install the disabled gate or equivalent durable control before any
administrator-grant authority is ever enabled, then disable or apply the same
control to every other administrator-grant worker, job, tool, and API until
bootstrap is verified complete. An environment that cannot prove that history
uses a separately reviewed migration or recovery procedure. Later delegation is
normal authorized role management. Total administrator loss uses a separately
approved break-glass ceremony with fresh IDs and never re-arms bootstrap or
reactivates a revoked lifecycle. This slice adds normative documentation and a
test-local executable in-memory composition, not a public API, production
coordinator, gate, credential, or persistence change. See
[Administrator bootstrap](ADMINISTRATOR_BOOTSTRAP.md).

**Exit criterion:** RetireGolden can assign and revoke Support and Admin roles
with an auditable history.

### Phase 4 — service boundaries

**Goal:** Let independently deployed modules consume access safely.

- [x] Define a short-lived access-grant JWT profile.
- [x] Use an application-controlled signing key and published JWKS.
- [x] Require issuer, audience, expiration, exact policy version and digest,
      principal ID, token kind, profile version, effective permissions, and a
      unique one-use identifier.
- [x] Complete the V1 organization-confinement decision: omit organization
      claims and reject organization-scoped source authorization, leaving any
      confinement design to a separate future profile.
- [x] Document key rotation, replay prevention, and token revocation limits.
- [x] Add verification libraries and cross-language test vectors.
- [x] Keep browser sessions and offline commercial licenses outside this token
      profile.

**Implemented boundary (2026-07-26):** The normative
[Pegma access-grant profile V1](ACCESS_GRANTS.md) fixes a separated
`pegma-access-grant+jwt` kind, ES256, exact issuer and one-service audience,
exact provider-neutral host application identity, host principal, integer
issuance and expiry times, collision-resistant one-use ID, profile version,
exact accepted policy-version-and-digest pair, and a canonical nonempty
audience-allowlisted subset of effective permissions. Roles, entitlements,
provider facts, serialized access contexts, and organization claims are
excluded. V1 accepts only application-scoped source authorization; a future
organization-confinement profile would require authoritative target-derived
scope and exact verifier binding without replacing membership or resource
checks.

Issuance has a 30-second nominal maximum and reserves the verifier's complete
five-second maximum negative clock offset inside the source monotonic deadline,
with zero positive expiration leeway, so it shortens and never restarts the
existing 60-second role-authorization bound. Verification requires fixed
issuer-bound HTTPS JWKS configuration, strict header/claim/key shapes, exact
policy-pair allowlisting, a replace-only public-key cache no older than 60
seconds, terminal monotonic-regression guards, bounded issuer-scoped unknown-key
refresh, and atomic one-time consumption keyed by
`(iss, application_id, aud, jti)`.

`@pegma/authorization-tokens` implements the profile with `jose` ES256 compact
signing and verification, opaque issuer-local source read and binding
capabilities, strict duplicate-aware JSON and canonical compact parsing,
public-only JWKS projection and complete set validation, fixed-origin
single-flight key caching shared weakly across verifier instances, and
verify-then-consume sequencing. Exact issuer/application/`jti` reservations
and service replay records use the separate declared
`authorization_access_grant_jti_reservations` and
`authorization_access_grant_replays` collections through host-supplied
`@pegma/storage-core` `Store` instances; Authorization Core adds no persistence
backend. A committed public-key-only vector exercises the exact
compact token and JWKS across implementations without repository private key
material.

The reference-store tests prove package-level sequencing and concurrent
one-winner behavior, not a production backend's multi-process durability,
atomicity, retention, access control, or independent clock accuracy. Those
remain deployment obligations covered by storage-core adapter conformance and
operations.

**Exit criterion:** A support module can verify a narrowly scoped access grant
without querying Auth0 or Stripe.

### Phase 5 — reference administration

**Goal:** Demonstrate a complete integration without turning the core into a
hosted product.

- Publish the first public `0.x` packages, together with the documentation
  deliverables listed below, so external integrations can depend on them.
- Publish an example API with `/access/me` and permission middleware.
- Add a minimal role-assignment administration example.
- Add structured decision and audit logging examples.
- Document multi-application and multi-organization scoping.
- Publish migration guidance from ad hoc role and plan checks.

**Pre-release integration boundary (2026-07-27):** The repository now contains a
clean-clone runnable Node reference API composed only through public package
entry points. It demonstrates post-verification Auth0 projection and exact
host identity linking, fresh principal-keyed Stripe state, authoritative
target-derived organization selection, explicit application and exact-scope
role reads, policy resolution, display-only `/access/me`, reusable allow and
deny middleware, combined audited role grant/revoke administration, safe
structured decision and audit logs, runtime-generated P-256 signing, public
JWKS, application-scoped grant issuance, protected-module
`verifyAndConsume`, and replay denial.

The provider inputs and memory stores are prominently non-production. The
example does not implement Auth0 verification, Stripe webhook processing,
durable persistence, production key custody, or a hosted service. Production
verifiers still require a fixed HTTPS JWKS endpoint; only the in-process demo
and tests use the public tokens testing subpath for injected JWKS. V1 continues
to reject organization-scoped grant sources.

Dedicated [getting-started](GETTING_STARTED.md),
[adapter-authoring](ADAPTER_AUTHORING.md), [migration](MIGRATION.md),
[scoping](SCOPING.md), and [integration security](SECURITY_MODEL.md) guides
cross-link the existing normative documents. A deterministic committed
[public API reference](api/README.md) is generated from exactly the seven
package entry points plus `@pegma/authorization-tokens/testing`; normal
verification rejects drift. No package has been published, versioned, tagged,
or released by this slice, so the publication item and Phase 5 exit criterion
remain pending.

**Release-bootstrap boundary (2026-07-27):** The repository now validates the
exact seven-package inventory, common version, internal dependency versions,
public metadata, lockfile, exports, package contents, and release tag before
publication. CI packs each package once and installs the resulting tarballs in
an isolated consumer under Node 22 and 24. The release workflow accepts stable
GitHub releases only, checks out the exact tag, requires its commit to be on
`origin/main`, prepares one contracts-first tarball set with a recorded commit
and integrity manifest, and publishes through the protected `npm-publish`
environment using pinned npm and OIDC provenance. A retry skips an immutable
registry version only when its integrity is byte-for-byte identical to the
prepared tarball; a different version payload fails closed.

Because npm cannot configure trusted publishing before a package exists, the
documented one-time ceremony publishes the reviewed `0.0.0` tarballs manually
under the non-default `bootstrap` dist-tag, then configures trusted publishing
for all seven packages. A later reviewed `0.1.0` version change and stable
GitHub release is the first advertised release and the first publication
through OIDC. This bootstrap slice does not publish a package, change a
version, create a tag, or create a release, so Phase 5 remains pending. See
[Release operations](RELEASING.md).

**Exit criterion:** A new SaaS project can integrate identity, billing, staff
roles, and one protected module using only public documentation.

### Phase 6 — ecosystem and stable release

**Goal:** Stabilize contracts after multiple real consumers.

- Integrate RetireGolden's support system as the second production consumer.
- Invite at least one non-RetireGolden adapter or application integration.
- Publish adapter conformance tests.
- Complete an external security review or focused authorization audit.
- Document semantic-versioning and deprecation policy.
- Add signing and provenance to the npm release process.
- Release `1.0.0` only after the contracts survive multiple consumers.

## RetireGolden integration sequence

RetireGolden should adopt Authorization Core incrementally:

1. Translate the existing internal account UUID into `principalId`.
2. Translate current Pro and Advisor subscription state into entitlements.
3. Define a RetireGolden-owned permission policy.
4. Add application-owned Support and Admin role assignments.
5. Replace route-specific plan and role checks with permission checks.
6. Expose a server-resolved access context to authenticated account surfaces,
   treating it as display-only data that may be filtered where permission
   names would reveal staffing or unreleased features.
7. Build the support system against permissions rather than RetireGolden plans.

RetireGolden policy, Stripe price IDs, support priorities, and offline desktop
license behavior remain in the RetireGolden repositories.

## Security requirements

Every release must preserve these invariants:

1. Unknown input never grants a permission beyond the policy's declared
   defaults.
2. Authorization occurs on a trusted server boundary.
3. A provider subject is namespaced by issuer before linking.
4. Email is never used as an authentication or authorization key.
5. Billing webhook authenticity is established outside the core.
6. Role assignment is an audited privileged operation.
7. Cached staff permissions expire quickly enough for practical revocation.
8. Persisted entitlement state has an enforced staleness bound so billing
   cancellation takes effect predictably.
9. Token audiences prevent grants from being replayed across services.
10. Private signing material never enters packages, logs, or examples.
11. Permission-granting changes include matching deny tests.

Before `1.0`, the project should publish a focused threat model covering
identity linking, webhook replay, confused-deputy behavior, stale grants,
administrator bootstrap, and signing-key compromise.

## Compatibility and release strategy

- Packages publish under the `@pegma` npm organization, registered on
  2026-07-26. Nothing is published until the Phase 5 release.
- All packages begin at `0.x`; breaking changes may occur with clear release
  notes.
- Packages in this repository release together until their contracts stabilize.
- Public contracts must not expose Auth0, Stripe, Azure, or RetireGolden SDK
  types.
- Permission strings belong to the host application and are not globally
  standardized by Authorization Core.
- New resolver behavior must be deterministic for identical subject and policy
  input.
- A `1.0` release requires at least two real consumers and an adapter
  conformance suite.

## Documentation deliverables

Before the first public package release, a Phase 5 deliverable:

- [Getting-started guide](GETTING_STARTED.md)
- Policy reference
- [Permission naming guide](PERMISSIONS.md)
- Auth0 and Stripe integration guides
- [Adapter authoring guide](ADAPTER_AUTHORING.md)
- [Security model](SECURITY_MODEL.md)
- [Migration guide from direct role and plan checks](MIGRATION.md)
- [Application and organization scoping guide](SCOPING.md)
- [API reference generated from source](api/README.md)
- [Complete runnable example](../examples/reference-api/README.md)

## Open questions

These decisions should be driven by real integrations rather than resolved
speculatively:

- Whether policy needs explicit deny rules
- Whether hierarchical roles provide enough value to justify their risk
- When a standalone access service becomes operationally worthwhile

## Near-term backlog

1. Perform the documented one-time `0.0.0` non-default bootstrap publication
   from the reviewed tarballs, configure npm trusted publishing for all seven
   packages, and verify registry integrity.
2. Review the synchronized `0.1.0` version and release notes, then create the
   first stable GitHub release so OIDC publishes the first advertised package
   set with provenance.

The backlog should stay small until the first integration reveals which
abstractions are genuinely reusable.
