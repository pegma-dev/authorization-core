# Security Policy

Authorization software sits on a sensitive trust boundary. Please report
suspected vulnerabilities privately.

## Reporting a vulnerability

Use
[GitHub private vulnerability reporting](https://github.com/pegma-dev/authorization-core/security/advisories/new).
Do not open a public issue.

Include, when possible:

- the affected package and version or commit;
- the expected and observed authorization behavior;
- a minimal reproduction;
- the potential impact;
- any suggested mitigation.

We will acknowledge a complete report as soon as practical, investigate it, and
coordinate remediation and disclosure with the reporter. Please avoid accessing
data that is not yours or disrupting production systems while researching a
report.

## Supported versions

Authorization Core is currently pre-release software. Until the first stable release,
only the latest commit on the default branch is supported.

## Security expectations

Applications integrating Authorization Core remain responsible for:

- verifying identity-provider tokens and sessions;
- resolving identity only by an exact issuer-and-subject tuple, never by email
  or a bare subject;
- validating billing-provider webhook signatures;
- ordering and deduplicating billing events before updating state;
- binding billing customers to the correct host principal and validating
  host-owned Price-ID and Feature-ID configuration;
- applying provider status and lifecycle policy before declaring facts active;
- persisting webhook-derived state, reconciling it against the provider
  (including full pagination when using Product Features), choosing and
  documenting a positive numeric freshness bound, and advancing the persisted
  provider-confirmation time only after successful confirmation;
- loading roles and entitlements from trusted server-side storage;
- using only combined audited role mutations unless a durable backend provides
  an equivalent transaction or transactional outbox;
- keeping administrator bootstrap out of signup, login, invitations, provider
  roles, and browser routes; independently verifying one pre-existing exact
  host principal; and using an access-controlled immutable retry manifest;
- protecting a durable, disabled-by-default, one-shot bootstrap CAS gate bound
  to the reviewed manifest digest and exact environment, storage, and
  application fingerprints;
- loading organization membership and active or requested organization scope
  as trusted host facts, deriving that scope from the exact authorization
  target, then selecting only the role assignments applicable to that same
  scope;
- performing authorization on the server;
- enforcing authoritative organization, ownership, assignment, and other
  resource relationships independently of an access context, while preserving
  the exact target-scope binding through any cache and the final decision;
- enforcing the documented 60,000 millisecond absolute read-start lifetime for
  role-derived cached authorization, targeting invalidation delivery within
  5,000 milliseconds, and fencing stale in-flight fills;
- when issuing signed access grants, preserving the source monotonic
  deadline, applying exact issuer/audience/policy allowlists, trusting keys only
  from the issuer-bound HTTPS JWKS endpoint, and atomically consuming each
  `(iss, application_id, aud, jti)` once;
- protecting signing keys and service credentials.

Authorization Core does not make browser-provided roles or entitlements trustworthy.
`@pegma/authorization-auth0` is a post-verification claims projection, not a token
decoder or verifier. Never pass it decoded-but-unverified JWT payloads or
browser-supplied claims.
Linking, unlinking, and merging identities are privileged host operations.
Hosts must authorize and audit them, fail closed on conflicts or operational
errors, and invalidate affected sessions and caches before changed identity
links can be trusted.

`@pegma/authorization-stripe` is an exact allowlist projection, not a webhook verifier,
Stripe client, billing ledger, or lifecycle engine. Pass only already-trusted
active Stripe Entitlements Feature IDs, or explicitly select the separate Price
ID fallback mode. Never pass raw Stripe objects, browser claims, customer IDs,
statuses, provider timestamps, webhook payloads, or untrusted configuration
into the translator facts. Unknown IDs grant nothing; malformed or proxied
inputs throw before producing output. Proxied containers are rejected before
reflective validation so their traps cannot fabricate trusted fields. The
package does not log rejected identifiers.

The official Stripe `EntitlementAdapter` accepts only an exact host
`principalId` request. It reloads persisted state once per resolution, rejects
missing or corrupt state and principal mismatches, and enforces its required
positive safe-integer maximum age against the record's host-generated
`refreshedAtEpochMs`. State at the exact bound is accepted; the adapter rejects
stale, future-dated, or malformed timestamps. The adapter does not cache or
return a last-known-good result after staleness or an operational failure. Hosts
must provide genuinely durable trusted state; implementing the loader over an
in-memory object does not satisfy that production obligation. Reads, ordinary
rewrites, and cache fills must not advance `refreshedAtEpochMs`. Passing webhook
payloads or other transient active facts directly at request time bypasses the
supported adapter boundary.

Core `AccessSubject` and `AccessContext` values remain principal-only. An
`AccessContext` proves neither organization membership nor ownership of or
access to a specific resource, even when its permissions came from
host-selected scoped role assignments. Hosts must not trust a
browser-selected organization or encode organization or tenant IDs into
permission strings as a substitute for server-side membership and resource
checks. A host must derive scope from the exact authorization target and must
not apply a context resolved from scoped roles for one organization to a target
in another; because the core context carries no scope, that binding remains
host-owned and must be enforced through cache lookup and the final decision.
Role-derived cache keys additionally bind the exact application namespace,
principal, tagged scope, policy version, and immutable policy content or
deployment digest. Final decision caches also bind the permission and every
resource or relationship input. Hosts snapshot these inputs before asynchronous
work, recompute and verify policy digests, construct application readers
together with their private storage namespaces, keep cache records immutable,
and never transfer raw monotonic deadlines across process clock domains. Exact
opaque domain tokens prevent same-name clock substitution. A clock anomaly
permanently retires that shared domain across caches and composed decisions.
Composed facts require identical application, principal,
scope, policy, and clock-domain identities. Expired, failed, partial, corrupt,
invalid or regressing-clock, or generation-invalidated reads fail closed
without stale fallback. See
[Fast role revocation and cache bounds](docs/ROLE_REVOCATION.md).

The Phase 4
[Pegma access-grant V1 profile](docs/ACCESS_GRANTS.md) carries only effective
permissions. It excludes roles, entitlements, provider identities, serialized
access contexts, and organization claims. A V1 issuer accepts only
application-scoped source authorization and rejects permissions derived from
organization-scoped role assignments. Any future organization-confinement
profile must receive scope from authoritative target-derived host facts,
require exact comparison with the verifier's target, and preserve current
membership and resource checks; core access contexts do not supply or imply
that confinement.

V1 access grants are bearer credentials before first consumption. A
collision-resistant `jti` is not sufficient by itself: after signature, claim,
policy, audience, and lifetime verification, the service must atomically
consume the exact `(iss, application_id, aud, jti)` tuple and retain it through
`exp` plus the maximum negative verifier offset, before any protected action.
Concurrent use has one winner, and replay-store outage, ambiguous write, or
corruption fails closed. The signed `application_id` is a provider-neutral
exact host application identity and must match immutable verifier
configuration. Issuance reserves that complete five-second negative offset
inside the original monotonic authorization deadline and never restarts that
deadline; verification rejects at `exp` with zero positive expiration leeway.
The issuer accepts only an opaque host-created source capability from its exact
guarded clock domain; clock regression permanently fails that domain.
Verifiers accept only ES256 public keys from their fixed issuer-bound HTTPS
JWKS URL, replace rather than union refreshed key sets, share one issuer-scoped
in-flight refresh, and rate-limit unknown-`kid` refreshes with bounded
issuer-wide negative-miss state. Their cache clock guard compares every sample
with the last observed sample and fails terminally on regression. They never
use token `jku`, `jwk`, or `x5u` input.
Ordinary role, entitlement, or policy changes cannot recall an unconsumed
grant; expiry, one-use consumption, and bounded JWKS refresh are the documented
limits. Private signing material must remain host-controlled and absent from
packages, browsers, logs, examples, and JWKS.

`@pegma/authorization-tokens` accepts the signing key only as a host-owned
private `CryptoKey`, projects only public P-256 coordinates into JWKS, and uses
`jose` with an ES256-only allowlist. Its strict parser rejects duplicate or
unknown JSON members and noncanonical compact segments before key lookup. The
verifier exposes no verify-only path: a successful return means the exact
replay tuple was inserted atomically into the declared
`authorization_access_grant_replays` collection. The package never constructs
a storage backend.

Identifier generation uses the process CSPRNG, then atomically reserves every
exact `(iss, application_id, jti)` in the separate declared
`authorization_access_grant_jti_reservations` collection before signing.
Reservations are retained indefinitely, so non-reuse remains exact across
issuer instances, concurrency, and process restarts that share the host's
durable `Store`. Reservation outage, ambiguity, conflict, or corrupt results
deny issuance. Hosts must still preserve CSPRNG quality and never substitute a
deterministic random source outside tests.

The `@pegma/authorization-storage` in-memory adapter is a reference implementation for
tests, examples, and contract evaluation. Its identity links are read-only
construction seeds, and its public surface omits raw role and audit write
methods so a role mutation and its derived audit event settle together. It is
ephemeral, single-process, non-durable, and unsuitable as a production role or
audit store. Do not infer cross-process transaction safety, restart recovery,
retention, tamper evidence, or durable audit completeness from its behavior.

`createRoleStore` is durable only when the `@pegma/storage-core` `Store` behind
it is, with the deployment's intended durability, access control, backup,
retention, and monitoring. One store instance binds one exact application ID,
and an assignment, its active-tuple guard, and its derived audit position
intentionally share one partition so they commit in one transaction. Do not
shard those records across partitions or collections, read from a
non-authoritative replica, or expose raw writes around the store; each change
weakens or removes the documented atomicity and freshness properties. Treat
backend credentials and identity-link record creation as privileged host
administration.

Administrator bootstrap is privileged host deployment administration, not an
identity or storage inference. The coordinator may call only
`grantRoleAssignmentWithAudit` on durable production storage, retries an
ambiguous outcome with the exact same manifest and IDs, and declares success
only after exact active assignment, sequence-one audit, active-selection, and
policy-permission readback. The host must compare independently observed
environment, storage, and application bindings with the manifest before
mutation, and the exact manifest role's own policy mapping must directly
contain the required permission at the manifest-bound policy version or digest;
policy defaults or unrelated roles do not satisfy bootstrap verification.
Immediately before consuming execution, the host revalidates the authoritative
principal and freshly reloads that exact policy version. Conflicts, revoked
`unchanged` results,
operational errors, disabled or unknown gate state, and any manifest or
deployment-binding mismatch fail closed before completion. A definitive
storage conflict or contradictory durable readback consumes the gate into
non-authorizing `failure_cleanup_pending`; only an indeterminate outcome that
might have committed retains its unique fenced `executing` claim for exact
reconciliation. Concurrent coordinators cannot share a claim or reach storage;
expired-claim recovery first fences old authority and verifies quiescence.
Failure cleanup uses a separate fenced cleanup-only claim that cannot grant or
mutate any other lifecycle. It idempotently reconciles and, when necessary,
revokes the exact committed grant, then removes bootstrap authority and
temporary credentials. The gate becomes terminally `failed` only after all
three results are verified. After successful verification, the host durably
enters `cleanup_pending`, where role mutation is forbidden and
bootstrap-authority removal plus temporary-credential rotation is idempotently
resumable. The gate becomes terminally `completed` only after cleanup is
verified.

Role tuple uniqueness cannot prove that no other principal holds an
administrator role. Existing Authorization Core ports cannot enforce global first- or
only-administrator exclusivity. The host-owned durable one-shot gate supplies
that deployment invariant only when the disabled gate or equivalent durable
control existed before any administrator-grant authority was ever enabled, and
every worker, job, tool, and API remains disabled or governed by that control
until bootstrap reaches verified completion. A deployment that cannot prove
that history must use a separately reviewed migration or recovery procedure,
not claim first-administrator bootstrap. Later delegation uses normal
authorized role management; loss of every administrator requires a separately
approved break-glass ceremony with fresh IDs and never re-arms bootstrap. See
the [administrator-bootstrap guide](docs/ADMINISTRATOR_BOOTSTRAP.md).
