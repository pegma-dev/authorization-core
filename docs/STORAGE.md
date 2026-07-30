# Storage ports

`@pegma/authorization-storage` defines provider-neutral persistence boundaries for exact
identity lookup, immutable role-assignment lifecycle records, and append-only
role lifecycle audit events. It implements them once, against a
[`@pegma/storage-core`](https://github.com/pegma-dev/storage-core) `Store`, so
the backend is the host's choice rather than this package's. It does not
provide a durable database, general runtime parsing, identity mutation, or
mutation actor authorization.

## Application partition

One store instance or namespace belongs to exactly one host application. A
backend shared by multiple applications must bind the application partition
when constructing each store instance. Application identity is intentionally
not a query parameter: callers cannot select or override another application's
partition during an authorization lookup or mutation.

This boundary supports embedded application storage. It is not a
cross-application control plane and does not define global identity, role, or
audit queries.

## Principal lookup

`PrincipalLookupStore` is structurally compatible with `IdentityAdapter`. It
resolves one exact, case-sensitive `IdentityLinkKey` issuer-and-subject tuple to
a host-owned `PrincipalId` or `null`.

- `null` means the exact link is definitively absent.
- Operational failures, incomplete reads, and corrupt records reject.
- Issuers and subjects are not normalized or concatenated into an ambiguous
  delimiter-separated key.
- The lookup surface does not create, unlink, transfer, or merge identity
  links; durable creation is the separate write below.

Provider identifiers remain lookup keys only. They never become principal IDs
or enter `AccessSubject` or `AccessContext`.

## Identity link writes

`IdentityLinkStore.linkIdentity` is the public write path for durable identity
links. It atomically claims one exact, case-sensitive issuer-and-subject tuple
for one host principal:

- `linked`: the tuple was free and now links to the written principal;
- `unchanged`: the exact tuple already links to the same principal — a safe
  replay; or
- `conflict` with reason `principal`: the tuple already links to a different
  principal. Each tuple links to at most one principal, while one principal may
  hold many tuples.

Successful results return the stored link, so a caller always reads back what
is actually persisted. Concurrent writes for one free tuple settle on exactly
one winner; the losers observe `conflict`.

There is deliberately no unlink, relink, or transfer operation. Moving a tuple
between principals is a host administrative decision with provider-specific
evidence requirements, outside this port. A host whose subject-to-principal
mapping already lives in its own account records may keep implementing the
`IdentityAdapter` port over that store instead of persisting a second copy;
`linkIdentity` exists so hosts without such a mapping can adopt the durable
link store entirely through the public surface.

## Role assignment reads

`RoleAssignmentStore.getRoleAssignment` reads one exact assignment ID and
returns its lifecycle record together with an opaque, record-scoped concurrency
token. `null` means the exact ID is definitively absent.

`listActiveRoleAssignments` requires both a principal ID and one explicit
`RoleAssignmentScope`. It returns the complete active set for that exact pair.
An empty array means definitive emptiness. The implementation rejects rather
than returning a partial, stale-on-error, or corrupt result.

Application and organization scopes are never implicit. A host that needs both
application-wide and one exact organization's roles performs two explicit
queries after deriving the organization from the authorization target and
validating membership. Organization A and organization B remain distinct.

Revoked assignments are excluded from active queries but retained by exact ID
with all original grant evidence.

`listRoleAssignments` takes the same exact principal-and-scope pair and returns
the complete lifecycle history: every assignment the principal has ever held in
that scope, active and revoked alike, each with its grant and — where revoked —
revocation evidence intact. Records are ordered by `grantedAtEpochMs` ascending
and then by assignment ID code-unit order, so a
grant-revoke-regrant sequence for one role reads in lifecycle order under new
IDs. An empty array means definitive emptiness, and the same rejection rules
apply. Like the active selection, it is a non-snapshot read of the
authoritative records.

### By-role selection across principals

Neither listing crosses principals. Records are partitioned by principal and
scope so both listings are one-partition reads, which means "every active
holder of role R" has no partition to read and no supported query. A host that
needs it — a role-administration panel, or a last-administrator guard refusing
to revoke the final active `Admin` — must maintain a secondary index, and the
index must fail in the safe direction:

1. Write the index entry **before** the audited grant, so the index can only
   over-report, never under-report. A grant refused after its index entry was
   written leaves a harmless superset row.
2. Never delete index entries on revocation; history is part of the point.
3. Verify every index candidate against the authoritative store before acting
   on it.

Under those rules an over-full index can only make a guard refuse — fail
closed. The check itself is still a non-snapshot read: a guard that verifies
"another active holder exists" and then revokes can race a concurrent
revocation of that other holder. A host enforcing an at-least-one invariant
must re-verify after its own revocation commits and compensate — regrant under
a fresh assignment ID — when the invariant was lost. Whether this index becomes
a library-maintained structure is tracked as Phase 6 integration feedback.

## Atomic create

`createRoleAssignment` is one atomic storage operation. It enforces both:

1. one immutable lifecycle per exact assignment ID; and
2. at most one active exact `(principalId, role, scope)` tuple.

The result statuses are:

- `created`: a new active lifecycle was created;
- `unchanged`: the exact assignment ID already contains identical grant
  evidence; or
- `conflict`: either `assignment_id` has different grant evidence or
  `active_tuple` is already active under a different ID.

An identical create against a revoked stored lifecycle is `unchanged`. It never
reactivates the record. Regranting requires a fresh assignment ID.

Implementations must make concurrent distinct-ID attempts for the same active
tuple single-winner. A check followed by an unprotected insert is not
conforming.

## Conditional revoke

`revokeRoleAssignment` targets one exact assignment ID and supplies:

- the expected opaque concurrency token for that record;
- `revokedBy`;
- `revokedAtEpochMs`; and
- an optional administrative reason.

A successful revocation preserves every grant field, adds immutable revocation
evidence, and advances the concurrency token. Replaying the exact completed
revocation is `unchanged`, including when the caller still holds the
pre-revocation token. A different operation against a revoked lifecycle returns
the `lifecycle` conflict. An active record with a stale token returns the
`concurrency` conflict, and an absent exact ID returns `not_found`.

The command never identifies a record by principal, role, or scope. A delayed
command for an old revoked assignment cannot revoke a fresh regrant under a new
ID. Tokens are opaque and record-scoped: do not parse, compare, order, or reuse
them across records.

## Append-only lifecycle audit

`RoleAssignmentAuditStore` accepts only two event variants:

- `granted`, carrying the complete `ActiveRoleAssignment`; and
- `revoked`, carrying the complete `RevokedRoleAssignment`.

Each event has an opaque host-selected ID. The store assigns a positive
safe-integer sequence independently for each assignment. Per-assignment listing
is complete and strictly increasing by that sequence. Exact replay of the same
event ID and content is `unchanged`. Reusing an ID for different content
returns `event_id`; an impossible or duplicate position in the
grant-then-revoke lifecycle returns `lifecycle_position`.

This contract has no update or delete operation. It also makes no claim of a
global gapless sequence, cross-assignment order, generic payload support,
search, retention, signing, hashing, or tamper evidence. Deployments that need
those properties add them behind or alongside this narrow port.

## Atomicity boundary

Role mutation and audit append are deliberately separate calls. Calling
`createRoleAssignment` or `revokeRoleAssignment` and then calling
`appendRoleAssignmentAuditEvent` does **not** guarantee an atomic audited
operation. The role write can succeed while the audit append fails, or vice
versa if a caller orders the operations incorrectly.

The safe `AuditedRoleAssignmentMutationStore` boundary closes this composition
gap by accepting a role command and exact host-selected `auditEventId` together.
Audit payloads are derived internally from the stored lifecycle evidence and
cannot be caller supplied. Role-side conflicts take precedence over audit-side
conflicts. A conforming implementation settles the role state and derived event
together or leaves assignment state, tokens, history, event IDs, and sequences
unchanged.

The combined methods are `grantRoleAssignmentWithAudit` and
`revokeRoleAssignmentWithAudit`. Their explicit names distinguish them from the
raw low-level writes and make accidental non-audited composition visible in
review.

Durable production adapters must implement that combined boundary with one
storage transaction, a transactional outbox, or an equivalently durable
design. Hosts must not claim that composing the raw ports alone produces
complete audit history.

## Record layout

`createRoleStore(store, applicationId)` binds three declared collections to one
`Store` and one host application.

`authorization_records` holds everything about one principal in one exact
scope. Its partition is `applicationId|principalId|scopeTag`, and it carries
three kinds of record distinguished by a `kind` field and by their record ID:

- `assignment|<assignmentId>` is the authoritative lifecycle record. It holds
  the complete grant evidence, any revocation evidence, and the caller-selected
  grant and revoke audit event IDs.
- `tuple|<role>` is the uniqueness guard for one exact
  `(principalId, role, scope)` tuple. It holds the assignment currently
  occupying the tuple, or `null` once that assignment is revoked. Retiring
  rather than deleting is deliberate: a transaction offers no
  version-conditional delete, so a tombstone is how a conditional removal is
  expressed.
- `audit|<assignmentId>|0001` and `|0002` are the two positions in an
  assignment's history. Each holds only its sequence and event ID; the event
  payload is derived from the assignment record, so history cannot disagree
  with the lifecycle it describes.

All three share one partition, so an audited grant or revoke is one `transact`
call. That single-partition limit is not an implementation detail leaking out:
it is the guarantee every backend worth targeting actually offers.

`authorization_assignment_pointers` maps an exact assignment ID to the
partition its records live in, because assignment reads are by ID while records
are partitioned by principal and scope. A pointer is immutable — an
assignment's location is fixed at grant and an ID is never reused — so it is
written with `insertIfAbsent` before the grant transaction rather than inside
it. A pointer that resolves to nothing reads as absence, which the port already
treats as definitive.

`authorization_identity_links` maps one exact issuer-and-subject tuple to a
principal. Issuer and subject are stored raw as well as encoded into the record
ID, so a reader confirms the exact case-sensitive tuple rather than trusting
that two distinct tuples did not encode alike. `linkIdentity` claims a tuple
with `insertIfAbsent`, which is what makes concurrent writes for one free tuple
settle on exactly one winner.

Every key segment escapes `%`, `|`, `/`, `\`, `#`, `?`, and control characters
as `%XX`. Escaping rather than hashing keeps keys readable and, more
importantly, keeps the mapping injective: two distinct roles can never collide
onto one record, which under this layout would be an authorization fault rather
than a storage one.

## Conflict decisions

Grant reads the tuple guard, then the assignment record, then commits.

- A guard held by a different assignment ID is `active_tuple`.
- An existing assignment record with the same grant event ID is `unchanged`,
  including when that record is already revoked. Replay never reactivates.
- An existing assignment record with a different grant event ID is `event_id`.
- A refused transaction is re-read rather than trusted to name its failed
  action: an assignment ID taken by a different grant is `assignment_id`, a
  taken tuple is `active_tuple`, and a competing identical grant is `unchanged`.

Revoke resolves the pointer, reads the assignment, and commits three
conditional writes together.

- No pointer, or no assignment record behind it, is `not_found`.
- An already-revoked record whose revoke event ID and revocation evidence match
  exactly is `unchanged`; any other operation against it is `lifecycle`.
- A record version other than `expectedConcurrencyToken`, or a version that
  moved before the transaction landed, is `concurrency`.
- Revocation earlier than its own grant is `lifecycle`.

Concurrency tokens are the `Store`'s record versions. They are opaque and
record-scoped: do not parse, compare, order, or reuse them across records.

Two conflict reasons the port declares are not produced by this
implementation. `lifecycle_position` cannot arise, because history positions are
derived from the assignment record instead of being appended independently.
`event_id` on grant means the exact assignment ID already carries a different
grant event, not that the ID was used anywhere else: there is no
application-wide event-ID index, because maintaining one would need a second
partition and would therefore leave the transaction boundary.

## Non-snapshot reads

`listActiveRoleAssignments` and `listRoleAssignments` are each one partition
read of the authoritative assignment records. There is no derived selection
index and no fence to compare, so there is nothing that can drift from the
records or that would need reconciling; but a partition listing is not a
snapshot, and a read that begins before a revocation may still observe the
assignment as active.

The host's cache generation fence is therefore load-bearing rather than
belt-and-braces. A fill must capture all applicable generations before its
first role read and publish only if they are unchanged after the complete read,
exactly as [Fast role revocation and cache bounds](ROLE_REVOCATION.md) requires.
Without it, an in-flight read that started before a revocation can refill a
cache after eviction. Caches around this read also follow the absolute
deadline, exact binding, invalidation, and stale-fill rules in that guide.

## In-memory reference adapter

`createInMemoryStorageAdapter` is `createRoleStore` over the storage-core
in-process memory store, bound to one application namespace. It implements
exact principal lookup, identity link writes, role reads, audit reads, and
combined audited grants and revocations. Its returned object deliberately has
no
`createRoleAssignment`, raw `revokeRoleAssignment` signature, or
`appendRoleAssignmentAuditEvent` capability outside the combined command
contract.

Because it is the same implementation, it enforces the same key, transaction,
and optimistic-concurrency rules a durable backend does: one active exact
principal, role, and scope tuple; immutable assignment IDs and irreversible
revocation; no audit position without its assignment; and non-negative
safe-integer lifecycle times with revocation no earlier than grant. Records
returned to callers are decoded fresh from storage and frozen, so no caller
holds a reference into stored state.

Optional `identityLinks` are copied before construction returns and remain
read-only, so a caller mutating its own array afterwards cannot change what the
instance resolves. Issuer and subject comparisons are exact and case-sensitive,
and delimiter, NUL, and prototype-sensitive strings stay distinct. Identical
seed duplicates are idempotent; one exact key mapped to different principals
rejects construction.

The memory store is ephemeral, non-durable, and single-process. It is
unsuitable for production authorization or audit retention: restart recovery,
cross-process coordination, tamper evidence, and durable audit completeness
require a real backend behind the same `Store` interface.

## Administrator bootstrap composition

The storage ports are building blocks for the host's one-time administrator
bootstrap; they do not identify the target or coordinate the ceremony. A
conforming host independently verifies one pre-existing principal, preserves
one immutable application-scoped manifest, and calls only
`grantRoleAssignmentWithAudit` on durable production storage. It verifies the
exact active lifecycle, sequence-one audit, exact-principal/application active
selection, and policy permissions before completing bootstrap.

The host must separately provide a durable, disabled-by-default one-shot CAS
gate armed for the exact reviewed manifest digest and environment, storage, and
application binding. Active-tuple uniqueness cannot prevent different
principals from each receiving an administrator role. No current query can
prove zero administrators or global first- or only-administrator exclusivity.
Those are host operational invariants, not promises of these ports.

The in-memory adapter is used by the repository's executable bootstrap contract
test only. It must never be used for production bootstrap. See
[Administrator bootstrap](ADMINISTRATOR_BOOTSTRAP.md).

## Authorization boundary

Storage returns trusted lifecycle records to server-side host code. The host:

1. derives the exact target scope and validates any organization membership;
2. loads complete active assignments for the principal and exact scope;
3. projects only application-owned role names into `AccessSubject.roles`; and
4. keeps assignment IDs, provider keys, actors, scope, concurrency tokens,
   audit IDs, sequences, and lifecycle times outside `AccessSubject` and
   `AccessContext`.

Unknown role names remain deny-by-default because permissions exist only when
the host policy explicitly maps a role. Storage records and audit events are
not permission grants by themselves.

## Deliberate exclusions

The storage contracts and this implementation do not add general runtime
parsers, identity-link mutation, organization membership, mutation actor
authorization, a bootstrap endpoint, durable one-shot gate, or bootstrap
coordinator, cache limits, generic audit payloads, audit search or retention,
audit signing, a cross-application control plane, or changes to core, policy,
Auth0, Stripe, or provider contracts. Backends are not implemented here either:
a durable deployment supplies a `@pegma/storage-core` `Store` and this package
declares its collections against it. This is not a published external
conformance suite.

See [Scoping](SCOPING.md) for application binding and exact organization
selection, and the [integration security model](SECURITY_MODEL.md) for
production obligations.
