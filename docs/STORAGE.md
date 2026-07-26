# Storage ports

`@pegma/authorization-storage` defines provider-neutral persistence boundaries for exact
identity lookup, immutable role-assignment lifecycle records, and append-only
role lifecycle audit events. It also provides an isolated in-memory reference
adapter for tests, examples, and contract evaluation. It does not provide a
durable database, general runtime parsing, identity mutation, or mutation actor
authorization.

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
- The port does not create, unlink, transfer, or merge identity links.

Provider identifiers remain lookup keys only. They never become principal IDs
or enter `AccessSubject` or `AccessContext`.

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

## In-memory reference adapter

`createInMemoryStorageAdapter` creates one closure-backed application namespace.
It implements exact principal lookup, role reads, audit reads, and combined
audited grants and revocations. Its returned object deliberately has no
`createRoleAssignment`, raw `revokeRoleAssignment` signature, or
`appendRoleAssignmentAuditEvent` capability outside the combined command
contract.

Optional `identityLinks` are copied at construction and remain read-only.
Issuer and subject comparisons are exact and case-sensitive. Nested maps keep
delimiter, NUL, and prototype-sensitive strings distinct. Identical seed
duplicates are idempotent; one exact key mapped to different principals rejects
construction.

Each mutation snapshots public input synchronously, prepares copy-on-write
state, and publishes it with one synchronous in-process commit. It enforces:

- one active exact principal, role, and scope tuple;
- immutable assignment IDs and irreversible revocation;
- one matching grant event for active records and one grant plus one revoke
  event for revoked records;
- no audit event without its assignment;
- opaque per-version concurrency tokens and positive per-assignment sequences;
- exact grant replay and revoke replay with its original pre-revocation token,
  without consuming counters;
- event-ID and lifecycle-position conflict rollback; and
- non-negative safe-integer lifecycle times with revocation no earlier than
  grant.

Every returned object, nested assignment, scope, actor, event, history, and list
is a fresh detached recursively frozen snapshot. Two factory instances are
isolated and may reuse every literal ID.

These properties prove synchronous linearization within one JavaScript adapter
instance, including calls started together with `Promise.all`. They do not
prove a cross-process transaction. The adapter is ephemeral, non-durable,
single-process, and unsuitable for production authorization or audit
retention. Restart recovery, cross-process coordination, tamper evidence, and
durable audit completeness require a real backend.

## Azure Table Storage adapter

`@pegma/authorization-azure-tables` implements the same safe surface over a
host-provisioned Azure `TableClient`: exact principal lookup, assignment and
audit reads, and combined audited grant and revoke. The factory deliberately
omits the raw role and audit mutation ports.

One adapter instance binds one exact host application ID. Every row for that
application shares one Table Storage partition so assignment state,
active-tuple uniqueness, the active-selection index, its per-principal/scope
selection fence and active count, the derived audit event, and application-wide
event-ID uniqueness can settle in one entity-group transaction. Splitting
those rows across partitions or tables is not conforming.

Opaque application and record values are length-framed as exact UTF-16 code
units and SHA-256 hashed into fixed Azure-safe keys. Rows retain the exact
unhashed values and schema kind. Reads recompute every binding and reject
collisions, wrong-application rows, malformed records, missing guards, orphan
indexes, and incomplete histories.

The Azure assignment ETag is the public record-scoped concurrency token. A
revoke compares the caller token exactly, rejects the wildcard token, and uses
the stored ETag on conditional `Replace` actions. Because the JavaScript SDK
does not carry a delete ETag inside a transaction, revoke conditionally
replaces the active-tuple guard with a retained tombstone. A later fresh-ID
regrant conditionally replaces that tombstone. The active-selection row is
deleted in the same transaction whose assignment and tuple writes are
ETag-conditional. Grant and revoke also conditionally advance the selection
fence and increment or decrement its exact active count.

Query methods consume every continuation page and validate the authoritative
assignment, tuple guard, grant audit, and event guard behind every active
selection. The selection count must equal the stable fence count. Because
Azure does not provide one snapshot across pages, the adapter compares the
fence ETag before and after enumeration and retries a bounded number of times;
continued churn rejects. It never returns a last-known-good, partial, or
mixed-generation result after an error. Hosts should keep active role counts
small. Caches around this complete read follow the absolute deadline, exact
binding, invalidation, and stale-fill rules in
[Fast role revocation and cache bounds](ROLE_REVOCATION.md).

See [the Azure deployment guide](AZURE_TABLES.md) for provisioning, primary
endpoint, throughput, testing, retention, and operational requirements.

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

The storage contracts and bundled adapters do not add general runtime parsers,
identity-link mutation, organization membership, mutation actor authorization,
a bootstrap endpoint, durable one-shot gate, or bootstrap coordinator, cache
limits, generic audit payloads, audit search or retention, audit signing, a
cross-application control plane, or changes to core, policy, Auth0, Stripe, or
provider contracts. The in-memory implementation stays inside
`@pegma/authorization-storage`; the durable Azure implementation is the separate
`@pegma/authorization-azure-tables` package. Neither is a published external conformance
suite.
