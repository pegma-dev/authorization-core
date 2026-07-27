# Fast role revocation and cache bounds

Role assignments are online authorization facts. A host may cache selected
roles, resolved access contexts, or access decisions, but every layer must
preserve the same bounded lifetime and exact authorization binding described
here. Authorization Core does not add a cache API: these are host integration
requirements around the existing storage and resolver contracts.

## Numeric guarantees

The hard maximum lifetime of any role-derived authorization snapshot is
**60,000 milliseconds**. A snapshot is usable only while:

```text
monotonicNow < authoritativeReadStartedAt + 60,000
```

It is expired at exactly 60,000 milliseconds. The trusted server samples
`authoritativeReadStartedAt` from an elapsed monotonic clock immediately before
starting the first authoritative role read. Read time consumes the budget.
Cache hits, policy resolution, and downstream caches in the same monotonic
clock domain preserve the original deadline; none may restart or extend it.
Raw monotonic timestamps and deadlines are process-local values. They are never
serialized, persisted, or compared in another process or after a restart.
Every bounded fact also carries an opaque in-process clock-domain token, and
consumers require exact token identity rather than trusting a repeatable string
label. A new clock object with the same display name is still a different
domain.
Cross-process consumers must perform a new authoritative read. A host may
instead define a transfer protocol only if it cryptographically binds the
snapshot, accounts for transit and queue time, never increases the source's
remaining lifetime, and rejects replay; otherwise it fails closed.

Hosts should deliver role-change invalidations to every online authorization
node within **5,000 milliseconds** of the durable audited mutation completing.
That target makes revocation operationally fast, but it is an accelerator, not
the safety bound. Lost, delayed, duplicated, or reordered invalidations must
never extend a snapshot past its 60,000 millisecond absolute deadline.

These limits bound when a new authorization decision must reload role state.
They do not promise to undo work already authorized, terminate authentication
sessions, or revoke future signed grants. Long-running requests, streams, and
background work must reauthorize before the remaining deadline is exhausted.

## Exact cache identity

Every role-derived cache entry must bind, as structured exact fields:

- the host application namespace;
- the exact host-owned `principalId`;
- an explicitly tagged application scope or one exact organization scope;
- the exact policy version; and
- an immutable policy content or deployment digest.

The application namespace is an immutable property of the authoritative
role-assignment reader and its storage namespace. The cache accepts that
inseparable application-bound reader rather than accepting an independent
application label at construction or lookup. A trusted application-storage
factory creates the reader and its private storage namespace together and
exposes only the resulting immutable application identity; it never pairs a
caller-supplied label with a pre-existing reader. Decorators preserve that
identity, and any expected-application assertion rejects a mismatch. The policy
digest is always required even when policy versions are intended to be unique, because rollback
and deployment mistakes must not alias different content. The host snapshots
the policy, deterministically recomputes its digest, and rejects a claimed
digest that does not match before cache lookup, resolution, composition, or
publication. It snapshots every other key input before the first asynchronous
operation, then uses only those immutable snapshots through lookup, resolution,
and publication. Returned entries and deadline metadata are immutable and
cannot expose a mutable internal cache record. Do not construct ambiguous
delimiter-concatenated keys. Browser-selected scope, provider subjects, email
addresses, assignment IDs, billing identifiers, and provider event times are
not cache identities.

The fields above identify cached role selections and resolved access contexts.
If a host caches a final `AccessDecision`, its key additionally binds the exact
permission or action and every resource, ownership, membership, relationship,
and target-version input used by that decision. If those inputs cannot be
represented as immutable exact identities, the host does not cache the final
decision.

For an organization target, the host derives and verifies the organization
from authoritative application data, loads application-wide and that exact
organization's active roles, and preserves the target-to-scope binding through
the final resource check. A principal-only `AccessContext` is never scope
evidence.

## Invalidation and concurrency

The durable audited storage commit completes the grant or revocation. Event
publication and cache eviction happen afterward and cannot roll back or
regrant the lifecycle.

After a definitive audited revoke result of `revoked` or the exact completed
`unchanged` replay, the host invalidates all affected role selections, access
contexts, and cached decisions. An application-scoped change invalidates every
organization-context variant for that application and principal. An
organization-scoped change invalidates that exact organization binding.
Successful grants apply the same rule so cached denials do not hide new access.

Invalidation is by the affected principal and scope, not only by assignment ID.
Each key family also needs a monotonically increasing in-process generation or
equivalent fence. A fill captures all applicable generations before its first
role read and may publish only if they are unchanged after the complete read.
This prevents an old read that began before revocation from refilling a cache
after eviction. A fresh regrant is a new lifecycle, while delayed old messages
remain harmless because principal-and-scope invalidation is idempotent and
only removes cached data.

## Fail-closed behavior

Expiry, operational read failures, incomplete or corrupt reads, invalid,
non-finite, or regressing clock samples, and generation changes deny or retry
from authoritative state. Every security-relevant clock sample is validated;
a backward jump irreversibly fails the shared in-process clock-domain guard for
role caches, composed authorization, and downstream decisions. Each consumer
clears its cached entries when it next observes that terminal state and requires
a fresh clock domain plus authoritative reload. Restoring the old numeric value
never re-enables pre-anomaly entries. Failures never serve stale last-known-good
authorization or use stale-while-revalidate. A refresh cannot fall back to an
expired allow decision.

When authorization combines multiple independently bounded facts, its deadline
is the earliest input deadline. Composition first requires exact equality of
the application, principal, tagged scope, policy version and digest, and
exact opaque monotonic clock-domain token carried by every input; a mismatch
rejects rather than mixing facts. Every input's read-start and expiry timestamps must be valid,
ordered values, and composition rejects if the earliest input is already
expired. In particular, a role-and-entitlement context cannot outlive either
the 60,000 millisecond role deadline or the remaining host-persisted
entitlement-state freshness window.

Revoking one assignment does not necessarily remove a permission that is still
granted by policy defaults, another active role, or an entitlement. The host
must reload all applicable facts and evaluate the resulting policy rather than
assuming that one revoked assignment implies one denied permission.

## Deliberate boundary

This contract adds no fields to `AccessSubject` or `AccessContext`, no public
cache or invalidation package, no storage port, no provider identifier, and no
runtime validator. The host owns cache infrastructure, invalidation delivery,
monotonic time, policy deployment identity, organization membership, resource
checks, sessions, and long-running operation reauthorization.

Phase 4 signed grants must either expire no later than the remaining
authorization deadline or use a separately proven mechanism whose effective
worst-case revocation bound is equal to or stricter than 60,000 milliseconds.
Such a mechanism may shorten the remaining role deadline but never extend,
restart, or bypass it.

See [Scoping](SCOPING.md) for exact cache identity across applications and
organizations and the [integration security model](SECURITY_MODEL.md) for the
complete fail-closed checklist.
