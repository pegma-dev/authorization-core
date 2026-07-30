# Role administration (`@pegma/authorization-admin` — proposed)

Status: **design under review** — no package exists yet, deliberately (an
empty package makes a compatibility promise while supplying nothing). This
document is the extraction design; implementation begins only after it is
accepted.

## Why now

The ecosystem's rule is extract-on-second-consumer, and the second consumer
has arrived. Two hosts independently built the same audited role-management
surface against this repository's packages:

- retiregolden.org `/account/admin/` (Azure Functions; Auth0 identity;
  Support and Admin roles; the integration that filed #23–#25), and
- pegma.dev, whose role adoption plan reaches the same surface as its
  Phase 5 (Cloudflare Workers; first-party passkey identity; Support live,
  Admin gated on this surface existing).

Both duplicated the same non-trivial logic — grants rendering with a
management policy, audited assign/revoke, a last-administrator guard with a
real concurrency treatment, per-principal history — and both carried the
same class of review findings on the way (TOCTOU dual-revoke, bootstrap
resurrection after revocation). That logic is the package. What differs per
host stays per host, forever.

## What the package owns

An HTTP-neutral, provider-neutral application service over the existing
storage and policy contracts. One instance per application; nothing crosses
applications.

**Grants view.** Active assignments for one principal with a `managedBy`
label derived from an explicit management policy: assignments granted by
ONGOING system actors are `system` (locked — the writer owns the record);
assignments granted by humans, or by system actors the host declares
ONE-TIME (bootstrap seeds, guard compensation), are `human` (editable).
Actor inference alone is not policy — the one-time set is explicit
configuration, a lesson from the reference host.

**Audited assign.** A permission-checked grant of a host-policy role with a
caller-supplied or generated assignment id, an audit event, and duplicate
refusal delegated to the store's active-tuple guarantee. The holder-index
row is written BEFORE the grant through the host port (superset invariant,
`docs/STORAGE.md` recipe), and only after a pre-check that the tuple is not
already active — a dangling row must be possible only from a crash, not
from a routine duplicate attempt.

**Audited revoke with the last-administrator guard.** Revoking the
administrator role runs the guard the reference host proved out, and the
guard's concurrency treatment is part of the contract, not an
implementation detail:

1. revocations are serialized in-process (per instance) — two concurrent
   revokes of the two last administrators must not interleave;
2. the by-role holder check runs before the revoke (refuse with a typed
   `last_administrator` outcome when no OTHER active holder exists);
3. after an administrator revoke commits, the guard RE-VERIFIES and, if no
   active administrator remains (a concurrent revoke on another instance
   won its race), writes a compensation grant with a dedicated system
   actor. In-process serialization cannot span instances; the compensation
   is what makes the guarantee honest. The compensation actor is in the
   default one-time set: the resulting assignment is human-managed.

The guard can only refuse harmlessly, never allow harmfully: the holder
index over-reports at worst, and every candidate is verified against the
authoritative store before it counts.

**Per-principal history.** The complete lifecycle for one principal via
`listRoleAssignments` (0.3.0) — grant and revocation evidence rendered as
an ordered event timeline. No host index involvement; pre-index grants
appear because the store is the authority.

**One-time seed helper.** Both hosts wrote the same bootstrap-adjacent
function; the third copy would be in this package's README, so it belongs
in the package: `ensureSeededAssignment` grants a role once per principal,
ever, with a deterministic assignment id and a system actor, treating ANY
existing assignment record for that role — active or revoked, whatever its
provenance — as already-seeded (`listRoleAssignments`; revocation is
durable evidence, proven on pegma.dev). This is a pure function over the
ports. It is NOT a bootstrap endpoint, tool, credential, or coordinator —
`docs/ADMINISTRATOR_BOOTSTRAP.md` remains normative for the ceremony that
decides WHETHER and FOR WHOM to call it, and everything that document
forbids stays forbidden.

## What the package refuses

- The HTTP envelope, status codes, and response shapes — hosts own routes.
- Any UI. One admin tool per site; shared package, separate instances.
- Principal lookup and directory (email search, display names) — identity
  is host-specific by design (Auth0 there, first-party passkeys here).
- Rate limiting — hosts already own durable limiters.
- Entitlement display or mutation. Entitlements are ledger-derived and
  admin-read-only at most; a surface that edits them is a different (and
  rejected) product.
- Cross-application or cross-host administration of any kind.
- Bootstrap ceremony, endpoint, or tooling (see above).

## Ports (all constructor-injected, host-owned)

| Port              | Provided by                               | Notes                                                                                                                                                                              |
| ----------------- | ----------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| Role store        | `createRoleStore` (authorization-storage) | reads, lifecycle enumeration, audited mutations                                                                                                                                    |
| Holder index      | host, per `docs/STORAGE.md` recipe        | `record(row)`, `listByRole(role)`; write-before-grant, never delete, verify-on-read. Stays a port until the library-maintained index (#24 follow-up) ships, then becomes optional. |
| Management policy | host configuration                        | `{ administratorRole, oneTimeSystemActors }`; the guard's compensation actor and the seed helper's actor are included by default                                                   |
| Clock             | host (`@pegma/spine`)                     | deterministic tests                                                                                                                                                                |

The service performs no permission checks on its own callers: the HOST
gates its routes with `hasPermission` against its own policy before
invoking the service, exactly as both hosts do today. Putting the check
inside the package would duplicate the host's policy resolution and invite
drift between the two.

## Package ceremony

Tenth package. Same rules as the eighth and ninth: implementation lands
with conformance-style tests against the memory store; the one-time `0.0.0`
name reservation publishes under the non-default `bootstrap` dist-tag;
trusted publishing is configured; the next synchronized `0.x` release is
its first advertised publication. No new storage: every durable record it
touches is either the existing authorization collections or the host's own
index collection reached through the port.

## Host adoption order (recorded, executed in the host repos)

pegma.dev (its plan's Phase 5): map `Admin` in the policy → one-time Admin
seed via the ceremony + seed helper (`PEGMA_ADMIN_BOOTSTRAP_PRINCIPALS`,
deterministic id, delete the var after) → ship the surface gated on
`Admin`, guard meaningful from the first request. retiregolden.org:
replace `api/src/lib/admin-handlers.js` internals with the service behind
the existing routes, keeping the HTTP envelope, rate limits, and UI
byte-compatible; its `role-index.js` becomes the holder-index port
implementation.
