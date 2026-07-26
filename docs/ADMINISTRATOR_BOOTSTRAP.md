# Administrator bootstrap

Administrator bootstrap is the one-time host procedure that creates an
application's first usable administrator assignment. It is an out-of-band,
short-lived, server-and-operator-only deployment ceremony. It must never be
reachable from signup, login, an invitation acceptance page, a browser request,
or a provider callback.

This guide is normative for hosts using Authorization Core's existing role and storage
contracts. Authorization Core does not ship a bootstrap endpoint, command-line tool,
principal directory, credential, or durable coordinator.

## Select the principal and role

An operator independently verifies one pre-existing principal in the
authoritative host principal directory and records its exact `principalId`.
The operator must not choose or derive the target from:

- email or display name;
- an identity-provider subject or issuer;
- signup, profile, or organization metadata;
- an identity-provider or billing-provider role;
- a first-user or first-login rule;
- an invitation or browser-selected value; or
- whichever account happens to invoke the procedure.

The manifest names one exact application-owned administrator role and explicit
`{ kind: "application" }` scope. The assignment becomes privileged only when
the validated, application-owned policy maps that exact role to the required
administrator permissions. Neither the role record nor the name
`administrator` has intrinsic permission semantics.

## Prepare one immutable manifest

Before enabling the procedure, prepare and access-control one immutable retry
manifest containing:

- the exact host `principalId`;
- the exact application-owned role;
- explicit application scope;
- a fresh opaque assignment ID;
- a fresh opaque grant audit-event ID;
- a separately reserved fresh opaque failure-cleanup revoke audit-event ID;
- one trusted host timestamp;
- a trusted `{ kind: "system", systemId }` actor;
- the required administrator permission used for verification;
- the exact reviewed application-policy version or digest; and
- exact environment, storage, and application fingerprints.

The manifest is secret-free, but it is privileged operational data and must not
be publicly writable or browser-readable. Preserve the same reviewed bytes and
digest until the attempt reaches a terminal result. A timeout, disconnect, or
ambiguous response retries the exact same manifest. Never generate replacement
IDs merely because the response was lost.

## Require a durable one-shot gate

Tuple uniqueness prevents two active copies of the same principal, role, and
scope. It does not prevent two different principals from each receiving an
administrator role. The host must therefore maintain a durable one-shot
compare-and-swap gate outside the Authorization Core ports:

1. The gate is disabled and unarmed by default.
2. Out-of-band deployment authority arms it for exactly one reviewed manifest
   digest bound to the expected environment, storage, and application
   fingerprints.
3. After all pre-mutation evidence checks, one coordinator must atomically claim
   the exact armed digest by changing `armed` to `executing` with a unique
   execution ID, generation, expiry, and fencing value. Only that claim may
   reach role storage. Concurrent contenders wait or fail closed; they do not
   share the claim or call storage.
4. The host binds short-lived role-mutation authority to that execution claim.
   Every storage call rechecks the live claim and fencing value immediately
   before mutation. Cleanup states cannot be entered until the claimed storage
   call has settled or its authority has been fenced and quiescence verified.
5. A crash while `executing` does not make the gate freely `armed`. The same
   owner may reconcile the exact manifest while its claim remains live. After
   expiry, recovery first fences and removes the old claim's authority, verifies
   no call remains in flight, and only then advances the generation for a new
   exact-manifest claim. A stale owner can never reach storage.
6. Concurrent or repeated attempts reconcile the same assignment and audit
   event, but only the current fenced claim performs storage calls.
7. Only after all verification succeeds does a durable CAS change `executing`
   to `cleanup_pending`. That state remains bound to the same manifest digest
   and generation, and it forbids any further role mutation.
8. From `cleanup_pending`, an idempotent cleanup path disables and removes
   bootstrap authority, rotates or removes temporary credentials, and verifies
   that neither remains usable. A crash or timeout resumes only this cleanup;
   it never replays the role grant.
9. Only after cleanup is verified does a durable CAS change `cleanup_pending`
   to `completed`.
10. A definitive storage conflict, revoked exact replay, or contradictory
    durable readback atomically consumes `executing` into
    `failure_cleanup_pending`, bound to the same manifest digest, generation,
    and immutable failure reason. This state never authorizes another grant.
11. One cleanup coordinator CAS-claims `failure_cleanup_pending` into
    `failure_cleanup_executing` with a separate unique execution ID, expiry,
    fencing value, and cleanup-only authority. That authority permits only
    readback and an audited revoke of the exact manifest assignment ID; it
    cannot call the grant operation, select another lifecycle, or mutate any
    other role. Concurrent cleanup contenders cannot share it. Expired cleanup
    recovery fences the old cleanup authority and verifies quiescence before a
    new cleanup claim is issued.
12. From `failure_cleanup_executing`, the durable idempotent failure-cleanup path
    reconciles the exact assignment and audit IDs. If the exact manifest grant
    committed, both every immutable grant field and the sequence-one grant audit
    event ID must exactly match the manifest before cleanup may revoke that
    lifecycle. Cleanup then verifies it is no longer active. If the assignment
    is absent, its audit history must also be definitively empty before absence
    counts as reconciled. If it is already revoked, the same immutable grant and
    sequence-one audit proof is still required before it counts as reconciled.
    Any contradictory object or audit history stays quarantined for operator
    resolution; it must not be overwritten, revoked, or treated as the manifest
    grant. The cleanup revoke may reuse the validated manifest timestamp because
    equality with the grant timestamp is permitted; it must not derive an unsafe
    timestamp with unchecked arithmetic. Recheck the live cleanup claim and
    fencing value after all read I/O and immediately before the revoke. A
    successful revoke response is not sufficient: exact durable readback must
    show the matching lifecycle revoked and exact-principal/application active
    selection must omit it. The same path removes bootstrap authority and
    temporary credentials and verifies that none remain usable.
13. Only after grant reconciliation and authority and credential cleanup are
    all verified does a durable CAS change `failure_cleanup_executing` to
    terminal `failed`, preserving the failure reason. Crashes resume only this
    cleanup path. Failed and completed gates cannot be re-armed. Removing a
    conflicting row later does not authorize a retry; recovery requires the
    separate break-glass ceremony with fresh IDs.

The gate and manifest must survive process restarts and must be protected at
least as strongly as the authorization store. An in-memory flag, deployment
replica local state, "no administrators found" query, or environment variable
alone is not a conforming one-shot gate.

The current storage ports cannot query or prove that zero other administrators
exist across every principal, cannot enforce global first- or only-admin
exclusivity, and cannot own this gate. Those are host operational invariants,
not storage promises.

The disabled gate or an equivalent durable deployment control must be installed
before any worker, system job, operator tool, or API is ever given authority to
grant the administrator role in that environment. If that history cannot be
proven, this ceremony must not claim or establish a first administrator; use a
separately reviewed migration or recovery procedure. Disabling existing tooling
only immediately before arming is insufficient.

Before arming bootstrap, the host must also verify every administrator-grant
path remains disabled or governed by the same deployment control and gate. That
exclusion remains in force through execution and cleanup. The one-shot gate
coordinates only callers governed by it; it cannot establish a
first-administrator invariant while an independent caller retains grant
authority. Normal administrator delegation may be enabled only after bootstrap
reaches verified `completed`. After terminal `failed`, recovery stays limited
to the separately approved break-glass ceremony.

## Execute using the safe durable boundary

After rechecking the authoritative principal, independently observe the current
environment, storage target, and application binding and compare all three
exactly with the manifest before any role mutation. Manifest-declared strings
are not evidence of the current deployment. Reject any scope other than exact
`{ kind: "application" }` before claiming the execution fence or calling role
storage. Before any role mutation, also load the validated application-owned
policy and prove that the exact manifest role's own mapping directly includes
the required administrator permission and that the policy version or digest
matches the manifest. Policy defaults and unrelated roles do not satisfy this
pre-mutation proof. Only then claim the durable execution fence and call
`grantRoleAssignmentWithAudit` on the host's durable production storage adapter.
Do not compose raw assignment and audit writes. Do not insert Azure Table rows
directly. Do not use `createInMemoryStorageAdapter` in production; it is only an
executable contract fixture.

Handle the result as follows:

- `granted` proceeds to independent verification.
- `unchanged` is success only after readback proves the same exact active
  lifecycle, sequence-one grant audit event, and active selection. An
  `unchanged` result for a revoked lifecycle is a definitive failure that
  consumes the gate into `failure_cleanup_pending`.
- Any conflict atomically consumes the gate into `failure_cleanup_pending`.
  Do not select a winner, alter the manifest, overwrite an existing assignment,
  or leave the manifest authorized for a later retry.
- Any definitive contradictory assignment, audit, or active-selection readback
  also consumes the gate into `failure_cleanup_pending`.
- Operational and indeterminate errors fail closed. If the outcome could have
  committed, retain the fenced `executing` claim for exact reconciliation. A
  replacement claim requires the expiry, authority fencing, quiescence, and
  generation-advance procedure above.

Every `failure_cleanup_pending` result must run the resumable failure-cleanup
path before the gate becomes terminal `failed`. Entering failure cleanup
preserves the closed failure outcome; it does not permit the grant to be
retried. Its separately fenced cleanup claim permits only exact reconciliation
and, when proven necessary, the exact audited revoke. A break-glass ceremony
must not begin until the failed bootstrap grant, bootstrap authority, and
temporary credentials have all been reconciled and verified inactive.

## Verify before declaring success

Read through the same durable production adapter and verify all of the
following:

1. Exact assignment-ID readback is active and every immutable grant field
   matches the manifest.
2. Audit history contains the exact sequence-one `granted` event with the
   reviewed event ID and assignment.
3. Active selection for the exact principal and application scope contains the
   exact assignment and no unexpected bootstrap result.
4. A fresh authoritative principal-directory read proves the exact principal
   still exists and is active. Fence principal deletion, disabling, or merging
   through this read and the transition to `cleanup_pending`, or fail into
   failure cleanup.
5. A fresh authoritative application-policy load matches the exact manifest
   version or digest and has an own mapping for the exact manifest role that
   directly includes the required administrator permission. Policy defaults,
   another selected role, or a previously loaded policy do not satisfy this
   bootstrap proof.
6. Passing all selected role names into that freshly loaded policy resolves the
   required administrator permissions for that principal.

Assignment IDs, audit IDs, scope, actors, timestamps, deployment fingerprints,
provider identifiers, and operator evidence stay outside `AccessSubject` and
`AccessContext`.

Immediately after these fresh principal and policy checks, atomically mark the
one-shot gate `cleanup_pending`.
Idempotently disable and remove bootstrap authority, rotate or remove temporary
credentials, and verify that neither remains usable. A restart in this state
resumes cleanup without calling role storage. Only after verified cleanup may
the gate become `completed`. Record the ceremony in the host's
access-controlled operational audit.

## Later delegation and recovery

Later administrator delegation is a normal, authenticated, authorized, and
audited role-management flow. It does not reuse or re-arm bootstrap.

If every administrator is lost, use a separately approved break-glass ceremony
with independently verified host state, fresh assignment and audit IDs, and
separate durable authorization. Break-glass must not reset the completed
bootstrap gate. Replaying a revoked assignment lifecycle never reactivates it;
a legitimate recovery grant always creates a new lifecycle with fresh IDs.

The repository contract test uses the in-memory adapter and a test-local gate
state machine to make these decisions executable. It demonstrates composition
only. It is not production bootstrap infrastructure and does not prove durable
coordination, credential removal, operator identity, or absence of other
administrators.
