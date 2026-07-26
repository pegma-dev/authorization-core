# Azure Table Storage adapter

`@pegma/authorization-azure-tables` is the durable Azure implementation of Authorization Core's
principal lookup, role-assignment read, audit read, and combined audited
mutation contracts. It preserves the provider-neutral contracts without
turning Azure credentials, connection strings, account names, or request-time
application selectors into Authorization Core inputs.

## Construction

The host provisions a table and constructs an Azure `TableClient` configured
for that table's primary endpoint. It then binds one exact host application:

```ts
import { TableClient } from "@azure/data-tables";
import { createAzureTableStorageAdapter } from "@pegma/authorization-azure-tables";

const tableClient = TableClient.fromConnectionString(
  process.env.AZURE_STORAGE_CONNECTION_STRING!,
  "PegmaAuthorization",
);

const storage = createAzureTableStorageAdapter({
  tableClient,
  applicationId: "retiregolden",
});
```

The adapter does not create the table, acquire credentials, choose retry or
telemetry policies, or fall back to a secondary endpoint. Prefer managed
identity or another short-lived credential mechanism in production. Limit the
credential to the intended table and operations where the deployment model
permits.

The table must already exist before the adapter is used. Table creation,
storage-account configuration, network access, backups, retention, monitoring,
and disaster recovery remain host responsibilities.

## Safe public surface

The returned object implements:

- exact read-only `PrincipalLookupStore`;
- `RoleAssignmentReader`;
- `RoleAssignmentAuditReader`; and
- `AuditedRoleAssignmentMutationStore`.

It intentionally does not expose `createRoleAssignment`, the raw revoke
signature, or `appendRoleAssignmentAuditEvent`. Every public role mutation
therefore derives and commits its lifecycle audit event in the same storage
transaction.

`createAzureTableIdentityLinkEntity` creates the exact entity shape expected by
principal lookup. A separate trusted administration path may create that
entity with the same table client. The helper performs no write and does not
define create, unlink, transfer, merge, or account-recovery authorization.

## Application partition and transactions

Azure Table Storage entity-group transactions require one physical table and
one partition. The adapter therefore hashes the construction-bound application
ID into one partition key and stores all of that application's authorization
rows there:

- authoritative assignment lifecycle rows;
- active principal, role, and scope tuple guards;
- active-selection index rows;
- retained per-principal/scope selection fences with exact active counts;
- sequence-one and sequence-two audit history rows;
- application-wide audit event-ID guards; and
- read-only identity-link rows.

An audited grant creates the assignment, active tuple, active selection, grant
audit, and event-ID guard and creates or conditionally advances the selection
fence together. A revoke conditionally replaces the assignment and tuple
guard, deletes the active selection, creates the revoke audit and event-ID
guard, and conditionally advances the fence together. The fence count is
incremented or decremented in the same transaction. Each mutation uses six
operations, below Azure's 100-operation entity-group limit.

This single partition is a correctness requirement, not a general scaling
recommendation. It can become a hot partition. Deployments whose per-application
authorization write rate approaches Azure partition limits should select a
backend with transactions across the required uniqueness and audit indexes
rather than splitting these rows and silently weakening invariants.

Azure also limits an entity-group transaction payload to 4 MiB, an entity to
1 MiB, and an individual string property to 64 KiB (roughly 32,000 UTF-16
characters). Assignment evidence is retained in several rows, so hosts must
apply substantially smaller application-level bounds to IDs, roles, actor
identifiers, organization IDs, and reasons. Oversized values reject at the
service; the adapter does not truncate authorization or audit evidence.

## Keys and collision handling

Authorization Core IDs may contain delimiters, slashes, backslashes, question marks,
number signs, controls, Unicode, lone UTF-16 surrogates, and prototype-sensitive
names. Azure row keys cannot safely contain all of those values and have a
finite length limit.

The adapter hashes domain-separated, length-framed exact UTF-16 code units with
SHA-256 and uses lowercase hexadecimal digests in Azure-safe keys. Every entity
also stores its exact source values. Reads recompute the expected key and
validate the application, entity kind, schema version, exact source values,
lifecycle, and related guard rows. A digest collision or mismatched row is
corrupt state and rejects. It never aliases one principal, scope, assignment,
or event to another.

## Concurrency and replay

The Azure assignment ETag is the opaque record-scoped concurrency token.
Callers must not parse, compare, sort, synthesize, or reuse it across records.
The adapter rejects the wildcard token and compares the submitted token to the
freshly read assignment before using that stored ETag in a conditional
`Replace`.

The Azure JavaScript SDK cannot attach an ETag to a transactional delete.
Revocation therefore conditionally replaces the active-tuple guard with a
tombstone instead of deleting it. A fresh-ID regrant conditionally replaces
that tombstone. The old assignment remains revoked and cannot be reactivated.

Revoked assignment rows retain the original pre-revocation ETag. An exact
completed revoke replay must present that token and the same actor, time,
reason, and event ID. A timed-out or disconnected transaction might already
have committed; after an error, the adapter rereads authoritative state and
returns `unchanged` only when the entire exact role-and-audit result is visible.
Incomplete or ambiguous state rejects.

## Reads and consistency

Point reads return `null` only for the entity-not-found service code
(`EntityNotFound`, plus Azurite's `ResourceNotFound` compatibility code).
`TableNotFound` and other table, authentication, network, throttling, server,
parsing, and corrupt-data failures reject.

Active-role and audit queries consume every continuation page. Active rows are
checked against their authoritative assignment, tuple guard, grant audit, and
event guard. Their number must match the exact count on the
principal-and-scope selection fence. Audit histories must be the exact
lifecycle prefix: sequence one for a grant and sequence two for a revoke, with
matching global event-ID guards.

Azure does not provide one snapshot across all pages of a query. The adapter
therefore reads the selection fence before and after enumeration. A changed
ETag causes a bounded retry; continued churn rejects instead of returning
roles combined from different committed generations. Keep role counts per
principal and scope small. Cache entries around these reads preserve the
project's 60,000 millisecond absolute read-start deadline and exact
application, principal, scope, and policy binding; invalidations target 5,000
milliseconds and fence in-flight stale fills. See
[Fast role revocation and cache bounds](ROLE_REVOCATION.md). Use the primary
endpoint for authorization reads. A
read-access geo-redundant secondary can be stale and is unsupported for this
boundary.

## Identity-link administration

Identity links remain host-owned privileged records. The adapter only resolves
an exact, case-sensitive issuer-and-subject tuple. It does not verify tokens or
create, unlink, transfer, merge, or recover accounts.

Provision a link through a trusted server-side administration path:

```ts
import {
  createAzureTableIdentityLinkEntity,
  createAzureTableStorageAdapter,
} from "@pegma/authorization-azure-tables";

await tableClient.createEntity(
  createAzureTableIdentityLinkEntity("retiregolden", {
    key: {
      issuer: "https://example.us.auth0.com/",
      subject: "auth0|example",
    },
    principalId: "account_123",
  }),
);
```

Creating the same exact link twice may be treated as an administrative replay
by the host. Mapping one exact identity tuple to another principal is a
privileged conflict and must not be implemented with upsert.

## Administrator bootstrap

The Azure adapter can supply the durable assignment, audit, and exact readback
boundary used by the host's administrator-bootstrap ceremony. The coordinator
calls only `grantRoleAssignmentWithAudit`; it must not insert assignment,
tuple, selection, fence, audit, or event-guard rows directly. An ambiguous
transaction response is retried with the same immutable manifest and exact
assignment and audit IDs. Before calling the adapter, one coordinator must hold
the gate's unique live `executing` claim and fenced short-lived mutation
authority. Concurrent or stale claims cannot reach the adapter, and cleanup
waits for the claimed call to settle or be fenced and verified quiescent.

A definitive tuple conflict or contradictory durable readback consumes the
host gate into non-authorizing `failure_cleanup_pending`. Its resumable cleanup
CAS-claims a separate fenced cleanup-only authority that can read and invoke the
audited revoke for only the exact manifest assignment ID; it cannot invoke the
grant operation or mutate another lifecycle. Cleanup reconciles and, when
necessary, removes the exact committed manifest grant, then verifies bootstrap
authority and temporary Azure credentials are unusable before entering terminal
`failed`. Removing a conflicting row later does not authorize the reviewed
bootstrap manifest to retry. An indeterminate transaction outcome that might
have committed instead retains its fenced execution claim for exact replay and
reconciliation. Expired-claim recovery must fence old authority and verify no
call remains in flight before advancing the generation.

The adapter does not supply the durable one-shot bootstrap CAS gate. The host
binds that disabled-by-default gate to the reviewed manifest digest and exact
environment, storage account/table, and application fingerprints. This avoids
running a reviewed production manifest against a different table or
application. The adapter's tuple guard prevents a duplicate exact
principal/role/scope tuple, but it cannot prevent another principal from
receiving the same role or prove that no administrator exists.

After exact assignment, audit, active-selection, and policy verification, the
host durably enters `cleanup_pending`. In that state it must not call role
storage; it idempotently removes bootstrap authority and rotates or removes
temporary Azure credentials, then completes the gate only after cleanup is
verified. The test-local in-memory composition is not production Azure
bootstrap infrastructure. See
[Administrator bootstrap](ADMINISTRATOR_BOOTSTRAP.md).

## Validation and service testing

Repository tests use a deterministic client façade to exercise schema,
transactions, conflicts, response-loss reconciliation, full enumeration,
fence-change retries, corruption, hostile IDs, and application isolation
without credentials. Those tests prove adapter logic, not Azure service
behavior.

Before production, run integration tests against the actual Azure Storage
account and configuration used by the deployment. Validate entity-group
transactions, conditional ETags, retry behavior, throttling, permissions,
network policy, backups, monitoring, and recovery. Azurite is useful for basic
table and query compatibility, but its missing-entity code differs from
Azure's and it is not evidence for all production transaction and failure
semantics.

## Deliberate exclusions

This package does not provide table or account provisioning, credentials,
identity mutation, actor authorization, a bootstrap endpoint, durable one-shot
gate, bootstrap coordinator, organization membership, cache bounds, audit
retention or search, audit signatures or tamper evidence, a cross-application
control plane, secondary-region fallback, Cosmos DB Table API guarantees,
provider translation, policy behavior, or core access-context changes.
