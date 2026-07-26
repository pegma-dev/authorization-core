# Identity linking

This guide defines how Authorization Core relates a provider identity to a stable,
host-owned principal. It is the normative identity-linking model; it does not
define a storage or mutation API.

## Resolution

The host verifies the provider token or session before identity lookup. A lookup
key is the tuple `{ issuer, subject }` from that trusted evidence. Both strings
are opaque and compared exactly and case-sensitively. Hosts must not trim,
case-fold, parse, rewrite, or otherwise normalize either component, and must
not substitute an email address or a subject without its issuer.

Each exact issuer-and-subject key links to zero or one principal. A principal
may have zero, one, or many linked keys. The `principalId` is assigned and owned
by the host; it is not an OIDC subject, provider user ID, or email address.

`IdentityAdapter.resolvePrincipalId` returns `null` only when no link exists.
Invalid or unverified identity evidence must be rejected before lookup, and
storage, network, configuration, or other operational failures must reject
rather than being collapsed into `null`.

## Linking

Creating a link is a privileged host operation. The host must require evidence
that the caller controls the provider identity and authorization to attach it
to the intended principal. Repeating the same key-to-principal link is
idempotent. Attempting to attach an already-linked key to a different principal
is a conflict and must fail closed without changing the existing edge.

Every link attempt and outcome must be auditable, including the acting
principal or trusted operator, the affected key and principal, the result, and
the host's approved reason or correlation data. Sensitive token material must
not enter the audit record.

## Unlinking

Unlink removes exactly one expected key-to-principal edge. It must use
conflict-safe storage behavior so it cannot remove a link that changed after
the caller read it. Other links to the principal remain unchanged.

Before unlinking, the host must decide whether another login or recovery method
will remain. Removing the final login may require an account-close or recovery
flow rather than an ordinary unlink. Unlinking is not full account deletion: it
does not by itself delete the principal, roles, entitlements, billing state,
organization membership, application resources, or audit history.

The host must audit the operation and invalidate affected sessions and identity
caches before relying on the changed link set.

## Account merging

A merge is directional: every identity link for a source principal moves to a
designated surviving principal. Existing survivor links remain. The transfer
must be atomic. Any ownership conflict or concurrent change aborts the entire
merge, with no partially moved link set.

After a successful merge, no identity key resolves to the source principal.
The losing principal is retired and must never be reused for a different
account. Identity-link transfer alone is not a complete account merge. The host
must explicitly define and perform migration or reconciliation of roles,
entitlements, billing records, organization membership, application resources,
and any other principal-owned data.

Merge authorization must be stronger than ordinary sign-in and appropriate to
the host's account-recovery risk. The host must invalidate sessions and caches
for both principals and create an audit trail sufficient to reconstruct the
source, survivor, moved links, actor, authorization basis, outcome, and related
data migrations.

## Deferred implementation choices

This model intentionally does not yet define:

- storage ports or a storage representation;
- transaction or compare-and-swap mechanisms;
- runtime link, unlink, or merge APIs and their error unions;
- an audit event schema;
- provider token verification, SDK integration, or full identity-adapter
  implementations;
- account-status or tombstone types;
- organization scope.

Those choices require later integration evidence. Provider SDK objects, email
fields, profiles, roles, entitlements, and organization data do not belong in
the identity-link contracts.
