# Adapter authoring

Provider adapters translate already trusted provider evidence into the narrow
ports in `@pegma/authorization-contracts`. Keep vendor SDK objects and lifecycle
semantics inside the adapter package; public contracts and the core remain
provider-neutral.

## Identity adapters

An `IdentityAdapter` receives a provider-specific evidence key chosen by the
adapter and returns a host-owned `principalId` or `null`.

- Verify tokens or sessions before adapter projection.
- Namespace subjects by exact issuer. Never use email or a bare subject.
- Preserve exact case-sensitive values unless the provider contract itself
  defines a normalization before evidence becomes trusted.
- Return `null` only for definitive absence. Reject storage, configuration,
  network, partial-read, and corrupt-data failures.
- Do not return provider profiles, roles, permissions, or organization claims.

The [Auth0 guide](AUTH0.md) and [identity-linking model](IDENTITY_LINKING.md)
show the official projection and host lookup split.

## Entitlement adapters

An `EntitlementAdapter` receives a host-owned request and returns active
host entitlement names.

- Authenticate provider callbacks and own ordering, deduplication, lifecycle,
  customer-to-principal binding, and complete pagination outside the port.
- Resolve from host-persisted trusted state at request time.
- Enforce a documented staleness bound and reject future, stale, missing,
  corrupt, or operationally unavailable state without fallback.
- Translate only through an exact host allowlist. Unknown facts grant nothing.
- Return detached, immutable, canonical host entitlement names; never provider
  IDs, statuses, raw objects, roles, or permissions.

The official [Stripe adapter](STRIPE.md) demonstrates Feature mode and explicit
Price fallback without mixing their namespaces.

## Package and test checklist

Depend on `@pegma/authorization-contracts`, not provider types in public
contracts. Keep persistence behind `@pegma/storage-core` rather than building a
backend in an authorization adapter. Test exact matching, malformed inputs,
unknown values, definitive absence, operational rejection, immutable output,
and at least one permission allow plus its matching deny after policy
resolution. Test that sensitive provider fields never enter the access context
or logs.

Published adapter conformance suites are a Phase 6 item and do not exist yet.
Until then, use the public interfaces, the official adapter tests, the
[getting-started composition](GETTING_STARTED.md), and the
[security model](SECURITY_MODEL.md) as the review checklist.
