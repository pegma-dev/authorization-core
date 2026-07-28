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

## Public conformance suites

`@pegma/authorization-core/conformance` exports runner-neutral case arrays for
the provider-neutral `IdentityAdapter` and `EntitlementAdapter` ports. It has no
test-framework dependency. The conformance entrypoint currently targets Node.js
22 or newer and uses `node:assert/strict` internally. Register each case with
the runner already used by the adapter:

```ts
import {
  entitlementAdapterConformanceCases,
  identityAdapterConformanceCases,
  type EntitlementAdapterConformanceFactory,
  type IdentityAdapterConformanceFactory,
} from "@pegma/authorization-core/conformance";

const createIdentityAdapter: IdentityAdapterConformanceFactory = async (
  fixture,
) => {
  // Populate the adapter's real test backend from fixture.links.
  // Configure fixture.unavailableKeys to reject as operational failures.
  // If the adapter requires richer verified input, return a semantic-key
  // resolver that adds that evidence before calling the real adapter.
  return buildIdentityAdapter(fixture);
};

const createEntitlementAdapter: EntitlementAdapterConformanceFactory = async (
  fixture,
) => {
  // Translate each semantic state into the adapter's persisted provider facts.
  // Repeated entries for one principal are successive request-time states.
  return buildEntitlementAdapter(fixture);
};

for (const testCase of identityAdapterConformanceCases) {
  it(testCase.name, () => testCase.run(createIdentityAdapter));
}

for (const testCase of entitlementAdapterConformanceCases) {
  it(testCase.name, () => testCase.run(createEntitlementAdapter));
}
```

The identity suite fixes only issuer-and-subject link semantics: exact
case-sensitive tuples, namespace and delimiter separation, multiple links to
one host principal, definitive absence, and operational rejection. The
entitlement suite fixes principal isolation, canonical immutable host names,
authoritative empty state, request-time reload without fallback, rejection of
missing or invalid state, and a matching permission allow-and-deny composition.

Factories translate those semantic fixtures into their real backend. The suite
does not standardize provider claims, SDK objects, webhook payloads, lifecycle
timestamps, persistence schemas, or logging APIs. Provider-specific tests must
still cover verification, malformed provider evidence, sensitive-field
exclusion from logs, callback ordering and deduplication, complete pagination,
customer binding, and the exact staleness calculation.
