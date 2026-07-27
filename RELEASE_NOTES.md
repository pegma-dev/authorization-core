# Authorization Core 0.1.0

Authorization Core 0.1.0 is the first advertised release of Pegma's
provider-neutral authorization packages.

## Highlights

- Provider-neutral identity, entitlement, policy, access-context, role
  assignment, audit, and signed access-grant contracts.
- Pure deterministic permission resolution with deny-by-default handling for
  unknown roles and entitlements.
- Strict policy parsing with stable diagnostics, opaque policy revisions, and
  immutable snapshots.
- Pure Auth0 identity and Stripe entitlement translation adapters that keep
  provider SDK types outside the public contracts.
- Audited role-assignment grant, revoke, regrant, administrator bootstrap, and
  fast-revocation behavior over host-supplied `@pegma/storage-core` stores.
- Application-scoped ES256 access grants with public JWKS, exact audience and
  policy binding, identifier reservation, and atomic one-use replay
  consumption.
- A runnable reference API, generated public API documentation, integration
  security guidance, migration guidance, and adapter-authoring documentation.

## Packages

- `@pegma/authorization-contracts`
- `@pegma/authorization-auth0`
- `@pegma/authorization-core`
- `@pegma/authorization-policy`
- `@pegma/authorization-stripe`
- `@pegma/authorization-storage`
- `@pegma/authorization-tokens`

All seven packages release together at `0.1.0`, require Node.js 22 or newer,
and are MIT licensed.

## Compatibility

This is a `0.x` release. Public contracts are usable but not yet stable; later
`0.x` releases may contain documented breaking changes. Host applications
remain responsible for provider verification, authoritative identity and
billing state, durable storage, signing-key custody, resource relationships,
and server-side authorization enforcement.
