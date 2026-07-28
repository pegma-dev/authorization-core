# Authorization Core 0.1.1

Authorization Core 0.1.1 is the first advertised release to include Pegma's
first-party Identity adapter. All eight public packages release together at one
version.

## Highlights

- Adds `@pegma/authorization-identity`, a small provider-neutral projection from
  the structural `@pegma/identity` verified-claims shape
  `{ issuer, subject, emailVerified: true }` to a fresh frozen
  `{ issuer, subject }` authorization identity-link key.
- Keeps Identity and Authorization independently publishable: the adapter has
  no dependency on `@pegma/identity`, and its only package dependency is the
  exact synchronized `@pegma/authorization-contracts` version.
- Requires exact enumerable own data properties, verified email eligibility,
  bounded well-formed opaque identifiers, and structurally excludes email and
  all contact data from authorization keys.
- Uses dependency-free portable ESM at runtime for Node, Workers, Deno, and Bun,
  with adversarial coverage for accessors, proxies, inherited and extra fields,
  control characters, malformed Unicode, and overlong identifiers.
- Extends generated API documentation, release inventory checks, clean-consumer
  package imports, and deterministic Node 22/24 packing to the eighth package.

## Packages

- `@pegma/authorization-contracts`
- `@pegma/authorization-auth0`
- `@pegma/authorization-identity`
- `@pegma/authorization-core`
- `@pegma/authorization-policy`
- `@pegma/authorization-stripe`
- `@pegma/authorization-storage`
- `@pegma/authorization-tokens`

All eight packages release together at `0.1.1`, require Node.js 22 or newer,
and are MIT licensed.

## Compatibility

This is a `0.x` release. Public contracts are usable but not yet stable; later
`0.x` releases may contain documented breaking changes. The existing seven
packages receive only the synchronized version and dependency update in this
release.

Hosts remain responsible for producing verified Identity claims, provider
verification, authoritative identity and billing state, durable storage,
signing-key custody, resource relationships, and server-side authorization
enforcement.
