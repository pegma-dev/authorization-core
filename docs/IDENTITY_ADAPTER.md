# The Identity adapter: `@pegma/authorization-identity`

Implemented 2026-07-27 against the current structural
`@pegma/identity` verified-claims contract. This is the decision record for
linking Pegma's first-party identity component into Authorization Core.

## Why an adapter at all

`@pegma/identity` deliberately does not depend on
`@pegma/authorization-contracts`. An identity provider that imports the
authorization layer couples the two halves this library exists to keep apart.
The projection from identity's verified claims to an `IdentityLinkKey`
therefore lives here, beside `packages/auth0`: already-verified claims in,
frozen `{ issuer, subject }` out, with no verification, network access,
storage, or identity resolution.

First-party identity gets no architectural shortcut for being ours. It enters
through the same door as Auth0 and Entra, which lets a host link identities
from multiple providers to one principal without special cases.

## Contract

- `issuer` is a host-configured stable string carried verbatim in identity's
  claims. It must not change after users exist because an issuer rename
  fragments every existing identity link.
- `subject` is identity's stable `PrincipalId`, treated here as an opaque
  provider subject and preserved verbatim.
- The accepted structural shape is exactly
  `{ issuer: string, subject: PrincipalId, emailVerified: true }`. This package
  exports that structural `VerifiedIdentityClaims` interface but deliberately
  does not depend on `@pegma/identity`; either package can evolve and publish
  independently while TypeScript proves the shapes remain compatible.
- Every field must be an enumerable own data property. Inherited fields,
  accessors, symbols, extra fields, and exotic ordinary containers are
  rejected. Descriptor-based validation does not execute getters on ordinary
  objects.
- Portable JavaScript cannot identify a `Proxy` without invoking reflective
  traps, and a transparent proxy is indistinguishable from its target. The
  adapter therefore makes no no-trap or blanket proxy-rejection promise:
  throwing reflection traps become the same generic malformed-claims error,
  while a transparent proxy may pass. Trusted hosts should pass the plain
  verified-claims snapshot produced by the identity boundary, not a proxy.
- `issuer` and `subject` must be nonblank, well-formed Unicode strings. The
  issuer is limited to 1,024 UTF-16 code units and the subject to 512. C0, DEL,
  and C1 control characters are rejected. Otherwise both identifiers are
  opaque and preserved exactly.
- `emailVerified` is an eligibility requirement, not authorization data. It
  must be exactly `true` and is omitted from the output. Email and all other
  contact data are not accepted, so they cannot leak into an identity-link
  key.

## Usage

```ts
import { identityLinkKeyFromVerifiedIdentityClaims } from "@pegma/authorization-identity";

const key = identityLinkKeyFromVerifiedIdentityClaims({
  issuer: "https://identity.example.test",
  subject: verifiedPrincipalId,
  emailVerified: true,
});
```

The host calls this only after its trusted identity flow has produced verified
claims. The adapter does not authenticate sessions, resolve or mutate
principal links, or persist anything.

## Publication

The package source is part of the synchronized Authorization Core package set.
The npm name is new, so it still requires a reviewed one-time `0.0.0`
non-default-tag bootstrap and trusted-publisher configuration before it can
join an advertised synchronized release. See
[RELEASING.md](RELEASING.md#bootstrap-for-the-new-identity-adapter-package).
