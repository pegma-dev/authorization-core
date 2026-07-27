# The Identity adapter: `@pegma/authorization-identity`

Decided 2026-07-27 as a plan; implementation waits for `@pegma/identity`
to exist (its plan: <https://github.com/pegma-dev/identity/blob/main/docs/PROJECT_PLAN.md> - that repository's plan, not this one's). This is the
decision record for the adapter linking Pegma's first-party identity
component into Authorization Core.

## Why an adapter at all

`@pegma/identity` deliberately does NOT depend on
`@pegma/authorization-contracts` — an identity provider that imports the
authorization layer couples the two halves this library exists to keep
apart. So the projection from identity's verified claims to an
`IdentityLinkKey` lives here, beside `packages/auth0`, in the same shape:
already-verified claims in, frozen `{ issuer, subject }` out, no
verification, no network, a few dozen lines. First-party identity gets no
architectural shortcut for being ours: it enters through the same door as
Auth0 and Entra, which is precisely what makes running it ALONGSIDE an
external provider (both linked to one principal) work with no special
cases.

## The decisions

- **`issuer` is a host-configured stable string** (identity's claims carry
  it verbatim). It must never change once users exist — renaming an issuer
  is mass identity fragmentation, the same trap the Entra record pins for
  v1/v2 profiles. The adapter validates presence and nonblankness, exactly
  like the Auth0 adapter's claim checks; choosing it wisely (an https URL
  under the host's domain) is the host's one-time job, documented loudly.
- **`subject` is identity's stable user id** (its `PrincipalId` value,
  projected verbatim as an opaque string). The adapter does not know or
  care that it happens to equal a storage principal — through this door it
  is a provider subject like any other.
- **Nothing else crosses.** `emailVerified` and contact email stay on the
  identity side; the core invariant (email is never an authorization key)
  already forbids them here, and the adapter's surface makes the refusal
  structural.

## Shape of the work

`packages/identity-link` (publishing `@pegma/authorization-identity`):
`identityLinkKeyFromVerifiedIdentityClaims({ iss, sub })`, the same
malformed-container rejections the Auth0 suite pins, tests mirroring
`packages/auth0/src/index.test.ts`. Smaller than this document.

## Timing

After `@pegma/identity` Phase 2 exists to emit real claims, and never
before this library's Phase 5 publish completes. The Entra record's gate
logic applies verbatim: plan now so the decisions are settled; implement
on pull.
