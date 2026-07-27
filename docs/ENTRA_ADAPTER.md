# The Entra adapter: `@pegma/authorization-entra`

Decided 2026-07-27 as a plan; implementation is deliberately deferred (see
Timing). This is the assignment record for a Microsoft Entra ID identity
adapter, modeled on `packages/auth0`.

## Why

A second identity provider proves the provider-neutral contracts the same
way a second storage backend proves Storage Core's conformance suite: the
`IdentityLinkKey` tuple either survives contact with a provider that was
not in the room when it was designed, or it gets fixed while fixing is
cheap. Entra is the right second provider because the stack's first
reference environment is Azure, and because the most plausible first
consumer is **staff sign-in**: support-desk Support/Admin roles
authenticating through a workforce tenant while customers stay on Auth0 —
two providers, one principal model, which is exactly the fragmentation this
library exists to prevent.

## Precedent: the Auth0 adapter's shape is the contract

`packages/auth0` is a pure projection: already-verified `{ iss, sub }` in,
frozen `{ issuer, subject }` out. No token decoding, no verification, no
network — trust is established by the host before the adapter is invoked.
The Entra adapter keeps exactly that shape and size.

## The decision this adapter exists to encode

Entra's claims do not map naively onto Auth0's:

- **`sub` is pairwise per app registration.** Stable for a user only within
  one application. A host with two app registrations in one tenant — a web
  app and a desktop client, say — would see the same human as two subjects,
  and issuer-namespaced `sub` linking would mint two principals. That is
  identity fragmentation, silently.
- **`oid` is the tenant-scoped stable object id** — the same value for the
  user across every app in the tenant. **The adapter links on
  `iss` + `oid`, and this is not configurable.** One right answer,
  documented, is worth more to an agent-assembled host than an option; a
  host that genuinely wants pairwise isolation is choosing fragmentation
  and can project its own key without this package.
- The tenant-specific `iss` (`https://login.microsoftonline.com/{tid}/v2.0`)
  slots into issuer-namespacing unchanged: B2B guests carry a resource-
  tenant `oid`, multi-tenant apps see one issuer per tenant, and Entra
  External ID (consumer CIAM) speaks the same protocol. All arrive as
  distinct, honest tuples with no special cases.
- Reject a missing/blank `oid` loudly (same posture as the Auth0 adapter's
  claim validation). Never touch `email`/`preferred_username` — the core
  invariant (email is not an authorization key) already forbids it, and
  Entra's are mutable besides.

## Shape of the work

`packages/entra`, publishing `@pegma/authorization-entra`:
`identityLinkKeyFromVerifiedEntraClaims({ iss, oid })` plus the same
malformed-container rejections `packages/auth0/src/index.test.ts` pins.
Phase 0 of the work is a contracts audit: confirm nothing in
`@pegma/authorization-contracts` quietly assumes Auth0-isms (it should not
— that is the point of checking). Tests mirror the Auth0 suite.

## Timing

Plan now, implement on pull. Two gates, in order: the library's Phase 5
(first public 0.x packages) ships first — nothing new lands in the middle
of the publishing slice — and a real consumer materializes (the support-desk
staff-SSO candidate above, or an Azure-side host). This document exists so
the decision — especially `oid`-not-`sub` — is already made when that day
comes.
