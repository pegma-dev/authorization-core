# The Entra adapter: `@pegma/authorization-entra`

Decided 2026-07-27 as a plan; both timing gates opened on 2026-07-29 and the
[implementation specification](#implementation-specification-2026-07-29) below
is now the actionable record. This is the decision record for a Microsoft
Entra ID identity adapter, modeled on `packages/auth0`. ("Decision record",
not "assignment record" — in this repository an assignment is a role
assignment.)

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
- **One issuer profile: v2 only.** Entra can issue the same tenant + `oid`
  under two valid issuer formats — v1 (`https://sts.windows.net/{tid}/`)
  and v2 (`https://login.microsoftonline.com/{tid}/v2.0`) — and exact
  tuple comparison would split one human across them, recreating the very
  fragmentation this decision exists to prevent. The adapter accepts the
  v2 issuer format ONLY and rejects v1 issuers loudly; a host still on v1
  tokens migrates first. Deliberately no silent v1→v2 canonicalization:
  rewriting an issuer is rewriting an identity, and a projection that
  edits its inputs is no longer honest.
- With that pinned, the tenant-specific v2 `iss` slots into
  issuer-namespacing unchanged: B2B guests carry a resource-tenant `oid`,
  multi-tenant apps see one issuer per tenant, and Entra External ID
  (consumer CIAM) speaks the same protocol. All arrive as distinct, honest
  tuples with no special cases.
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

**Both gates opened.** Phase 5 shipped as the synchronized `0.1.2` release on
2026-07-27, and the real consumer materialized on 2026-07-29: the Exsimplify
migration — a Node host on Azure Container Apps keeping Entra External ID
(CIAM) for admin and stylist sign-in (`docs/Pegma-Migration-Plan.md` in that
repository). The consumer arrived as the "Azure-side host" candidate rather
than the workforce support-desk guess; External ID speaks the same v2
protocol, so nothing in the decision changes.

## Implementation specification (2026-07-29)

The decision above is the contract; this section makes it buildable. Where
this section is silent, `packages/auth0` is the answer.

### Phase 0 — contracts audit

Before any code, confirm `@pegma/authorization-contracts` holds no Auth0-isms
(it should not — that is the point of checking):

- `IdentityLinkKey` is an exact, case-sensitive `{ issuer, subject }` tuple
  with no subject-format assumptions (`packages/contracts/src/index.ts`).
- The identity conformance cases in `@pegma/authorization-core/conformance`
  fix only tuple semantics — nothing assumes a `provider|account` subject
  shape or an Auth0 issuer form.
- No public doc equates `subject` with a JWT `sub` claim in a way that would
  make an `oid`-sourced subject read as a violation.

Record the audit outcome in the pull request; expected result is no changes.

### Public API

One exported claims interface and one exported projection function, mirroring
`packages/auth0/src/index.ts`:

```ts
import type { IdentityLinkKey } from "@pegma/authorization-contracts";

/**
 * Minimal Entra claims accepted after the host has verified the token that
 * supplied them. `oid` is the tenant-scoped stable object id; `sub` is
 * pairwise per app registration and is deliberately not accepted.
 */
export interface EntraIssuerObjectIdClaims {
  readonly iss: string;
  readonly oid: string;
}

export const identityLinkKeyFromVerifiedEntraClaims = (
  claims: EntraIssuerObjectIdClaims,
): IdentityLinkKey => /* frozen { issuer: iss, subject: oid } */;
```

Container semantics are identical to the Auth0 adapter: `iss` and `oid` must
be own, nonblank, primitive-string data properties read via property
descriptors (accessors rejected without executing their getters, inherited
properties rejected, boxed strings rejected); all other claims are discarded;
every rejection is a `TypeError`; the output is a fresh frozen object detached
from the input. A `sub` present on the container is ignored like any other
extra claim — it is never a fallback.

### The v2-issuer gate

The single behavior beyond the Auth0 shape, encoding the "v2 only" decision:

- After the own-data checks, the exact preserved `iss` string must end with
  the case-sensitive suffix `/v2.0`. No URL parsing, trimming, host
  allowlisting, or rewriting — the value is still copied exactly.
- Rejection is a `TypeError`. When the rejected issuer contains
  `sts.windows.net`, the message names the v1 token profile and says to move
  the app registration to v2 tokens, so the most likely misconfiguration is
  loud and diagnosable rather than generically malformed.
- Workforce (`https://login.microsoftonline.com/{tid}/v2.0`) and External ID
  CIAM (`https://{name}.ciamlogin.com/{tid}/v2.0`) issuers both pass and
  remain distinct tuples — exact issuer namespacing is doing its job, not a
  special case.

There is deliberately no expected-issuer parameter: the host's verifier
already pinned the exact issuer before projection. The suffix gate only
refuses the v1 profile that verifier configuration might otherwise let
through.

### Tests

Mirror `packages/auth0/src/index.test.ts` one-for-one (realistic-claims
projection, fresh-frozen-detached output, exact preservation, malformed-claims
matrix over both fields, inherited and accessor rejection with a
getter-call-count assertion, and the identity-lookup composition block with a
stub `IdentityAdapter` proving `null`-only-for-unlinked and
operational-failure propagation), then add the Entra-specific pins:

- realistic verified claims carrying `sub`, `tid`, `aud`, `azp`, `email`,
  `preferred_username`, and `roles` project to exactly
  `{ issuer, subject: oid }` — and never the `sub` value;
- the same `oid` under the workforce and CIAM issuer forms yields distinct
  tuples;
- a v1 `sts.windows.net` issuer throws with the v1-specific diagnostic; any
  issuer without the `/v2.0` suffix throws;
- `oid` is preserved exactly with no GUID case normalization;
- `email` and `preferred_username` never appear in outputs or in thrown
  messages (the sensitive-field exclusion the authoring guide requires).

The public conformance suite targets `IdentityAdapter` implementations, not
projections; like Auth0, this package ships composition tests instead of
registering the suite.

### Package and repository wiring

`packages/entra`, publishing `@pegma/authorization-entra`. The manifest,
`tsconfig.json` (project reference to `../contracts`), `LICENSE`, and README
shape mirror `packages/auth0` exactly, changing only name, description, and
`repository.directory`. The `@pegma/authorization-contracts` dependency uses
the exact synchronized version, per the release invariants.

Root wiring the pull request must include:

- `tsconfig.json` — add the `./packages/entra` project reference;
- `tsconfig.check.json` — add the `@pegma/authorization-entra` path mapping;
- `scripts/release-packages.mjs` — add
  `{ directory: "entra", name: "@pegma/authorization-entra", exports: ["."], modules: ["index"] }`
  to `RELEASE_PACKAGES`, and extend the new-package bootstrap machinery
  (either generalize the `IDENTITY_BOOTSTRAP_*` block to a parameterized
  new-package bootstrap or mirror it as `ENTRA_BOOTSTRAP_*` — decide in
  review; verify `scripts/api-docs.mjs` picks up the ninth package);
- `docs/ENTRA.md` — host integration guide modeled on `docs/AUTH0.md`
  (verification prerequisites, exact-copy rules, the v2-only gate, the
  External ID note);
- `docs/PROJECT_PLAN.md` — package-table row and rewording of the
  "remains decided but deliberately unimplemented" paragraph;
- `RELEASING.md` — the eight-package inventory invariant becomes nine, and
  the bootstrap record gains the entra entry;
- root `README.md` package list.

### Release sequence

Three steps, in order, following the Identity precedent exactly:

1. Land the pull request (package, tests, docs, tooling). Nothing publishes
   on merge.
2. One-time name bootstrap: publish `@pegma/authorization-entra@0.0.0` under
   the `bootstrap` dist-tag and configure npm trusted publishing. Never
   promote `0.0.0`.
3. Synchronized release `0.1.3`: root, all nine package manifests, every
   exact internal dependency, and the lockfile advance together;
   `RELEASE_NOTES.md` announces entra as the ninth package with no behavioral
   changes to the other eight.

### Consumer proof

Exsimplify's host wires the full path — `jose` JWKS verification against the
exact CIAM authority, projection through this package, identity-link lookup to
a host principal (linked on first sign-in via the stylist invite flow), then
policy resolution. Anything that path teaches about the contract feeds back
here before any 0.2.x change.
