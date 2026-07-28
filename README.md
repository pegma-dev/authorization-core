# Authorization Core

[![CI](https://github.com/pegma-dev/authorization-core/actions/workflows/ci.yml/badge.svg)](https://github.com/pegma-dev/authorization-core/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

Provider-neutral roles, entitlements, and permissions for SaaS applications.

> [!IMPORTANT]
> Authorization Core is in early `0.x` development and its public API is not
> yet stable. The original seven packages are published at `0.1.0`; the new
> `@pegma/authorization-identity` package awaits its one-time npm bootstrap
> before its first advertised release.

## Why Authorization Core?

Authentication providers answer **who someone is**. Billing providers report
**what they purchased**. Applications still need one trustworthy place to
combine those facts with staff roles and decide **what the person may do**.

Authorization Core provides that small authorization boundary without replacing your
identity provider, billing provider, or application database.

```text
OIDC identity ───────┐
                    ├──> Authorization Core policy ──> permissions
Billing grants ─────┤
Application roles ──┘
```

## Design principles

- **Provider-neutral:** Auth0 and Stripe integrations are adapters, not
  requirements.
- **Explicit permissions:** Applications authorize actions, not plan names.
- **Separate roles from purchases:** Staff responsibility and commercial access
  can coexist without becoming the same concept.
- **Deny by default:** Unknown roles and entitlements grant nothing.
- **Server-side trust boundary:** Browser-provided roles, plans, and permissions
  are never authoritative.
- **Embeddable first:** The initial product is a library, not another service to
  deploy.

## Current packages

| Package                          | Purpose                                         |
| -------------------------------- | ----------------------------------------------- |
| `@pegma/authorization-contracts` | Provider-neutral access and policy types        |
| `@pegma/authorization-core`      | Pure permission resolution and access decisions |
| `@pegma/authorization-policy`    | Policy parsing, validation, and diagnostics     |
| `@pegma/authorization-auth0`     | Verified Auth0 claims to identity-link keys     |
| `@pegma/authorization-identity`  | Verified first-party claims to identity keys    |
| `@pegma/authorization-stripe`    | Trusted Stripe IDs to active entitlements       |
| `@pegma/authorization-storage`   | Persistence ports over `@pegma/storage-core`    |
| `@pegma/authorization-tokens`    | Signed one-use grants, JWKS, and verification   |

Storage declares its collections against a `@pegma/storage-core` `Store`, so
the assignment-and-audit transaction boundary closes in one single-partition
transaction on whatever backend the host supplies.
`@pegma/authorization-tokens` likewise declares separate identifier-reservation
and replay-consumption collections against host-supplied `Store` instances; it
does not provide or select a persistence backend.

## Start here

The [getting-started guide](docs/GETTING_STARTED.md) gives the complete
integration order. The runnable [reference API](examples/reference-api/README.md)
uses only public package entry points and demonstrates identity linking, fresh
billing state, target-scoped roles, permission middleware, audited
administration, safe logs, public JWKS, and one-use service grants:

```sh
npm ci
npm run example
```

It is explicitly a non-production composition with synthetic provider inputs
and ephemeral memory storage. No example implements Auth0 token verification,
Stripe webhook handling, durable persistence, or production key custody.

Integration documentation:

- [Getting started](docs/GETTING_STARTED.md)
- [Policy reference](docs/POLICY.md) and
  [permission naming](docs/PERMISSIONS.md)
- [Auth0](docs/AUTH0.md), [Stripe](docs/STRIPE.md), and
  [adapter authoring](docs/ADAPTER_AUTHORING.md)
- [Role assignments](docs/ROLE_ASSIGNMENTS.md),
  [storage](docs/STORAGE.md), and
  [administrator bootstrap](docs/ADMINISTRATOR_BOOTSTRAP.md)
- [Application and organization scoping](docs/SCOPING.md)
- [Migration from direct checks](docs/MIGRATION.md)
- [Integration security model](docs/SECURITY_MODEL.md)
- [Signed access grants](docs/ACCESS_GRANTS.md)
- [Generated public API reference](docs/api/README.md)
- [Release operations](docs/RELEASING.md) for maintainers

## Resolver example

```ts
import {
  decideAccess,
  resolveAccess,
  resolveAccessWithDiagnostics,
  serializeAccessContext,
} from "@pegma/authorization-core";
import { parsePolicy } from "@pegma/authorization-policy";

const policy = parsePolicy({
  schemaVersion: 1,
  version: "2026-07-01",
  defaults: ["account.read.own"],
  roles: {
    support: ["support.queue.read", "support.ticket.reply.any"],
  },
  entitlements: {
    "plan.pro": ["support.ticket.create", "support.ticket.read.own"],
  },
});

const access = resolveAccess(
  {
    principalId: "account_123",
    roles: ["support"],
    entitlements: ["plan.pro"],
  },
  policy,
);

const decision = decideAccess(access, "support.queue.read");
// { allowed: true, permission: "support.queue.read", reason: "granted" }

const snapshot = serializeAccessContext(access);
// Stable compact JSON with principalId, policyVersion, roles, entitlements,
// and permissions in that order.

const resolution = resolveAccessWithDiagnostics(
  {
    principalId: "account_456",
    roles: ["renamed-support-role"],
  },
  policy,
);
// resolution.diagnostics.unknownRoles === ["renamed-support-role"]
// resolution.context.permissions still contains defaults only
```

Callers are responsible for verifying identity and loading applicable roles and
entitlements from trusted sources before calling the resolver.

Core `AccessSubject` and `AccessContext` values are principal-only; they do not
carry tenant or organization scope. When a host supports organizations, it
must derive the scope from the exact authorization target, load trusted
membership for that scope, then select only the role assignments applicable to
that same scope before resolution. The host must preserve this binding outside
the access context through any cache key and the final resource check; it must
never apply permissions resolved for one organization to a target in another.
The resulting access context is not proof of organization membership, resource
ownership, or any other relationship. The trusted server must still load the
target resource and enforce its authoritative organization and relationship
checks.

Role-derived authorization caches are host-owned and have a hard 60,000
millisecond lifetime measured from immediately before the first authoritative
role read. Hosts target grant and revocation invalidation delivery within
5,000 milliseconds, while preserving the absolute deadline when delivery is
lost. Exact cache identity includes the application, principal, tagged scope,
policy version, and immutable policy content or deployment digest; cached final
decisions additionally bind their permission and resource relationship inputs.
The application namespace is created inseparably with its authoritative reader
and storage namespace, and policy digests are recomputed from immutable snapshots.
Monotonic deadlines remain in one process clock domain, composed facts require
the same opaque domain token and matching identities, and entries and inputs are
immutable snapshots. Expiry, invalid or regressing clock state, refresh
failure, and stale in-flight fills fail closed; a clock anomaly permanently
retires that shared domain for caches and composed decisions. See
[Fast role revocation and cache bounds](docs/ROLE_REVOCATION.md).

The [Pegma access-grant V1 profile](docs/ACCESS_GRANTS.md) and
`@pegma/authorization-tokens` implement a short-lived, one-use service
credential.
It carries only a canonical nonempty audience-allowlisted subset of effective
permissions, plus exact issuer, one service audience, host principal, lifetime,
policy version and digest, exact provider-neutral host application identity,
and profile metadata. It never carries roles, entitlements, provider
identities, or a serialized access context. V1 is application-scoped and has no
organization claim; organization-derived permissions require a future
separately confined profile. ES256 verification uses only a fixed issuer-bound
HTTPS JWKS endpoint, and atomic consumption of
`(iss, application_id, aud, jti)` occurs after every other verification
succeeds and before any protected action, preventing reuse after the first
successful request. The 30-second nominal lifetime reserves a maximum
five-second negative verifier clock offset inside the source monotonic
authorization deadline and permits no positive expiration leeway.

The issuer owns its source reader, application-controlled P-256 private key,
clocks, and secure identifier generation. Its opaque read evidence snapshots
the authoritative `AccessContext` and original deadline before it can be bound
and signed. Before signing, it atomically and permanently reserves the
issuer/application/`jti` tuple through its host-supplied
`@pegma/storage-core` `Store`. The verifier owns one exact
issuer/application/audience/policy configuration and exposes only
`verifyAndConsume`; it validates a fixed HTTPS JWKS, then atomically inserts
the separate replay tuple before returning verified permissions. Private keys
never enter a Pegma package or JWKS.

`resolveAccessWithDiagnostics` is an opt-in observability API. It returns the
same access context as `resolveAccess` plus canonical lists of unknown subject
roles and entitlements. Diagnostics never grant permissions, fail startup, or
log automatically; the host decides whether and where to record them.

`serializeAccessContext` produces a stable, compact JSON snapshot for storage,
logging, or display. The snapshot is unauthenticated: never accept it from a
browser as authoritative input or use it in place of a signed access grant.
Browser-facing snapshots may also need filtering when role or permission names
would reveal staff responsibilities or unreleased features.

### Adapter boundary

`@pegma/authorization-contracts` exposes narrow async provider-neutral ports:

```ts
import type {
  IdentityAdapter,
  IdentityLink,
} from "@pegma/authorization-contracts";
import { identityLinkKeyFromVerifiedAuth0Claims } from "@pegma/authorization-auth0";
import {
  createStripeEntitlementAdapter,
  type StripeEntitlementStateLoader,
} from "@pegma/authorization-stripe";

const hostIdentityLinks: readonly IdentityLink[] = [
  {
    key: {
      issuer: "https://identity.example.test/",
      subject: "provider|account",
    },
    principalId: "account_123",
  },
];
const identity: IdentityAdapter = {
  resolvePrincipalId: async (key) =>
    hostIdentityLinks.find(
      (link) =>
        link.key.issuer === key.issuer && link.key.subject === key.subject,
    )?.principalId ?? null,
};

// The host verifies the token before calling this projection.
const key = identityLinkKeyFromVerifiedAuth0Claims({
  iss: "https://identity.example.test/",
  sub: "provider|account",
});
const principalId = await identity.resolvePrincipalId(key);

const stripeStateLoader: StripeEntitlementStateLoader = {
  loadPersistedEntitlementState: async (principalId) => {
    const state = await hostBillingStore.load(principalId);
    if (state === null) {
      throw new Error("persisted entitlement state is missing");
    }
    return state;
  },
};

const billing = createStripeEntitlementAdapter(
  [
    {
      kind: "feature",
      id: "feat_priority_support",
      entitlements: ["support.priority"],
    },
    {
      kind: "price",
      id: "price_pro_monthly",
      entitlements: ["plan.pro"],
    },
  ],
  stripeStateLoader,
  15 * 60 * 1000, // Host-chosen and documented 15-minute maximum state age.
);

if (principalId === null) throw new Error("identity is not linked");
const entitlements = await billing.resolveEntitlements({ principalId });
```

Identity adapters consume host-verified issuer-and-subject evidence and return a
host-owned principal ID, never a provider subject or email. Each exact,
case-sensitive issuer-and-subject tuple links to zero or one principal; a
principal may have multiple linked tuples. `null` means no link exists, while
operational failures reject. The host owns verification and the privileged
link, unlink, and merge lifecycle.

Entitlement adapters accept a host principal key and return currently active
host entitlement names only. The official Stripe adapter reloads trusted
persisted state for that principal on every resolution, then applies the
compiled exact-ID allowlist in either Product Feature or Price fallback mode.
Each persisted record includes a host-recorded `refreshedAtEpochMs`, and adapter
construction requires a positive safe-integer maximum age. State exactly at the
bound is accepted; the adapter rejects older, future-dated, or malformed state,
so a missed webhook cannot silently preserve paid access indefinitely.
Request-time callers do not pass transient billing facts. The host loads roles
separately and remains responsible for webhook verification, lifecycle
decisions, durable storage, choosing and documenting the bound, and
reconciliation. A webhook or
reconciliation writer advances `refreshedAtEpochMs` only after successfully
confirming complete provider state; database reads, rewrites, and cache fills
must not advance it. The low-level translator remains available for trusted
webhook and reconciliation pipelines, but wrapping transient request facts in a
custom adapter bypasses this supported request-time boundary. See the
[identity-linking guide](docs/IDENTITY_LINKING.md) for the normative model and
lifecycle requirements, the [Auth0 guide](docs/AUTH0.md) for verification
prerequisites and identity translation, and the
[Stripe guide](docs/STRIPE.md) for the billing trust boundary and translation
modes. Application-owned staff grants follow the immutable
[role-assignment model](docs/ROLE_ASSIGNMENTS.md): the host selects active
assignments by exact principal and target-derived scope, then passes role names
only into access resolution. The
[administrator-bootstrap guide](docs/ADMINISTRATOR_BOOTSTRAP.md) defines the
separate one-time host ceremony for the first application administrator. It
requires an independently verified pre-existing host principal, an immutable
retry manifest, a durable host-owned one-shot gate, the combined audited
mutation boundary, exact durable readback, policy verification, and prompt
resumable removal of bootstrap authority and temporary credentials before the
gate becomes terminal. It is never a signup, login, invitation, browser,
first-user, or provider-role flow. The types-first
[storage package](docs/STORAGE.md) defines exact principal lookup, atomic
role-lifecycle persistence, append-only role audit ports, and one
implementation of them over a `@pegma/storage-core` `Store`. One store instance
belongs to one host application; a shared backend binds that application
partition at construction instead of accepting it as query input. The low-level
role mutation and audit append ports remain separate, non-atomic contracts,
while `createRoleStore` exposes only combined audited mutations and settles
each one in a single-partition transaction. `createInMemoryStorageAdapter` is
that same implementation over the in-process memory store, so it is ephemeral
and non-durable but enforces the same key and concurrency rules.

Validate application-owned policy during startup and stop boot when
`parsePolicy` reports an error. See the [policy guide](docs/POLICY.md) for the
schema, parser-enforced grammar, version semantics, and diagnostic API. See the
[permission guide](docs/PERMISSIONS.md) for application naming conventions,
authorization boundaries, compatibility effects, and safe staged migrations.

## Development

Authorization Core requires Node.js 22 or newer.

```sh
npm ci
npm run check
npm test
npm run format:check
npm run docs:api:check
```

See the [project plan](docs/PROJECT_PLAN.md) for scope, architecture, milestones,
and the path to the first stable release.

## Contributing and security

Contributions are welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md) before
opening a pull request.

Do not report vulnerabilities in public issues. Follow
[SECURITY.md](SECURITY.md) instead.

## Origin

Authorization Core was created by [RetireGolden](https://retiregolden.org) as a reusable
access boundary for modern SaaS applications. The core project is intentionally
not retirement-specific.

## License

[MIT](LICENSE) © 2026 RetireGolden, LLC
