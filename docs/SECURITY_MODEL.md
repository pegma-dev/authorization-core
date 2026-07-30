# Integration security model

Authorization Core is the trusted server boundary between independently trusted
identity and billing systems, host-owned authorization facts, and protected
application actions.

```text
verified identity ──> exact identity link ──┐
fresh persisted billing facts ─────────────┼─> policy ─> permission decision
target-bound audited roles ────────────────┘                 │
authoritative target relationships ──────────────────────────┘
```

The detailed normative requirements remain in the component guides. This page
is the integration review checklist.

## Trust sources

- Identity is usable only after signature, issuer, audience, lifetime, token
  kind, and flow-specific verification. Provider subject is always paired with
  exact issuer; email is never an authorization key. See
  [Auth0](AUTH0.md), [Entra](ENTRA.md), and [Identity linking](IDENTITY_LINKING.md).
- Billing is usable only after webhook authenticity, ordering, deduplication,
  lifecycle interpretation, customer-to-principal binding, complete
  reconciliation, durable persistence, and freshness enforcement. See
  [Stripe](STRIPE.md).
- Roles come only from audited host storage, selected by exact principal and
  authoritative target-derived scope. See
  [Role assignments](ROLE_ASSIGNMENTS.md), [Storage](STORAGE.md), and
  [Scoping](SCOPING.md).
- Policy is immutable, application-owned, validated at startup, and bound to an
  exact revision and digest. See [Policy](POLICY.md) and
  [Permissions](PERMISSIONS.md).

The host owns a deterministic serialization procedure for the policy and every
deployment input whose change can affect authorization. It computes the policy
digest from those exact reviewed bytes, parses that same snapshot, and
configures grant issuers and verifiers with the resulting version/digest pair.
A copied constant that can outlive a content change is not a policy binding.

## Fail-closed conditions

Unverified or unlinked identity, provider or storage outage, missing or stale
billing state, incomplete or corrupt reads, membership failure, unknown roles
or entitlements, invalid policy, cache expiry or clock regression, stale
in-flight cache fills, grant verification failure, JWKS failure, and replay
conflict deny. Unknown policy inputs may retain declared defaults but never
gain another permission. No path serves stale authorization as a fallback.

An access context or `/access/me` response is display data, not a signed
credential or relationship proof. The trusted server still loads the target and
checks organization, ownership, assignment, and other relationships.

## Privileged mutation and caching

Role changes use only the combined audited mutation API on durable production
storage. Administrative request authentication returns trusted exact actor
evidence; application-scoped `roles.manage` authorization and the audit
mutation use that same host principal. Actor identity never comes from a
mutation body. The host generates lifecycle and audit evidence and durably
binds a validated application-scoped idempotency key to the exact operation,
actor, canonical command, and prepared store command before mutation. Exact
retries reuse that evidence; mismatched reuse conflicts. Revocation is
irreversible, and regrant requires a new key and fresh assignment ID. The first
administrator follows the separate
[bootstrap ceremony](ADMINISTRATOR_BOOTSTRAP.md), never signup or first-login.

Every role-derived cache expires strictly before the original authoritative
read-start plus 60,000 milliseconds. Invalidation targets 5,000 milliseconds
and generation fences prevent a pre-change read from refilling after eviction.
See [Fast role revocation](ROLE_REVOCATION.md).

## Service boundary and secrets

V1 grants are narrow, application-scoped, audience-bound, at most 30 seconds,
and one-use. The issuer owns a runtime or secret-manager supplied P-256 private
key and atomically reserves identifiers. The verifier uses one fixed
issuer-bound HTTPS JWKS URL and atomically consumes the replay tuple before the
protected action. V1 rejects organization-scoped source authorization. See
[Access grants](ACCESS_GRANTS.md).

Never log or return compact grants, identity-provider tokens, private keys,
secrets, emails, provider subjects, billing IDs, raw provider objects, or
sensitive administrative reasons. Structured decision logs should contain only
the host application, principal, target/scope identity when operationally
appropriate, policy revision, exact permission, outcome, and generic reason.
Structured role audit logs may contain host assignment/event IDs, host actor,
role, scope, operation, and result under access-controlled retention.

The runnable [reference API](../examples/reference-api/README.md) exercises
these shapes with synthetic inputs and memory stores. Those fixtures prove
composition, not Auth0 verification, Stripe webhook processing, durable
storage, production key custody, or multi-process replay safety.
