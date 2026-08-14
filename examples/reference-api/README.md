# Reference API

This is the complete Phase 5 composition of Authorization Core's public package
entry points. It uses Node's built-in HTTP server and demonstrates:

- post-verification Auth0 issuer/subject projection and exact host identity
  linking;
- request-time Stripe entitlement resolution from freshly loaded persisted
  state;
- target-derived organization scope, membership validation, exact active-role
  selection, and policy resolution;
- display-only `GET /access/me` output;
- reusable allow and deny permission middleware;
- audited role grant and revoke administration through the combined safe
  mutation API;
- structured decision and role-audit logs;
- a deterministic SHA-256 digest computed from the exact canonical policy
  snapshot parsed by the resolver and accepted by grant issuer/verifier;
- runtime-generated P-256 signing, public JWKS, application-scoped grant
  issuance, `verifyAndConsume`, and replay denial.

## Run it

From a clean clone with Node.js 22 or newer:

```sh
pnpm install --frozen-lockfile
pnpm run example
```

That command runs the complete allow, deny, service-call, and replay scenario
and exits. To leave the HTTP API listening on `http://127.0.0.1:3000`:

```sh
pnpm run example:serve
```

Useful routes are:

- `GET /access/me`
- `GET /support/queue`
- `GET /support/destructive`
- `GET /.well-known/jwks.json`
- `POST /admin/role-assignments/grant`
- `POST /admin/role-assignments/revoke`

The administration bodies use exact schemas. Grant accepts only
`principalId`, `role`, and `scope`; the host generates the fresh assignment ID,
grant event ID, and trusted timestamp. Revoke accepts only an existing
`assignmentId` as an untrusted exact-record selector and an optional `reason`;
the host reads the authoritative record token and generates the revoke event ID
and trusted timestamp. Actor, audit IDs, timestamps, concurrency tokens, and a
new grant assignment ID are rejected if supplied in JSON.

Both routes require a bounded `Idempotency-Key` header. Before mutation, the
example atomically binds that key within the application to the exact
operation, trusted actor, canonical validated command, generated identifiers,
timestamp, and—for revoke—the authoritative pre-revocation token. An exact
retry reuses that prepared command; any key reuse with another operation,
actor, target, role, scope, or reason returns a conflict. A fresh regrant uses a
new key and therefore a fresh assignment and event ID, while retrying an old
grant can never reactivate its revoked lifecycle.

Actor identity is never accepted from a body. The routes deny every request
unless the host injects `authorizeAdministrativeRequest`, which returns trusted
verified evidence containing the exact host principal. That principal is then
authorized for application-scoped `roles.manage` and bound to the mutation and
audit. The direct `adminGrantRole` and `adminRevokeRole` helpers require actor
evidence separately and carry the idempotency key in their typed command.

The example manifest is process-local memory so it can demonstrate retries but
is not production durability. A real API must authenticate the request before
returning actor evidence and persist the application-scoped idempotency binding
atomically before mutation, retaining it across ambiguous failures and
restarts. It must also add CSRF protection where applicable, rate limiting, and
durable operational auditing.

`REFERENCE_POLICY_CANONICAL_JSON` is produced from one reviewed JSON data model
by lexicographically sorting object keys. `REFERENCE_POLICY_DIGEST` is computed
with SHA-256 over those exact UTF-8 bytes, and the resolver parses that same
snapshot. Production hosts own this process: their deterministic digest input
must include every policy and deployment fact whose change can affect
authorization, and issuer/verifier configuration must accept only the matching
version and digest.

> [!WARNING]
> This example is not production infrastructure. Its Auth0-shaped claims and
> Stripe facts are synthetic. The claims stand in for output from a real Auth0
> verifier; Authorization Core does not verify them. Its role, identifier
> reservation, and replay stores are ephemeral in-process memory stores, and
> its billing state is an in-memory stand-in for persisted host state.

The example generates a fresh P-256 key at runtime and commits no private key.
Only this in-process demo and its tests import
`@pegma/authorization-tokens/testing`: the issuer receives the demo's wall
clock together with a real monotonic clock and CSPRNG, while the verifier
receives that same wall clock and the public JWKS behind a fixed synthetic
HTTPS URL. Production code uses `createAccessGrantIssuer` and
`createAccessGrantVerifier` with their production dependencies, real HTTPS, and
durable reservation and replay stores. The production verifier intentionally
requires a fixed HTTPS JWKS endpoint.

See [Getting started](../../docs/GETTING_STARTED.md),
[Scoping](../../docs/SCOPING.md), the
[security model](../../docs/SECURITY_MODEL.md), and the normative
[access-grant profile](../../docs/ACCESS_GRANTS.md).
