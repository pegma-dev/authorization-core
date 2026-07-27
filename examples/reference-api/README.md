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
npm ci
npm run example
```

That command runs the complete allow, deny, service-call, and replay scenario
and exits. To leave the HTTP API listening on `http://127.0.0.1:3000`:

```sh
npm run example:serve
```

Useful routes are:

- `GET /access/me`
- `GET /support/queue`
- `GET /support/destructive`
- `GET /.well-known/jwks.json`
- `POST /admin/role-assignments/grant`
- `POST /admin/role-assignments/revoke`

The administration bodies contain only mutation commands. Actor identity is
never accepted from those bodies. The HTTP routes deny every request unless the
host injects an `authorizeAdministrativeRequest` function that returns trusted,
verified actor evidence containing the exact host principal. That principal is
then authorized for application-scoped `roles.manage` and bound to both the
combined mutation and its audit record. The in-process `adminGrantRole` and
`adminRevokeRole` helpers likewise require actor evidence as a separate first
argument. A real API must authenticate the request before returning that
evidence, then also add command schema validation, CSRF protection where
applicable, rate limiting, and durable operational auditing.

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
The production verifier intentionally requires a fixed HTTPS JWKS endpoint.
Only this in-process demo and its tests import
`@pegma/authorization-tokens/testing` to inject the public JWKS behind a fixed
synthetic HTTPS URL. Production code uses `createAccessGrantVerifier`, real
HTTPS, and a durable replay `Store`.

See [Getting started](../../docs/GETTING_STARTED.md),
[Scoping](../../docs/SCOPING.md), the
[security model](../../docs/SECURITY_MODEL.md), and the normative
[access-grant profile](../../docs/ACCESS_GRANTS.md).
