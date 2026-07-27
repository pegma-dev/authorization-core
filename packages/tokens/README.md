# @pegma/authorization-tokens

Issues and verifies short-lived, one-use Pegma access grants.

```sh
npm install @pegma/authorization-tokens @pegma/storage-core jose
```

The package implements the application-scoped ES256 V1 profile, public JWKS
projection, identifier reservation, and atomic replay consumption. Private keys
remain host-owned.

The `@pegma/authorization-tokens/testing` export permits injected JWKS fetches
for tests and the in-process reference example. It is not a production
verification path.

See the [access-grant profile](https://github.com/pegma-dev/authorization-core/blob/main/docs/ACCESS_GRANTS.md).
