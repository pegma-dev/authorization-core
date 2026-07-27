# @pegma/authorization-auth0

Projects verified Auth0 issuer-and-subject claims into provider-neutral identity
link keys.

```sh
npm install @pegma/authorization-auth0
```

The host must verify the Auth0 token before calling this package. Authorization
Core does not verify Auth0 tokens, link accounts, or use email as an identity
key.

See the [Auth0 integration guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/AUTH0.md).
