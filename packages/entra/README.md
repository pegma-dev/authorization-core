# @pegma/authorization-entra

Projects verified Entra issuer and object-id claims into provider-neutral
identity link keys.

```sh
npm install @pegma/authorization-entra
```

The host must verify the Entra token before calling this package. Authorization
Core does not verify Entra tokens, link accounts, or use email as an identity
key. Linking uses tenant-scoped `oid`, never pairwise `sub`, and only the v2
issuer profile is accepted.

See the [Entra integration guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/ENTRA.md).
