# Authorization Core 0.1.4

Authorization Core 0.1.4 is the first advertised synchronized release that
includes `@pegma/authorization-entra` as the ninth public package. There are no
runtime or public API changes to the other eight packages.

`@pegma/authorization-entra` projects already-verified Entra v2 `iss` and `oid`
claims into provider-neutral `IdentityLinkKey` values. Linking uses the
tenant-scoped object id rather than pairwise `sub`, and only issuers ending in
the exact `/v2.0` suffix are accepted. A rejected issuer that begins with
`https://sts.windows.net/` gets a v1-specific diagnostic; every other rejected
issuer gets the generic suffix message. The host must verify the token before
calling the projection. Email, `preferred_username`, and other claims never
enter the key.

The package's one-time `0.0.0` name reservation is published under the
non-default `bootstrap` dist-tag from merge commit
`b609f709fecbcc0507b7021e7177d488f0aad574`, and npm trusted publishing is
configured for the existing `publish.yml` / `npm-publish` path. This release
moves the package's `latest` tag to `0.1.4` while republishing the synchronized
version of the eight existing packages. Confirm after publication that `latest`
is `0.1.4`, `bootstrap` remains `0.0.0`, and both registry integrities match.

The root, all nine public package manifests, every exact internal Authorization
dependency, and the lockfile advance together to `0.1.4`. All nine packages
require Node.js 22 or newer and remain MIT licensed.
