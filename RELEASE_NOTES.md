# Authorization Core 0.2.0

Authorization Core 0.2.0 is a synchronized dependency-alignment release. It
aligns `@pegma/storage-core` at `0.4.0` in `@pegma/authorization-storage` and
`@pegma/authorization-tokens`, matching the pin already used by webhooks, mail,
and identity so host dependency trees resolve a single storage-core and no
longer need an npm override to avoid two incompatible `Store` types.

There are no runtime, behavioral, or public API changes in any package. The
version advances to `0.2.0` (rather than a patch) because consumers that
compose `@pegma/authorization-storage` or `@pegma/authorization-tokens` must
now supply a storage-core `0.4.0` `Store`, which is a breaking composition
change under `0.x` semver.

The root, all nine public package manifests, every exact internal Authorization
dependency, and the lockfile advance together to `0.2.0`. All nine packages
require Node.js 22 or newer and remain MIT licensed.
