# Authorization Core 0.1.2

Authorization Core 0.1.2 is a focused release correction and the first
advertised stable publication of `@pegma/authorization-identity`.

The `v0.1.1` release workflow stopped in its unprivileged test step. One
Identity bootstrap assertion expected the synchronized root-version guard, but
the release event's `RELEASE_TAG`, `RELEASE_COMMIT`, and
`RELEASE_PRERELEASE` variables correctly triggered the earlier manual-only
bootstrap authority guard. Tarball preparation, artifact upload, and the OIDC
publisher were skipped, so no `0.1.1` npm package was published.

This release:

- isolates and restores those three release variables around the assertion so
  it tests the intended bootstrap source-root version guard during release
  workflows;
- advances the root, all eight public package manifests, every exact internal
  Authorization dependency, and the lockfile together to `0.1.2`; and
- publishes the already bootstrapped `@pegma/authorization-identity` adapter
  under its first advertised stable version.

There are no runtime, public API, or behavioral changes. The original seven
packages receive only the synchronized version and internal dependency update.
All eight packages require Node.js 22 or newer and remain MIT licensed.
