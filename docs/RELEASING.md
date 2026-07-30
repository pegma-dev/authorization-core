# Release operations

Authorization Core releases all nine public workspace packages at one common
version. No package is published by merging a pull request. Publication is a
separate operator action after review.

The normal release path is a stable GitHub release. Its workflow uses npm
trusted publishing and provenance, packs the release commit once, and publishes
those exact tarballs in dependency order. The one-time `0.0.0` bootstrap below
exists only because npm cannot configure a trusted publisher until each package
name exists.

## Release invariants

The release tool fails before packing unless all of these remain true:

- the public inventory is exactly contracts, Auth0, Entra, first-party Identity,
  core, policy, Stripe, storage, and tokens;
- every root and workspace manifest has one stable semantic version;
- every internal `@pegma/authorization-*` dependency uses that exact version;
- the lockfile matches the manifests;
- all workspaces are public MIT-licensed ESM packages for Node 22 or newer,
  with the expected repository, files allowlist, and exports;
- every package contains its own README and license;
- packed exports can be imported from a clean consumer installation; and
- packed source maps include their source.

The prepared `package-manifest.json` records the exact Git commit, release tag
when supplied, package order, tarball filename, SHA-1, SHA-512 integrity, and
file inventory. Publication rechecks the event commit, tag, package order, and
every tarball hash.

## One-time package-name bootstrap

Completed on 2026-07-27. All seven `0.0.0` packages were published under the
non-default `bootstrap` dist-tag and configured for trusted publishing. Do not
repeat this ceremony or promote `0.0.0` to `latest`; the instructions remain
below only as the recovery and audit record.

Do this only once, after the release-bootstrap pull request is merged. Create a
protected signed annotated Git tag for the audited bootstrap commit, but do not
create a GitHub release for `0.0.0` and do not use the `latest` dist-tag. The
bootstrap packages intentionally have no GitHub provenance; the signed tag is
their durable source anchor. They exist only to permit trusted-publisher
configuration. `0.1.0` became the first advertised release on 2026-07-27.

### 1. Prepare the reviewed bytes

Use a clean checkout of the reviewed commit on `main`, with Node 24 and the
reviewed npm version:

```sh
git fetch origin
git switch --detach origin/main
npm install --global npm@11.18.0
npm ci
npm run format:check
npm run check
npm test
npm run release:pack -- -- --require-clean --require-main-ancestor --output .release
npm run release:registry:check -- -- --manifest .release/package-manifest.json
```

Before the first publish, the registry check must report all seven versions as
`absent`. Preserve the complete `.release` directory until the ceremony is
finished. It is ignored by Git.

### 2. Sign and protect the source tag

Before pushing, ensure the repository's tag ruleset covers `v*`, restricts tag
updates and deletions, and permits only the release maintainers to create a
release tag. Release automation uses Git's SSH signature format and an explicit
allowed-signers file, so configure the maintainer's approved SSH signing key
before creating the signed annotated tag:

```sh
git config gpg.format ssh
git config user.signingkey ~/.ssh/pegma-release-signing-key
git config gpg.ssh.allowedSignersFile ~/.config/pegma/release-allowed-signers
git tag --sign v0.0.0 --message "Authorization Core bootstrap v0.0.0" HEAD
git verify-tag v0.0.0
git rev-parse HEAD
git rev-parse "v0.0.0^{commit}"
git push origin refs/tags/v0.0.0
```

The two commit IDs must equal each other and the `gitCommit` in
`.release/package-manifest.json`. Verify the pushed tag from a fresh fetch.
Never move, replace, or delete this tag; if any byte or metadata must change,
prepare a new version.

### 3. Publish under the non-default npm tag

Authenticate the human npm operator using npm's current interactive login
requirements. Publish only these prepared tarballs, in this order:

```sh
npm publish .release/pegma-authorization-contracts-0.0.0.tgz --access public --tag bootstrap
npm publish .release/pegma-authorization-auth0-0.0.0.tgz --access public --tag bootstrap
npm publish .release/pegma-authorization-core-0.0.0.tgz --access public --tag bootstrap
npm publish .release/pegma-authorization-policy-0.0.0.tgz --access public --tag bootstrap
npm publish .release/pegma-authorization-stripe-0.0.0.tgz --access public --tag bootstrap
npm publish .release/pegma-authorization-storage-0.0.0.tgz --access public --tag bootstrap
npm publish .release/pegma-authorization-tokens-0.0.0.tgz --access public --tag bootstrap
```

Run the registry check after each command. An already-published package is safe
to continue past only when it reports `exact`:

```sh
npm run release:registry:check -- -- --manifest .release/package-manifest.json
```

The check treats only npm `E404` as absent. It fails if an existing version has
different integrity or if the registry lookup itself fails. Never unpublish and
reuse a version; npm versions are immutable.

If the workstation or connection fails partway through, keep or reconstruct the
same clean checkout with Node 24 and npm 11.18.0, prepare the tarballs again,
and run the registry check. Skip entries reported as `exact`, publish entries
reported as `absent` in the listed order, and stop on any mismatch.

### 4. Configure trusted publishing

For each of the seven packages on npmjs.com, add this GitHub Actions trusted
publisher:

- organization or user: `pegma-dev`
- repository: `authorization-core`
- workflow: `publish.yml`
- environment: `npm-publish`
- allowed action: `npm publish` only

The workflow name is relative to `.github/workflows`; do not enter a branch or
tag. Trusted-publisher configuration can only be conclusively tested by a real
publish, so verify every field twice.

Create the `npm-publish` GitHub environment if it does not already exist.
The environment name must match npm's publisher configuration. In an
organization with multiple independent release maintainers, protect it with a
required approval and prevent the workflow initiator from self-approving. A
single-maintainer organization cannot provide an independent approval and must
not add a second account solely to simulate one; leave required reviewers
unset until another independent maintainer exists. The signed protected tag,
approved-signer check, exact artifact verification, and environment-scoped OIDC
identity remain the release controls. Do not add an npm token or a
`NODE_AUTH_TOKEN` secret.

Create the repository Actions variable `RELEASE_ALLOWED_SIGNERS`. Its value is
the reviewed Git SSH allowed-signers content, with one approved principal and
public key per line, for example:

```text
release-maintainer@example.com ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAA...
```

This is public key material, not a secret. Keep the variable's administrative
write access as narrow as tag and environment administration. The workflow
writes it to a fresh runner-local file and configures
`gpg.ssh.allowedSignersFile`; an absent variable, lightweight tag, unsigned tag,
unlisted signer, or invalid signature fails before dependency installation.
Test signer rotation with a disposable signed tag before removing an old key.

Confirm that `bootstrap` is not the default npm dist-tag for any package. Leave
the package names otherwise untouched until the `0.1.0` release.

## Bootstrap for the new Identity adapter package

`@pegma/authorization-identity` was not one of the seven names reserved by the
2026-07-27 bootstrap. Before the package joins an advertised synchronized
release, it needs the same one-time name reservation and trusted-publisher
configuration. This does not reopen or alter the completed seven-package
`v0.0.0` ceremony.

The audited bootstrap source stays internally consistent: root and all eight
source packages use common version `0.1.0`, and the new package keeps its exact
`@pegma/authorization-contracts@0.1.0` dependency. The signed annotated
`authorization-identity-v0.0.0` tag targets merged `main` commit
`afdf3f168d355629b2721512c246c1a18fd54c9d`. Always prepare the name-reservation
artifact from that tag, never from the later synchronized release branch. The
dedicated package-only gate stages only the new package with publish version
`0.0.0`; no intermediate version-mismatched source tree is needed:

```sh
git fetch origin tag authorization-identity-v0.0.0
git verify-tag authorization-identity-v0.0.0
test "$(git rev-parse 'authorization-identity-v0.0.0^{commit}')" = "afdf3f168d355629b2721512c246c1a18fd54c9d"
git switch --detach authorization-identity-v0.0.0
npm ci
npm run format:check
npm run check
npm test
npm run identity-bootstrap:check
npm run identity-bootstrap:pack -- -- --require-clean --require-main-ancestor --output .identity-bootstrap
npm run identity-bootstrap:registry:check -- -- --manifest .identity-bootstrap/identity-bootstrap-manifest.json
```

Run the normal gate and the package-only gate on Node 22 and 24. The bootstrap
tool verifies common-version source metadata and lockfile state, the exact
single dependency, package-local `prepack`, allowlisted files, inline-source
maps, dependency-free portable ESM import, a clean consumer install, production
dependency audit, tarball hashes, and npm registry integrity. Its manifest has
a bootstrap-only schema and exactly one package. There is deliberately no
bootstrap publish command, the tool refuses release/OIDC authority, and the
stable OIDC publisher rejects its manifest.

The protected signed annotated `authorization-identity-v0.0.0` source tag
already exists. Fetch it and verify both its approved signature and exact
`afdf3f168d355629b2721512c246c1a18fd54c9d` target as shown above. If any check
fails, stop: do not recreate, move, or force the tag. Publish only the prepared
tarball manually:

```sh
npm publish .identity-bootstrap/pegma-authorization-identity-0.0.0.tgz --access public --tag bootstrap
```

For a package's first-ever publication, npm forces `latest` to the first
version even when `--tag bootstrap` was requested. An immediate attempt to
remove that only `latest` tag can fail with HTTP 400. Do not unpublish, retry
with different bytes, or treat tag removal as a bootstrap prerequisite.
Verify the `0.0.0` integrity, ensure the `bootstrap` tag points to it, and
configure the same `publish.yml` / `npm-publish` trusted publisher described
above.

Keep the unavoidable `latest=0.0.0` window as short as operationally possible.
The synchronized `v0.1.1` workflow stopped in its unprivileged test step before
tarball preparation, artifact upload, or OIDC publication. No `0.1.1` package
version was published. The focused synchronized `0.1.2` correction therefore
moves the new package's `latest` tag to `0.1.2` while publishing the
synchronized version of the seven existing packages. Confirm `latest` is
`0.1.2`, `bootstrap` remains `0.0.0`, and both registry integrities match. Do
not create a GitHub release for the package-name reservation itself.

## Bootstrap for the new Entra adapter package

`@pegma/authorization-entra` was not one of the eight names reserved by the
completed bootstrap ceremonies. Before the package joins an advertised
synchronized release, it needs the same one-time name reservation and
trusted-publisher configuration. This does not reopen or alter the completed
seven-package `v0.0.0` ceremony or the Identity package bootstrap.

The audited bootstrap source stays internally consistent: root and all nine
source packages use common version `0.1.3`, and the new package keeps its exact
`@pegma/authorization-contracts@0.1.3` dependency. After the Entra adapter pull
request merges, create a protected signed annotated
`authorization-entra-v0.0.0` source tag targeting that exact merge commit.
Always prepare the name-reservation artifact from that tag, never from a later
synchronized release branch. The dedicated package-only gate stages only the
new package with publish version `0.0.0`:

```sh
git fetch origin tag authorization-entra-v0.0.0
git verify-tag authorization-entra-v0.0.0
git switch --detach authorization-entra-v0.0.0
npm ci
npm run format:check
npm run check
npm test
npm run entra-bootstrap:check
npm run entra-bootstrap:pack -- -- --require-clean --require-main-ancestor --output .entra-bootstrap
npm run entra-bootstrap:registry:check -- -- --manifest .entra-bootstrap/entra-bootstrap-manifest.json
```

Run the normal gate and the package-only gate on Node 22 and 24. The bootstrap
tool verifies common-version source metadata and lockfile state, the exact
single dependency, package-local `prepack`, allowlisted files, inline-source
maps, dependency-free portable ESM import, a clean consumer install, production
dependency audit, tarball hashes, and npm registry integrity. Its manifest has
a bootstrap-only schema and exactly one package. There is deliberately no
bootstrap publish command, the tool refuses release/OIDC authority, and the
stable OIDC publisher rejects its manifest.

After verifying the signed annotated `authorization-entra-v0.0.0` source tag,
publish only the prepared tarball manually:

```sh
npm publish .entra-bootstrap/pegma-authorization-entra-0.0.0.tgz --access public --tag bootstrap
```

For a package's first-ever publication, npm forces `latest` to the first
version even when `--tag bootstrap` was requested. An immediate attempt to
remove that only `latest` tag can fail with HTTP 400. Do not unpublish, retry
with different bytes, or treat tag removal as a bootstrap prerequisite.
Verify the `0.0.0` integrity, ensure the `bootstrap` tag points to it, and
configure the same `publish.yml` / `npm-publish` trusted publisher described
above.

Keep the unavoidable `latest=0.0.0` window as short as operationally possible.
The synchronized `0.1.4` release then moves the new package's `latest` tag to
`0.1.4` while publishing the synchronized version of the eight existing
packages. Confirm `latest` is `0.1.4`, `bootstrap` remains `0.0.0`, and both
registry integrities match. Do not create a GitHub release for the package-name
reservation itself.

## First advertised release and later releases

The first advertised release completed on 2026-07-27. The protected signed
annotated `v0.1.0` tag targets
`c5186b8258a786641da15b9f47404630c4374aee`; the release workflow published all
seven `0.1.0` packages through OIDC with exact prepared integrity and
provenance. The procedure remains below as the release contract for later
versions.

The `0.1.0` release pull request:

1. changes the root and all seven workspaces from `0.0.0` to `0.1.0`;
2. changes every internal `@pegma/authorization-*` dependency to exact
   `0.1.0`;
3. regenerates the lockfile and confirms it has the same versions and ranges;
4. adds reviewed release notes; and
5. passes the normal gate and `npm run release:pack` under Node 22 and 24.

External dependency versions are independent and must not be changed merely to
match this repository's release.

The `0.1.1` release pull request followed the same invariant with eight
workspaces, but its release-event test run failed before any package was
prepared or published. The `0.1.2` correction changes only the release test,
the common synchronized version, exact internal dependency versions, lockfile,
and these release records. It is the first advertised stable release for
`@pegma/authorization-identity`; there are no runtime or public API changes.

After that pull request is merged, identify the exact `origin/main` commit.
With the same protected `v*` tag ruleset, create and push a signed annotated tag
whose name exactly matches the manifests. Verify the pushed tag before creating
the non-prerelease GitHub release:

```sh
git fetch origin
git switch --detach origin/main
git config gpg.format ssh
git config user.signingkey ~/.ssh/pegma-release-signing-key
git config gpg.ssh.allowedSignersFile ~/.config/pegma/release-allowed-signers
git tag --sign v0.1.0 --message "Authorization Core v0.1.0" HEAD
git verify-tag v0.1.0
git push origin refs/tags/v0.1.0
git fetch origin tag v0.1.0 --force
git verify-tag v0.1.0
gh release create v0.1.0 --verify-tag --title "v0.1.0" --notes-file RELEASE_NOTES.md
```

For this prepared release, use `v0.1.2` consistently in those commands after
the reviewed release pull request merges. Never move the existing `v0.1.0` or
`v0.1.1` tags.

The workflow's unprivileged preparation job checks out the fully qualified tag,
requires an approved valid SSH-signed annotated tag, and proves that the tag
target, checkout, and GitHub release-event commit are identical. It rejects
prereleases, a tag/version mismatch, a tag commit not contained in
`origin/main`, a dirty or inconsistent package set, or changed tarball bytes.
That job uses Node 24.18.0 and npm 11.18.0, runs the full gate without OIDC
publication authority, and uploads the prepared directory with a recorded
artifact digest.

Only the minimal protected `npm-publish` job receives `id-token: write`. It
runs pinned checkout, Node setup, and artifact-download actions, installs no
dependencies, uses the reviewed Node 24.18.0 runtime whose bundled npm supports
trusted publishing (npm 11.5.1 or newer), rechecks the event commit, manifest
tag, and tarball hashes, then publishes contracts first, followed by the five
contracts-only consumers, storage, and tokens. The downloaded Actions artifact
also fails on a transport digest mismatch.

Do not let `gh release create` create a tag, and do not move or recreate a
release tag. If a release needs different bytes, prepare a new version.

## Workflow recovery

The workflow is globally serialized. If it stops after publishing only part of
the package set, rerun the failed jobs for the same GitHub release and unchanged
tag. The prepared artifact name is stable across attempts and is retained for
30 days, so the publisher reuses the verified tarballs from the same workflow
run. A full rerun may replace that artifact with freshly prepared bytes from the
same authenticated commit. Before each publish:

- absent version: publish the prepared tarball;
- existing version with identical `dist.integrity`: verify and skip it;
- existing version with different integrity: stop without publishing later
  packages; or
- any registry error other than `E404`: stop.

After a publish, the workflow waits for npm to expose the exact expected
integrity before advancing. This makes a retry safe without making immutable
npm versions appear replaceable.
