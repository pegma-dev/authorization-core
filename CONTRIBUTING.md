# Contributing to Authorization Core

Thank you for helping improve Authorization Core.

## Before opening an issue

- Search existing issues for related work.
- Use GitHub's private vulnerability reporting flow for security concerns.
- Keep proposals provider-neutral unless they are explicitly for an adapter.
- Describe the authorization behavior and trust boundary, not only the desired
  API shape.

## Local development

Authorization Core requires Node.js 22 or newer. Node 25 and newer do not
bundle Corepack, so install it before enabling the pinned pnpm.

```sh
npm install -g corepack
corepack enable
pnpm install --frozen-lockfile
pnpm run check
pnpm test
pnpm run format:check
```

## Pull requests

Keep pull requests focused. Include:

- the problem being solved;
- the intended user or adapter behavior;
- tests for new authorization behavior;
- documentation for public API changes;
- security and compatibility considerations.

Permission-granting changes must include both allow and deny tests. Changes to
public contracts should explain their migration impact while the project is in
`0.x`.

## Project conventions

- Use provider-neutral terms in `contracts` and `core`.
- Put vendor-specific behavior in an adapter package.
- Treat external identity, billing, and storage data as untrusted until its
  adapter has verified it.
- Prefer explicit permissions over wildcard grants.
- Never use an email address as a principal identifier.
- Avoid adding a production dependency when a small local implementation is
  sufficient.

## Commits

Use concise, imperative commit subjects. The project uses pull requests and
squash merging, so a clean pull-request description matters more than an
elaborate local commit history.

By contributing, you agree that your contributions are licensed under the
project's MIT License.
