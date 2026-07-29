# Security Scan — authorization-core

**Date:** 2026-07-28
**Scope:** Full repository (all packages, workflows, tooling)
**Method:** Manual code review, static analysis, dependency and workflow audit. Findings appended incrementally as they are discovered.

## Findings

### F-01 — `defaultJwksFetcher` has no timeout and no response-size limit

- **Severity:** Low (defense-in-depth gap)
- **Evidence:** `packages/tokens/src/jwks.ts:163-178`. `fetch(url, ...)` is issued with no `AbortSignal`/timeout, and `await response.arrayBuffer()` buffers the response body with no byte cap before `validateJwks` runs.
- **Exploitability:** The JWKS URL is host-configured and HTTPS-pinned with a post-redirect origin check (`jwks.ts:188-207, 351-361`), so an attacker would need to control or degrade the configured endpoint (or its network path) to exploit this. In that case a hung connection stalls every verifier share of that cache indefinitely (`#refreshInFlight` serializes refreshes), and an unbounded body is buffered into memory. Verification fails closed, so no forgery is possible — the impact is availability only.
- **Recommendation:** Add an `AbortSignal.timeout(...)` and a maximum accepted body size (e.g. stream-read with a 64 KiB cap).

### F-02 — No size limit on the compact grant string presented to the verifier

- **Severity:** Low
- **Evidence:** `packages/tokens/src/verifier.ts:251-253` — `verifyAndConsume(compact)` accepts any string; `parseCompactGrant` (`verifier.ts:97-124`) splits and base64-decodes all three segments before any length check. The strict JSON parser (`packages/tokens/src/internal.ts:212-363`) is recursive-descent with no depth or input-size cap.
- **Exploitability:** An unauthenticated caller able to reach a host endpoint that verifies grants can present arbitrarily large tokens, costing CPU/memory linear in input size before rejection. Deeply nested JSON recurses in `StrictJsonParser.#value/#array/#object`; Node throws `RangeError` on stack exhaustion, which is caught by the fail-closed `catch` at `verifier.ts:305-309`, so it degrades to per-request cost rather than process death. All failure paths are closed; impact is limited to resource consumption, and the host's HTTP layer normally bounds body size.
- **Recommendation:** Reject compact inputs above a small fixed bound (a V1 grant is well under 2 KiB) before splitting.

### F-03 — Verified-positive observations in the tokens package (no action needed)

Logged for completeness so the review trail shows these were checked and hold:

- Algorithm is pinned to ES256 in three places: header shape check (`verifier.ts:131-137`), `compactVerify` `algorithms` option (`verifier.ts:256-258`), and JWK `alg` member (`jwks.ts:66-88`). No `alg: none` or algorithm-confusion path exists; JWKS keys are validated as public P-256 verify-only CryptoKeys (`jwks.ts:55-64, 114`).
- Canonical base64url is enforced by decode-then-re-encode round-trip (`internal.ts:145-162`), so malleable encodings are rejected.
- Duplicate JSON member names are rejected by the strict parser (`internal.ts:259-261`) because `JSON.parse` would silently keep the last one; header/claims/JWK field sets must match exactly (`internal.ts:69-85`).
- Replay protection burns the `jti` with `insertIfAbsent` *before* the grant is returned, re-checks time window and JWKS freshness after the store round-trip (`verifier.ts:279-291`), and treats store errors as denial (`replay.ts:121-128`). Signature verification precedes replay-store writes, so unauthenticated callers cannot pollute the replay store.
- Issuer reserves the `jti` durably *before* signing (`issuer.ts:363-367`), uses CSPRNG 256-bit identifiers (`issuer.ts:179-181, 355-362`), and requires a private P-256 sign-only key (`issuer.ts:166-177`).
- Grant lifetime is capped at 30 s with a 5 s negative verifier offset (`internal.ts:6-7`); source-authorization snapshots are monotonic-clock-bound and single-domain via WeakMap capabilities (`issuer.ts:88-95, 292-307`).
- All verifier runtime failures collapse into one `AccessGrantError` so callers cannot probe keys, policies, permissions, or replay state (`verifier.ts:305-309`).
### F-04 — Assignment-pointer write result is discarded: cross-partition assignment-ID reuse is silently accepted

- **Severity:** Medium (conditional on host-supplied IDs)
- **Evidence:** `packages/storage/src/role-store.ts:378-384`. `grantRoleAssignmentWithAudit` issues `pointers.insertIfAbsent({ ...location, assignmentId: assignment.id, role: assignment.role })` and **ignores the result**. The port contract advertises enforcement of a "unique assignment ID" (`packages/storage/src/index.ts:103-106`), but uniqueness is only enforced by that pointer insert — and nothing checks whether it actually inserted.
- **Exploitability:** Assignment IDs are host-supplied. If a host ever derives or accepts an assignment ID that can collide (e.g. client-influenced identifiers, id reuse across environments), the following occurs:
  1. Grant assignment `X` for principal P1 → pointer `(app, X) → P1-partition` written, grant commits.
  2. Grant assignment `X` for principal P2 (different partition) → pointer insert is a no-op (already exists, never compared), the tuple guard in P2's partition is free, no assignment record exists there, so **the second grant commits**.
  Result: two active assignments share one ID. `revokeRoleAssignmentWithAudit(X)` and `getRoleAssignment(X)` resolve only through the first pointer (`role-store.ts:243-251, 494-503`), so the second assignment **cannot be revoked or read by ID** while remaining fully active in `listActiveRoleAssignments(P2, …)` — an unrevocable privilege grant, the exact ABA/revocation class of fault this repository's design is built to prevent.
- **Confirmation:** **Reproduced** with a runtime proof-of-concept against the built package (script run from `C:\TEMP\opencode\f04-poc.mjs`, no repository files modified): the second cross-partition grant returned `granted`, both principals listed the same active assignment ID, and a successful `revoked` result for the ID left the second principal's assignment active.
- **Recommendation:** When `insertIfAbsent` reports `inserted: false`, compare the existing pointer's location and role against the attempted grant; if they differ, return `conflict("assignment_id")` before touching the tuple guard.

### F-05 — Grant idempotent replay does not compare assignment payload

- **Severity:** Informational
- **Evidence:** `packages/storage/src/role-store.ts:411-419`. An exact `(assignmentId, auditEventId)` replay returns `unchanged` without comparing the stored assignment's role, scope, principal, or actor against the incoming command.
- **Exploitability:** None directly — no state changes. But a host that retries a grant with the same event ID and *different* content receives a success-shaped `unchanged` result for content that was never written, which can mask operator or integration errors. Idempotency keyed on event ID alone is a defensible design; it should be documented explicitly at the port.
- **Recommendation:** Document that `unchanged` attests only to the event ID, or compare the full stored assignment and return `conflict("event_id")` on mismatch.

### F-06 — Lifecycle commands accept unvalidated field content (empty/unbounded IDs, roles, principals)

- **Severity:** Low (host-trusted input boundary)
- **Evidence:** `packages/storage/src/role-store.ts:81-99` (`snapshotActive`) and `160-173` (`snapshotRevokeCommand`) copy `id`, `principalId`, `role`, `organizationId`, and `auditEventId` with no non-empty, length, or character checks, unlike the tokens package which enforces bounded identities (`packages/tokens/src/internal.ts:99-107`).
- **Exploitability:** Requires a host to pass malformed values — not attacker-reachable in a correct integration. Empty principal IDs or multi-megabyte role names would be persisted as-is. Key encoding (`packages/storage/src/collections.ts:25-39`) is injective and escape-safe, so no cross-record collision or key injection results.
- **Recommendation:** Mirror the tokens package's bounded-identity validation at the lifecycle command boundary so garbage fails fast at the port instead of persisting.

### F-07 — Reference example reads request bodies with no size limit

- **Severity:** Low (example code, explicitly non-production)
- **Evidence:** `examples/reference-api/reference-integration.ts:251-258` — `readJson` buffers the entire request body (`Buffer.concat(chunks)`) with no byte cap, and the file binds an HTTP server (`--serve`) on port 3000.
- **Exploitability:** Anyone able to reach the demo server can stream an unbounded body to exhaust memory. The file header states NON-PRODUCTION and the server binds `127.0.0.1`, limiting exposure to local processes. Hosts copying this example into production code would inherit the flaw.
- **Recommendation:** Add a cumulative byte cap with a 413-style failure in the example, since examples are the most-copied code in any repository.

### F-08 — Published `testing` subpath exposes injectable clocks, entropy, and JWKS fetch

- **Severity:** Informational (documented design, misuse hazard)
- **Evidence:** `packages/tokens/src/testing.ts` re-exports `createAccessGrantIssuerInternal`/`createAccessGrantVerifierInternal` with fully injectable `wallNowEpochMs`, `randomBytes32`, and `fetchJwks`; the subpath is published (`packages/tokens/package.json:18-21`). The reference example uses it for its demo server (`examples/reference-api/reference-integration.ts:38-41, 903, 933`).
- **Exploitability:** None in this repository. The hazard is a host accidentally wiring the testing factory into production with a permissive fetcher or weak entropy. The module docstring states "Trusted test-only construction hooks," and the internal factories do validate injected values (key shape, random length, clock sanity) before use, so even misuse fails loudly rather than silently.
- **Recommendation:** No change required; consider a runtime warning when the testing factory is used outside a test runner if the project wants belt-and-suspenders.

## Supply-chain, workflow, and secrets audit (all clear)

- **Dependencies:** Runtime deps are exact-pinned and minimal — `jose@6.2.3` (tokens) and `@pegma/storage-core@0.3.0` (sibling). `npm audit` (with and without dev) reports **0 vulnerabilities**. Dependabot covers npm and github-actions.
- **CI/publish:** All GitHub Actions are pinned to full commit SHAs; workflows default to `permissions: contents: read`. The publish workflow obtains `id-token: write` only in the `publish` job, gated by the `npm-publish` environment, publishes prepared tarballs only (no rebuild in the privileged job), requires an expected release commit, configures an SSH `allowedSignersFile` for tag verification (`publish.yml:38-49`), and has no npm-token fallback (OIDC trusted publishing only). Concurrency group prevents parallel publishes.
- **Scripts:** `scripts/release-packages.mjs` shells out exclusively via `spawnSync` with `shell: false` and argument arrays (line 120-127) — no shell-interpolation injection surface for tag names or versions.
- **Secrets:** Repository-wide pattern scan (private keys, `sk_live`/`sk_test`/`whsec_`, hardcoded passwords/API keys) found nothing. The reference integration generates its P-256 keypair at runtime and commits nothing (`reference-integration.ts:888-895`). Release/bootstrap tarball directories are git-ignored (`.gitignore:4-5`).
- **CodeQL:** Scheduled + per-push CodeQL analysis is enabled with least-privilege permissions.

## Summary

| ID | Severity | Title |
|----|----------|-------|
| F-04 | **Medium** | Cross-partition assignment-ID reuse silently commits a second, unrevocable-by-ID grant (**PoC-confirmed**) |
| F-01 | Low | JWKS fetcher lacks timeout and response-size limit |
| F-02 | Low | No size limit on compact grant input to the verifier |
| F-06 | Low | Lifecycle commands accept unvalidated field content |
| F-07 | Low | Reference example reads unbounded request bodies |
| F-05 | Informational | Grant idempotent replay does not compare assignment payload |
| F-08 | Informational | Published `testing` subpath is a documented misuse hazard |
| F-03 | Positive | Tokens package invariants verified holding (alg pinning, canonical encodings, replay-before-return, fail-closed error unification, unknown-kid cooldown) |

**One actionable Medium (F-04, runtime-confirmed)** and four Low hardening items. No critical or high findings. The codebase is unusually disciplined: exact-field JSON parsing with duplicate rejection, algorithm pinning, capability-based issuer state, fail-closed error paths, injective storage-key encoding, and single-partition lifecycle transactions are all implemented as documented.

**Recommended next step for F-04:** in `grantRoleAssignmentWithAudit`, inspect the `insertIfAbsent` result — when not inserted, compare the existing pointer's `applicationId`/`principalId`/`scope`/`role` against the incoming grant and return `conflict("assignment_id")` on any mismatch.

