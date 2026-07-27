# Pegma access-grant profile V1

This document defines the first signed access-grant profile for Authorization
Core. It is a narrow, short-lived, one-use credential for a trusted host to
delegate effective permissions to exactly one independently deployed service.
It is a specification boundary only: this slice does not add a token package,
signer, verifier, key server, or cryptographic dependency.

The profile uses the JWT claims model from
[RFC 7519](https://www.rfc-editor.org/rfc/rfc7519), public JSON Web Keys from
[RFC 7517](https://www.rfc-editor.org/rfc/rfc7517), and the defensive
verification rules in
[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725). It is a Pegma
access-grant, not an Auth0 token, an OIDC ID token, a browser session, or an
OAuth access token. In particular, using a JWT does not claim conformance with
the [RFC 9068 OAuth 2.0 access-token
profile](https://www.rfc-editor.org/rfc/rfc9068). The token kind, claim set,
one-use rule, and trust relationship here are Pegma-specific.

## Fixed V1 constants

V1 has one algorithm and one vocabulary. Issuers and verifiers do not
negotiate alternatives from token input.

| Property                               | V1 value                                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------- |
| Compact serialization                  | JWS compact serialization with exactly three canonical, unpadded base64url segments |
| Protected `typ`                        | `pegma-access-grant+jwt`                                                            |
| Profile version                        | integer `1`                                                                         |
| Signing algorithm                      | `ES256` (ECDSA using P-256 and SHA-256)                                             |
| Maximum nominal lifetime               | 30 seconds                                                                          |
| Maximum negative verifier clock offset | 5 seconds                                                                           |
| Positive expiration leeway             | 0 seconds                                                                           |
| Minimum unknown-`kid` refresh interval | 5,000 milliseconds                                                                  |
| Maximum JWKS cache age                 | 60,000 milliseconds                                                                 |

`ES256` is the only initial algorithm because P-256 and SHA-256 have mature,
cross-language implementations. Supporting another algorithm requires a new
profile version or an explicit later profile change; an issuer never copies an
algorithm requested by a caller, and a verifier never derives its allowlist
from `alg`.

## What a grant carries

A grant carries only effective permission names. It never carries roles,
entitlements, assignment or source-grant records, provider subjects, email,
billing facts, or the five-field serialized `AccessContext`.

The issuer starts with one trusted, immutable `AccessContext` that is
inseparably bound to the source authorization's exact application, principal,
policy version and digest, application scope, opaque clock-domain token, and
monotonic deadline. A caller cannot pair an unrelated context with a fresh
deadline. The issuer then chooses a nonempty subset of `context.permissions`
using the immutable permission allowlist configured for the exact requested
audience. Every requested permission must occur exactly in both:

1. that context's canonical `permissions`; and
2. the host-configured allowlist for the exact target audience.

If either membership test fails, issuance rejects the whole request. It does
not silently intersect, partially grant, use prefixes or wildcards, normalize
names, or infer a permission from a role or entitlement. The resulting claim
is deduplicated and sorted by ascending JavaScript string comparison, and each
name must satisfy the V1 policy permission grammar. An empty result is
rejected.

The issuer must use the context's exact `principalId` and `policyVersion`; a
caller cannot override them. It also receives the immutable policy content or
deployment digest that was bound to the authorization snapshot. The digest is
not derivable from the five-field context and must come from the same trusted
host composition that produced the source deadline.

## Exact protected header

The decoded protected header is a JSON object with exactly these own fields:

```json
{
  "alg": "ES256",
  "kid": "2026-07-26T15-30-00Z_A7mK2pQx",
  "typ": "pegma-access-grant+jwt"
}
```

- `alg` and `typ` are the fixed strings above.
- `kid` is a case-sensitive 16-128 character ASCII identifier matching
  `[A-Za-z0-9][A-Za-z0-9._:-]{15,127}`.
- A `kid` identifies one signing public key under one issuer. The issuer
  generates a collision-resistant fresh value for every new key and never
  reuses a retired value, even if key material or an old deployment is
  restored.

The header contains no `jku`, `jwk`, `x5u`, `x5c`, `crit`, or unprotected
parameters. Duplicate or unknown fields, a non-object header, a noncanonical
compact encoding, or a value of the wrong JSON type rejects the token.

## Exact claims

The decoded payload is a JSON object with exactly these fields:

```json
{
  "iss": "https://authorization.example.test",
  "application_id": "retire-golden-production",
  "aud": "support-api",
  "sub": "f8ea9308-1bdb-49b0-89a9-eef2af28eb6b",
  "exp": 1785087030,
  "iat": 1785087000,
  "jti": "uN5Kf6xVw2aY0dPcR8sE3gH1mQ9tL4zB7iJkOeWcX_A",
  "profile_version": 1,
  "policy_version": "2026-07-26.1",
  "policy_digest": "sha256:ad1b38ea08c91e2e66d6ab4d2f19a70dee7c067ba3c3223a2728f5d2f74a17e3",
  "permissions": ["support.queue.read", "support.ticket.reply.any"]
}
```

The rules are:

- `iss` is the exact configured issuer string. No URL normalization, discovery,
  redirects, aliases, or trailing-slash adjustment occurs.
- `application_id` is the exact provider-neutral host application identity
  inseparably bound to the source authorization. It is not an identity-provider
  client ID, provider tenant, organization, audience, or browser input. V1
  requires a nonblank string of at most 255 Unicode code points with no leading
  or trailing whitespace or ASCII control characters.
- `aud` is one string naming exactly one configured service. An array and
  multiple audiences are invalid. A token for one service cannot be replayed
  at another.
- `sub` is the exact host-owned `PrincipalId`, never a provider subject or
  email. V1 requires a nonblank string of at most 255 Unicode code points with
  no leading or trailing whitespace or ASCII control characters.
- `iat` and `exp` are positive safe-integer NumericDate seconds. Fractions,
  numeric strings, non-finite values, and JavaScript-unsafe integers are
  invalid. `exp` is strictly greater than `iat`, and `exp - iat` is at most 30.
- `jti` is a unique, unpredictable 256-bit value encoded as exactly 43
  canonical unpadded base64url characters. Decoding must produce exactly 32
  bytes, and re-encoding those bytes must reproduce the claim exactly. It is
  generated by the issuer's cryptographically secure random source and is
  never reused under the same issuer and application. It participates in
  replay prevention; its mere presence is not replay protection.
- `profile_version` is the JSON number `1`.
- `policy_version` is the context's exact opaque policy revision and satisfies
  the policy V1 version grammar.
- `policy_digest` is the exact lowercase
  `sha256:` followed by 64 hexadecimal digits for the immutable policy content
  or reviewed deployment identity used during resolution.
- `permissions` is a nonempty, duplicate-free, ascending canonical array of
  V1 permission strings. It contains only the issuer-approved subset described
  above.

Duplicate or unknown claims reject the token. V1 has no optional payload
fields.

## Lifetime and the source monotonic deadline

Issuance consumes, rather than restarts, the source authorization deadline from
[Fast role revocation and cache bounds](ROLE_REVOCATION.md). All source
monotonic samples remain in the one opaque in-process clock domain in which the
authorization was resolved.

The issuer receives that bound source authorization as an opaque host-created
capability, not as caller-populated context, identity, clock, or deadline
fields. The capability belongs to one exact issuer instance and clock-domain
token and is unusable after a process restart or with another issuer instance.
The issuer owns the guarded monotonic clock and wall-clock readers; an issuance
request cannot supply or observe their samples. Any invalid or regressing
monotonic sample permanently fails that in-process clock domain, clears
dependent authorization state, and requires a new process domain plus
authoritative reload. Restoring the previous numeric value does not revive it.

Immediately before signing, the issuer samples that trusted monotonic clock and
its trusted wall clock. Let:

```text
remainingMs = sourceExpiresAtMonotonicMs - monotonicNowMs
iat = floor(wallNowEpochMs / 1,000)
wholeRemainingSeconds = floor(remainingMs / 1,000)
nominalLifetimeSeconds = min(30, wholeRemainingSeconds - 5)
exp = iat + nominalLifetimeSeconds
```

Issuance rejects unless the clock-domain token is identical, every sample and
deadline is finite and ordered, `monotonicNowMs < sourceExpiresAtMonotonicMs`,
and `nominalLifetimeSeconds >= 1`. Thus at least six whole seconds must remain:
exactly 6,000 milliseconds can produce a one-second nominal token, while 5,999
milliseconds cannot. Flooring the wall clock and remaining time is
deliberately conservative.

A verifier accepts the time window only when:

```text
iat <= verifierNowNumericDate + 5
verifierNowNumericDate < exp
```

It rejects at exactly `exp`; V1 configures zero positive expiration leeway.
The reserved five seconds cover only the maximum permitted negative verifier
wall-clock offset, including integer truncation. They also permit `iat` to
appear at most five seconds in the future to that slow verifier. A deployment
must not configure a JWT library to add expiration tolerance, and must fail
closed if its clock discipline cannot prove that the verifier is no more than
five seconds behind the issuer.

In real time, the slowest permitted verifier can therefore accept only while
its clock is below `exp`, strictly before the source monotonic deadline. Replay
state is retained through `exp + 5` on an independently accurate store clock so
it covers every such accepted instant. The 30-second nominal cap shortens the
normal exposure further. Queueing, signing, transmission, retries, caches, and
downstream delegation never recompute `iat`, restart the 30 seconds, or extend
`exp`. Any mismatch in the bound application, principal, policy version,
policy digest, application scope, clock-domain token, or deadline fails closed,
as does a regressing or invalid clock or expired source authorization.

## Organization confinement

V1 has no organization claim and an issuer must not mint a V1 grant from
permissions derived from an organization-scoped role assignment. The only V1
source scope is the explicitly tagged application scope. An
`organization_id`, tenant claim, or similar field is unknown and therefore
rejected.

This is a deliberate safety decision, not evidence that organization scope
belongs in `AccessContext`. A future, separately versioned confinement profile
would have to receive the organization from authoritative target-derived host
facts, never infer it from `AccessContext` or a browser selection, and require
the verifier to compare it exactly with the organization derived from its
actual target. Even then, the service would still load and enforce current
membership, ownership, assignment, and resource relationships. Absence or
mismatch would deny. Application-wide V1 makes no organization assertion.

## Verifier configuration and sequence

A verifier has immutable startup configuration for:

- one exact issuer;
- one exact provider-neutral host application identity;
- one exact service audience;
- the immutable permission allowlist for that exact audience;
- protected `typ` `pegma-access-grant+jwt`;
- profile version `1`;
- algorithm `ES256`;
- one issuer-bound, fixed HTTPS JWKS URL;
- a JWKS cache age from 1 through 60,000 milliseconds;
- exact accepted `(policy_version, policy_digest)` pairs;
- the header, claim, key, permission, and time shapes in this document; and
- an atomic replay store whose retention covers `exp + 5`.

The verifier performs these checks without using untrusted claims to choose a
parser, algorithm, issuer configuration, audience, key endpoint, policy, or
clock. A conforming implementation:

1. requires exactly three canonical unpadded base64url compact segments;
2. parses the protected header and payload with duplicate-member detection;
3. rejects unknown members and invalid JSON types or shapes;
4. checks fixed `typ`, profile version, and `alg`;
5. looks up `kid` only at the issuer-bound configured JWKS endpoint;
6. verifies the ES256 signature with the selected valid public key;
7. compares `iss`, `application_id`, and the single string `aud` exactly;
8. validates `sub`, `iat`, `exp`, `jti`, the permission array, and the exact
   accepted policy-version-and-digest pair;
9. enforces `iat <= now + 5` and `now < exp` with no positive expiration
   leeway; and
10. after every other verification succeeds, atomically consumes the exact
    `(iss, application_id, aud, jti)` replay key before any protected action.

Ordering may be optimized only if every failure still denies and unverified
data never causes an unsafe network lookup, policy selection, log entry, or
authorization side effect. Error responses should not reveal whether a key,
principal, permission, or policy exists.

## One-use and revocation limits

A V1 grant is a bearer credential until its first successful consumption.
Possession before that point is sufficient to race the intended caller.
Transport security, strict recipient handling, secret-free logs, and narrow
audiences and permissions remain necessary.

After all other verification succeeds and before any protected action, the
service atomically inserts a replay record keyed by the exact structured tuple
`(iss, application_id, aud, jti)`. The store uses an accurate clock independent
of the verifier and retains the record through `exp + 5` NumericDate seconds.
Exactly one concurrent consumer wins; every later or losing attempt denies. A
replay-store timeout, outage, ambiguous write, corrupt record, or inability to
provide atomic insert-if-absent semantics fails closed. Concatenated ambiguous
keys are not acceptable. A `jti` without this atomic operation does not prevent
replay.

The executable contract uses a deterministic in-process model to exercise
these semantics. It does not prove multi-process atomicity, durability, clock
quality, or production-backend behavior. A future implementation must declare
the replay collection against `@pegma/storage-core` and use a host-supplied
`Store`; it must not add bespoke persistence here.

Ordinary role revocation, entitlement invalidation, policy replacement, or
principal changes cannot recall an unconsumed issued grant. Expiry plus allowed
maximum negative verifier offset is the normal real-time outer revocation
bound; the verifier itself applies zero positive expiration leeway. Atomic
consumption prevents successful reuse. V1 defines no refresh token, session,
online introspection, or general token denylist. Long-running work must finish
within the remaining deadline or obtain a newly resolved grant; consuming a
grant does not authorize unbounded background work.

Signing-key compromise is limited by both token expiry and verifier JWKS cache
behavior, but emergency public-key removal is not instantaneous at a verifier
that still has a fresh cached key. V1 makes no promise to undo already
authorized work.

## JWKS trust and rotation

The host controls private P-256 signing keys. Private values never enter an
Authorization Core package, JWKS response, repository example, browser,
telemetry field, error, or log.

The configured HTTPS JWKS document contains exactly `{"keys": [...]}`. Each V1
key is a public JWK with exactly:

```json
{
  "kty": "EC",
  "crv": "P-256",
  "x": "<canonical 32-byte base64url coordinate>",
  "y": "<canonical 32-byte base64url coordinate>",
  "use": "sig",
  "alg": "ES256",
  "kid": "<fresh non-reused key id>"
}
```

The set rejects duplicate `kid` values, private `d`, symmetric key material,
unknown members, invalid coordinates, a key not marked for signatures, or an
algorithm/key-type mismatch. TLS and endpoint ownership are deployment trust
requirements; redirects to a different origin are rejected.

Each `x` and `y` coordinate is canonical unpadded base64url: decoding must
produce exactly 32 bytes and re-encoding those bytes must reproduce the member
exactly. Length or alphabet checks alone are insufficient because some
decoders accept noncanonical aliases.

A verifier may use a successfully validated set only while its monotonic age is
strictly less than its configured maximum. At the exact maximum it must
refresh. Refresh is single-flight per configured issuer and endpoint: concurrent
requests share one in-flight fetch. A successful refresh validates the complete
response and atomically replaces the cached set; it never unions old and new
keys.

The cache validates every monotonic sample against the last observed sample,
not merely the time at which keys were loaded. Any regression permanently fails
that cache clock domain and clears its keys; a later numerically equal or
greater sample does not revive it. Recovery constructs a new guarded domain and
fetches authoritative keys again.

When the requested `kid` is absent from a fresh set, the verifier may trigger
one refresh only if at least 5,000 milliseconds have elapsed since the last
unknown-`kid` refresh attempt. The issuer-scoped cooldown begins before the
fetch and suppresses refreshes for every other missing `kid`, including random
attacker values; those tokens reject immediately. Fetch failure also preserves
the cooldown. At the exact end of the interval, one request may refresh and a
newly published rotation key can become usable. This bounded issuer-wide
negative-miss state avoids an attacker-controlled cache entry per `kid`.

Fetch, parse, validation, clock, or required-refresh failure denies; there is
no stale-key fallback after cache expiry. A still-fresh known key may be used
until its cache deadline.

Safe routine rotation is staged:

1. publish the new public key with a fresh `kid` alongside the old key;
2. wait at least the configured maximum cache age for every verifier;
3. begin signing new grants with the new key;
4. stop signing with the old key; and
5. retain the old public key for at least 35 seconds after its last issuance,
   then remove it and allow one full cache age for removal to reach verifiers.

Deployments may use longer overlap. Emergency removal skips the overlap but
cannot prevent a verifier from using a compromised key already in a fresh
cache for up to its configured cache age; token expiry and one-use consumption
still apply. A deployment needing a stronger compromise response requires a
separately designed online mechanism.

## Explicit exclusions

V1 does not define or assert:

- browser sessions, browser authority, OIDC identity, or OAuth behavior;
- refresh tokens, token exchange, or offline commercial licenses;
- provider subjects, email, billing IDs, roles, entitlements, or source grants;
- resource ownership, organization membership, assignment, or relationships;
- organization or tenant confinement;
- raw private or public key material inside an access context or permission;
- a persistence implementation, general denylist, or introspection service.

The consuming service always performs its own authoritative resource and
relationship checks after grant verification. A permission authorizes an
attempted action; it is not proof about a particular resource.
