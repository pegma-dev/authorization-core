# Entra identity translation

`@pegma/authorization-entra` projects issuer and object-id claims from an
already-verified Microsoft Entra ID token into Authorization Core's
provider-neutral `IdentityLinkKey`. It does not decode tokens, verify tokens,
fetch keys, or resolve a principal.

## Integration sequence

1. The host verifies the Entra access or ID token using an appropriate,
   well-maintained verifier (for example `jose` against the tenant JWKS).
2. The host passes its verified `iss` and `oid` claims to
   `identityLinkKeyFromVerifiedEntraClaims`.
3. The host passes the returned key to its `IdentityAdapter` or identity-link
   store.
4. The host uses the returned host-owned principal ID. A provider object id is
   never a principal ID.

```ts
import { identityLinkKeyFromVerifiedEntraClaims } from "@pegma/authorization-entra";

const verifiedClaims = await verifyEntraAccessToken(encodedToken);
const key = identityLinkKeyFromVerifiedEntraClaims(verifiedClaims);
const principalId = await hostIdentityAdapter.resolvePrincipalId(key);
```

The verification and lookup functions in this example belong to the host; they
are not exported by Authorization Core.

## Why `oid`, not `sub`

Entra's `sub` is pairwise per app registration. A host with two registrations
in one tenant — for example a web app and a desktop client — would see the same
human as two subjects. Linking on issuer-namespaced `sub` would mint two
principals and silently fragment identity.

`oid` is the tenant-scoped stable object id: the same value for the user across
every app in the tenant. This package links on `iss` + `oid`, and that choice
is not configurable. A host that deliberately wants pairwise isolation can
project its own key without this package.

A `sub` present on the claims container is ignored like any other extra claim.
It is never a fallback.

## Verification prerequisites

Translation is safe only after the host has established all applicable token
requirements, including:

- a valid cryptographic signature using a trusted key for the configured
  issuer;
- an explicitly allowed signing algorithm and safe key selection;
- an exact expected issuer matching the v2 token profile;
- the intended API audience;
- expiration and any applicable not-before time;
- token-kind rules that prevent an ID token, access token, or session artifact
  from being accepted in the wrong context;
- nonce checks for applicable interactive ID-token flows;
- authorized-party (`azp`) checks when required by the token shape or flow.

The translation function deliberately cannot prove that these checks occurred.
Do not pass decoded-but-unverified JWT payloads or browser claims to it.

## Exact issuer and object-id rules

The package copies nonblank `iss` and `oid` strings exactly. It does not trim,
case-fold, normalize Unicode, parse URLs, rewrite tenant ids, or normalize GUID
case.

Only the v2 issuer profile is accepted: the exact preserved `iss` string must
end with the case-sensitive suffix `/v2.0`. There is no silent v1→v2
canonicalization. A v1 `sts.windows.net` issuer throws a `TypeError` that names
the v1 token profile and tells the host to move the app registration to v2
tokens. Any other issuer lacking the `/v2.0` suffix also throws.

Workforce issuers (`https://login.microsoftonline.com/{tid}/v2.0`) and Entra
External ID CIAM issuers (`https://{name}.ciamlogin.com/{tid}/v2.0`) both pass
and remain distinct tuples. Exact issuer namespacing is doing its job; neither
form is a special case.

There is deliberately no expected-issuer parameter. The host's verifier already
pinned the exact issuer before projection. The suffix gate only refuses the v1
profile that verifier configuration might otherwise let through.

Only own primitive-string data properties are accepted. Missing, blank,
non-string, inherited, or accessor `iss` or `oid` claims throw `TypeError`.
Other claims are discarded. The package never falls back to `sub`, `email`,
`preferred_username`, roles, or any other field.

## Lookup results and failures

Translation returns a fresh frozen key or throws. It never returns `null`.
After translation, the host identity lookup returns `null` only when the valid
issuer-and-object-id key has no link. Storage, network, configuration, and other
operational failures must reject rather than being converted to an unlinked
result.

See [Identity linking](IDENTITY_LINKING.md) for cardinality, linking, unlinking,
and merge requirements. The decision record for this adapter is in
[The Entra adapter](ENTRA_ADAPTER.md). Custom identity integrations should follow
[Adapter authoring](ADAPTER_AUTHORING.md), and deployments should review the
[integration security model](SECURITY_MODEL.md).
