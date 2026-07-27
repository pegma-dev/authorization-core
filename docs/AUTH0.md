# Auth0 identity translation

`@pegma/authorization-auth0` projects issuer and subject claims from an already-verified
Auth0 token or session into Authorization Core's provider-neutral `IdentityLinkKey`. It
does not decode tokens, verify tokens, fetch keys, or resolve a principal.

## Integration sequence

1. The host verifies the Auth0 token or session using an appropriate,
   well-maintained verifier.
2. The host passes its verified `iss` and `sub` claims to
   `identityLinkKeyFromVerifiedAuth0Claims`.
3. The host passes the returned key to its `IdentityAdapter` or identity-link
   store.
4. The host uses the returned host-owned principal ID. A provider subject is
   never a principal ID.

```ts
import { identityLinkKeyFromVerifiedAuth0Claims } from "@pegma/authorization-auth0";

const verifiedClaims = await verifyAuth0AccessToken(encodedToken);
const key = identityLinkKeyFromVerifiedAuth0Claims(verifiedClaims);
const principalId = await hostIdentityAdapter.resolvePrincipalId(key);
```

The verification and lookup functions in this example belong to the host; they
are not exported by Authorization Core.

## Verification prerequisites

Translation is safe only after the host has established all applicable token
requirements, including:

- a valid cryptographic signature using a trusted key for the configured
  issuer;
- an explicitly allowed signing algorithm and safe key selection;
- an exact expected issuer;
- the intended API audience;
- expiration and any applicable not-before time;
- token-kind rules that prevent an ID token, access token, or session artifact
  from being accepted in the wrong context;
- nonce checks for applicable interactive ID-token flows;
- authorized-party (`azp`) checks when required by the token shape or flow.

The translation function deliberately cannot prove that these checks occurred.
Do not pass decoded-but-unverified JWT payloads or browser claims to it.

## Exact issuer and subject rules

The package copies nonblank `iss` and `sub` strings exactly. It does not trim,
case-fold, normalize Unicode, parse URLs, add or remove trailing slashes, or
rewrite Auth0 subject prefixes.

An Auth0 custom domain and the tenant's canonical Auth0 domain are different
issuers. Configure verification for the issuer actually used, preserve that
exact verified `iss`, and do not treat the two domains as interchangeable even
when their `sub` values match.

Only own primitive-string data properties are accepted. Missing, blank,
non-string, inherited, or accessor `iss` or `sub` claims throw `TypeError`.
Other claims are discarded. The package never falls back to `email`,
`user_id`, organization claims, roles, or any other field.

## Lookup results and failures

Translation returns a fresh frozen key or throws. It never returns `null`.
After translation, the host identity lookup returns `null` only when the valid
issuer-and-subject key has no link. Storage, network, configuration, and other
operational failures must reject rather than being converted to an unlinked
result.

For RetireGolden's existing single-issuer flow, the host verifies the configured
Auth0 issuer and subject, then reattaches that exact configured verified issuer
to the verified subject before translation. RetireGolden's separate account
UUID remains the principal ID.

See [Identity linking](IDENTITY_LINKING.md) for cardinality, linking, unlinking,
and merge requirements. Custom identity integrations should follow
[Adapter authoring](ADAPTER_AUTHORING.md), and deployments should review the
[integration security model](SECURITY_MODEL.md).
