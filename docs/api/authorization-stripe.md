<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-stripe

Generated from the public declaration entry point `packages/stripe/dist/index.d.ts`. Internal modules are intentionally excluded.

## createStripeEntitlementAdapter

**Kind:** const

Creates a principal-keyed adapter that reloads host-persisted state on every
resolution before applying the compiled exact-ID translator.

The host owns durable storage and all webhook, lifecycle, reconciliation,
retry, and cache policy. `maximumStateAgeMs` is required and accepts state
whose age is exactly equal to the bound. The persisted confirmation time
must advance only when Stripe is successfully re-confirmed. The adapter
rejects missing, corrupt, mismatched, stale, future-dated, or operationally
unavailable state.

```ts
export declare const createStripeEntitlementAdapter: (
  rules: readonly StripeEntitlementRule[],
  loader: StripeEntitlementStateLoader,
  maximumStateAgeMs: number,
  trustedClock?: StripeEntitlementClock,
) => StripeEntitlementAdapter;
```

## createStripeEntitlementTranslator

**Kind:** const

Validates and compiles a host-owned exact identifier allowlist once.

Runtime calls accept either authoritative Feature IDs or authoritative Price
IDs. The modes are never combined and unknown valid identifiers grant
nothing. Verification, lifecycle policy, persistence, reconciliation, and
loading active provider state remain host responsibilities.

```ts
export declare const createStripeEntitlementTranslator: (
  rules: readonly StripeEntitlementRule[],
) => StripeEntitlementTranslator;
```

## StripeActiveEntitlementFacts

**Kind:** type

Exactly one authoritative Stripe entitlement input mode.

```ts
export type StripeActiveEntitlementFacts =
  StripeFeatureEntitlementFacts | StripePriceEntitlementFacts;
```

## StripeEntitlementAdapter

**Kind:** type

Principal-keyed Stripe adapter backed by host persistence.

```ts
export type StripeEntitlementAdapter =
  EntitlementAdapter<StripeEntitlementRequest>;
```

## StripeEntitlementClock

**Kind:** type

Trusted epoch-millisecond clock sampled once per adapter resolution.

```ts
export type StripeEntitlementClock = () => number;
```

## StripeEntitlementRequest

**Kind:** interface

Exact request accepted by the persisted-state Stripe adapter.

```ts
export interface StripeEntitlementRequest {
  readonly principalId: PrincipalId;
}
```

## StripeEntitlementRule

**Kind:** type

One entry in the host-owned Stripe identifier allowlist.

```ts
export type StripeEntitlementRule =
  StripeFeatureEntitlementRule | StripePriceEntitlementRule;
```

## StripeEntitlementStateLoader

**Kind:** interface

Host-owned reader for persisted Stripe entitlement state.

```ts
export interface StripeEntitlementStateLoader {
  readonly loadPersistedEntitlementState: (
    principalId: PrincipalId,
  ) => Promise<StripePersistedEntitlementState>;
}
```

## StripeEntitlementTranslator

**Kind:** type

A compiled, synchronous projection from trusted facts to entitlements.

```ts
export type StripeEntitlementTranslator = (
  facts: StripeActiveEntitlementFacts,
) => readonly EntitlementName[];
```

## StripeFeatureEntitlementFacts

**Kind:** interface

Authoritative active Stripe Entitlements Feature IDs already loaded and
trusted by the host.

```ts
export interface StripeFeatureEntitlementFacts {
  readonly mode: "feature";
  readonly activeFeatureIds: readonly string[];
}
```

## StripeFeatureEntitlementRule

**Kind:** interface

One exact Stripe Entitlements Feature ID to host-entitlement rule.

```ts
export interface StripeFeatureEntitlementRule {
  readonly kind: "feature";
  readonly id: string;
  readonly entitlements: readonly EntitlementName[];
}
```

## StripePersistedEntitlementState

**Kind:** interface

Trusted Stripe facts persisted by the host for one principal.

`refreshedAtEpochMs` is the host-recorded time at which the facts were last
confirmed against Stripe. Database reads, rewrites, and cache fills must not
advance it.

```ts
export interface StripePersistedEntitlementState {
  readonly principalId: PrincipalId;
  readonly refreshedAtEpochMs: number;
  readonly facts: StripeActiveEntitlementFacts;
}
```

## StripePriceEntitlementFacts

**Kind:** interface

Authoritative active Stripe Price IDs already resolved and trusted by the
host when Product Features are not the source of truth.

```ts
export interface StripePriceEntitlementFacts {
  readonly mode: "price";
  readonly activePriceIds: readonly string[];
}
```

## StripePriceEntitlementRule

**Kind:** interface

One exact Stripe Price ID to host-entitlement fallback rule.

```ts
export interface StripePriceEntitlementRule {
  readonly kind: "price";
  readonly id: string;
  readonly entitlements: readonly EntitlementName[];
}
```
