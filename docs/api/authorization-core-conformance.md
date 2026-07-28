<!-- @pegma/authorization-core:generated-api-doc -->

# @pegma/authorization-core/conformance

Generated from the public declaration entry point `packages/core/dist/conformance.d.ts`. Internal modules are intentionally excluded.

## EntitlementAdapterConformanceCase

**Kind:** interface

One framework-independent entitlement-adapter conformance case.

```ts
export interface EntitlementAdapterConformanceCase {
  readonly name: string;
  run(createAdapter: EntitlementAdapterConformanceFactory): Promise<void>;
}
```

## entitlementAdapterConformanceCases

**Kind:** const

Behaviour every request-time {@link EntitlementAdapter} must exhibit.

The cases have no test-framework dependency:

```ts
for (const testCase of entitlementAdapterConformanceCases) {
  it(testCase.name, () => testCase.run(createEntitlementAdapter));
}
```

```ts
export declare const entitlementAdapterConformanceCases: readonly EntitlementAdapterConformanceCase[];
```

## EntitlementAdapterConformanceFactory

**Kind:** type

Build an adapter over the exact semantic fixture supplied by the suite.

The factory translates these states into its provider and persistence model;
the public adapter remains principal-keyed and provider-neutral.

```ts
export type EntitlementAdapterConformanceFactory = (
  fixture: EntitlementAdapterConformanceFixture,
) => Promise<EntitlementAdapter>;
```

## EntitlementAdapterConformanceFixture

**Kind:** interface

Semantic entitlement state supplied to one conformance case.

Repeated entries for one principal are successive authoritative states.
Factories must consume one entry on every resolution so the suite can prove
that a previous success is not used as fallback.

```ts
export interface EntitlementAdapterConformanceFixture {
  readonly states: readonly EntitlementAdapterConformanceState[];
}
```

## EntitlementAdapterConformanceState

**Kind:** interface

One principal's state for one successive request-time resolution.

```ts
export interface EntitlementAdapterConformanceState {
  readonly principalId: PrincipalId;
  readonly state: EntitlementFixtureState;
}
```

## EntitlementFixtureState

**Kind:** type

Semantic request-time state for one entitlement resolution.

```ts
export type EntitlementFixtureState =
  | Readonly<{
      readonly kind: "current";
      readonly entitlements: readonly EntitlementName[];
    }>
  | Readonly<{
      readonly kind: "missing" | "stale" | "future" | "corrupt" | "unavailable";
    }>;
```

## IdentityAdapterConformanceCase

**Kind:** interface

One framework-independent identity-adapter conformance case.

```ts
export interface IdentityAdapterConformanceCase {
  readonly name: string;
  run(createAdapter: IdentityAdapterConformanceFactory): Promise<void>;
}
```

## identityAdapterConformanceCases

**Kind:** const

Behaviour every provider-neutral {@link IdentityAdapter} must exhibit.

The cases have no test-framework dependency:

```ts
for (const testCase of identityAdapterConformanceCases) {
  it(testCase.name, () => testCase.run(createIdentityAdapter));
}
```

```ts
export declare const identityAdapterConformanceCases: readonly IdentityAdapterConformanceCase[];
```

## IdentityAdapterConformanceFactory

**Kind:** type

Build an adapter over the exact semantic fixture supplied by the suite.

Provider-specific evidence, storage, and configuration remain inside the
factory. Return the adapter directly when it accepts an {@link IdentityLinkKey};
for richer adapter inputs, return a semantic-key resolver that supplies the
additional verified evidence before calling the real adapter. Keys in
`unavailableKeys` must exercise an operational failure.

```ts
export type IdentityAdapterConformanceFactory = (
  fixture: IdentityAdapterConformanceFixture,
) => Promise<IdentityAdapterConformanceSubject>;
```

## IdentityAdapterConformanceFixture

**Kind:** interface

Semantic identity state supplied to one conformance case.

```ts
export interface IdentityAdapterConformanceFixture {
  readonly links: readonly IdentityLink[];
  readonly unavailableKeys: readonly IdentityLinkKey[];
}
```

## IdentityAdapterConformanceSubject

**Kind:** interface

Semantic-key lookup surface exercised by the identity conformance cases.

An {@link IdentityAdapter} whose input carries additional verified evidence
can expose that real adapter through this surface by constructing its richer
input for each supplied issuer-and-subject key.

```ts
export interface IdentityAdapterConformanceSubject {
  readonly resolvePrincipalId: (
    key: IdentityLinkKey,
  ) => Promise<PrincipalId | null>;
}
```
