# @pegma/authorization-tokens/testing

Generated from the public declaration entry point `packages/tokens/dist/testing.d.ts`. Internal modules are intentionally excluded.

## AccessGrantIssuerDependencies

**Kind:** interface

```ts
export interface AccessGrantIssuerDependencies {
  readonly monotonicNowMs: () => number;
  readonly wallNowEpochMs: () => number;
  readonly randomBytes32: () => Uint8Array;
}
```

## AccessGrantVerifierDependencies

**Kind:** interface

```ts
export interface AccessGrantVerifierDependencies {
  readonly verifierWallNowEpochMs: () => number;
  readonly jwksMonotonicNowMs: () => number;
  readonly replayStoreNowEpochMs: () => number;
  readonly fetchJwks: JwksFetcher;
}
```

## createTestAccessGrantIssuer

**Kind:** function

```ts
export declare function createTestAccessGrantIssuer<ReadRequest>(
  configuration: AccessGrantIssuerConfiguration<ReadRequest>,
  store: Store,
  dependencies: AccessGrantIssuerDependencies,
): AccessGrantIssuer<ReadRequest>;
```

## createTestAccessGrantVerifier

**Kind:** function

```ts
export declare function createTestAccessGrantVerifier(
  configuration: AccessGrantVerifierConfiguration,
  store: Store,
  dependencies: AccessGrantVerifierDependencies,
): AccessGrantVerifier;
```

## JwksFetcher

**Kind:** type

```ts
export type JwksFetcher = (url: string) => Promise<JwksFetchResult>;
```

## JwksFetchResult

**Kind:** interface

```ts
export interface JwksFetchResult {
  /** Raw UTF-8 JSON. Raw input is required so duplicate members remain visible. */
  readonly body: string | Uint8Array;
  /** Final URL after any redirect handling. */
  readonly finalUrl: string;
}
```
