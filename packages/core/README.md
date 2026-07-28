# @pegma/authorization-core

Pure, deterministic permission resolution for Authorization Core.

```sh
npm install @pegma/authorization-core
```

Use it to combine trusted roles and entitlements with a parsed application
policy, produce an access context, and decide whether a permission is present.
The host remains responsible for identity verification, authoritative data
loading, resource relationships, and server-side enforcement.

See the [getting-started guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/GETTING_STARTED.md).

## Adapter conformance

The `@pegma/authorization-core/conformance` subpath exports
framework-independent identity and entitlement adapter cases. Adapter authors
translate the suite's semantic fixtures into their provider and persistence
model, then register the cases with their existing test runner. The conformance
entrypoint currently expects Node.js 22 or newer and uses `node:assert/strict`
internally:

```ts
import {
  entitlementAdapterConformanceCases,
  identityAdapterConformanceCases,
} from "@pegma/authorization-core/conformance";

for (const testCase of identityAdapterConformanceCases) {
  it(testCase.name, () => testCase.run(createIdentityAdapter));
}

for (const testCase of entitlementAdapterConformanceCases) {
  it(testCase.name, () => testCase.run(createEntitlementAdapter));
}
```

See the
[adapter-authoring guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/ADAPTER_AUTHORING.md)
for the factory contracts and the boundary that remains provider-specific.
