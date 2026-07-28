# @pegma/authorization-identity

Projects already-verified first-party identity claims into provider-neutral
Authorization Core identity-link keys.

```sh
npm install @pegma/authorization-identity
```

The accepted structural claims contract matches `@pegma/identity`:
`{ issuer, subject, emailVerified: true }`. The host must obtain those claims
from a trusted identity flow before calling this adapter. The adapter does not
authenticate sessions, resolve account links, or accept email as identity.

Only the exact own-data-property claims shape is accepted. The result is a
fresh frozen `{ issuer, subject }`; verification evidence and all contact data
remain structurally absent.

The runtime uses only standard JavaScript APIs and is suitable for Node,
Workers, Deno, and Bun. Descriptor validation does not execute ordinary-object
getters. JavaScript cannot portably detect a proxy without invoking reflection
traps, so trusted callers should pass a plain verified-claims snapshot.

See the
[identity adapter guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/IDENTITY_ADAPTER.md).
