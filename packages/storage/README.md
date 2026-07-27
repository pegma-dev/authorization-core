# @pegma/authorization-storage

Role-assignment and access-grant collections over `@pegma/storage-core`.

```sh
npm install @pegma/authorization-storage @pegma/storage-core
```

The package declares collections and implements the audited role-assignment
lifecycle against a host-supplied `Store`. It does not contain a persistence
backend; durability, transaction, and multi-process guarantees come from the
adapter selected by the host.

See the [storage guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/STORAGE.md).
