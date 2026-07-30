# @pegma/authorization-admin

HTTP-neutral audited role administration for Authorization Core hosts.

```sh
npm install @pegma/authorization-admin @pegma/authorization-storage @pegma/storage-core
```

The package owns the role-management logic both reference hosts duplicated:
a grants view with an explicit management policy, audited assign, audited
revoke with the last-administrator guard (serialize, pre-check, re-verify,
compensate), per-principal lifecycle history, and the one-time seed helper.
The host owns the HTTP envelope, UI, principal lookup, rate limiting, and
the authorization of the service's own callers — one admin tool per site,
separate instances, nothing crossing hosts.

See the [administration guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/ADMINISTRATION.md).
