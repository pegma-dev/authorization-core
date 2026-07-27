# @pegma/authorization-stripe

Translates trusted Stripe Product Feature or Price identifiers into
application-owned entitlements.

```sh
npm install @pegma/authorization-stripe
```

The host verifies webhooks, persists complete provider state, and supplies a
principal-keyed state loader. This package enforces the configured state-age
bound; it does not call Stripe or decide subscription lifecycle.

See the [Stripe integration guide](https://github.com/pegma-dev/authorization-core/blob/main/docs/STRIPE.md).
