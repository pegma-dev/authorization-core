# Stripe entitlement translation

`@pegma/authorization-stripe` translates already-trusted active Stripe identifiers into
host-owned Authorization Core entitlement names and supplies a principal-keyed adapter
over host-persisted state. It is not a Stripe integration runtime. It has no
Stripe SDK dependency and performs no network, webhook, storage writes,
logging, or policy work.

Stripe's [Entitlements documentation][stripe-entitlements] explains Product
Features and active entitlements. Stripe's
[webhook documentation][stripe-webhooks] covers endpoint signature
verification and event delivery. Hosts should use those provider facilities
before calling this package.

## Compile the host allowlist

Create one translator from trusted startup configuration:

```ts
import { createStripeEntitlementTranslator } from "@pegma/authorization-stripe";

const translateStripeEntitlements = createStripeEntitlementTranslator([
  {
    kind: "feature",
    id: "feat_priority_support",
    entitlements: ["support.priority"],
  },
  {
    kind: "feature",
    id: "feat_advanced_reports",
    entitlements: ["reports.advanced"],
  },
  {
    kind: "price",
    id: "price_pro_monthly",
    entitlements: ["plan.pro"],
  },
]);
```

Rules use two explicit namespaces:

- `feature` means an exact Stripe Entitlements **Feature ID**, such as a
  `feat_...` identifier. It does not mean a Feature `lookup_key`, a Product
  attachment, a Product or Feature name, or metadata.
- `price` means an exact Stripe Price ID used only by a host that has selected
  Price IDs as its fallback source of active billing facts.

The same literal may appear once in each namespace and maps independently.
Duplicate `(kind, id)` rules throw during translator creation. Rule IDs,
entitlement names, and runtime IDs are nonblank primitive strings compared
exactly. The package does not trim, case-fold, normalize Unicode, parse,
wildcard-match, or infer relationships.

Creation validates the entire allowlist before returning a translator. Rules
must be a dense plain array of plain records containing exactly own
`kind`, `id`, and `entitlements` data properties. Entitlement lists must be
dense plain arrays of primitive strings. Inherited, accessor, boxed, sparse,
blank, extra, proxied, and otherwise malformed values throw `TypeError`.
Proxied containers are rejected before reflective inspection, and getters are
not executed. The compiled rules are detached and frozen, so later mutation of
startup configuration has no effect.

## Select one authoritative mode

A translation call selects exactly one source:

```ts
const fromFeatures = translateStripeEntitlements({
  mode: "feature",
  activeFeatureIds: ["feat_priority_support", "feat_advanced_reports"],
});
// ["reports.advanced", "support.priority"]

const fromPrices = translateStripeEntitlements({
  mode: "price",
  activePriceIds: ["price_pro_monthly"],
});
// ["plan.pro"]
```

Feature mode is authoritative when selected. An empty
`activeFeatureIds` list produces no entitlements; the translator does not fall
back to Price rules or add Price grants. Price fallback requires a separate
call with `mode: "price"`. This prevents Product Features and legacy Price
mapping from accidentally granting access additively.

Runtime facts use the same defensive value rules as configuration and contain
only `mode` plus the matching dense ID array. Raw Stripe objects, customer IDs,
statuses, timestamps, products, subscriptions, webhook payloads, and both modes
in one object are rejected. Fact records and ID arrays must not be proxies.
Unknown but valid IDs grant nothing. Successful results are fresh, frozen,
deduplicated, and sorted.

## Request-time persisted-state adapter

The supported request-time boundary accepts only an exact host principal key:

```ts
import {
  createStripeEntitlementAdapter,
  type StripeEntitlementStateLoader,
} from "@pegma/authorization-stripe";

const loader: StripeEntitlementStateLoader = {
  loadPersistedEntitlementState: async (principalId) => {
    const state = await hostBillingStore.load(principalId);
    if (state === null) {
      throw new Error("persisted entitlement state is missing");
    }
    return state;
  },
};

const billing = createStripeEntitlementAdapter(
  [
    {
      kind: "feature",
      id: "feat_priority_support",
      entitlements: ["support.priority"],
    },
    {
      kind: "price",
      id: "price_pro_monthly",
      entitlements: ["plan.pro"],
    },
  ],
  loader,
  15 * 60 * 1000, // Host-chosen and documented 15-minute maximum state age.
);

const entitlements = await billing.resolveEntitlements({
  principalId: "account_123",
});
```

The loader returns exactly `{ principalId, refreshedAtEpochMs, facts }`.
`refreshedAtEpochMs` is a host-recorded nonnegative safe-integer Unix epoch
millisecond at which the complete active facts were last successfully confirmed
against Stripe. It is not a provider object timestamp. Webhook ingestion and
reconciliation may advance it only after successfully confirming and
transactionally persisting complete provider state. Database reads, ordinary
rewrites, migrations that do not reconfirm Stripe, and cache fills must not
advance it.

Adapter construction requires a positive safe-integer maximum state age in
milliseconds; there is no optional fail-open default. Hosts must select and
document a numeric bound appropriate to their cancellation and outage
requirements. On every resolution, the adapter samples its trusted clock once.
An age exactly equal to the configured maximum is accepted. An age one
millisecond greater is rejected, as are future-dated or malformed confirmation
and clock values. A missed webhook therefore expires paid access at the
configured bound unless reconciliation successfully reconfirms the state.
An optional final zero-argument clock parameter exists for deterministic
contract tests; production callers normally omit it and use `Date.now`.

The adapter validates the request before calling the loader, forwards the exact
nonblank primitive principal ID once, and requires the loaded state's principal
ID to match before validating freshness or translating its facts. It reloads
for every resolution and has no cache, retry, last-known-good, or fallback
behavior.

The loader function may be an own object method or a class prototype method;
the adapter invokes it with the original loader as `this`. Accessor methods,
proxied loaders or prototype objects, and methods inherited from
`Object.prototype` are rejected without executing their getters or traps.

The adapter rejects missing, corrupt, mismatched, and operationally unavailable
state. It also rejects stale and future-dated state rather than reusing an
earlier successful grant. Only a fresh, successfully loaded state containing an
explicitly empty active-ID array is an authoritative empty state. Requests
cannot carry transient facts, statuses, customers, or timestamps, and extra
fields are rejected. Persisted state records are also exact defensive values.
Accessors and
proxies cannot fabricate a principal binding, provider-confirmation time, or
facts.

The loader is a read port, not a storage implementation. The host must back it
with genuinely durable trusted persistence and own the writer, transactions,
schema migration, and operational behavior. An in-memory fixture can test the
contract but does not satisfy the production durability obligation.

`createStripeEntitlementTranslator` remains the lower-level primitive for
trusted webhook ingestion or reconciliation pipelines and for the
webhook-ledger composition below. Using it to accept transient provider facts
directly during an authorization request — facts carried by the request rather
than read from trusted durable state — bypasses the supported boundaries.

## Webhook-maintained ledgers

The full adapter's freshness contract assumes the host periodically
re-confirms facts against Stripe and advances `refreshedAtEpochMs`. A host
whose durable subscription ledger is maintained purely by verified webhooks
has no such cadence: no news means no change, and a subscription last
confirmed weeks ago is still exactly correct. For that host no value of
`maximumStateAgeMs` is honest — a small bound manufactures staleness
rejections of valid grants, and a huge bound demands a confirmation time the
host has no truthful way to advance.

The supported composition for such hosts is the pure translator over the
host's own lifecycle policy: derive the granting facts from the durable
webhook ledger at request time, then apply `createStripeEntitlementTranslator`
to those facts. This is first-class, not a workaround — deriving which
lifecycle statuses grant remains host policy under the adapter contract
either way, and the translator is the same compiled exact-ID rule set the full
adapter applies.

What the host takes on by choosing it is exactly what the wall-clock bound
otherwise enforces (security requirement 8 in the project plan: cancellation
must take effect predictably):

1. the ledger read at authorization time must be from trusted durable state,
   fail closed when missing or unavailable, and never fall back to
   last-known-good;
2. webhook pipeline health becomes the freshness guarantee, and it must stay
   fail-closed rather than alert-only. A silently dead endpoint no longer ages
   grants out, and monitoring by itself leaves paid access open until a human
   responds. The host must therefore confirm pipeline health on a bounded
   cadence — for example a periodic job that verifies the endpoint's
   registration and recent event flow against Stripe and advances a single
   durable pipeline-health confirmation time — and the authorization-time read
   must reject when that confirmation exceeds the host's chosen and documented
   bound. This is the same enforced-staleness obligation the full adapter's
   `maximumStateAgeMs` implements (security requirement 8 in the project
   plan), moved from per-principal facts — where a webhook ledger has no
   honest confirmation time — to the pipeline whose silence is the actual
   risk. A dead pipeline then denies predictably instead of granting
   indefinitely;
3. event ordering and supersession decide correctness: a fact must never be
   overwritten by an older event. Stripe does not deliver a total order across
   independently changing objects, so ordering is tracked per independently
   superseded object — for example per subscription — never as one
   per-customer watermark, which would discard an older but still-necessary
   event for a different object, including a cancellation. Alternatively the
   writer re-fetches authoritative complete state after each event and
   persists that, making delivery order irrelevant.

Hosts that do run periodic reconciliation against Stripe should prefer the
full adapter: its enforced bound is then honest and turns a broken pipeline
into predictable expiry instead of an alert dependency.

## Host-owned trust and lifecycle

Before translation, the host remains responsible for:

1. verifying webhook signatures from the exact bytes and expected endpoint
   secret;
2. ordering and deduplicating events, handling retries, and deciding which
   provider facts supersede older state;
3. binding each Stripe customer to the correct host principal;
4. owning and validating the environment-specific Price and Feature allowlist;
5. interpreting subscription, invoice, entitlement, and other provider
   lifecycle status;
6. persisting the resulting active billing facts and their host-recorded
   provider-confirmation time transactionally;
7. reconciling persisted state against Stripe and refreshing the confirmation
   time only after a complete successful provider read;
8. loading trusted active facts at authorization time — through the
   principal-keyed persisted-state adapter with a chosen and documented
   numeric maximum state age, or through the webhook-ledger composition
   above;
9. loading roles separately and applying application-owned permission policy.

The `entitlements.active_entitlement_summary.updated` webhook summary contains
at most ten active entitlements. It must not be treated as a complete list.
After receiving it, the host must page the
[full active-entitlement list API][stripe-active-list] for the customer and
persist the complete reconciled result before translating Feature IDs.

Operational failures must not be converted into an empty list that looks like
a successful revocation. The adapter rejects failures and stale state without a
last-known-good fallback. The host decides its surrounding fail-closed behavior
and retry policy and must choose the maximum acceptable state age.

## RetireGolden status

RetireGolden currently reads its persisted account/Price-tier ledger and does
not use Stripe Product Features as its source of truth. Its host can select
price fallback mode after applying its existing lifecycle policy. This existing
durability shape informed the adapter contract, but it is not a live
RetireGolden Authorization Core integration. The Product Feature examples and
provider-focused tests in this repository are fixtures; they are not evidence
of a deployed Product Features integration or live Stripe conformance testing.

[stripe-entitlements]: https://docs.stripe.com/billing/entitlements
[stripe-webhooks]: https://docs.stripe.com/webhooks
[stripe-active-list]: https://docs.stripe.com/api/entitlements/active-entitlement/list

For another billing provider, follow [Adapter authoring](ADAPTER_AUTHORING.md).
For the surrounding host trust boundaries, see the
[integration security model](SECURITY_MODEL.md) and [Scoping](SCOPING.md).
