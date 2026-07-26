import { readFileSync } from "node:fs";

import { describe, expect, it } from "vitest";

import { identityLinkKeyFromVerifiedAuth0Claims } from "@pegma/authorization-auth0";
import type {
  AccessContext,
  AccessPolicy,
  IdentityAdapter,
  IdentityLink,
  IdentityLinkKey,
} from "@pegma/authorization-contracts";
import { resolveAccess } from "@pegma/authorization-core";
import {
  createStripeEntitlementAdapter,
  type StripeActiveEntitlementFacts,
  type StripeEntitlementAdapter,
  type StripeEntitlementRule,
  type StripePersistedEntitlementState,
} from "@pegma/authorization-stripe";

interface FixtureMetadata {
  readonly capturedAt: string;
  readonly sanitized: boolean;
  readonly sources: readonly string[];
  readonly notes: string;
}

interface Auth0AccessTokenPayload {
  readonly iss: string;
  readonly sub: string;
  readonly aud: string | readonly string[];
  readonly iat: number;
  readonly exp: number;
  readonly scope: string;
  readonly permissions: readonly string[];
  readonly org_id: string;
  readonly org_name: string;
  readonly "https://claims.fixture.example/roles": readonly string[];
  readonly azp?: string;
  readonly client_id?: string;
  readonly jti?: string;
}

interface Auth0Fixture {
  readonly _fixture: FixtureMetadata;
  readonly auth0Profile: Auth0AccessTokenPayload;
  readonly rfc9068Profile: Auth0AccessTokenPayload;
}

interface StripeActiveEntitlement {
  readonly id: string;
  readonly object: "entitlements.active_entitlement";
  readonly feature: string;
  readonly lookup_key: string;
  readonly livemode: boolean;
}

interface StripeListResponse {
  readonly object: "list";
  readonly url: string;
  readonly has_more: boolean;
  readonly data: readonly StripeActiveEntitlement[];
}

interface StripePageFixture {
  readonly request: {
    readonly customer: string;
    readonly starting_after: string | null;
  };
  readonly response: StripeListResponse;
}

interface StripeEntitlementFixture {
  readonly _fixture: FixtureMetadata;
  readonly customer: string;
  readonly webhookTrigger: {
    readonly id: string;
    readonly object: "event";
    readonly created: number;
    readonly type: "entitlements.active_entitlement_summary.updated";
    readonly data: {
      readonly object: {
        readonly object: "entitlements.active_entitlement_summary";
        readonly customer: string;
        readonly entitlements: StripeListResponse;
      };
    };
  };
  readonly pages: readonly StripePageFixture[];
}

interface StripePrice {
  readonly id: string;
  readonly object: "price";
  readonly active: boolean;
  readonly billing_scheme: string;
  readonly created: number;
  readonly currency: string;
  readonly custom_unit_amount: null;
  readonly livemode: boolean;
  readonly lookup_key: string;
  readonly metadata: Readonly<Record<string, string>>;
  readonly nickname: string;
  readonly product: string;
  readonly recurring: {
    readonly interval: string;
    readonly interval_count: number;
    readonly trial_period_days: null;
    readonly usage_type: string;
  };
  readonly tax_behavior: string;
  readonly tiers_mode: null;
  readonly transform_quantity: null;
  readonly type: "recurring";
  readonly unit_amount: number;
  readonly unit_amount_decimal: string;
}

interface StripePriceFixture {
  readonly _fixture: FixtureMetadata;
  readonly price: StripePrice;
}

interface TrustedHostPriceSelection {
  readonly principalId: string;
  readonly stripeCustomerId: string;
  readonly activePriceId: string;
  readonly confirmedAtEpochMs: number;
}

interface StripeCustomerPrincipalLink {
  readonly stripeCustomerId: string;
  readonly principalId: string;
}

const readFixture = <Fixture>(filename: string): Fixture =>
  JSON.parse(
    readFileSync(new URL(`./fixtures/${filename}`, import.meta.url), "utf8"),
  ) as Fixture;

const auth0Fixture = readFixture<Auth0Fixture>(
  "auth0-access-token-profiles.json",
);
const stripeEntitlementFixture = readFixture<StripeEntitlementFixture>(
  "stripe-active-entitlements-pages.json",
);
const stripePriceFixture = readFixture<StripePriceFixture>("stripe-price.json");

const principalId = "account_fixture_8c53c9f1";
const confirmedAtEpochMs = 1_800_000_000_000;
const maximumStateAgeMs = 5 * 60 * 1000;

const policy: AccessPolicy = {
  version: "fixture-policy-2026-07-25",
  roles: {
    "staff.advisor": ["accounts.read"],
  },
  entitlements: {
    "support.priority": ["support.priority"],
    "reports.advanced": ["reports.read"],
    "plan.advisor": ["planning.projections"],
  },
};

const rules: readonly StripeEntitlementRule[] = [
  {
    kind: "feature",
    id: "feat_test_fixture_priority_0001",
    entitlements: ["support.priority"],
  },
  {
    kind: "feature",
    id: "feat_test_fixture_reports_0011",
    entitlements: ["reports.advanced"],
  },
  {
    kind: "price",
    id: stripePriceFixture.price.id,
    entitlements: ["plan.advisor"],
  },
];

const linkedIdentity: IdentityLink = {
  key: identityLinkKeyFromVerifiedAuth0Claims(auth0Fixture.auth0Profile),
  principalId,
};

const linkedStripeCustomer: StripeCustomerPrincipalLink = {
  stripeCustomerId: stripeEntitlementFixture.customer,
  principalId,
};

const keysEqual = (left: IdentityLinkKey, right: IdentityLinkKey): boolean =>
  left.issuer === right.issuer && left.subject === right.subject;

const hostIdentityAdapter: IdentityAdapter = {
  resolvePrincipalId: async (key) =>
    keysEqual(key, linkedIdentity.key) ? linkedIdentity.principalId : null,
};

const createPersistedAdapter = (
  state: StripePersistedEntitlementState,
): StripeEntitlementAdapter =>
  createStripeEntitlementAdapter(
    rules,
    {
      loadPersistedEntitlementState: async () => state,
    },
    maximumStateAgeMs,
    () => confirmedAtEpochMs,
  );

const projectTrustedHostPriceSelection = (
  selection: TrustedHostPriceSelection,
  providerPrice: StripePrice,
): StripePersistedEntitlementState => {
  if (
    selection.principalId !== principalId ||
    selection.stripeCustomerId !== stripeEntitlementFixture.customer ||
    selection.activePriceId !== providerPrice.id
  ) {
    throw new Error("trusted host Price selection is not exactly bound");
  }

  return {
    principalId: selection.principalId,
    refreshedAtEpochMs: selection.confirmedAtEpochMs,
    facts: {
      mode: "price",
      activePriceIds: [selection.activePriceId],
    },
  };
};

const resolveHostAccess = async (
  claims: Auth0AccessTokenPayload,
  identityAdapter: IdentityAdapter,
  entitlementAdapter: StripeEntitlementAdapter,
): Promise<AccessContext> => {
  const identityKey = identityLinkKeyFromVerifiedAuth0Claims(claims);
  const resolvedPrincipalId =
    await identityAdapter.resolvePrincipalId(identityKey);

  if (resolvedPrincipalId === null) {
    throw new Error("access denied: verified identity has no host link");
  }

  const entitlements = await entitlementAdapter.resolveEntitlements({
    principalId: resolvedPrincipalId,
  });

  return resolveAccess(
    {
      principalId: resolvedPrincipalId,
      roles: ["staff.advisor"],
      entitlements,
    },
    policy,
  );
};

const reconcileCompleteFeatureList = async (
  destinationPrincipalId: string,
): Promise<{
  readonly state: StripePersistedEntitlementState;
  readonly requestedCursors: readonly (string | null)[];
}> => {
  const customer = stripeEntitlementFixture.webhookTrigger.data.object.customer;
  if (
    linkedStripeCustomer.stripeCustomerId !== customer ||
    linkedStripeCustomer.principalId !== destinationPrincipalId
  ) {
    throw new Error("Stripe customer is not bound to destination principal");
  }

  const requestedCursors: (string | null)[] = [];
  const activeFeatureIds: string[] = [];
  let startingAfter: string | null = null;

  while (true) {
    requestedCursors.push(startingAfter);
    const pageFixture = stripeEntitlementFixture.pages.find(
      (page) =>
        page.request.customer === customer &&
        page.request.starting_after === startingAfter,
    );

    if (pageFixture === undefined) {
      throw new Error("fixture does not contain the requested Stripe page");
    }

    activeFeatureIds.push(
      ...pageFixture.response.data.map((entitlement) => entitlement.feature),
    );

    if (!pageFixture.response.has_more) {
      break;
    }

    const lastEntitlement = pageFixture.response.data.at(-1);
    if (lastEntitlement === undefined) {
      throw new Error("a paged Stripe response cannot advance without data");
    }
    startingAfter = lastEntitlement.id;
  }

  return {
    requestedCursors,
    state: {
      principalId: destinationPrincipalId,
      refreshedAtEpochMs: confirmedAtEpochMs,
      facts: {
        mode: "feature",
        activeFeatureIds,
      },
    },
  };
};

const allProviderOnlyStrings = (): readonly string[] => [
  auth0Fixture.auth0Profile.iss,
  auth0Fixture.auth0Profile.sub,
  ...(typeof auth0Fixture.auth0Profile.aud === "string"
    ? [auth0Fixture.auth0Profile.aud]
    : auth0Fixture.auth0Profile.aud),
  auth0Fixture.auth0Profile.scope,
  ...(auth0Fixture.auth0Profile.azp === undefined
    ? []
    : [auth0Fixture.auth0Profile.azp]),
  ...auth0Fixture.auth0Profile.permissions,
  ...auth0Fixture.auth0Profile["https://claims.fixture.example/roles"],
  auth0Fixture.auth0Profile.org_id,
  auth0Fixture.auth0Profile.org_name,
  stripeEntitlementFixture.customer,
  stripeEntitlementFixture.webhookTrigger.id,
  ...stripeEntitlementFixture.pages.flatMap((page) =>
    page.response.data.flatMap((entitlement) => [
      entitlement.id,
      entitlement.feature,
      entitlement.lookup_key,
    ]),
  ),
  stripePriceFixture.price.id,
  stripePriceFixture.price.lookup_key,
  stripePriceFixture.price.product,
];

describe("provider-fixture adapter contract", () => {
  it("composes verified Auth0 identity through fully reconciled Stripe features into provider-neutral access", async () => {
    expect(auth0Fixture._fixture).toMatchObject({
      capturedAt: "2026-07-25",
      sanitized: true,
    });
    expect(stripeEntitlementFixture._fixture).toMatchObject({
      capturedAt: "2026-07-25",
      sanitized: true,
    });

    const { state, requestedCursors } =
      await reconcileCompleteFeatureList(principalId);
    const access = await resolveHostAccess(
      auth0Fixture.auth0Profile,
      hostIdentityAdapter,
      createPersistedAdapter(state),
    );

    expect(requestedCursors).toEqual([null, "ent_test_fixture_unmapped_0010"]);
    expect(state.refreshedAtEpochMs).toBe(confirmedAtEpochMs);
    expect(state.refreshedAtEpochMs).not.toBe(
      stripeEntitlementFixture.webhookTrigger.created * 1000,
    );
    const summary =
      stripeEntitlementFixture.webhookTrigger.data.object.entitlements;
    expect(summary.data).toHaveLength(10);
    expect(summary.has_more).toBe(true);
    expect(summary.url).toBe(
      `/v1/customer/${stripeEntitlementFixture.customer}/entitlements`,
    );
    expect(
      summary.data.map((entitlement) => entitlement.feature),
    ).not.toContain("feat_test_fixture_reports_0011");
    expect(
      (state.facts as { readonly activeFeatureIds: readonly string[] })
        .activeFeatureIds,
    ).toHaveLength(11);
    expect(
      (state.facts as { readonly activeFeatureIds: readonly string[] })
        .activeFeatureIds,
    ).toContain("feat_test_fixture_reports_0011");

    expect(access).toEqual({
      principalId,
      policyVersion: "fixture-policy-2026-07-25",
      roles: ["staff.advisor"],
      entitlements: ["reports.advanced", "support.priority"],
      permissions: ["accounts.read", "reports.read", "support.priority"],
    });
    expect(Object.keys(access)).toEqual([
      "principalId",
      "policyVersion",
      "roles",
      "entitlements",
      "permissions",
    ]);

    const serializedAccess = JSON.stringify(access);
    for (const providerOnlyValue of allProviderOnlyStrings()) {
      expect(serializedAccess).not.toContain(providerOnlyValue);
    }
  });

  it("rejects fully reconciled Stripe features for a different destination principal", async () => {
    await expect(
      reconcileCompleteFeatureList("account_fixture_other_principal"),
    ).rejects.toThrow("Stripe customer is not bound to destination principal");
  });

  it("uses a host-selected Price ID only in explicit fallback mode", async () => {
    expect(stripePriceFixture._fixture).toMatchObject({
      capturedAt: "2026-07-25",
      sanitized: true,
    });

    const price = stripePriceFixture.price;
    const trustedHostLedgerSelection: TrustedHostPriceSelection = {
      principalId,
      stripeCustomerId: stripeEntitlementFixture.customer,
      activePriceId: price.id,
      confirmedAtEpochMs,
    };
    const persistedState = projectTrustedHostPriceSelection(
      trustedHostLedgerSelection,
      price,
    );

    const access = await resolveHostAccess(
      auth0Fixture.auth0Profile,
      hostIdentityAdapter,
      createPersistedAdapter(persistedState),
    );

    expect(persistedState.facts).toEqual({
      mode: "price",
      activePriceIds: [price.id],
    });
    expect(access.entitlements).toEqual(["plan.advisor"]);
    expect(access.permissions).toEqual([
      "accounts.read",
      "planning.projections",
    ]);
    expect(JSON.stringify(access)).not.toContain(price.id);
    expect(JSON.stringify(access)).not.toContain(price.lookup_key);
  });

  it("denies an already-verified but unlinked Auth0 identity before billing lookup", async () => {
    let billingLoads = 0;
    const billingAdapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async () => {
          billingLoads += 1;
          throw new Error(
            "billing must not be loaded for an unlinked identity",
          );
        },
      },
      maximumStateAgeMs,
      () => confirmedAtEpochMs,
    );

    await expect(
      resolveHostAccess(
        auth0Fixture.rfc9068Profile,
        hostIdentityAdapter,
        billingAdapter,
      ),
    ).rejects.toThrow("verified identity has no host link");
    expect(billingLoads).toBe(0);
  });

  it.each([
    {
      label: "Feature",
      facts: {
        mode: "feature",
        activeFeatureIds: ["feat_test_fixture_unknown_only"],
      },
    },
    {
      label: "Price",
      facts: {
        mode: "price",
        activePriceIds: ["price_fixture_unknown_only"],
      },
    },
  ] as const)(
    "grants nothing for an unmapped $label identifier",
    async ({ facts }) => {
      const adapter = createPersistedAdapter({
        principalId,
        refreshedAtEpochMs: confirmedAtEpochMs,
        facts: facts as StripeActiveEntitlementFacts,
      });
      const entitlements = await adapter.resolveEntitlements({ principalId });
      const access = resolveAccess({ principalId, entitlements }, policy);

      expect(entitlements).toEqual([]);
      expect(access.permissions).toEqual([]);
    },
  );
});
