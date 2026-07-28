import { describe, it } from "vitest";

import type {
  EntitlementAdapter,
  IdentityAdapter,
  IdentityLinkKey,
} from "@pegma/authorization-contracts";
import {
  entitlementAdapterConformanceCases,
  identityAdapterConformanceCases,
  type EntitlementAdapterConformanceFactory,
  type EntitlementFixtureState,
  type IdentityAdapterConformanceFactory,
} from "@pegma/authorization-core/conformance";
import { createInMemoryStorageAdapter } from "@pegma/authorization-storage";
import {
  createStripeEntitlementAdapter,
  type StripeEntitlementRule,
  type StripePersistedEntitlementState,
} from "@pegma/authorization-stripe";

function keysEqual(left: IdentityLinkKey, right: IdentityLinkKey): boolean {
  return left.issuer === right.issuer && left.subject === right.subject;
}

const createIdentityAdapter: IdentityAdapterConformanceFactory = async (
  fixture,
) => {
  const storage = createInMemoryStorageAdapter({
    identityLinks: fixture.links,
  });
  const adapter: IdentityAdapter = {
    resolvePrincipalId: async (key) => {
      if (
        fixture.unavailableKeys.some((candidate) => keysEqual(candidate, key))
      ) {
        throw new Error("identity store unavailable");
      }
      return storage.resolvePrincipalId(key);
    },
  };
  return adapter;
};

const currentTimeEpochMs = 1_800_000_000_000;
const maximumStateAgeMs = 60_000;

function stripeState(
  principalId: string,
  state: EntitlementFixtureState,
  featureIds: ReadonlyMap<string, string>,
): StripePersistedEntitlementState {
  if (state.kind === "corrupt") {
    return {
      principalId,
      refreshedAtEpochMs: currentTimeEpochMs,
      facts: {
        mode: "feature",
        activeFeatureIds: [1],
      },
    } as unknown as StripePersistedEntitlementState;
  }

  const refreshedAtEpochMs =
    state.kind === "stale"
      ? currentTimeEpochMs - maximumStateAgeMs - 1
      : state.kind === "future"
        ? currentTimeEpochMs + 1
        : currentTimeEpochMs;
  const entitlements = state.kind === "current" ? state.entitlements : [];
  return {
    principalId,
    refreshedAtEpochMs,
    facts: {
      mode: "feature",
      activeFeatureIds: entitlements.map((name) => {
        const featureId = featureIds.get(name);
        if (featureId === undefined) {
          throw new Error(`missing conformance feature for ${name}`);
        }
        return featureId;
      }),
    },
  };
}

const createEntitlementAdapter: EntitlementAdapterConformanceFactory = async (
  fixture,
) => {
  const names = [
    ...new Set(
      fixture.states.flatMap(({ state }) =>
        state.kind === "current" ? state.entitlements : [],
      ),
    ),
  ].sort();
  const featureIds = new Map(
    names.map((name, index) => [name, `feat_conformance_${String(index)}`]),
  );
  const rules: readonly StripeEntitlementRule[] = names.map((name) => ({
    kind: "feature",
    id: featureIds.get(name)!,
    entitlements: [name],
  }));
  const states = new Map<string, EntitlementFixtureState[]>();
  for (const { principalId, state } of fixture.states) {
    const sequence = states.get(principalId) ?? [];
    sequence.push(state);
    states.set(principalId, sequence);
  }

  const adapter: EntitlementAdapter = createStripeEntitlementAdapter(
    rules,
    {
      loadPersistedEntitlementState: async (principalId) => {
        const state = states.get(principalId)?.shift();
        if (
          state === undefined ||
          state.kind === "missing" ||
          state.kind === "unavailable"
        ) {
          throw new Error(`entitlement state ${state?.kind ?? "missing"}`);
        }
        return stripeState(principalId, state, featureIds);
      },
    },
    maximumStateAgeMs,
    () => currentTimeEpochMs,
  );
  return adapter;
};

describe("official adapter conformance", () => {
  describe("@pegma/authorization-storage identity lookup", () => {
    for (const testCase of identityAdapterConformanceCases) {
      it(testCase.name, () => testCase.run(createIdentityAdapter));
    }
  });

  describe("@pegma/authorization-stripe entitlement resolution", () => {
    for (const testCase of entitlementAdapterConformanceCases) {
      it(testCase.name, () => testCase.run(createEntitlementAdapter));
    }
  });
});
