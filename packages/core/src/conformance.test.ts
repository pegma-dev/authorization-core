import { describe, expect, it } from "vitest";

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
} from "./conformance.js";

function keysEqual(left: IdentityLinkKey, right: IdentityLinkKey): boolean {
  return left.issuer === right.issuer && left.subject === right.subject;
}

const createIdentityAdapter: IdentityAdapterConformanceFactory = async (
  fixture,
) => {
  const links = fixture.links.map(({ key, principalId }) => ({
    key: { ...key },
    principalId,
  }));
  const unavailableKeys = fixture.unavailableKeys.map((key) => ({ ...key }));
  const adapter: IdentityAdapter = {
    resolvePrincipalId: async (key) => {
      if (unavailableKeys.some((candidate) => keysEqual(candidate, key))) {
        throw new Error("identity store unavailable");
      }
      return (
        links.find((candidate) => keysEqual(candidate.key, key))?.principalId ??
        null
      );
    },
  };
  return adapter;
};

const createEntitlementAdapter: EntitlementAdapterConformanceFactory = async (
  fixture,
) => {
  const states = new Map<string, EntitlementFixtureState[]>();
  for (const { principalId, state } of fixture.states) {
    const sequence = states.get(principalId) ?? [];
    sequence.push(state);
    states.set(principalId, sequence);
  }

  const adapter: EntitlementAdapter = {
    resolveEntitlements: async ({ principalId }) => {
      const sequence = states.get(principalId);
      const state = sequence?.shift();
      if (state === undefined || state.kind !== "current") {
        throw new Error(
          `entitlement state ${state?.kind ?? "missing"} is not current`,
        );
      }
      return Object.freeze([...new Set(state.entitlements)].sort());
    },
  };
  return adapter;
};

const createGlobalQueueEntitlementAdapter: EntitlementAdapterConformanceFactory =
  async (fixture) => {
    const states = [...fixture.states];
    return {
      resolveEntitlements: async () => {
        const state = states.shift()?.state;
        if (state === undefined || state.kind !== "current") {
          throw new Error(
            `entitlement state ${state?.kind ?? "missing"} is not current`,
          );
        }
        return Object.freeze([...new Set(state.entitlements)].sort());
      },
    };
  };

const createFallbackEntitlementAdapter: EntitlementAdapterConformanceFactory =
  async (fixture) => {
    const states = new Map<string, EntitlementFixtureState[]>();
    for (const { principalId, state } of fixture.states) {
      const sequence = states.get(principalId) ?? [];
      sequence.push(state);
      states.set(principalId, sequence);
    }
    const cache = new Map<string, readonly string[]>();
    return {
      resolveEntitlements: async ({ principalId }) => {
        const state = states.get(principalId)?.shift();
        if (state?.kind === "current") {
          const result = Object.freeze([...new Set(state.entitlements)].sort());
          cache.set(principalId, result);
          return result;
        }
        const previous = cache.get(principalId);
        if (previous !== undefined) return previous;
        throw new Error(
          `entitlement state ${state?.kind ?? "missing"} is not current`,
        );
      },
    };
  };

const createCachedSuccessEntitlementAdapter: EntitlementAdapterConformanceFactory =
  async (fixture) => {
    const states = new Map<string, EntitlementFixtureState[]>();
    for (const { principalId, state } of fixture.states) {
      const sequence = states.get(principalId) ?? [];
      sequence.push(state);
      states.set(principalId, sequence);
    }
    const cache = new Map<string, readonly string[]>();
    return {
      resolveEntitlements: async ({ principalId }) => {
        const previous = cache.get(principalId);
        if (previous !== undefined) return previous;
        const state = states.get(principalId)?.shift();
        if (state === undefined || state.kind !== "current") {
          throw new Error(
            `entitlement state ${state?.kind ?? "missing"} is not current`,
          );
        }
        const result = Object.freeze([...new Set(state.entitlements)].sort());
        cache.set(principalId, result);
        return result;
      },
    };
  };

describe("@pegma/authorization-core/conformance", () => {
  describe("identity adapters", () => {
    for (const testCase of identityAdapterConformanceCases) {
      it(testCase.name, () => testCase.run(createIdentityAdapter));
    }
  });

  describe("entitlement adapters", () => {
    for (const testCase of entitlementAdapterConformanceCases) {
      it(testCase.name, () => testCase.run(createEntitlementAdapter));
    }
  });

  it("publishes unique case names", () => {
    const names = [
      ...identityAdapterConformanceCases,
      ...entitlementAdapterConformanceCases,
    ].map(({ name }) => name);

    expect(new Set(names).size).toBe(names.length);
  });

  it("rejects an adapter that ignores the requested principal", async () => {
    const testCase = entitlementAdapterConformanceCases.find(
      ({ name }) =>
        name === "entitlement resolution stays isolated by host principal",
    );

    await expect(
      testCase?.run(createGlobalQueueEntitlementAdapter),
    ).rejects.toThrow();
  });

  it("rejects cached success instead of authoritative current refresh", async () => {
    const testCase = entitlementAdapterConformanceCases.find(
      ({ name }) =>
        name === "a later current state replaces prior entitlement output",
    );

    await expect(
      testCase?.run(createCachedSuccessEntitlementAdapter),
    ).rejects.toThrow();
  });

  for (const kind of [
    "missing",
    "stale",
    "future",
    "corrupt",
    "unavailable",
  ] as const) {
    it(`rejects last-known-good fallback after ${kind} state`, async () => {
      const testCase = entitlementAdapterConformanceCases.find(
        ({ name }) =>
          name ===
          `a later ${kind} entitlement state cannot use last-known-good output`,
      );

      await expect(
        testCase?.run(createFallbackEntitlementAdapter),
      ).rejects.toThrow();
    });
  }
});
