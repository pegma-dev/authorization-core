import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  AccessSubject,
  EntitlementRequest,
  PrincipalId,
} from "@pegma/authorization-contracts";

import {
  createStripeEntitlementAdapter,
  createStripeEntitlementTranslator,
  type StripeActiveEntitlementFacts,
  type StripeEntitlementAdapter,
  type StripeEntitlementClock,
  type StripeEntitlementRequest,
  type StripeEntitlementRule,
  type StripeEntitlementStateLoader,
  type StripePersistedEntitlementState,
} from "./index.js";

const rules: readonly StripeEntitlementRule[] = [
  {
    kind: "feature",
    id: "feat_support",
    entitlements: ["support.priority", "plan.pro"],
  },
  {
    kind: "feature",
    id: "feat_reports",
    entitlements: ["reports.advanced", "plan.pro"],
  },
  {
    kind: "price",
    id: "price_pro_monthly",
    entitlements: ["plan.pro"],
  },
];

const asRules = (value: unknown): readonly StripeEntitlementRule[] =>
  value as readonly StripeEntitlementRule[];

const asFacts = (value: unknown): StripeActiveEntitlementFacts =>
  value as StripeActiveEntitlementFacts;

const asRequest = (value: unknown): StripeEntitlementRequest =>
  value as StripeEntitlementRequest;

const asPersistedState = (value: unknown): StripePersistedEntitlementState =>
  value as StripePersistedEntitlementState;

describe("createStripeEntitlementTranslator", () => {
  it("allows mapped active Feature IDs and denies unknown valid IDs", () => {
    const translate = createStripeEntitlementTranslator(rules);

    expect(
      translate({
        mode: "feature",
        activeFeatureIds: ["feat_reports", "feat_unknown", "feat_support"],
      }),
    ).toEqual(["plan.pro", "reports.advanced", "support.priority"]);
    expect(
      translate({
        mode: "feature",
        activeFeatureIds: ["feat_unknown"],
      }),
    ).toEqual([]);
  });

  it("translates Price IDs only in explicit price fallback mode", () => {
    const translate = createStripeEntitlementTranslator(rules);

    expect(
      translate({
        mode: "price",
        activePriceIds: ["price_pro_monthly", "price_unknown"],
      }),
    ).toEqual(["plan.pro"]);
    expect(
      translate({
        mode: "feature",
        activeFeatureIds: ["price_pro_monthly"],
      }),
    ).toEqual([]);
  });

  it("treats an empty authoritative feature list as no access without price fallback", () => {
    const translate = createStripeEntitlementTranslator(rules);

    expect(translate({ mode: "feature", activeFeatureIds: [] })).toEqual([]);
  });

  it("keeps the same literal distinct across feature and price namespaces", () => {
    const translate = createStripeEntitlementTranslator([
      {
        kind: "feature",
        id: "__proto__",
        entitlements: ["from.feature"],
      },
      {
        kind: "price",
        id: "__proto__",
        entitlements: ["from.price"],
      },
    ]);

    expect(
      translate({ mode: "feature", activeFeatureIds: ["__proto__"] }),
    ).toEqual(["from.feature"]);
    expect(translate({ mode: "price", activePriceIds: ["__proto__"] })).toEqual(
      ["from.price"],
    );
  });

  it("compares IDs exactly without case, whitespace, or Unicode normalization", () => {
    const translate = createStripeEntitlementTranslator([
      {
        kind: "feature",
        id: "feat_Caf\u00e9",
        entitlements: [" entitlement.\u00c9lite "],
      },
      {
        kind: "price",
        id: " price_exact ",
        entitlements: ["plan.whitespace"],
      },
    ]);

    expect(
      translate({ mode: "feature", activeFeatureIds: ["feat_Caf\u00e9"] }),
    ).toEqual([" entitlement.\u00c9lite "]);
    expect(
      translate({
        mode: "feature",
        activeFeatureIds: [
          "feat_caf\u00e9",
          " feat_Caf\u00e9",
          "feat_Cafe\u0301",
        ],
      }),
    ).toEqual([]);
    expect(
      translate({ mode: "price", activePriceIds: ["price_exact"] }),
    ).toEqual([]);
    expect(
      translate({ mode: "price", activePriceIds: [" price_exact "] }),
    ).toEqual(["plan.whitespace"]);
  });

  it("handles prototype-sensitive identifiers as ordinary exact strings", () => {
    const translate = createStripeEntitlementTranslator([
      {
        kind: "feature",
        id: "constructor",
        entitlements: ["grant.constructor"],
      },
      {
        kind: "feature",
        id: "toString",
        entitlements: ["grant.toString"],
      },
      {
        kind: "feature",
        id: "__proto__",
        entitlements: ["grant.prototype"],
      },
    ]);

    expect(
      translate({
        mode: "feature",
        activeFeatureIds: ["toString", "__proto__", "constructor"],
      }),
    ).toEqual(["grant.constructor", "grant.prototype", "grant.toString"]);
  });

  it("rejects duplicate identifiers within one namespace", () => {
    expect(() =>
      createStripeEntitlementTranslator([
        {
          kind: "feature",
          id: "feat_duplicate",
          entitlements: ["one"],
        },
        {
          kind: "feature",
          id: "feat_duplicate",
          entitlements: ["two"],
        },
      ]),
    ).toThrow(TypeError);
  });

  it("returns deduplicated sorted fresh frozen output", () => {
    const translate = createStripeEntitlementTranslator([
      {
        kind: "feature",
        id: "feat_one",
        entitlements: ["zeta", "alpha", "alpha"],
      },
      {
        kind: "feature",
        id: "feat_two",
        entitlements: ["middle", "zeta"],
      },
    ]);

    const first = translate({
      mode: "feature",
      activeFeatureIds: ["feat_two", "feat_one", "feat_one"],
    });
    const second = translate({
      mode: "feature",
      activeFeatureIds: ["feat_one", "feat_two"],
    });

    expect(first).toEqual(["alpha", "middle", "zeta"]);
    expect(Object.isFrozen(first)).toBe(true);
    expect(first).not.toBe(second);
    expect(() => (first as string[]).push("changed")).toThrow(TypeError);
  });

  it("detaches compiled rules from every caller-owned array and object", () => {
    const mutableEntitlements = ["plan.original"];
    const mutableRule = {
      kind: "feature" as const,
      id: "feat_original",
      entitlements: mutableEntitlements,
    };
    const mutableRules = [mutableRule];
    const translate = createStripeEntitlementTranslator(mutableRules);

    mutableRule.id = "feat_changed";
    mutableEntitlements[0] = "plan.changed";
    mutableRules.push({
      kind: "feature",
      id: "feat_added",
      entitlements: ["plan.added"],
    });

    expect(
      translate({ mode: "feature", activeFeatureIds: ["feat_original"] }),
    ).toEqual(["plan.original"]);
    expect(
      translate({
        mode: "feature",
        activeFeatureIds: ["feat_changed", "feat_added"],
      }),
    ).toEqual([]);
  });

  it("accepts frozen and null-prototype rule records with own data fields", () => {
    const nullPrototypeRule = Object.assign(Object.create(null), {
      kind: "feature",
      id: "feat_null_prototype",
      entitlements: Object.freeze(["plan.safe"]),
    });
    const translate = createStripeEntitlementTranslator(
      Object.freeze(asRules([nullPrototypeRule])),
    );

    expect(
      translate({
        mode: "feature",
        activeFeatureIds: ["feat_null_prototype"],
      }),
    ).toEqual(["plan.safe"]);
  });

  it.each([
    ["non-array rules", {}],
    ["null rules", null],
    ["missing fields", [{ kind: "feature", id: "feat_missing" }]],
    [
      "extra provider fields",
      [
        {
          kind: "feature",
          id: "feat_extra",
          entitlements: ["plan.pro"],
          lookup_key: "pro",
        },
      ],
    ],
    [
      "invalid namespace",
      [{ kind: "product", id: "prod_123", entitlements: ["plan.pro"] }],
    ],
    [
      "boxed ID",
      [
        {
          kind: "feature",
          id: new String("feat_boxed"),
          entitlements: ["plan.pro"],
        },
      ],
    ],
    [
      "blank ID",
      [{ kind: "feature", id: " \t\n", entitlements: ["plan.pro"] }],
    ],
    [
      "boxed entitlement",
      [
        {
          kind: "feature",
          id: "feat_boxed",
          entitlements: [new String("plan.pro")],
        },
      ],
    ],
    [
      "blank entitlement",
      [{ kind: "feature", id: "feat_blank", entitlements: ["\u00a0"] }],
    ],
    ["array rule", [["feature", "feat_array", ["plan.pro"]]]],
    ["exotic rule", [new Date()]],
  ])("rejects malformed rules: %s", (_name, value) => {
    expect(() => createStripeEntitlementTranslator(asRules(value))).toThrow(
      TypeError,
    );
  });

  it("rejects sparse and accessor rule arrays without executing getters", () => {
    const sparseRules = new Array(1);
    let getterCalls = 0;
    const accessorRules: unknown[] = [];
    Object.defineProperty(accessorRules, "0", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return rules[0];
      },
    });
    accessorRules.length = 1;

    expect(() =>
      createStripeEntitlementTranslator(asRules(sparseRules)),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementTranslator(asRules(accessorRules)),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it("rejects proxied rule arrays, records, and entitlement arrays before traps execute", () => {
    let trapCalls = 0;
    let getterCalls = 0;
    const fabricated = {
      get rule() {
        getterCalls += 1;
        return {
          kind: "feature",
          id: "feat_fabricated",
          entitlements: ["plan.fabricated"],
        };
      },
      get id() {
        getterCalls += 1;
        return "feat_fabricated";
      },
      get entitlement() {
        getterCalls += 1;
        return "plan.fabricated";
      },
    };

    const proxiedRules = new Proxy(new Array<unknown>(1), {
      getPrototypeOf: () => {
        trapCalls += 1;
        return Array.prototype;
      },
      ownKeys: () => {
        trapCalls += 1;
        return ["0", "length"];
      },
      getOwnPropertyDescriptor: (target, property) => {
        trapCalls += 1;
        if (property === "length") {
          return Reflect.getOwnPropertyDescriptor(target, property);
        }
        if (property === "0") {
          return {
            configurable: true,
            enumerable: true,
            writable: true,
            value: fabricated.rule,
          };
        }
        return undefined;
      },
    });

    const proxiedRule = new Proxy(
      {
        kind: "feature",
        id: "not-used",
        entitlements: ["not-used"],
      },
      {
        getPrototypeOf: () => {
          trapCalls += 1;
          return Object.prototype;
        },
        ownKeys: () => {
          trapCalls += 1;
          return ["kind", "id", "entitlements"];
        },
        getOwnPropertyDescriptor: (target, property) => {
          trapCalls += 1;
          const descriptor = Reflect.getOwnPropertyDescriptor(target, property);
          if (property === "id" && descriptor !== undefined) {
            return { ...descriptor, value: fabricated.id };
          }
          return descriptor;
        },
      },
    );

    const proxiedEntitlements = new Proxy(new Array<unknown>(1), {
      getPrototypeOf: () => {
        trapCalls += 1;
        return Array.prototype;
      },
      ownKeys: () => {
        trapCalls += 1;
        return ["0", "length"];
      },
      getOwnPropertyDescriptor: (target, property) => {
        trapCalls += 1;
        if (property === "length") {
          return Reflect.getOwnPropertyDescriptor(target, property);
        }
        if (property === "0") {
          return {
            configurable: true,
            enumerable: true,
            writable: true,
            value: fabricated.entitlement,
          };
        }
        return undefined;
      },
    });

    expect(() =>
      createStripeEntitlementTranslator(asRules(proxiedRules)),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementTranslator(asRules([proxiedRule])),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementTranslator(
        asRules([
          {
            kind: "feature",
            id: "feat_proxy_entitlements",
            entitlements: proxiedEntitlements,
          },
        ]),
      ),
    ).toThrow(TypeError);
    expect(trapCalls).toBe(0);
    expect(getterCalls).toBe(0);
  });

  it("rejects inherited and accessor rule fields without executing getters", () => {
    const inherited = Object.assign(Object.create({ kind: "feature" }), {
      id: "feat_inherited",
      entitlements: ["plan.pro"],
    });
    let getterCalls = 0;
    const accessor = {
      kind: "feature",
      entitlements: ["plan.pro"],
    };
    Object.defineProperty(accessor, "id", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "feat_accessor";
      },
    });

    expect(() =>
      createStripeEntitlementTranslator(asRules([inherited])),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementTranslator(asRules([accessor])),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it("rejects sparse and accessor entitlement arrays without partial compilation", () => {
    const sparseEntitlements = ["plan.first", , "plan.third"];
    let getterCalls = 0;
    const accessorEntitlements = ["plan.first"];
    Object.defineProperty(accessorEntitlements, "1", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "plan.second";
      },
    });
    accessorEntitlements.length = 2;

    expect(() =>
      createStripeEntitlementTranslator(
        asRules([
          rules[0],
          {
            kind: "feature",
            id: "feat_sparse",
            entitlements: sparseEntitlements,
          },
        ]),
      ),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementTranslator(
        asRules([
          rules[0],
          {
            kind: "feature",
            id: "feat_accessor",
            entitlements: accessorEntitlements,
          },
        ]),
      ),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });
});

describe("Stripe active fact validation", () => {
  const translate = createStripeEntitlementTranslator(rules);

  it.each([
    ["null", null],
    ["array", []],
    ["Date", new Date()],
    ["missing mode", { activeFeatureIds: ["feat_support"] }],
    [
      "wrong discriminator",
      { mode: "features", activeFeatureIds: ["feat_support"] },
    ],
    [
      "wrong field for feature mode",
      { mode: "feature", activePriceIds: ["price_pro_monthly"] },
    ],
    [
      "both modes supplied",
      {
        mode: "feature",
        activeFeatureIds: ["feat_support"],
        activePriceIds: ["price_pro_monthly"],
      },
    ],
    [
      "raw provider lifecycle field",
      {
        mode: "feature",
        activeFeatureIds: ["feat_support"],
        status: "active",
      },
    ],
    [
      "raw customer field",
      {
        mode: "price",
        activePriceIds: ["price_pro_monthly"],
        customer: "cus_123",
      },
    ],
    [
      "boxed active ID",
      {
        mode: "feature",
        activeFeatureIds: [new String("feat_support")],
      },
    ],
    ["blank active ID", { mode: "feature", activeFeatureIds: [" \t"] }],
    [
      "non-array IDs",
      { mode: "feature", activeFeatureIds: new Set(["feat_support"]) },
    ],
  ])("rejects malformed facts: %s", (_name, value) => {
    expect(() => translate(asFacts(value))).toThrow(TypeError);
  });

  it("rejects inherited and accessor fact fields without executing getters", () => {
    const inherited = Object.assign(Object.create({ mode: "feature" }), {
      activeFeatureIds: ["feat_support"],
    });
    let getterCalls = 0;
    const accessor = { activeFeatureIds: ["feat_support"] };
    Object.defineProperty(accessor, "mode", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "feature";
      },
    });

    expect(() => translate(asFacts(inherited))).toThrow(TypeError);
    expect(() => translate(asFacts(accessor))).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it("rejects proxied fact records and active ID arrays before traps execute", () => {
    let trapCalls = 0;
    let getterCalls = 0;
    const fabricated = {
      get mode() {
        getterCalls += 1;
        return "feature";
      },
      get activeFeatureIds() {
        getterCalls += 1;
        return ["feat_support"];
      },
      get activeId() {
        getterCalls += 1;
        return "feat_support";
      },
    };

    const proxiedFacts = new Proxy(
      {
        mode: "price",
        activePriceIds: ["price_pro_monthly"],
      },
      {
        getPrototypeOf: () => {
          trapCalls += 1;
          return Object.prototype;
        },
        ownKeys: () => {
          trapCalls += 1;
          return ["mode", "activeFeatureIds"];
        },
        getOwnPropertyDescriptor: (target, property) => {
          trapCalls += 1;
          if (property === "mode") {
            return {
              configurable: true,
              enumerable: true,
              writable: true,
              value: fabricated.mode,
            };
          }
          if (property === "activeFeatureIds") {
            return {
              configurable: true,
              enumerable: true,
              writable: true,
              value: fabricated.activeFeatureIds,
            };
          }
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );

    const proxiedIds = new Proxy(new Array<unknown>(1), {
      getPrototypeOf: () => {
        trapCalls += 1;
        return Array.prototype;
      },
      ownKeys: () => {
        trapCalls += 1;
        return ["0", "length"];
      },
      getOwnPropertyDescriptor: (target, property) => {
        trapCalls += 1;
        if (property === "length") {
          return Reflect.getOwnPropertyDescriptor(target, property);
        }
        if (property === "0") {
          return {
            configurable: true,
            enumerable: true,
            writable: true,
            value: fabricated.activeId,
          };
        }
        return undefined;
      },
    });

    expect(() => translate(asFacts(proxiedFacts))).toThrow(TypeError);
    expect(() =>
      translate(asFacts({ mode: "feature", activeFeatureIds: proxiedIds })),
    ).toThrow(TypeError);
    expect(trapCalls).toBe(0);
    expect(getterCalls).toBe(0);
  });

  it("rejects sparse and accessor active ID arrays without partial output", () => {
    const sparseIds = ["feat_support", , "feat_reports"];
    let getterCalls = 0;
    const accessorIds = ["feat_support"];
    Object.defineProperty(accessorIds, "1", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return "feat_reports";
      },
    });
    accessorIds.length = 2;

    expect(() =>
      translate(asFacts({ mode: "feature", activeFeatureIds: sparseIds })),
    ).toThrow(TypeError);
    expect(() =>
      translate(asFacts({ mode: "feature", activeFeatureIds: accessorIds })),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it("rejects exotic array subclasses", () => {
    class FeatureIdList extends Array<string> {}
    const ids = new FeatureIdList("feat_support");

    expect(() =>
      translate(asFacts({ mode: "feature", activeFeatureIds: ids })),
    ).toThrow(TypeError);
  });
});

describe("createStripeEntitlementAdapter", () => {
  const accountId = "account_123";
  const secondAccountId = "account_456";
  const currentTimeEpochMs = 1_800_000_000_000;
  const maximumStateAgeMs = 60_000;
  const refreshedAtEpochMs = currentTimeEpochMs - 1_000;
  const clock: StripeEntitlementClock = () => currentTimeEpochMs;

  it("has a principal-keyed request type compatible with the shared contract", () => {
    type AdapterRequest = Parameters<
      StripeEntitlementAdapter["resolveEntitlements"]
    >[0];

    expectTypeOf<AdapterRequest>().toEqualTypeOf<StripeEntitlementRequest>();
    expectTypeOf<AdapterRequest>().toExtend<EntitlementRequest>();
    expectTypeOf<AdapterRequest["principalId"]>().toEqualTypeOf<PrincipalId>();
    expectTypeOf<keyof AdapterRequest>().toEqualTypeOf<"principalId">();
    expectTypeOf<keyof StripePersistedEntitlementState>().toEqualTypeOf<
      "principalId" | "refreshedAtEpochMs" | "facts"
    >();
    expectTypeOf<StripePersistedEntitlementState>().toEqualTypeOf<{
      readonly principalId: PrincipalId;
      readonly refreshedAtEpochMs: number;
      readonly facts: StripeActiveEntitlementFacts;
    }>();
    type FactoryParameters = Parameters<typeof createStripeEntitlementAdapter>;
    expectTypeOf<FactoryParameters[0]>().toEqualTypeOf<
      readonly StripeEntitlementRule[]
    >();
    expectTypeOf<
      FactoryParameters[1]
    >().toEqualTypeOf<StripeEntitlementStateLoader>();
    expectTypeOf<FactoryParameters[2]>().toEqualTypeOf<number>();
    expectTypeOf<FactoryParameters[3]>().toEqualTypeOf<
      StripeEntitlementClock | undefined
    >();
    expectTypeOf<FactoryParameters["length"]>().toEqualTypeOf<3 | 4>();
    expectTypeOf<
      ReturnType<typeof createStripeEntitlementAdapter>
    >().toEqualTypeOf<StripeEntitlementAdapter>();
  });

  it("forwards the exact principal once and translates persisted feature facts", async () => {
    const loadedPrincipals: string[] = [];
    const loader: StripeEntitlementStateLoader = {
      loadPersistedEntitlementState: async (principalId) => {
        loadedPrincipals.push(principalId);
        return {
          principalId,
          refreshedAtEpochMs,
          facts: {
            mode: "feature",
            activeFeatureIds: ["feat_support", "feat_reports"],
          },
        };
      },
    };
    const adapter = createStripeEntitlementAdapter(
      rules,
      loader,
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "reports.advanced", "support.priority"]);
    expect(loadedPrincipals).toEqual([accountId]);
  });

  it("accepts state whose age exactly equals the configured maximum", async () => {
    let loaderCalls = 0;
    let clockCalls = 0;
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          loaderCalls += 1;
          return {
            principalId,
            refreshedAtEpochMs: currentTimeEpochMs - maximumStateAgeMs,
            facts: {
              mode: "feature",
              activeFeatureIds: ["feat_support"],
            },
          };
        },
      },
      maximumStateAgeMs,
      () => {
        clockCalls += 1;
        return currentTimeEpochMs;
      },
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "support.priority"]);
    expect(loaderCalls).toBe(1);
    expect(clockCalls).toBe(1);
  });

  it("rejects state one millisecond beyond the configured maximum before reading facts", async () => {
    let loaderCalls = 0;
    let getterCalls = 0;
    const staleState = {
      principalId: accountId,
      refreshedAtEpochMs: currentTimeEpochMs - maximumStateAgeMs - 1,
    };
    Object.defineProperty(staleState, "facts", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return {
          mode: "feature",
          activeFeatureIds: ["feat_support"],
        };
      },
    });
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async () => {
          loaderCalls += 1;
          return asPersistedState(staleState);
        },
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow("exceeds the configured maximum state age");
    expect(loaderCalls).toBe(1);
    expect(getterCalls).toBe(0);
  });

  it("rejects future-dated state before translation", async () => {
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => ({
          principalId,
          refreshedAtEpochMs: currentTimeEpochMs + 1,
          facts: {
            mode: "feature",
            activeFeatureIds: ["feat_support"],
          },
        }),
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow("must not be future-dated");
  });

  it.each([
    ["missing", undefined],
    ["null", null],
    ["NaN", Number.NaN],
    ["positive infinity", Number.POSITIVE_INFINITY],
    ["negative infinity", Number.NEGATIVE_INFINITY],
    ["negative", -1],
    ["fractional", currentTimeEpochMs - 0.5],
    ["unsafe", Number.MAX_SAFE_INTEGER + 1],
    ["boxed", new Number(refreshedAtEpochMs)],
  ])(
    "rejects a malformed provider-confirmation timestamp: %s",
    async (_name, timestamp) => {
      let loaderCalls = 0;
      const state =
        timestamp === undefined
          ? {
              principalId: accountId,
              facts: { mode: "feature", activeFeatureIds: ["feat_support"] },
            }
          : {
              principalId: accountId,
              refreshedAtEpochMs: timestamp,
              facts: { mode: "feature", activeFeatureIds: ["feat_support"] },
            };
      const adapter = createStripeEntitlementAdapter(
        rules,
        {
          loadPersistedEntitlementState: async () => {
            loaderCalls += 1;
            return asPersistedState(state);
          },
        },
        maximumStateAgeMs,
        clock,
      );

      await expect(
        adapter.resolveEntitlements({ principalId: accountId }),
      ).rejects.toThrow(TypeError);
      expect(loaderCalls).toBe(1);
    },
  );

  it("rejects an accessor confirmation timestamp without executing its getter", async () => {
    let getterCalls = 0;
    const state = {
      principalId: accountId,
      facts: { mode: "feature", activeFeatureIds: ["feat_support"] },
    };
    Object.defineProperty(state, "refreshedAtEpochMs", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return refreshedAtEpochMs;
      },
    });
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async () => asPersistedState(state),
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["zero", 0],
    ["negative", -1],
    ["fractional", 1.5],
    ["NaN", Number.NaN],
    ["infinity", Number.POSITIVE_INFINITY],
    ["unsafe", Number.MAX_SAFE_INTEGER + 1],
    ["boxed", new Number(maximumStateAgeMs)],
  ])("rejects an invalid maximum state age: %s", (_name, maximumAge) => {
    expect(() =>
      createStripeEntitlementAdapter(
        rules,
        {
          loadPersistedEntitlementState: async (principalId) => ({
            principalId,
            refreshedAtEpochMs,
            facts: { mode: "feature", activeFeatureIds: [] },
          }),
        },
        maximumAge as number,
        clock,
      ),
    ).toThrow(TypeError);
  });

  it.each([
    ["null", null],
    ["negative", -1],
    ["fractional", currentTimeEpochMs + 0.5],
    ["NaN", Number.NaN],
    ["infinity", Number.POSITIVE_INFINITY],
    ["unsafe", Number.MAX_SAFE_INTEGER + 1],
    ["boxed", new Number(currentTimeEpochMs)],
  ])("rejects invalid trusted-clock output: %s", async (_name, value) => {
    let loaderCalls = 0;
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          loaderCalls += 1;
          return {
            principalId,
            refreshedAtEpochMs,
            facts: { mode: "feature", activeFeatureIds: ["feat_support"] },
          };
        },
      },
      maximumStateAgeMs,
      () => value as number,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow(TypeError);
    expect(loaderCalls).toBe(1);
  });

  it("propagates trusted-clock failures without translating loaded facts", async () => {
    let loaderCalls = 0;
    let clockCalls = 0;
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          loaderCalls += 1;
          return {
            principalId,
            refreshedAtEpochMs,
            facts: { mode: "feature", activeFeatureIds: ["feat_support"] },
          };
        },
      },
      maximumStateAgeMs,
      () => {
        clockCalls += 1;
        throw new Error("trusted clock unavailable");
      },
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow("trusted clock unavailable");
    expect(loaderCalls).toBe(1);
    expect(clockCalls).toBe(1);
  });

  it("rejects non-functions and proxied clocks without executing traps", () => {
    let trapCalls = 0;
    const proxiedClock = new Proxy(clock, {
      apply: (target, thisArgument, argumentList) => {
        trapCalls += 1;
        return Reflect.apply(target, thisArgument, argumentList) as number;
      },
    });
    const loader: StripeEntitlementStateLoader = {
      loadPersistedEntitlementState: async (principalId) => ({
        principalId,
        refreshedAtEpochMs,
        facts: { mode: "feature", activeFeatureIds: [] },
      }),
    };

    expect(() =>
      createStripeEntitlementAdapter(
        rules,
        loader,
        maximumStateAgeMs,
        null as unknown as StripeEntitlementClock,
      ),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementAdapter(
        rules,
        loader,
        maximumStateAgeMs,
        proxiedClock,
      ),
    ).toThrow(TypeError);
    expect(trapCalls).toBe(0);
  });

  it("preserves this for an object-literal loader method", async () => {
    const loader = {
      persisted: new Map<string, StripePersistedEntitlementState>([
        [
          accountId,
          {
            principalId: accountId,
            refreshedAtEpochMs,
            facts: {
              mode: "feature",
              activeFeatureIds: ["feat_support"],
            },
          },
        ],
      ]),
      async loadPersistedEntitlementState(principalId: PrincipalId) {
        const state = this.persisted.get(principalId);
        if (state === undefined) {
          throw new Error("missing persisted state");
        }
        return state;
      },
    };
    const adapter = createStripeEntitlementAdapter(
      rules,
      loader,
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "support.priority"]);
  });

  it("supports a class prototype loader method and preserves its receiver", async () => {
    class TestStateLoader implements StripeEntitlementStateLoader {
      constructor(
        private readonly persisted: ReadonlyMap<
          PrincipalId,
          StripePersistedEntitlementState
        >,
      ) {}

      async loadPersistedEntitlementState(
        principalId: PrincipalId,
      ): Promise<StripePersistedEntitlementState> {
        const state = this.persisted.get(principalId);
        if (state === undefined) {
          throw new Error("missing persisted state");
        }
        return state;
      }
    }

    const adapter = createStripeEntitlementAdapter(
      rules,
      new TestStateLoader(
        new Map([
          [
            accountId,
            {
              principalId: accountId,
              refreshedAtEpochMs,
              facts: {
                mode: "price" as const,
                activePriceIds: ["price_pro_monthly"],
              },
            },
          ],
        ]),
      ),
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro"]);
  });

  it("translates explicitly persisted price fallback facts", async () => {
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: {
            mode: "price",
            activePriceIds: ["price_pro_monthly"],
          },
        }),
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro"]);
  });

  it("isolates persisted state for two principals", async () => {
    const persisted = new Map<string, StripePersistedEntitlementState>([
      [
        accountId,
        {
          principalId: accountId,
          refreshedAtEpochMs,
          facts: {
            mode: "feature",
            activeFeatureIds: ["feat_support"],
          },
        },
      ],
      [
        secondAccountId,
        {
          principalId: secondAccountId,
          refreshedAtEpochMs,
          facts: {
            mode: "feature",
            activeFeatureIds: ["feat_reports"],
          },
        },
      ],
    ]);
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          const state = persisted.get(principalId);
          if (state === undefined) {
            throw new Error("missing persisted state");
          }
          return state;
        },
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "support.priority"]);
    await expect(
      adapter.resolveEntitlements({ principalId: secondAccountId }),
    ).resolves.toEqual(["plan.pro", "reports.advanced"]);
  });

  it("rejects a loaded state for a different principal before reading facts", async () => {
    let getterCalls = 0;
    const mismatchedState = {
      principalId: secondAccountId,
      refreshedAtEpochMs,
    };
    Object.defineProperty(mismatchedState, "facts", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return {
          mode: "feature",
          activeFeatureIds: ["feat_support"],
        };
      },
    });
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async () =>
          asPersistedState(mismatchedState),
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow("must exactly match");
    expect(getterCalls).toBe(0);
  });

  it.each([
    ["undefined", undefined],
    ["null", null],
    ["missing facts", { principalId: accountId, refreshedAtEpochMs }],
    [
      "extra field",
      {
        principalId: accountId,
        refreshedAtEpochMs,
        facts: { mode: "feature", activeFeatureIds: [] },
        updatedAt: "2026-07-25T00:00:00Z",
      },
    ],
  ])("rejects missing or corrupt persisted state: %s", async (_name, state) => {
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async () => asPersistedState(state),
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow(TypeError);
  });

  it("propagates loader operational failures", async () => {
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async () => {
          throw new Error("entitlement store unavailable");
        },
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow("entitlement store unavailable");
  });

  it("returns frozen empty output only from valid explicitly empty persisted facts", async () => {
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: { mode: "feature", activeFeatureIds: [] },
        }),
      },
      maximumStateAgeMs,
      clock,
    );

    const entitlements = await adapter.resolveEntitlements({
      principalId: accountId,
    });

    expect(entitlements).toEqual([]);
    expect(Object.isFrozen(entitlements)).toBe(true);
  });

  it.each([
    ["extra field", { principalId: accountId, tenant: "tenant_123" }],
    [
      "transient facts",
      {
        principalId: accountId,
        facts: { mode: "feature", activeFeatureIds: ["feat_support"] },
      },
    ],
    ["missing principal", {}],
    ["blank principal", { principalId: " \t" }],
    ["boxed principal", { principalId: new String(accountId) }],
  ])(
    "rejects malformed request input before loading: %s",
    async (_name, request) => {
      let loaderCalls = 0;
      const adapter = createStripeEntitlementAdapter(
        rules,
        {
          loadPersistedEntitlementState: async (principalId) => {
            loaderCalls += 1;
            return {
              principalId,
              refreshedAtEpochMs,
              facts: { mode: "feature", activeFeatureIds: ["feat_support"] },
            };
          },
        },
        maximumStateAgeMs,
        clock,
      );

      await expect(
        adapter.resolveEntitlements(asRequest(request)),
      ).rejects.toThrow(TypeError);
      expect(loaderCalls).toBe(0);
    },
  );

  it("rejects inherited, accessor, and proxied requests before loading or executing traps", async () => {
    let loaderCalls = 0;
    let getterCalls = 0;
    let trapCalls = 0;
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          loaderCalls += 1;
          return {
            principalId,
            refreshedAtEpochMs,
            facts: { mode: "feature", activeFeatureIds: [] },
          };
        },
      },
      maximumStateAgeMs,
      clock,
    );
    const inheritedRequest = Object.create({ principalId: accountId });
    const accessorRequest = {};
    Object.defineProperty(accessorRequest, "principalId", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return accountId;
      },
    });
    const proxiedRequest = new Proxy(
      { principalId: accountId },
      {
        getPrototypeOf: (target) => {
          trapCalls += 1;
          return Reflect.getPrototypeOf(target);
        },
        ownKeys: (target) => {
          trapCalls += 1;
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor: (target, property) => {
          trapCalls += 1;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );

    for (const request of [inheritedRequest, accessorRequest, proxiedRequest]) {
      await expect(
        adapter.resolveEntitlements(asRequest(request)),
      ).rejects.toThrow(TypeError);
    }
    expect(loaderCalls).toBe(0);
    expect(getterCalls).toBe(0);
    expect(trapCalls).toBe(0);
  });

  it("rejects accessor and proxied loaded states without executing getters or reflection traps", async () => {
    let getterCalls = 0;
    let trapCalls = 0;
    const accessorState = {
      principalId: accountId,
      refreshedAtEpochMs,
      get facts() {
        getterCalls += 1;
        return {
          mode: "feature" as const,
          activeFeatureIds: ["feat_support"],
        };
      },
    };
    const proxiedState = new Proxy(
      {
        principalId: accountId,
        refreshedAtEpochMs,
        facts: {
          mode: "feature" as const,
          activeFeatureIds: ["feat_support"],
        },
      },
      {
        getPrototypeOf: (target) => {
          trapCalls += 1;
          return Reflect.getPrototypeOf(target);
        },
        ownKeys: (target) => {
          trapCalls += 1;
          return Reflect.ownKeys(target);
        },
        getOwnPropertyDescriptor: (target, property) => {
          trapCalls += 1;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );
    const states = [
      asPersistedState(accessorState),
      asPersistedState(proxiedState),
    ];
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async () => {
          const state = states.shift();
          if (state === undefined) {
            throw new Error("fixture exhausted");
          }
          return state;
        },
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow(TypeError);
    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow(TypeError);
    expect(getterCalls).toBe(0);
    expect(trapCalls).toBe(0);
  });

  it("rejects accessor and proxied loader methods or prototypes without executing them", () => {
    let getterCalls = 0;
    let trapCalls = 0;
    const accessorLoader = {
      get loadPersistedEntitlementState() {
        getterCalls += 1;
        return async (principalId: PrincipalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: { mode: "feature" as const, activeFeatureIds: [] },
        });
      },
    };
    const proxiedLoader = new Proxy(
      {
        loadPersistedEntitlementState: async (principalId: PrincipalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: { mode: "feature" as const, activeFeatureIds: [] },
        }),
      },
      {
        getOwnPropertyDescriptor: (target, property) => {
          trapCalls += 1;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );
    const accessorPrototype = {};
    Object.defineProperty(accessorPrototype, "loadPersistedEntitlementState", {
      get: () => {
        getterCalls += 1;
        return async (principalId: PrincipalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: { mode: "feature" as const, activeFeatureIds: [] },
        });
      },
    });
    const inheritedAccessorLoader = Object.create(accessorPrototype);
    const proxiedPrototype = new Proxy(
      {
        loadPersistedEntitlementState: async (principalId: PrincipalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: { mode: "feature" as const, activeFeatureIds: [] },
        }),
      },
      {
        getPrototypeOf: (target) => {
          trapCalls += 1;
          return Reflect.getPrototypeOf(target);
        },
        getOwnPropertyDescriptor: (target, property) => {
          trapCalls += 1;
          return Reflect.getOwnPropertyDescriptor(target, property);
        },
      },
    );
    const proxiedPrototypeLoader = Object.create(proxiedPrototype);

    expect(() =>
      createStripeEntitlementAdapter(
        rules,
        accessorLoader as StripeEntitlementStateLoader,
        maximumStateAgeMs,
        clock,
      ),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementAdapter(
        rules,
        proxiedLoader,
        maximumStateAgeMs,
        clock,
      ),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementAdapter(
        rules,
        inheritedAccessorLoader as StripeEntitlementStateLoader,
        maximumStateAgeMs,
        clock,
      ),
    ).toThrow(TypeError);
    expect(() =>
      createStripeEntitlementAdapter(
        rules,
        proxiedPrototypeLoader as StripeEntitlementStateLoader,
        maximumStateAgeMs,
        clock,
      ),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
    expect(trapCalls).toBe(0);
  });

  it("does not accept a loader method polluted onto Object.prototype", () => {
    const field = "loadPersistedEntitlementState";
    const previous = Object.getOwnPropertyDescriptor(Object.prototype, field);

    try {
      Object.defineProperty(Object.prototype, field, {
        configurable: true,
        value: async (principalId: PrincipalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: { mode: "feature" as const, activeFeatureIds: [] },
        }),
      });

      expect(() =>
        createStripeEntitlementAdapter(
          rules,
          {} as StripeEntitlementStateLoader,
          maximumStateAgeMs,
          clock,
        ),
      ).toThrow(TypeError);
    } finally {
      if (previous === undefined) {
        Reflect.deleteProperty(Object.prototype, field);
      } else {
        Object.defineProperty(Object.prototype, field, previous);
      }
    }
  });

  it("reloads persisted state for every resolution without caching", async () => {
    let loaderCalls = 0;
    const persistedIds: string[][] = [["feat_support"], ["feat_reports"]];
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          const activeFeatureIds = persistedIds[loaderCalls];
          loaderCalls += 1;
          if (activeFeatureIds === undefined) {
            throw new Error("fixture exhausted");
          }
          return {
            principalId,
            refreshedAtEpochMs,
            facts: { mode: "feature", activeFeatureIds },
          };
        },
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "support.priority"]);
    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "reports.advanced"]);
    expect(loaderCalls).toBe(2);
  });

  it("samples advancing time once per call and never returns a last-known-good grant after staleness", async () => {
    let loaderCalls = 0;
    let clockCalls = 0;
    const sampledTimes = [
      refreshedAtEpochMs + maximumStateAgeMs,
      refreshedAtEpochMs + maximumStateAgeMs + 1,
    ];
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          loaderCalls += 1;
          return {
            principalId,
            refreshedAtEpochMs,
            facts: {
              mode: "feature",
              activeFeatureIds: ["feat_support"],
            },
          };
        },
      },
      maximumStateAgeMs,
      () => {
        const sampledTime = sampledTimes[clockCalls];
        clockCalls += 1;
        if (sampledTime === undefined) {
          throw new Error("fixture exhausted");
        }
        return sampledTime;
      },
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "support.priority"]);
    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow("exceeds the configured maximum state age");
    expect(loaderCalls).toBe(2);
    expect(clockCalls).toBe(2);
  });

  it("does not return a last-known-good grant after a later loader failure", async () => {
    let loaderCalls = 0;
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => {
          loaderCalls += 1;
          if (loaderCalls === 2) {
            throw new Error("entitlement store unavailable");
          }
          return {
            principalId,
            refreshedAtEpochMs,
            facts: {
              mode: "feature",
              activeFeatureIds: ["feat_support"],
            },
          };
        },
      },
      maximumStateAgeMs,
      clock,
    );

    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro", "support.priority"]);
    await expect(
      adapter.resolveEntitlements({ principalId: accountId }),
    ).rejects.toThrow("entitlement store unavailable");
    expect(loaderCalls).toBe(2);
  });

  it("returns canonical immutable entitlements and keeps roles separate", async () => {
    const adapter = createStripeEntitlementAdapter(
      rules,
      {
        loadPersistedEntitlementState: async (principalId) => ({
          principalId,
          refreshedAtEpochMs,
          facts: {
            mode: "feature",
            activeFeatureIds: ["feat_reports", "feat_support", "feat_reports"],
          },
        }),
      },
      maximumStateAgeMs,
      clock,
    );

    const entitlements = await adapter.resolveEntitlements({
      principalId: accountId,
    });
    const subject: AccessSubject = {
      principalId: accountId,
      roles: ["support"],
      entitlements,
    };

    expect(entitlements).toEqual([
      "plan.pro",
      "reports.advanced",
      "support.priority",
    ]);
    expect(Object.isFrozen(entitlements)).toBe(true);
    expect(subject.roles).toEqual(["support"]);
    expect(subject.entitlements).toEqual(entitlements);
  });
});
