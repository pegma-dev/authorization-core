import { types as nodeTypes } from "node:util";

import type {
  EntitlementAdapter,
  EntitlementName,
  PrincipalId,
} from "@pegma/authorization-contracts";

/** One exact Stripe Entitlements Feature ID to host-entitlement rule. */
export interface StripeFeatureEntitlementRule {
  readonly kind: "feature";
  readonly id: string;
  readonly entitlements: readonly EntitlementName[];
}

/** One exact Stripe Price ID to host-entitlement fallback rule. */
export interface StripePriceEntitlementRule {
  readonly kind: "price";
  readonly id: string;
  readonly entitlements: readonly EntitlementName[];
}

/** One entry in the host-owned Stripe identifier allowlist. */
export type StripeEntitlementRule =
  StripeFeatureEntitlementRule | StripePriceEntitlementRule;

/**
 * Authoritative active Stripe Entitlements Feature IDs already loaded and
 * trusted by the host.
 */
export interface StripeFeatureEntitlementFacts {
  readonly mode: "feature";
  readonly activeFeatureIds: readonly string[];
}

/**
 * Authoritative active Stripe Price IDs already resolved and trusted by the
 * host when Product Features are not the source of truth.
 */
export interface StripePriceEntitlementFacts {
  readonly mode: "price";
  readonly activePriceIds: readonly string[];
}

/** Exactly one authoritative Stripe entitlement input mode. */
export type StripeActiveEntitlementFacts =
  StripeFeatureEntitlementFacts | StripePriceEntitlementFacts;

/** A compiled, synchronous projection from trusted facts to entitlements. */
export type StripeEntitlementTranslator = (
  facts: StripeActiveEntitlementFacts,
) => readonly EntitlementName[];

/** Exact request accepted by the persisted-state Stripe adapter. */
export interface StripeEntitlementRequest {
  readonly principalId: PrincipalId;
}

/**
 * Trusted Stripe facts persisted by the host for one principal.
 *
 * `refreshedAtEpochMs` is the host-recorded time at which the facts were last
 * confirmed against Stripe. Database reads, rewrites, and cache fills must not
 * advance it.
 */
export interface StripePersistedEntitlementState {
  readonly principalId: PrincipalId;
  readonly refreshedAtEpochMs: number;
  readonly facts: StripeActiveEntitlementFacts;
}

/** Host-owned reader for persisted Stripe entitlement state. */
export interface StripeEntitlementStateLoader {
  readonly loadPersistedEntitlementState: (
    principalId: PrincipalId,
  ) => Promise<StripePersistedEntitlementState>;
}

/** Principal-keyed Stripe adapter backed by host persistence. */
export type StripeEntitlementAdapter =
  EntitlementAdapter<StripeEntitlementRequest>;

/** Trusted epoch-millisecond clock sampled once per adapter resolution. */
export type StripeEntitlementClock = () => number;

type PlainRecord = Record<PropertyKey, unknown>;

interface CompiledRule {
  readonly kind: "feature" | "price";
  readonly id: string;
  readonly entitlements: readonly EntitlementName[];
}

const describeField = (label: string, field: PropertyKey): string =>
  `${label}.${String(field)}`;

const rejectProxy = (value: unknown, label: string): void => {
  if (nodeTypes.isProxy(value)) {
    throw new TypeError(`${label} must not be a Proxy`);
  }
};

const requirePlainRecord = (value: unknown, label: string): PlainRecord => {
  rejectProxy(value, label);

  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    throw new TypeError(`${label} must be a plain object`);
  }

  const prototype = Object.getPrototypeOf(value);
  if (prototype !== Object.prototype && prototype !== null) {
    throw new TypeError(`${label} must be a plain object`);
  }

  return value as PlainRecord;
};

const requireOwnEnumerableDataValue = (
  record: object,
  field: PropertyKey,
  label: string,
): unknown => {
  const descriptor = Object.getOwnPropertyDescriptor(record, field);
  if (
    descriptor === undefined ||
    !("value" in descriptor) ||
    descriptor.enumerable !== true
  ) {
    throw new TypeError(
      `${describeField(label, field)} must be an own enumerable data property`,
    );
  }

  return descriptor.value;
};

const requireExactFields = (
  record: object,
  expected: readonly string[],
  label: string,
): void => {
  const expectedFields = new Set<PropertyKey>(expected);
  const ownKeys = Reflect.ownKeys(record);

  if (
    ownKeys.length !== expected.length ||
    ownKeys.some((key) => !expectedFields.has(key))
  ) {
    throw new TypeError(
      `${label} must contain exactly the fields ${expected.join(", ")}`,
    );
  }
};

const requireNonblankString = (value: unknown, label: string): string => {
  if (typeof value !== "string" || value.trim().length === 0) {
    throw new TypeError(`${label} must be a nonblank primitive string`);
  }

  return value;
};

const requireNonnegativeSafeInteger = (
  value: unknown,
  label: string,
): number => {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new TypeError(`${label} must be a nonnegative safe integer`);
  }

  return value;
};

const requirePositiveSafeInteger = (value: unknown, label: string): number => {
  const integer = requireNonnegativeSafeInteger(value, label);
  if (integer === 0) {
    throw new TypeError(`${label} must be a positive safe integer`);
  }

  return integer;
};

const readDenseArray = (value: unknown, label: string): readonly unknown[] => {
  rejectProxy(value, label);

  if (
    !Array.isArray(value) ||
    Object.getPrototypeOf(value) !== Array.prototype
  ) {
    throw new TypeError(`${label} must be a plain array`);
  }

  const lengthDescriptor = Object.getOwnPropertyDescriptor(value, "length");
  if (
    lengthDescriptor === undefined ||
    !("value" in lengthDescriptor) ||
    typeof lengthDescriptor.value !== "number"
  ) {
    throw new TypeError(`${label} must have an own data length`);
  }

  const length = lengthDescriptor.value;
  const ownKeys = Reflect.ownKeys(value);
  if (ownKeys.length !== length + 1) {
    throw new TypeError(`${label} must be dense and contain no extra fields`);
  }

  const copy: unknown[] = [];
  for (let index = 0; index < length; index += 1) {
    const descriptor = Object.getOwnPropertyDescriptor(value, String(index));
    if (
      descriptor === undefined ||
      !("value" in descriptor) ||
      descriptor.enumerable !== true
    ) {
      throw new TypeError(
        `${label}[${index}] must be an own enumerable data property`,
      );
    }

    copy.push(descriptor.value);
  }

  return copy;
};

const readStringArray = (value: unknown, label: string): readonly string[] => {
  const values = readDenseArray(value, label);
  const copy = values.map((item, index) =>
    requireNonblankString(item, `${label}[${index}]`),
  );
  return Object.freeze(copy);
};

const compileRule = (value: unknown, index: number): CompiledRule => {
  const label = `rules[${index}]`;
  const record = requirePlainRecord(value, label);
  requireExactFields(record, ["kind", "id", "entitlements"], label);

  const kind = requireOwnEnumerableDataValue(record, "kind", label);
  if (kind !== "feature" && kind !== "price") {
    throw new TypeError(`${label}.kind must be exactly feature or price`);
  }

  const id = requireNonblankString(
    requireOwnEnumerableDataValue(record, "id", label),
    `${label}.id`,
  );
  const entitlements = readStringArray(
    requireOwnEnumerableDataValue(record, "entitlements", label),
    `${label}.entitlements`,
  );

  return Object.freeze({ kind, id, entitlements });
};

const compileRules = (
  rules: readonly StripeEntitlementRule[],
): readonly CompiledRule[] => {
  const suppliedRules = readDenseArray(rules, "rules");
  const compiledRules = suppliedRules.map(compileRule);
  const featureIds = new Set<string>();
  const priceIds = new Set<string>();

  for (const rule of compiledRules) {
    const ids = rule.kind === "feature" ? featureIds : priceIds;
    if (ids.has(rule.id)) {
      throw new TypeError(
        `rules contains duplicate ${rule.kind} identifier ${JSON.stringify(rule.id)}`,
      );
    }
    ids.add(rule.id);
  }

  return Object.freeze(compiledRules);
};

const compileNamespace = (
  rules: readonly CompiledRule[],
  kind: "feature" | "price",
): ReadonlyMap<string, readonly EntitlementName[]> => {
  const namespace = new Map<string, readonly EntitlementName[]>();
  for (const rule of rules) {
    if (rule.kind === kind) {
      namespace.set(rule.id, rule.entitlements);
    }
  }
  return namespace;
};

const readActiveFacts = (
  facts: StripeActiveEntitlementFacts,
): {
  readonly kind: "feature" | "price";
  readonly ids: readonly string[];
} => {
  const record = requirePlainRecord(facts, "facts");
  const mode = requireOwnEnumerableDataValue(record, "mode", "facts");

  if (mode === "feature") {
    requireExactFields(record, ["mode", "activeFeatureIds"], "facts");
    return Object.freeze({
      kind: "feature",
      ids: readStringArray(
        requireOwnEnumerableDataValue(record, "activeFeatureIds", "facts"),
        "facts.activeFeatureIds",
      ),
    });
  }

  if (mode === "price") {
    requireExactFields(record, ["mode", "activePriceIds"], "facts");
    return Object.freeze({
      kind: "price",
      ids: readStringArray(
        requireOwnEnumerableDataValue(record, "activePriceIds", "facts"),
        "facts.activePriceIds",
      ),
    });
  }

  throw new TypeError("facts.mode must be exactly feature or price");
};

/**
 * Validates and compiles a host-owned exact identifier allowlist once.
 *
 * Runtime calls accept either authoritative Feature IDs or authoritative Price
 * IDs. The modes are never combined and unknown valid identifiers grant
 * nothing. Verification, lifecycle policy, persistence, reconciliation, and
 * loading active provider state remain host responsibilities.
 */
export const createStripeEntitlementTranslator = (
  rules: readonly StripeEntitlementRule[],
): StripeEntitlementTranslator => {
  const compiledRules = compileRules(rules);
  const featureRules = compileNamespace(compiledRules, "feature");
  const priceRules = compileNamespace(compiledRules, "price");

  const translate: StripeEntitlementTranslator = (facts) => {
    const active = readActiveFacts(facts);
    const namespace = active.kind === "feature" ? featureRules : priceRules;
    const entitlements = new Set<EntitlementName>();

    for (const id of active.ids) {
      const grants = namespace.get(id);
      if (grants !== undefined) {
        for (const entitlement of grants) {
          entitlements.add(entitlement);
        }
      }
    }

    return Object.freeze([...entitlements].sort());
  };

  return Object.freeze(translate);
};

type LoadPersistedEntitlementState =
  StripeEntitlementStateLoader["loadPersistedEntitlementState"];

const readStateLoader = (
  loader: StripeEntitlementStateLoader,
): LoadPersistedEntitlementState => {
  rejectProxy(loader, "loader");

  if (typeof loader !== "object" || loader === null || Array.isArray(loader)) {
    throw new TypeError("loader must be an object");
  }

  let owner: object = loader;
  while (owner !== Object.prototype) {
    rejectProxy(owner, "loader prototype chain");
    const descriptor = Object.getOwnPropertyDescriptor(
      owner,
      "loadPersistedEntitlementState",
    );

    if (descriptor !== undefined) {
      if (!("value" in descriptor)) {
        throw new TypeError(
          "loader.loadPersistedEntitlementState must be a data property",
        );
      }

      rejectProxy(descriptor.value, "loader.loadPersistedEntitlementState");
      if (typeof descriptor.value !== "function") {
        throw new TypeError(
          "loader.loadPersistedEntitlementState must be a function",
        );
      }

      const load = descriptor.value as LoadPersistedEntitlementState;
      return (principalId) =>
        Reflect.apply(load, loader, [
          principalId,
        ]) as Promise<StripePersistedEntitlementState>;
    }

    const prototype = Object.getPrototypeOf(owner);
    if (prototype === null || prototype === Object.prototype) {
      break;
    }
    owner = prototype;
  }

  throw new TypeError(
    "loader.loadPersistedEntitlementState must be an own or class prototype data method",
  );
};

const readStripeEntitlementRequest = (
  request: StripeEntitlementRequest,
): PrincipalId => {
  const record = requirePlainRecord(request, "request");
  requireExactFields(record, ["principalId"], "request");
  return requireNonblankString(
    requireOwnEnumerableDataValue(record, "principalId", "request"),
    "request.principalId",
  );
};

const readPersistedEntitlementState = (
  state: StripePersistedEntitlementState,
  requestedPrincipalId: PrincipalId,
  currentTimeEpochMs: number,
  maximumStateAgeMs: number,
): StripeActiveEntitlementFacts => {
  const record = requirePlainRecord(state, "persisted state");
  requireExactFields(
    record,
    ["principalId", "refreshedAtEpochMs", "facts"],
    "persisted state",
  );
  const persistedPrincipalId = requireNonblankString(
    requireOwnEnumerableDataValue(record, "principalId", "persisted state"),
    "persisted state.principalId",
  );

  if (persistedPrincipalId !== requestedPrincipalId) {
    throw new TypeError(
      "persisted state principalId must exactly match the requested principalId",
    );
  }

  const refreshedAtEpochMs = requireNonnegativeSafeInteger(
    requireOwnEnumerableDataValue(
      record,
      "refreshedAtEpochMs",
      "persisted state",
    ),
    "persisted state.refreshedAtEpochMs",
  );

  if (refreshedAtEpochMs > currentTimeEpochMs) {
    throw new TypeError(
      "persisted state.refreshedAtEpochMs must not be future-dated",
    );
  }

  if (currentTimeEpochMs - refreshedAtEpochMs > maximumStateAgeMs) {
    throw new TypeError(
      "persisted state exceeds the configured maximum state age",
    );
  }

  return requireOwnEnumerableDataValue(
    record,
    "facts",
    "persisted state",
  ) as StripeActiveEntitlementFacts;
};

/**
 * Creates a principal-keyed adapter that reloads host-persisted state on every
 * resolution before applying the compiled exact-ID translator.
 *
 * The host owns durable storage and all webhook, lifecycle, reconciliation,
 * retry, and cache policy. `maximumStateAgeMs` is required and accepts state
 * whose age is exactly equal to the bound. The persisted confirmation time
 * must advance only when Stripe is successfully re-confirmed. The adapter
 * rejects missing, corrupt, mismatched, stale, future-dated, or operationally
 * unavailable state.
 */
export const createStripeEntitlementAdapter = (
  rules: readonly StripeEntitlementRule[],
  loader: StripeEntitlementStateLoader,
  maximumStateAgeMs: number,
  trustedClock: StripeEntitlementClock = Date.now,
): StripeEntitlementAdapter => {
  const compiledMaximumStateAgeMs = requirePositiveSafeInteger(
    maximumStateAgeMs,
    "maximumStateAgeMs",
  );
  rejectProxy(trustedClock, "trustedClock");
  if (typeof trustedClock !== "function") {
    throw new TypeError("trustedClock must be a function");
  }

  const translate = createStripeEntitlementTranslator(rules);
  const loadPersistedEntitlementState = readStateLoader(loader);

  return Object.freeze({
    resolveEntitlements: async (request: StripeEntitlementRequest) => {
      const principalId = readStripeEntitlementRequest(request);
      const state = await loadPersistedEntitlementState(principalId);
      const currentTimeEpochMs = requireNonnegativeSafeInteger(
        Reflect.apply(trustedClock, undefined, []) as unknown,
        "trustedClock result",
      );
      const facts = readPersistedEntitlementState(
        state,
        principalId,
        currentTimeEpochMs,
        compiledMaximumStateAgeMs,
      );
      return translate(facts);
    },
  });
};
