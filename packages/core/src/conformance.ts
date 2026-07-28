import assert from "node:assert/strict";

import type {
  EntitlementAdapter,
  EntitlementName,
  IdentityAdapter,
  IdentityLink,
  IdentityLinkKey,
  PrincipalId,
} from "@pegma/authorization-contracts";

import { decideAccess, resolveAccess } from "./index.js";

/** Semantic identity state supplied to one conformance case. */
export interface IdentityAdapterConformanceFixture {
  readonly links: readonly IdentityLink[];
  readonly unavailableKeys: readonly IdentityLinkKey[];
}

/**
 * Build an adapter over the exact semantic fixture supplied by the suite.
 *
 * Provider-specific evidence, storage, and configuration remain inside the
 * factory. Keys in `unavailableKeys` must exercise an operational failure.
 */
export type IdentityAdapterConformanceFactory = (
  fixture: IdentityAdapterConformanceFixture,
) => Promise<IdentityAdapter>;

/** One framework-independent identity-adapter conformance case. */
export interface IdentityAdapterConformanceCase {
  readonly name: string;
  run(createAdapter: IdentityAdapterConformanceFactory): Promise<void>;
}

/** Semantic request-time state for one entitlement resolution. */
export type EntitlementFixtureState =
  | Readonly<{
      readonly kind: "current";
      readonly entitlements: readonly EntitlementName[];
    }>
  | Readonly<{
      readonly kind: "missing" | "stale" | "future" | "corrupt" | "unavailable";
    }>;

type CurrentEntitlementFixtureState = Extract<
  EntitlementFixtureState,
  Readonly<{ readonly kind: "current" }>
>;

/** One principal's state for one successive request-time resolution. */
export interface EntitlementAdapterConformanceState {
  readonly principalId: PrincipalId;
  readonly state: EntitlementFixtureState;
}

/**
 * Semantic entitlement state supplied to one conformance case.
 *
 * Repeated entries for one principal are successive authoritative states.
 * Factories must consume one entry on every resolution so the suite can prove
 * that a previous success is not used as fallback.
 */
export interface EntitlementAdapterConformanceFixture {
  readonly states: readonly EntitlementAdapterConformanceState[];
}

/**
 * Build an adapter over the exact semantic fixture supplied by the suite.
 *
 * The factory translates these states into its provider and persistence model;
 * the public adapter remains principal-keyed and provider-neutral.
 */
export type EntitlementAdapterConformanceFactory = (
  fixture: EntitlementAdapterConformanceFixture,
) => Promise<EntitlementAdapter>;

/** One framework-independent entitlement-adapter conformance case. */
export interface EntitlementAdapterConformanceCase {
  readonly name: string;
  run(createAdapter: EntitlementAdapterConformanceFactory): Promise<void>;
}

const hostPrincipalOne = "host-principal-one";
const hostPrincipalTwo = "host-principal-two";
const issuer = "https://identity.example.test/";
const subject = "provider|one";

function frozenKey(
  key: Readonly<{ readonly issuer: string; readonly subject: string }>,
): IdentityLinkKey {
  return Object.freeze({ issuer: key.issuer, subject: key.subject });
}

function identityFixture(
  links: readonly IdentityLink[],
  unavailableKeys: readonly IdentityLinkKey[] = [],
): IdentityAdapterConformanceFixture {
  return Object.freeze({
    links: Object.freeze(
      links.map(({ key, principalId }) =>
        Object.freeze({ key: frozenKey(key), principalId }),
      ),
    ),
    unavailableKeys: Object.freeze(unavailableKeys.map(frozenKey)),
  });
}

function current(
  entitlements: readonly EntitlementName[],
): CurrentEntitlementFixtureState {
  return Object.freeze({
    kind: "current",
    entitlements: Object.freeze([...entitlements]),
  });
}

function entitlementFixture(
  states: readonly EntitlementAdapterConformanceState[],
): EntitlementAdapterConformanceFixture {
  return Object.freeze({
    states: Object.freeze(
      states.map(({ principalId, state }) =>
        Object.freeze({ principalId, state }),
      ),
    ),
  });
}

function entitlementState(
  principalId: PrincipalId,
  state: EntitlementFixtureState,
): EntitlementAdapterConformanceState {
  return Object.freeze({ principalId, state });
}

async function expectResolutionFailure(
  createAdapter: EntitlementAdapterConformanceFactory,
  kind: Exclude<EntitlementFixtureState["kind"], "current">,
): Promise<void> {
  const adapter = await createAdapter(
    entitlementFixture([
      entitlementState(hostPrincipalOne, Object.freeze({ kind })),
    ]),
  );

  await assert.rejects(
    adapter.resolveEntitlements({ principalId: hostPrincipalOne }),
  );
}

/**
 * Behaviour every provider-neutral {@link IdentityAdapter} must exhibit.
 *
 * The cases have no test-framework dependency:
 *
 * ```ts
 * for (const testCase of identityAdapterConformanceCases) {
 *   it(testCase.name, () => testCase.run(createIdentityAdapter));
 * }
 * ```
 */
export const identityAdapterConformanceCases: readonly IdentityAdapterConformanceCase[] =
  Object.freeze([
    {
      name: "an exact linked identity resolves to its host principal",
      run: async (createAdapter) => {
        const key = frozenKey({ issuer, subject });
        const adapter = await createAdapter(
          identityFixture([{ key, principalId: hostPrincipalOne }]),
        );

        assert.equal(await adapter.resolvePrincipalId(key), hostPrincipalOne);
        assert.notEqual(hostPrincipalOne, subject);
      },
    },
    {
      name: "a definitively unlinked identity resolves to null",
      run: async (createAdapter) => {
        const adapter = await createAdapter(identityFixture([]));

        assert.equal(
          await adapter.resolvePrincipalId(frozenKey({ issuer, subject })),
          null,
        );
      },
    },
    {
      name: "issuer and subject namespaces stay distinct",
      run: async (createAdapter) => {
        const adapter = await createAdapter(
          identityFixture([
            {
              key: frozenKey({ issuer, subject }),
              principalId: hostPrincipalOne,
            },
          ]),
        );

        assert.equal(
          await adapter.resolvePrincipalId(
            frozenKey({
              issuer: "https://other-identity.example.test/",
              subject,
            }),
          ),
          null,
        );
        assert.equal(
          await adapter.resolvePrincipalId(
            frozenKey({ issuer, subject: "provider|other" }),
          ),
          null,
        );
      },
    },
    {
      name: "identity keys are exact and case-sensitive",
      run: async (createAdapter) => {
        const adapter = await createAdapter(
          identityFixture([
            {
              key: frozenKey({
                issuer: "https://Issuer.example/",
                subject: "Subject",
              }),
              principalId: hostPrincipalOne,
            },
            {
              key: frozenKey({
                issuer: "https://issuer.example/",
                subject: "Subject",
              }),
              principalId: hostPrincipalTwo,
            },
            {
              key: frozenKey({
                issuer: "https://Issuer.example/",
                subject: "subject",
              }),
              principalId: "host-principal-three",
            },
          ]),
        );

        assert.equal(
          await adapter.resolvePrincipalId(
            frozenKey({
              issuer: "https://Issuer.example/",
              subject: "Subject",
            }),
          ),
          hostPrincipalOne,
        );
        assert.equal(
          await adapter.resolvePrincipalId(
            frozenKey({
              issuer: "https://issuer.example/",
              subject: "Subject",
            }),
          ),
          hostPrincipalTwo,
        );
        assert.equal(
          await adapter.resolvePrincipalId(
            frozenKey({
              issuer: "https://Issuer.example/",
              subject: "subject",
            }),
          ),
          "host-principal-three",
        );
      },
    },
    {
      name: "identity tuple components cannot collide through delimiters",
      run: async (createAdapter) => {
        const first = frozenKey({ issuer: "a", subject: "\u0000b" });
        const second = frozenKey({ issuer: "a\u0000", subject: "b" });
        const adapter = await createAdapter(
          identityFixture([
            { key: first, principalId: hostPrincipalOne },
            { key: second, principalId: hostPrincipalTwo },
          ]),
        );

        assert.equal(await adapter.resolvePrincipalId(first), hostPrincipalOne);
        assert.equal(
          await adapter.resolvePrincipalId(second),
          hostPrincipalTwo,
        );
      },
    },
    {
      name: "multiple identity keys may resolve to one host principal",
      run: async (createAdapter) => {
        const first = frozenKey({ issuer, subject });
        const second = frozenKey({
          issuer: "https://second-identity.example.test/",
          subject: "other-provider-subject",
        });
        const adapter = await createAdapter(
          identityFixture([
            { key: first, principalId: hostPrincipalOne },
            { key: second, principalId: hostPrincipalOne },
          ]),
        );

        assert.equal(await adapter.resolvePrincipalId(first), hostPrincipalOne);
        assert.equal(
          await adapter.resolvePrincipalId(second),
          hostPrincipalOne,
        );
      },
    },
    {
      name: "identity operational failures reject instead of returning null",
      run: async (createAdapter) => {
        const unavailable = frozenKey({ issuer, subject });
        const adapter = await createAdapter(identityFixture([], [unavailable]));

        await assert.rejects(adapter.resolvePrincipalId(unavailable));
      },
    },
  ]);

const failureKinds = [
  "missing",
  "stale",
  "future",
  "corrupt",
  "unavailable",
] as const;

const entitlementCases: EntitlementAdapterConformanceCase[] = [
  {
    name: "entitlement resolution stays isolated by host principal",
    run: async (createAdapter) => {
      const adapter = await createAdapter(
        entitlementFixture([
          entitlementState(
            hostPrincipalOne,
            current(["plan.pro", "support.priority"]),
          ),
          entitlementState(hostPrincipalTwo, current(["plan.advisor"])),
        ]),
      );

      assert.deepEqual(
        await adapter.resolveEntitlements({
          principalId: hostPrincipalTwo,
        }),
        ["plan.advisor"],
      );
      assert.deepEqual(
        await adapter.resolveEntitlements({
          principalId: hostPrincipalOne,
        }),
        ["plan.pro", "support.priority"],
      );
    },
  },
  {
    name: "current entitlements are canonical immutable host names",
    run: async (createAdapter) => {
      const sourceState = current([
        "support.priority",
        "plan.pro",
        "support.priority",
      ]);
      const adapter = await createAdapter(
        entitlementFixture([entitlementState(hostPrincipalOne, sourceState)]),
      );

      const entitlements = await adapter.resolveEntitlements({
        principalId: hostPrincipalOne,
      });
      assert.deepEqual(entitlements, ["plan.pro", "support.priority"]);
      assert.notEqual(entitlements, sourceState.entitlements);
      assert.equal(Object.isFrozen(entitlements), true);
      assert.equal(entitlements.includes(hostPrincipalOne), false);
    },
  },
  {
    name: "authoritative current absence returns an immutable empty list",
    run: async (createAdapter) => {
      const adapter = await createAdapter(
        entitlementFixture([entitlementState(hostPrincipalOne, current([]))]),
      );

      const entitlements = await adapter.resolveEntitlements({
        principalId: hostPrincipalOne,
      });
      assert.deepEqual(entitlements, []);
      assert.equal(Object.isFrozen(entitlements), true);
    },
  },
  {
    name: "a later current state replaces prior entitlement output",
    run: async (createAdapter) => {
      const adapter = await createAdapter(
        entitlementFixture([
          entitlementState(hostPrincipalOne, current(["plan.pro"])),
          entitlementState(hostPrincipalOne, current(["plan.advisor"])),
        ]),
      );

      assert.deepEqual(
        await adapter.resolveEntitlements({
          principalId: hostPrincipalOne,
        }),
        ["plan.pro"],
      );
      assert.deepEqual(
        await adapter.resolveEntitlements({
          principalId: hostPrincipalOne,
        }),
        ["plan.advisor"],
      );
    },
  },
  {
    name: "known entitlements allow and authoritative absence denies",
    run: async (createAdapter) => {
      const adapter = await createAdapter(
        entitlementFixture([
          entitlementState(hostPrincipalOne, current(["plan.pro"])),
          entitlementState(hostPrincipalTwo, current([])),
        ]),
      );
      const policy = Object.freeze({
        version: "conformance-v1",
        entitlements: Object.freeze({
          "plan.pro": Object.freeze(["support.ticket.create"]),
        }),
      });
      const deniedEntitlements = await adapter.resolveEntitlements({
        principalId: hostPrincipalTwo,
      });
      const allowedEntitlements = await adapter.resolveEntitlements({
        principalId: hostPrincipalOne,
      });

      assert.deepEqual(
        decideAccess(
          resolveAccess(
            {
              principalId: hostPrincipalOne,
              entitlements: allowedEntitlements,
            },
            policy,
          ),
          "support.ticket.create",
        ),
        {
          allowed: true,
          permission: "support.ticket.create",
          reason: "granted",
        },
      );
      assert.deepEqual(
        decideAccess(
          resolveAccess(
            {
              principalId: hostPrincipalTwo,
              entitlements: deniedEntitlements,
            },
            policy,
          ),
          "support.ticket.create",
        ),
        {
          allowed: false,
          permission: "support.ticket.create",
          reason: "not_granted",
        },
      );
    },
  },
];

for (const kind of failureKinds) {
  entitlementCases.push({
    name: `a later ${kind} entitlement state cannot use last-known-good output`,
    run: async (createAdapter) => {
      const adapter = await createAdapter(
        entitlementFixture([
          entitlementState(hostPrincipalOne, current(["plan.pro"])),
          entitlementState(hostPrincipalOne, Object.freeze({ kind })),
        ]),
      );

      assert.deepEqual(
        await adapter.resolveEntitlements({
          principalId: hostPrincipalOne,
        }),
        ["plan.pro"],
      );
      await assert.rejects(
        adapter.resolveEntitlements({ principalId: hostPrincipalOne }),
      );
    },
  });
  entitlementCases.push({
    name: `${kind} entitlement state rejects instead of granting or returning empty`,
    run: (createAdapter) => expectResolutionFailure(createAdapter, kind),
  });
}

/**
 * Behaviour every request-time {@link EntitlementAdapter} must exhibit.
 *
 * The cases have no test-framework dependency:
 *
 * ```ts
 * for (const testCase of entitlementAdapterConformanceCases) {
 *   it(testCase.name, () => testCase.run(createEntitlementAdapter));
 * }
 * ```
 */
export const entitlementAdapterConformanceCases: readonly EntitlementAdapterConformanceCase[] =
  Object.freeze(entitlementCases);
