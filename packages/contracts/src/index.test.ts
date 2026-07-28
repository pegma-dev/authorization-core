import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  AccessSubject,
  EntitlementAdapter,
  EntitlementRequest,
  IdentityAdapter,
  IdentityLink,
  IdentityLinkKey,
  PrincipalId,
} from "./index.js";

const accountId = "f8ea9308-1bdb-49b0-89a9-eef2af28eb6b";
const secondAccountId = "6958edb4-a3f1-4d2d-94f1-b403523db949";
const providerSubject = "provider|retiregolden-test-account";
const issuer = "https://identity.example.test/";

const keysEqual = (left: IdentityLinkKey, right: IdentityLinkKey): boolean =>
  left.issuer === right.issuer && left.subject === right.subject;

type MutableIdentityLink = {
  readonly key: IdentityLinkKey;
  principalId: PrincipalId;
};

class TestIdentityLinks implements IdentityAdapter {
  readonly #links: MutableIdentityLink[] = [];

  constructor(links: readonly IdentityLink[] = []) {
    for (const { key, principalId } of links) {
      this.link(key, principalId);
    }
  }

  readonly resolvePrincipalId = async (
    key: IdentityLinkKey,
  ): Promise<PrincipalId | null> =>
    this.#links.find((link) => keysEqual(link.key, key))?.principalId ?? null;

  link(key: IdentityLinkKey, principalId: PrincipalId): void {
    const existing = this.#links.find((link) => keysEqual(link.key, key));
    if (existing !== undefined) {
      if (existing.principalId !== principalId) {
        throw new Error("identity key is already linked to another principal");
      }
      return;
    }

    this.#links.push({ key: { ...key }, principalId });
  }

  unlink(key: IdentityLinkKey, expectedPrincipalId: PrincipalId): void {
    const index = this.#links.findIndex((link) => keysEqual(link.key, key));
    if (
      index === -1 ||
      this.#links[index]?.principalId !== expectedPrincipalId
    ) {
      throw new Error("expected identity link does not exist");
    }

    this.#links.splice(index, 1);
  }

  merge(source: PrincipalId, survivor: PrincipalId): void {
    if (source === survivor) {
      throw new Error("merge source and survivor must differ");
    }

    for (const link of this.#links) {
      if (link.principalId === source) {
        link.principalId = survivor;
      }
    }
  }
}

const identityAdapter = new TestIdentityLinks([
  {
    key: { issuer, subject: providerSubject },
    principalId: accountId,
  },
]);

type ProviderBillingState = Readonly<{
  plan: "pro" | "advisor";
  status: "active" | "inactive";
}>;

const persistedBillingState = new Map<PrincipalId, ProviderBillingState>([
  [accountId, { plan: "pro", status: "active" }],
  [secondAccountId, { plan: "advisor", status: "inactive" }],
]);

const entitlementAdapter: EntitlementAdapter = {
  resolveEntitlements: async ({ principalId }) => {
    const state = persistedBillingState.get(principalId);
    if (state === undefined) {
      throw new Error("persisted entitlement state is missing");
    }
    return Object.freeze(
      state.status === "active" ? [`plan.${state.plan}`] : [],
    );
  },
};

describe("IdentityAdapter", () => {
  it("maps issuer-namespaced evidence to a stable host principal", async () => {
    const principalId = await identityAdapter.resolvePrincipalId({
      issuer,
      subject: providerSubject,
    });

    expect(principalId).toBe(accountId);
    expect(principalId).not.toBe(providerSubject);
  });

  it("does not link the same provider subject from another issuer", async () => {
    await expect(
      identityAdapter.resolvePrincipalId({
        issuer: "https://other-identity.example.test/",
        subject: providerSubject,
      }),
    ).resolves.toBeNull();
  });

  it("does not link another subject from the same issuer", async () => {
    await expect(
      identityAdapter.resolvePrincipalId({
        issuer,
        subject: "provider|other-account",
      }),
    ).resolves.toBeNull();
  });

  it("compares both tuple components exactly and case-sensitively", async () => {
    const links = new TestIdentityLinks([
      {
        key: { issuer: "https://Issuer.example/", subject: "Subject" },
        principalId: accountId,
      },
      {
        key: { issuer: "https://issuer.example/", subject: "Subject" },
        principalId: secondAccountId,
      },
      {
        key: { issuer: "https://Issuer.example/", subject: "subject" },
        principalId: "third-account",
      },
    ]);

    await expect(
      links.resolvePrincipalId({
        issuer: "https://Issuer.example/",
        subject: "Subject",
      }),
    ).resolves.toBe(accountId);
    await expect(
      links.resolvePrincipalId({
        issuer: "https://issuer.example/",
        subject: "Subject",
      }),
    ).resolves.toBe(secondAccountId);
    await expect(
      links.resolvePrincipalId({
        issuer: "https://Issuer.example/",
        subject: "subject",
      }),
    ).resolves.toBe("third-account");
  });

  it("keeps delimiter-containing tuple components structurally distinct", async () => {
    const links = new TestIdentityLinks([
      {
        key: { issuer: "a", subject: "\u0000b" },
        principalId: accountId,
      },
      {
        key: { issuer: "a\u0000", subject: "b" },
        principalId: secondAccountId,
      },
    ]);

    await expect(
      links.resolvePrincipalId({ issuer: "a", subject: "\u0000b" }),
    ).resolves.toBe(accountId);
    await expect(
      links.resolvePrincipalId({ issuer: "a\u0000", subject: "b" }),
    ).resolves.toBe(secondAccountId);
  });

  it("allows multiple distinct keys to resolve one stable principal", async () => {
    const links = new TestIdentityLinks([
      {
        key: { issuer, subject: providerSubject },
        principalId: accountId,
      },
      {
        key: {
          issuer: "https://second-identity.example.test/",
          subject: "different-provider-subject",
        },
        principalId: accountId,
      },
    ]);

    await expect(
      links.resolvePrincipalId({ issuer, subject: providerSubject }),
    ).resolves.toBe(accountId);
    await expect(
      links.resolvePrincipalId({
        issuer: "https://second-identity.example.test/",
        subject: "different-provider-subject",
      }),
    ).resolves.toBe(accountId);
  });

  it("allows adapter inputs to carry richer provider evidence", async () => {
    type ProviderEvidence = IdentityLinkKey &
      Readonly<{ providerSessionId: string }>;
    const adapter: IdentityAdapter<ProviderEvidence> = {
      resolvePrincipalId: async ({ issuer: inputIssuer, subject }) =>
        inputIssuer === issuer && subject === providerSubject
          ? accountId
          : null,
    };

    await expect(
      adapter.resolvePrincipalId({
        issuer,
        subject: providerSubject,
        providerSessionId: "provider-session",
      }),
    ).resolves.toBe(accountId);
  });

  it("returns null when no host principal is linked", async () => {
    await expect(
      identityAdapter.resolvePrincipalId({
        issuer: "https://identity.example.test/",
        subject: "provider|unknown",
      }),
    ).resolves.toBeNull();
  });

  it("rejects operational failures instead of reporting an unlinked identity", async () => {
    const unavailableAdapter: IdentityAdapter = {
      resolvePrincipalId: async () => {
        throw new Error("identity link store unavailable");
      },
    };

    await expect(
      unavailableAdapter.resolvePrincipalId({
        issuer,
        subject: providerSubject,
      }),
    ).rejects.toThrow("identity link store unavailable");
  });
});

describe("identity-link lifecycle model", () => {
  it("links idempotently but rejects a conflicting principal", async () => {
    const links = new TestIdentityLinks();
    const key = { issuer, subject: providerSubject };

    links.link(key, accountId);
    links.link(key, accountId);

    await expect(links.resolvePrincipalId(key)).resolves.toBe(accountId);
    expect(() => links.link(key, secondAccountId)).toThrow(
      "identity key is already linked to another principal",
    );
    await expect(links.resolvePrincipalId(key)).resolves.toBe(accountId);
  });

  it("unlinks exactly one expected edge and preserves other links", async () => {
    const removedKey = { issuer, subject: providerSubject };
    const preservedKey = {
      issuer: "https://second-identity.example.test/",
      subject: "second-subject",
    };
    const links = new TestIdentityLinks([
      { key: removedKey, principalId: accountId },
      { key: preservedKey, principalId: accountId },
    ]);

    expect(() => links.unlink(removedKey, secondAccountId)).toThrow(
      "expected identity link does not exist",
    );
    links.unlink(removedKey, accountId);

    await expect(links.resolvePrincipalId(removedKey)).resolves.toBeNull();
    await expect(links.resolvePrincipalId(preservedKey)).resolves.toBe(
      accountId,
    );
  });

  it("merges every source link into the survivor without losing survivor links", async () => {
    const sourceKeys = [
      { issuer, subject: providerSubject },
      {
        issuer: "https://second-identity.example.test/",
        subject: "source-subject",
      },
    ] as const;
    const survivorKey = {
      issuer: "https://third-identity.example.test/",
      subject: "survivor-subject",
    };
    const links = new TestIdentityLinks([
      { key: sourceKeys[0], principalId: secondAccountId },
      { key: sourceKeys[1], principalId: secondAccountId },
      { key: survivorKey, principalId: accountId },
    ]);

    links.merge(secondAccountId, accountId);

    for (const key of [...sourceKeys, survivorKey]) {
      await expect(links.resolvePrincipalId(key)).resolves.toBe(accountId);
    }
    for (const key of sourceKeys) {
      await expect(links.resolvePrincipalId(key)).resolves.not.toBe(
        secondAccountId,
      );
    }
  });
});

describe("EntitlementAdapter", () => {
  it("requires principal-keyed request input at the type boundary", () => {
    type DefaultRequest = Parameters<
      EntitlementAdapter["resolveEntitlements"]
    >[0];

    expectTypeOf<DefaultRequest>().toEqualTypeOf<EntitlementRequest>();
    expectTypeOf<DefaultRequest["principalId"]>().toEqualTypeOf<PrincipalId>();
  });

  it("loads persisted host state by principal instead of accepting transient facts", async () => {
    await expect(
      entitlementAdapter.resolveEntitlements({ principalId: accountId }),
    ).resolves.toEqual(["plan.pro"]);

    await expect(
      entitlementAdapter.resolveEntitlements({ principalId: secondAccountId }),
    ).resolves.toEqual([]);
  });

  it("rejects missing persisted state instead of treating it as empty", async () => {
    await expect(
      entitlementAdapter.resolveEntitlements({ principalId: "missing" }),
    ).rejects.toThrow("persisted entitlement state is missing");
  });

  it("keeps host roles separate when assembling an access subject", async () => {
    const principalId = await identityAdapter.resolvePrincipalId({
      issuer,
      subject: providerSubject,
    });
    if (principalId === null) {
      throw new Error("expected fixture identity to resolve");
    }

    const entitlements = await entitlementAdapter.resolveEntitlements({
      principalId,
    });
    const assignedRoles = ["support"] as const;
    const subject: AccessSubject = {
      principalId,
      roles: assignedRoles,
      entitlements,
    };

    expect(subject).toEqual({
      principalId: accountId,
      roles: ["support"],
      entitlements: ["plan.pro"],
    });
  });
});
