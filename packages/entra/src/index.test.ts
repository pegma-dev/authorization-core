import { describe, expect, it } from "vitest";

import type {
  IdentityAdapter,
  IdentityLinkKey,
  PrincipalId,
} from "@pegma/authorization-contracts";

import {
  identityLinkKeyFromVerifiedEntraClaims,
  type EntraIssuerObjectIdClaims,
} from "./index.js";

const tenantId = "11111111-2222-3333-4444-555555555555";
const issuer = `https://login.microsoftonline.com/${tenantId}/v2.0`;
const ciamIssuer = `https://contoso.ciamlogin.com/${tenantId}/v2.0`;
const objectId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
const pairwiseSub = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const accountId = "f8ea9308-1bdb-49b0-89a9-eef2af28eb6b";

const asClaims = (value: unknown): EntraIssuerObjectIdClaims =>
  value as EntraIssuerObjectIdClaims;

const expectRejectionOmitsSensitiveFields = (error: unknown): void => {
  expect(error).toBeInstanceOf(TypeError);
  const message = error instanceof Error ? error.message : String(error);
  expect(message).not.toMatch(/email|preferred_username/iu);
};

describe("identityLinkKeyFromVerifiedEntraClaims", () => {
  it("projects only exact issuer and oid from realistic verified claims", () => {
    const verifiedClaims = {
      iss: issuer,
      oid: objectId,
      sub: pairwiseSub,
      tid: tenantId,
      aud: ["api://resource", "client-id"],
      azp: "client-id",
      email: "person@example.test",
      preferred_username: "person@example.test",
      roles: ["Admin"],
    };

    expect(identityLinkKeyFromVerifiedEntraClaims(verifiedClaims)).toEqual({
      issuer,
      subject: objectId,
    });
    expect(
      Object.keys(identityLinkKeyFromVerifiedEntraClaims(verifiedClaims)),
    ).toEqual(["issuer", "subject"]);
    expect(
      identityLinkKeyFromVerifiedEntraClaims(verifiedClaims).subject,
    ).not.toBe(pairwiseSub);
  });

  it("returns a fresh, frozen output detached from the claims container", () => {
    const verifiedClaims = { iss: issuer, oid: objectId };
    const first = identityLinkKeyFromVerifiedEntraClaims(verifiedClaims);
    const second = identityLinkKeyFromVerifiedEntraClaims(verifiedClaims);

    verifiedClaims.iss = "https://changed.example/v2.0";

    expect(first).toEqual({ issuer, subject: objectId });
    expect(Object.isFrozen(first)).toBe(true);
    expect(first).not.toBe(second);
  });

  it("preserves case, slashes, delimiters, Unicode, and surrounding whitespace", () => {
    const exactIssuer = " HTTPS://Login.Example/Tenant/v2.0";
    const exactObjectId = " AAAAAAAA-BBBB-CCCC-DDDD-EEEEEEEEEEEE\u0000 ";

    expect(
      identityLinkKeyFromVerifiedEntraClaims({
        iss: exactIssuer,
        oid: exactObjectId,
      }),
    ).toEqual({
      issuer: exactIssuer,
      subject: exactObjectId,
    });
  });

  it("keeps the same oid under workforce and CIAM issuers distinct", () => {
    expect(
      identityLinkKeyFromVerifiedEntraClaims({ iss: issuer, oid: objectId }),
    ).not.toEqual(
      identityLinkKeyFromVerifiedEntraClaims({
        iss: ciamIssuer,
        oid: objectId,
      }),
    );
  });

  it("preserves oid GUID case exactly with no normalization", () => {
    const mixedCaseOid = "AaAaAaAa-BbBb-CcCc-DdDd-EeEeEeEeEeEe";

    expect(
      identityLinkKeyFromVerifiedEntraClaims({
        iss: issuer,
        oid: mixedCaseOid,
      }),
    ).toEqual({
      issuer,
      subject: mixedCaseOid,
    });
  });

  it("rejects a v1 sts.windows.net issuer with a v1-specific diagnostic", () => {
    try {
      identityLinkKeyFromVerifiedEntraClaims({
        iss: `https://sts.windows.net/${tenantId}/`,
        oid: objectId,
      });
      expect.unreachable("expected TypeError");
    } catch (error) {
      expectRejectionOmitsSensitiveFields(error);
      expect(error).toBeInstanceOf(TypeError);
      expect((error as TypeError).message).toMatch(/v1 token profile/u);
      expect((error as TypeError).message).toMatch(/sts\.windows\.net/u);
      expect((error as TypeError).message).toMatch(/\/v2\.0/u);
    }
  });

  it("names the v1 profile only for the exact v1 issuer origin", () => {
    try {
      identityLinkKeyFromVerifiedEntraClaims({
        iss: `https://sts.windows.net.example.test/${tenantId}/`,
        oid: objectId,
      });
      expect.unreachable("expected TypeError");
    } catch (error) {
      expect(error).toBeInstanceOf(TypeError);
      expect((error as TypeError).message).not.toMatch(/v1 token profile/u);
      expect((error as TypeError).message).toMatch(/\/v2\.0/u);
    }
  });

  it.each([
    [
      "v1 login.microsoftonline.com without suffix",
      `https://login.microsoftonline.com/${tenantId}/`,
    ],
    ["issuer missing /v2.0 suffix", "https://login.microsoftonline.com/tenant"],
    [
      "issuer with uppercase V2.0 suffix",
      `https://login.microsoftonline.com/${tenantId}/V2.0`,
    ],
  ])("rejects issuer without the /v2.0 suffix: %s", (_name, badIssuer) => {
    expect(() =>
      identityLinkKeyFromVerifiedEntraClaims({
        iss: badIssuer,
        oid: objectId,
      }),
    ).toThrow(TypeError);
  });

  it.each([
    ["missing issuer", { oid: objectId }],
    ["missing oid", { iss: issuer }],
    ["null issuer", { iss: null, oid: objectId }],
    ["numeric oid", { iss: issuer, oid: 42 }],
    ["boxed issuer", { iss: new String(issuer), oid: objectId }],
    ["boxed oid", { iss: issuer, oid: new String(objectId) }],
    ["blank issuer", { iss: " \t\n", oid: objectId }],
    ["blank oid", { iss: issuer, oid: "\u00a0" }],
    [
      "email and preferred_username fallbacks",
      { email: "person@example.test", preferred_username: objectId },
    ],
    ["sub without oid", { iss: issuer, sub: pairwiseSub }],
    ["null claims", null],
  ])("rejects malformed claims: %s", (_name, claims) => {
    try {
      identityLinkKeyFromVerifiedEntraClaims(asClaims(claims));
      expect.unreachable("expected TypeError");
    } catch (error) {
      expectRejectionOmitsSensitiveFields(error);
    }
  });

  it("rejects inherited issuer or oid properties", () => {
    const inheritedIssuer = Object.assign(Object.create({ iss: issuer }), {
      oid: objectId,
    });
    const inheritedOid = Object.assign(Object.create({ oid: objectId }), {
      iss: issuer,
    });

    expect(() =>
      identityLinkKeyFromVerifiedEntraClaims(asClaims(inheritedIssuer)),
    ).toThrow(TypeError);
    expect(() =>
      identityLinkKeyFromVerifiedEntraClaims(asClaims(inheritedOid)),
    ).toThrow(TypeError);
  });

  it("rejects accessor claims without executing their getters", () => {
    let getterCalls = 0;
    const accessorIssuer = { oid: objectId };
    Object.defineProperty(accessorIssuer, "iss", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return issuer;
      },
    });
    const accessorOid = { iss: issuer };
    Object.defineProperty(accessorOid, "oid", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return objectId;
      },
    });

    expect(() =>
      identityLinkKeyFromVerifiedEntraClaims(asClaims(accessorIssuer)),
    ).toThrow(TypeError);
    expect(() =>
      identityLinkKeyFromVerifiedEntraClaims(asClaims(accessorOid)),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });
});

describe("identity lookup composition", () => {
  const linkedKey = identityLinkKeyFromVerifiedEntraClaims({
    iss: issuer,
    oid: objectId,
  });

  const keysEqual = (left: IdentityLinkKey, right: IdentityLinkKey): boolean =>
    left.issuer === right.issuer && left.subject === right.subject;

  const identityAdapter: IdentityAdapter = {
    resolvePrincipalId: async (key): Promise<PrincipalId | null> => {
      if (key.issuer === "https://unavailable.example.test/v2.0") {
        throw new Error("identity store unavailable");
      }
      return keysEqual(key, linkedKey) ? accountId : null;
    },
  };

  it("resolves verified claims through a host-owned identity link", async () => {
    const principalId = await identityAdapter.resolvePrincipalId(linkedKey);

    expect(principalId).toBe(accountId);
    expect(principalId).not.toBe(objectId);
    expect(principalId).not.toBe(pairwiseSub);
  });

  it("returns null only for a valid but unlinked key", async () => {
    const unlinkedKey = identityLinkKeyFromVerifiedEntraClaims({
      iss: issuer,
      oid: "ffffffff-ffff-ffff-ffff-ffffffffffff",
    });

    await expect(
      identityAdapter.resolvePrincipalId(unlinkedKey),
    ).resolves.toBeNull();
  });

  it("propagates host lookup failures", async () => {
    const validKey = identityLinkKeyFromVerifiedEntraClaims({
      iss: "https://unavailable.example.test/v2.0",
      oid: objectId,
    });

    await expect(identityAdapter.resolvePrincipalId(validKey)).rejects.toThrow(
      "identity store unavailable",
    );
  });
});
