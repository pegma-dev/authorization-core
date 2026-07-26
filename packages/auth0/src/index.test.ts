import { describe, expect, it } from "vitest";

import type {
  IdentityAdapter,
  IdentityLinkKey,
  PrincipalId,
} from "@pegma/authorization-contracts";

import {
  identityLinkKeyFromVerifiedAuth0Claims,
  type Auth0IssuerSubjectClaims,
} from "./index.js";

const issuer = "https://tenant.example.auth0.com/";
const subject = "auth0|67f09f4a60d72516c1123456";
const accountId = "f8ea9308-1bdb-49b0-89a9-eef2af28eb6b";

const asClaims = (value: unknown): Auth0IssuerSubjectClaims =>
  value as Auth0IssuerSubjectClaims;

describe("identityLinkKeyFromVerifiedAuth0Claims", () => {
  it("projects only exact issuer and subject from realistic verified claims", () => {
    const verifiedClaims = {
      iss: issuer,
      sub: subject,
      aud: ["https://api.example.test", "client-id"],
      azp: "client-id",
      email: "person@example.test",
      user_id: "auth0|fallback-must-not-be-used",
      roles: ["admin"],
      org_id: "org_example",
    };

    expect(identityLinkKeyFromVerifiedAuth0Claims(verifiedClaims)).toEqual({
      issuer,
      subject,
    });
    expect(
      Object.keys(identityLinkKeyFromVerifiedAuth0Claims(verifiedClaims)),
    ).toEqual(["issuer", "subject"]);
  });

  it("returns a fresh, frozen output detached from the claims container", () => {
    const verifiedClaims = { iss: issuer, sub: subject };
    const first = identityLinkKeyFromVerifiedAuth0Claims(verifiedClaims);
    const second = identityLinkKeyFromVerifiedAuth0Claims(verifiedClaims);

    verifiedClaims.iss = "https://changed.example/";

    expect(first).toEqual({ issuer, subject });
    expect(Object.isFrozen(first)).toBe(true);
    expect(first).not.toBe(second);
  });

  it("preserves case, slashes, delimiters, Unicode, and surrounding whitespace", () => {
    const exactIssuer = " HTTPS://Tenant.Example/Auth0/\u0000 ";
    const exactSubject = " auth0|Case/Subject:é\u0000 ";

    expect(
      identityLinkKeyFromVerifiedAuth0Claims({
        iss: exactIssuer,
        sub: exactSubject,
      }),
    ).toEqual({
      issuer: exactIssuer,
      subject: exactSubject,
    });
  });

  it("keeps the same subject under different issuers distinct", () => {
    expect(
      identityLinkKeyFromVerifiedAuth0Claims({ iss: issuer, sub: subject }),
    ).not.toEqual(
      identityLinkKeyFromVerifiedAuth0Claims({
        iss: "https://custom-login.example.test/",
        sub: subject,
      }),
    );
  });

  it.each([
    ["missing issuer", { sub: subject }],
    ["missing subject", { iss: issuer }],
    ["null issuer", { iss: null, sub: subject }],
    ["numeric subject", { iss: issuer, sub: 42 }],
    ["boxed issuer", { iss: new String(issuer), sub: subject }],
    ["boxed subject", { iss: issuer, sub: new String(subject) }],
    ["blank issuer", { iss: " \t\n", sub: subject }],
    ["blank subject", { iss: issuer, sub: "\u00a0" }],
    [
      "email and user_id fallbacks",
      { email: "person@example.test", user_id: subject },
    ],
    ["null claims", null],
  ])("rejects malformed claims: %s", (_name, claims) => {
    expect(() =>
      identityLinkKeyFromVerifiedAuth0Claims(asClaims(claims)),
    ).toThrow(TypeError);
  });

  it("rejects inherited issuer or subject properties", () => {
    const inheritedIssuer = Object.assign(Object.create({ iss: issuer }), {
      sub: subject,
    });
    const inheritedSubject = Object.assign(Object.create({ sub: subject }), {
      iss: issuer,
    });

    expect(() =>
      identityLinkKeyFromVerifiedAuth0Claims(asClaims(inheritedIssuer)),
    ).toThrow(TypeError);
    expect(() =>
      identityLinkKeyFromVerifiedAuth0Claims(asClaims(inheritedSubject)),
    ).toThrow(TypeError);
  });

  it("rejects accessor claims without executing their getters", () => {
    let getterCalls = 0;
    const accessorIssuer = { sub: subject };
    Object.defineProperty(accessorIssuer, "iss", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return issuer;
      },
    });
    const accessorSubject = { iss: issuer };
    Object.defineProperty(accessorSubject, "sub", {
      enumerable: true,
      get: () => {
        getterCalls += 1;
        return subject;
      },
    });

    expect(() =>
      identityLinkKeyFromVerifiedAuth0Claims(asClaims(accessorIssuer)),
    ).toThrow(TypeError);
    expect(() =>
      identityLinkKeyFromVerifiedAuth0Claims(asClaims(accessorSubject)),
    ).toThrow(TypeError);
    expect(getterCalls).toBe(0);
  });
});

describe("identity lookup composition", () => {
  const linkedKey = identityLinkKeyFromVerifiedAuth0Claims({
    iss: issuer,
    sub: subject,
  });

  const keysEqual = (left: IdentityLinkKey, right: IdentityLinkKey): boolean =>
    left.issuer === right.issuer && left.subject === right.subject;

  const identityAdapter: IdentityAdapter = {
    resolvePrincipalId: async (key): Promise<PrincipalId | null> => {
      if (key.issuer === "https://unavailable.example.test/") {
        throw new Error("identity store unavailable");
      }
      return keysEqual(key, linkedKey) ? accountId : null;
    },
  };

  it("resolves verified claims through a host-owned identity link", async () => {
    const principalId = await identityAdapter.resolvePrincipalId(linkedKey);

    expect(principalId).toBe(accountId);
    expect(principalId).not.toBe(subject);
  });

  it("returns null only for a valid but unlinked key", async () => {
    const unlinkedKey = identityLinkKeyFromVerifiedAuth0Claims({
      iss: issuer,
      sub: "auth0|unlinked",
    });

    await expect(
      identityAdapter.resolvePrincipalId(unlinkedKey),
    ).resolves.toBeNull();
  });

  it("propagates host lookup failures", async () => {
    const validKey = identityLinkKeyFromVerifiedAuth0Claims({
      iss: "https://unavailable.example.test/",
      sub: subject,
    });

    await expect(identityAdapter.resolvePrincipalId(validKey)).rejects.toThrow(
      "identity store unavailable",
    );
  });
});
