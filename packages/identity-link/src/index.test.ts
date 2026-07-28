import { describe, expect, it } from "vitest";

import type {
  IdentityLinkKey,
  PrincipalId,
} from "@pegma/authorization-contracts";

import {
  identityLinkKeyFromVerifiedIdentityClaims,
  type VerifiedIdentityClaims,
} from "./index.js";

const issuer = "https://accounts.example.test";
const subject = "5ad74a3e-21ef-4b2f-ad52-f80922678cb5" as PrincipalId;

interface IdentityPackageVerifiedClaims {
  readonly issuer: string;
  readonly subject: PrincipalId;
  readonly emailVerified: true;
}

const asClaims = (value: unknown): VerifiedIdentityClaims =>
  value as VerifiedIdentityClaims;

describe("identityLinkKeyFromVerifiedIdentityClaims", () => {
  it("matches the first-party verified-claims contract and projects only the link key", () => {
    const identityClaims: IdentityPackageVerifiedClaims = {
      issuer,
      subject,
      emailVerified: true,
    };
    const claims: VerifiedIdentityClaims = identityClaims;
    const sameIdentityShape: IdentityPackageVerifiedClaims = claims;
    const key: IdentityLinkKey =
      identityLinkKeyFromVerifiedIdentityClaims(sameIdentityShape);

    expect(key).toEqual({ issuer, subject });
    expect(Object.keys(key)).toEqual(["issuer", "subject"]);
    expect("email" in key).toBe(false);
    expect("emailVerified" in key).toBe(false);
  });

  it("returns fresh frozen output detached from the claims container", () => {
    const claims = { issuer, subject, emailVerified: true as const };
    const first = identityLinkKeyFromVerifiedIdentityClaims(claims);
    const second = identityLinkKeyFromVerifiedIdentityClaims(claims);

    claims.issuer = "https://changed.example.test";

    expect(first).toEqual({ issuer, subject });
    expect(Object.isFrozen(first)).toBe(true);
    expect(first).not.toBe(second);
  });

  it("preserves valid opaque values exactly at their hard bounds", () => {
    const boundedIssuer = `😀${"I".repeat(1_022)}`;
    const boundedSubject = `😀${"S".repeat(510)}` as PrincipalId;

    expect(
      identityLinkKeyFromVerifiedIdentityClaims({
        issuer: boundedIssuer,
        subject: boundedSubject,
        emailVerified: true,
      }),
    ).toEqual({
      issuer: boundedIssuer,
      subject: boundedSubject,
    });
  });

  it.each([
    ["missing issuer", { subject, emailVerified: true }],
    ["missing subject", { issuer, emailVerified: true }],
    ["missing verification", { issuer, subject }],
    ["false verification", { issuer, subject, emailVerified: false }],
    ["string verification", { issuer, subject, emailVerified: "true" }],
    ["null issuer", { issuer: null, subject, emailVerified: true }],
    ["numeric subject", { issuer, subject: 42, emailVerified: true }],
    ["blank issuer", { issuer: " \t\n", subject, emailVerified: true }],
    ["blank subject", { issuer, subject: "\u00A0", emailVerified: true }],
    [
      "overlong issuer",
      { issuer: "i".repeat(1_025), subject, emailVerified: true },
    ],
    [
      "overlong subject",
      { issuer, subject: "s".repeat(513), emailVerified: true },
    ],
    [
      "issuer control",
      { issuer: "https://issuer.example/\u0000", subject, emailVerified: true },
    ],
    [
      "subject C1 control",
      { issuer, subject: "subject\u0085", emailVerified: true },
    ],
    [
      "malformed Unicode",
      { issuer, subject: "subject\uD800", emailVerified: true },
    ],
    [
      "email field",
      {
        issuer,
        subject,
        emailVerified: true,
        email: "person@example.test",
      },
    ],
    ["extra field", { issuer, subject, emailVerified: true, role: "admin" }],
    [
      "symbol field",
      Object.assign(
        { issuer, subject, emailVerified: true },
        {
          [Symbol("extra")]: "unsafe",
        },
      ),
    ],
    ["array container", [issuer, subject, true]],
    ["date container", new Date()],
    ["boxed container", new String(issuer)],
    ["null container", null],
    ["function container", () => undefined],
  ])("rejects malformed claims: %s", (_name, value) => {
    expect(() =>
      identityLinkKeyFromVerifiedIdentityClaims(asClaims(value)),
    ).toThrow(TypeError);
  });

  it.each(["\u0000", "\u001F", "\u007F", "\u0080", "\u009F"])(
    "rejects every control range boundary: %s",
    (control) => {
      expect(() =>
        identityLinkKeyFromVerifiedIdentityClaims({
          issuer,
          subject: `subject${control}` as PrincipalId,
          emailVerified: true,
        }),
      ).toThrow(TypeError);
    },
  );

  it("rejects inherited and non-enumerable claims", () => {
    const inheritedIssuer = Object.assign(Object.create({ issuer }), {
      subject,
      emailVerified: true,
    });
    const nonEnumerable = { issuer, subject };
    Object.defineProperty(nonEnumerable, "emailVerified", {
      value: true,
      enumerable: false,
    });

    expect(() =>
      identityLinkKeyFromVerifiedIdentityClaims(asClaims(inheritedIssuer)),
    ).toThrow(TypeError);
    expect(() =>
      identityLinkKeyFromVerifiedIdentityClaims(asClaims(nonEnumerable)),
    ).toThrow(TypeError);
  });

  it("rejects accessors without executing getters", () => {
    let getterCalls = 0;
    for (const name of ["issuer", "subject", "emailVerified"] as const) {
      const claims: Record<string, unknown> = {
        issuer,
        subject,
        emailVerified: true,
      };
      Object.defineProperty(claims, name, {
        enumerable: true,
        get() {
          getterCalls += 1;
          return name === "emailVerified"
            ? true
            : name === "issuer"
              ? issuer
              : subject;
        },
      });

      expect(() =>
        identityLinkKeyFromVerifiedIdentityClaims(asClaims(claims)),
      ).toThrow(TypeError);
    }
    expect(getterCalls).toBe(0);
  });

  it("wraps throwing proxy traps without reading claim values", () => {
    let reflectionTrapCalls = 0;
    let valueReadCalls = 0;
    const proxy = new Proxy(
      { issuer, subject, emailVerified: true as const },
      {
        getPrototypeOf() {
          reflectionTrapCalls += 1;
          throw new Error("must not run");
        },
        ownKeys() {
          reflectionTrapCalls += 1;
          throw new Error("must not run");
        },
        getOwnPropertyDescriptor() {
          reflectionTrapCalls += 1;
          throw new Error("must not run");
        },
        get() {
          valueReadCalls += 1;
          throw new Error("must not run");
        },
      },
    );

    expect(() =>
      identityLinkKeyFromVerifiedIdentityClaims(asClaims(proxy)),
    ).toThrow(
      "Verified identity claims must be an exact own-data-only issuer, subject, and emailVerified object",
    );
    expect(reflectionTrapCalls).toBeGreaterThan(0);
    expect(valueReadCalls).toBe(0);
  });

  it("rejects revoked proxies with the generic malformed-claims error", () => {
    const { proxy, revoke } = Proxy.revocable(
      { issuer, subject, emailVerified: true as const },
      {},
    );
    revoke();

    expect(() =>
      identityLinkKeyFromVerifiedIdentityClaims(asClaims(proxy)),
    ).toThrow(TypeError);
  });

  it("documents that a transparent proxy is indistinguishable in portable JavaScript", () => {
    const proxy = new Proxy(
      { issuer, subject, emailVerified: true as const },
      {},
    );

    expect(identityLinkKeyFromVerifiedIdentityClaims(proxy)).toEqual({
      issuer,
      subject,
    });
  });
});
