import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";

import { describe, expect, it } from "vitest";

describe("@pegma/authorization-identity portable ESM", () => {
  it("imports and projects claims without Node or package runtime imports", async () => {
    const source = await readFile(
      new URL("../packages/identity-link/dist/index.js", import.meta.url),
      "utf8",
    );

    expect(source).not.toContain("node:");
    expect(source).not.toMatch(/\bfrom\s+["']/u);
    expect(source).not.toContain("require(");

    const specifier = `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`;
    const module = (await import(/* @vite-ignore */ specifier)) as {
      identityLinkKeyFromVerifiedIdentityClaims: (claims: {
        issuer: string;
        subject: string;
        emailVerified: true;
      }) => unknown;
    };

    expect(
      module.identityLinkKeyFromVerifiedIdentityClaims({
        issuer: "https://identity.example.test",
        subject: "portable-subject",
        emailVerified: true,
      }),
    ).toEqual({
      issuer: "https://identity.example.test",
      subject: "portable-subject",
    });
  });
});
