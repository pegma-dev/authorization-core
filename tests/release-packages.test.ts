import { execFileSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  ADMIN_BOOTSTRAP_PACKAGE,
  ENTRA_BOOTSTRAP_PACKAGE,
  IDENTITY_BOOTSTRAP_PACKAGE,
  RELEASE_PACKAGES,
  decidePublication,
  parseArguments,
  releaseImportSpecifiers,
  resolvedVersionMatchesSpecifier,
  validateAdminBootstrapRepository,
  validateEntraBootstrapRepository,
  validateIdentityBootstrapRepository,
  validateReleaseTag,
  validateRepository,
  verifyPreparedReleaseManifest,
} from "../scripts/release-packages.mjs";

const git = process.platform === "win32" ? "git.exe" : "git";

function run(command: string, arguments_: string[], cwd?: string): string {
  return execFileSync(command, arguments_, {
    cwd,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  }).trim();
}

describe("release package metadata", () => {
  it("accepts npm's cross-platform argument separator", () => {
    expect(parseArguments(["--", "--output", ".release"])).toEqual({
      output: ".release",
    });
  });

  it("keeps the exact contracts-first public package inventory", () => {
    expect(RELEASE_PACKAGES.map(({ name }) => name)).toEqual([
      "@pegma/authorization-contracts",
      "@pegma/authorization-auth0",
      "@pegma/authorization-entra",
      "@pegma/authorization-identity",
      "@pegma/authorization-core",
      "@pegma/authorization-policy",
      "@pegma/authorization-stripe",
      "@pegma/authorization-storage",
      "@pegma/authorization-admin",
      "@pegma/authorization-tokens",
    ]);
  });

  it("smoke-imports every declared public package export", () => {
    expect(releaseImportSpecifiers()).toEqual([
      "@pegma/authorization-contracts",
      "@pegma/authorization-auth0",
      "@pegma/authorization-entra",
      "@pegma/authorization-identity",
      "@pegma/authorization-core",
      "@pegma/authorization-core/conformance",
      "@pegma/authorization-policy",
      "@pegma/authorization-stripe",
      "@pegma/authorization-storage",
      "@pegma/authorization-admin",
      "@pegma/authorization-tokens",
      "@pegma/authorization-tokens/testing",
    ]);
  });

  it("validates the repository, package manifests, and lockfile together", async () => {
    await expect(validateRepository()).resolves.toMatchObject({
      version: "0.4.0",
    });
  });

  it("matches each lockfile dependency to its own specifier and resolved version", () => {
    expect(resolvedVersionMatchesSpecifier("0.4.0", "link:../contracts")).toBe(
      true,
    );
    expect(resolvedVersionMatchesSpecifier("0.4.0", "0.4.0")).toBe(true);
    expect(resolvedVersionMatchesSpecifier("^26.1.1", "26.1.1")).toBe(true);
    expect(
      resolvedVersionMatchesSpecifier(
        "^4.1.10",
        "4.1.10(@types/node@26.1.1)(vite@8.1.5(@types/node@26.1.1))",
      ),
    ).toBe(true);
    expect(resolvedVersionMatchesSpecifier("0.4.0", "999.0.0")).toBe(false);
    expect(resolvedVersionMatchesSpecifier("^26.1.1", "999.0.0")).toBe(false);
    expect(resolvedVersionMatchesSpecifier("0.4.0", undefined)).toBe(false);
  });

  it("keeps the identity name-reservation bootstrap package-only and version-split", async () => {
    expect(IDENTITY_BOOTSTRAP_PACKAGE).toEqual({
      directory: "identity-link",
      name: "@pegma/authorization-identity",
      sourceVersion: "0.1.0",
      version: "0.0.0",
    });
    const releaseEnvironmentKeys = [
      "RELEASE_TAG",
      "RELEASE_COMMIT",
      "RELEASE_PRERELEASE",
      "GITHUB_EVENT_NAME",
      "ACTIONS_ID_TOKEN_REQUEST_URL",
      "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ] as const;
    const releaseEnvironment = new Map(
      releaseEnvironmentKeys.map((key) => [key, process.env[key]]),
    );
    try {
      for (const key of releaseEnvironmentKeys) delete process.env[key];
      await expect(validateIdentityBootstrapRepository()).rejects.toThrow(
        "identity bootstrap source requires root 0.1.0, found 0.4.0",
      );
    } finally {
      for (const [key, value] of releaseEnvironment) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
    await expect(
      validateIdentityBootstrapRepository({ releaseTag: "v0.4.0" }),
    ).rejects.toThrow("refuses release or OIDC authority");

    const rootManifest = JSON.parse(
      readFileSync(join(process.cwd(), "package.json"), "utf8"),
    );
    expect(rootManifest.scripts["identity-bootstrap:pack"]).toContain(
      "identity-bootstrap-pack",
    );
    expect(rootManifest.scripts["identity-bootstrap:registry:check"]).toContain(
      "identity-bootstrap-registry-check",
    );
    expect(rootManifest.scripts["identity-bootstrap:publish"]).toBeUndefined();
  });

  it("requires the existing signed Identity bootstrap tag without recreating it", () => {
    const releaseGuide = readFileSync(
      join(process.cwd(), "docs", "RELEASING.md"),
      "utf8",
    );
    const identityBootstrap = releaseGuide
      .split("## Bootstrap for the new Identity adapter package")[1]
      ?.split("## Bootstrap for the new Entra adapter package")[0];
    expect(identityBootstrap).toBeDefined();
    expect(identityBootstrap).toContain(
      "git fetch origin tag authorization-identity-v0.0.0",
    );
    expect(identityBootstrap).toContain(
      "git verify-tag authorization-identity-v0.0.0",
    );
    expect(identityBootstrap).toContain(
      "afdf3f168d355629b2721512c246c1a18fd54c9d",
    );
    expect(identityBootstrap).toContain(
      "do not recreate, move, or force the tag",
    );
    expect(identityBootstrap).not.toMatch(/\bgit tag\b/);
  });

  it("keeps the entra name-reservation bootstrap package-only and version-split", async () => {
    expect(ENTRA_BOOTSTRAP_PACKAGE).toEqual({
      directory: "entra",
      name: "@pegma/authorization-entra",
      sourceVersion: "0.1.3",
      version: "0.0.0",
    });
    const releaseEnvironmentKeys = [
      "RELEASE_TAG",
      "RELEASE_COMMIT",
      "RELEASE_PRERELEASE",
      "GITHUB_EVENT_NAME",
      "ACTIONS_ID_TOKEN_REQUEST_URL",
      "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ] as const;
    const releaseEnvironment = new Map(
      releaseEnvironmentKeys.map((key) => [key, process.env[key]]),
    );
    try {
      for (const key of releaseEnvironmentKeys) delete process.env[key];
      await expect(validateEntraBootstrapRepository()).rejects.toThrow(
        "entra bootstrap source requires root 0.1.3, found 0.4.0",
      );
    } finally {
      for (const [key, value] of releaseEnvironment) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
    await expect(
      validateEntraBootstrapRepository({ releaseTag: "v0.4.0" }),
    ).rejects.toThrow("refuses release or OIDC authority");

    const rootManifest = JSON.parse(
      readFileSync(join(process.cwd(), "package.json"), "utf8"),
    );
    expect(rootManifest.scripts["entra-bootstrap:pack"]).toContain(
      "entra-bootstrap-pack",
    );
    expect(rootManifest.scripts["entra-bootstrap:registry:check"]).toContain(
      "entra-bootstrap-registry-check",
    );
    expect(rootManifest.scripts["entra-bootstrap:publish"]).toBeUndefined();
  });

  it("documents the Entra bootstrap ceremony without a publish command", () => {
    const releaseGuide = readFileSync(
      join(process.cwd(), "docs", "RELEASING.md"),
      "utf8",
    );
    const entraBootstrap = releaseGuide
      .split("## Bootstrap for the new Entra adapter package")[1]
      ?.split("## First advertised release and later releases")[0];
    expect(entraBootstrap).toBeDefined();
    expect(entraBootstrap).toContain("authorization-entra-v0.0.0");
    expect(entraBootstrap).toMatch(
      /git fetch origin\r?\ngit fetch origin tag authorization-entra-v0\.0\.0/u,
    );
    expect(entraBootstrap).toContain("npm run entra-bootstrap:check");
    expect(entraBootstrap).toContain(
      "npm publish .entra-bootstrap/pegma-authorization-entra-0.0.0.tgz",
    );
    expect(entraBootstrap).toContain("0.1.4");
    expect(entraBootstrap).not.toMatch(/\bentra-bootstrap:publish\b/);
  });

  it("keeps the admin name-reservation bootstrap package-only and version-split", async () => {
    expect(ADMIN_BOOTSTRAP_PACKAGE).toEqual({
      directory: "admin",
      name: "@pegma/authorization-admin",
      sourceVersion: "0.3.0",
      version: "0.0.0",
    });
    const releaseEnvironmentKeys = [
      "RELEASE_TAG",
      "RELEASE_COMMIT",
      "RELEASE_PRERELEASE",
      "GITHUB_EVENT_NAME",
      "ACTIONS_ID_TOKEN_REQUEST_URL",
      "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    ] as const;
    const releaseEnvironment = new Map(
      releaseEnvironmentKeys.map((key) => [key, process.env[key]]),
    );
    try {
      for (const key of releaseEnvironmentKeys) delete process.env[key];
      await expect(validateAdminBootstrapRepository()).rejects.toThrow(
        "admin bootstrap source requires root 0.3.0, found 0.4.0",
      );
    } finally {
      for (const [key, value] of releaseEnvironment) {
        if (value === undefined) delete process.env[key];
        else process.env[key] = value;
      }
    }
    await expect(
      validateAdminBootstrapRepository({ releaseTag: "v0.4.0" }),
    ).rejects.toThrow("refuses release or OIDC authority");

    const rootManifest = JSON.parse(
      readFileSync(join(process.cwd(), "package.json"), "utf8"),
    );
    expect(rootManifest.scripts["admin-bootstrap:pack"]).toContain(
      "admin-bootstrap-pack",
    );
    expect(rootManifest.scripts["admin-bootstrap:registry:check"]).toContain(
      "admin-bootstrap-registry-check",
    );
    expect(rootManifest.scripts["admin-bootstrap:publish"]).toBeUndefined();
  });

  it("documents the Admin bootstrap ceremony without a publish command", () => {
    const releaseGuide = readFileSync(
      join(process.cwd(), "docs", "RELEASING.md"),
      "utf8",
    );
    const adminBootstrap = releaseGuide
      .split("## Bootstrap for the new Admin package")[1]
      ?.split("## First advertised release and later releases")[0];
    expect(adminBootstrap).toBeDefined();
    expect(adminBootstrap).toContain("authorization-admin-v0.0.0");
    expect(adminBootstrap).toMatch(
      /git fetch origin\r?\ngit fetch origin tag authorization-admin-v0\.0\.0/u,
    );
    expect(adminBootstrap).toContain("npm run admin-bootstrap:check");
    expect(adminBootstrap).toContain(
      "npm publish .admin-bootstrap/pegma-authorization-admin-0.0.0.tgz",
    );
    expect(adminBootstrap).toContain("@pegma/authorization-storage@0.3.0");
    expect(adminBootstrap).toContain("0.4.0");
    expect(adminBootstrap).not.toMatch(/\badmin-bootstrap:publish\b/);
  });

  it("never accepts a bootstrap manifest as a synchronized release manifest", async () => {
    const root = mkdtempSync(
      join(tmpdir(), "authorization-bootstrap-manifest-"),
    );
    try {
      const manifestPath = join(root, "identity-bootstrap-manifest.json");
      writeFileSync(
        manifestPath,
        `${JSON.stringify({
          schemaVersion: 1,
          kind: "authorization-identity-package-bootstrap",
          sourceVersion: "0.1.0",
          version: "0.0.0",
          gitCommit: "0".repeat(40),
          package: {
            name: "@pegma/authorization-identity",
          },
        })}\n`,
      );
      await expect(verifyPreparedReleaseManifest(manifestPath)).rejects.toThrow(
        "invalid package inventory",
      );
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("requires a stable release tag that exactly matches the common version", async () => {
    await expect(validateRepository({ releaseTag: "v0.1.5" })).rejects.toThrow(
      "release tag must be v0.4.0",
    );
    await expect(
      validateRepository({
        releaseTag: "v0.4.0",
        releasePrerelease: true,
      }),
    ).rejects.toThrow("prereleases cannot publish packages");
  });
});

describe("release source authentication", () => {
  it("accepts only an approved signed annotated tag at the event commit", () => {
    const root = mkdtempSync(join(tmpdir(), "authorization-release-tag-"));
    try {
      run(git, ["init", "--quiet"], root);
      run(git, ["config", "user.name", "Release Test"], root);
      run(git, ["config", "user.email", "release@example.com"], root);
      writeFileSync(join(root, "README.md"), "release test\n");
      run(git, ["add", "README.md"], root);
      run(git, ["commit", "--quiet", "-m", "release"], root);
      const releaseCommit = run(git, ["rev-parse", "HEAD"], root);

      const signingKey = join(root, "release-signing-key");
      run("ssh-keygen", [
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-C",
        "release@example.com",
        "-f",
        signingKey,
      ]);
      const allowedSigners = join(root, "allowed-signers");
      writeFileSync(
        allowedSigners,
        `release@example.com ${readFileSync(`${signingKey}.pub`, "utf8").trim()}\n`,
      );
      run(git, ["config", "gpg.format", "ssh"], root);
      run(git, ["config", "user.signingkey", signingKey], root);
      run(git, ["config", "gpg.ssh.allowedSignersFile", allowedSigners], root);

      run(git, ["tag", "--sign", "v0.0.0", "--message", "signed"], root);
      expect(
        validateReleaseTag({
          root,
          releaseTag: "v0.0.0",
          expectedReleaseCommit: releaseCommit,
        }),
      ).toEqual({ headCommit: releaseCommit, releaseTag: "v0.0.0" });

      run(git, ["tag", "v0.0.1"], root);
      expect(() =>
        validateReleaseTag({
          root,
          releaseTag: "v0.0.1",
          expectedReleaseCommit: releaseCommit,
        }),
      ).toThrow("annotated tag object");

      run(
        git,
        [
          "-c",
          "commit.gpgsign=false",
          "tag",
          "--annotate",
          "v0.0.2",
          "--message",
          "unsigned",
        ],
        root,
      );
      expect(() =>
        validateReleaseTag({
          root,
          releaseTag: "v0.0.2",
          expectedReleaseCommit: releaseCommit,
        }),
      ).toThrow("not valid for an approved signer");

      expect(() =>
        validateReleaseTag({
          root,
          releaseTag: "v0.0.0",
          expectedReleaseCommit: "0".repeat(40),
        }),
      ).toThrow("release event commit must match");

      writeFileSync(join(root, "README.md"), "later commit\n");
      run(git, ["add", "README.md"], root);
      run(git, ["commit", "--quiet", "-m", "later"], root);
      expect(() =>
        validateReleaseTag({
          root,
          releaseTag: "v0.0.0",
          expectedReleaseCommit: run(git, ["rev-parse", "HEAD"], root),
        }),
      ).toThrow("release event commit must match");
    } finally {
      rmSync(root, { recursive: true, force: true });
    }
  });

  it("keeps broad preparation outside the OIDC-enabled publisher job", () => {
    const workflow = readFileSync(
      join(process.cwd(), ".github", "workflows", "publish.yml"),
      "utf8",
    );
    const jobsMarker = "\njobs:\n";
    const jobsIndex = workflow.indexOf(jobsMarker);
    expect(jobsIndex).toBeGreaterThanOrEqual(0);
    const header = workflow.slice(0, jobsIndex);
    const jobs = workflow.slice(jobsIndex + jobsMarker.length);
    expect(header).not.toContain("id-token: write");
    const prepareStart = jobs.indexOf("  prepare:");
    const publishStart = jobs.indexOf("\n  publish:");
    expect(prepareStart).toBeGreaterThanOrEqual(0);
    expect(publishStart).toBeGreaterThan(prepareStart);
    const prepare = jobs.slice(prepareStart, publishStart);
    const publish = jobs.slice(publishStart);
    expect(prepare).not.toContain("id-token: write");
    expect(publish).toContain("id-token: write");
    expect(publish).not.toContain("corepack");
    expect(publish).not.toContain("pnpm");
    expect(publish).not.toContain("release:pack");
    expect(publish).toContain("npm install --global npm@11.18.0");
    expect(publish).toContain("npm run release:publish");
    expect(workflow).not.toContain("identity-bootstrap");
    expect(workflow).not.toContain("github.run_attempt");
    expect(workflow).toContain("retention-days: 30");
  });
});

describe("partial publish recovery", () => {
  const integrity = "sha512-cHJlcGFyZWQtdGFyYmFsbA==";

  it("publishes an absent version", () => {
    expect(decidePublication(integrity, null)).toBe("publish");
  });

  it("skips a byte-identical existing version", () => {
    expect(decidePublication(integrity, integrity)).toBe("skip");
  });

  it("rejects an existing version with different bytes", () => {
    expect(() => decidePublication(integrity, "sha512-ZGlmZmVyZW50")).toThrow(
      "different tarball integrity",
    );
  });
});
