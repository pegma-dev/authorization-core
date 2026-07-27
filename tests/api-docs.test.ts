import { execFile } from "node:child_process";
import { access, readFile, unlink, writeFile } from "node:fs/promises";
import { promisify } from "node:util";

import { afterEach, describe, expect, it } from "vitest";

const run = promisify(execFile);
const repositoryRoot = process.cwd();
const generator = `${repositoryRoot}/scripts/api-docs.mjs`;
const stalePage = `${repositoryRoot}/docs/api/obsolete-generated-page.md`;
const nearMatchPage = `${repositoryRoot}/docs/api/hand-authored-api-notes.md`;
const ownershipMarker = "<!-- @pegma/authorization-core:generated-api-doc -->";

afterEach(async () => {
  await Promise.all([
    unlink(stalePage).catch(() => undefined),
    unlink(nearMatchPage).catch(() => undefined),
  ]);
});

describe("public API documentation generator", () => {
  it("removes only obsolete generated Markdown and restores a clean drift check", async () => {
    await writeFile(
      stalePage,
      [
        ownershipMarker,
        "",
        "# @pegma/obsolete-generated-page",
        "",
        "Generated from the public declaration entry point `packages/obsolete/dist/index.d.ts`. Internal modules are intentionally excluded.",
        "",
      ].join("\n"),
      "utf8",
    );
    const nearMatchContent = [
      "# @pegma/hand-authored-api-notes",
      "",
      "This hand-authored page quotes legacy generator prose:",
      "",
      "Generated from the public declaration entry point `packages/example/dist/index.d.ts`. Internal modules are intentionally excluded.",
      "",
    ].join("\n");
    await writeFile(nearMatchPage, nearMatchContent, "utf8");

    await expect(
      run(process.execPath, [generator, "--check"], {
        cwd: repositoryRoot,
      }),
    ).rejects.toMatchObject({
      stderr: expect.stringContaining("obsolete-generated-page.md"),
    });

    await run(process.execPath, [generator], { cwd: repositoryRoot });
    await expect(access(stalePage)).rejects.toMatchObject({ code: "ENOENT" });
    await expect(readFile(nearMatchPage, "utf8")).resolves.toBe(
      nearMatchContent,
    );

    await unlink(nearMatchPage);
    await expect(
      run(process.execPath, [generator, "--check"], {
        cwd: repositoryRoot,
      }),
    ).resolves.toMatchObject({
      stdout: expect.stringContaining("API documentation is current"),
    });
  });
});
