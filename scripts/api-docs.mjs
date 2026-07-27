import {
  lstat,
  mkdir,
  readFile,
  readdir,
  unlink,
  writeFile,
} from "node:fs/promises";
import { dirname, extname, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

import prettier from "prettier";

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const packagesDirectory = resolve(repositoryRoot, "packages");

async function discoverPublicEntries() {
  const entries = [];
  const packageDirectories = (
    await readdir(packagesDirectory, {
      withFileTypes: true,
    })
  )
    .filter((entry) => entry.isDirectory())
    .sort((left, right) => left.name.localeCompare(right.name));
  for (const packageDirectory of packageDirectories) {
    const manifestPath = resolve(
      packagesDirectory,
      packageDirectory.name,
      "package.json",
    );
    const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
    if (
      typeof manifest.name !== "string" ||
      !/^@pegma\/[a-z0-9][a-z0-9-]*$/.test(manifest.name) ||
      typeof manifest.exports !== "object" ||
      manifest.exports === null
    ) {
      throw new Error(
        `${relative(repositoryRoot, manifestPath)} must declare a package name and exports`,
      );
    }
    for (const [subpath, conditions] of Object.entries(manifest.exports)) {
      if (
        (subpath !== "." && !/^\.\/[a-z0-9][a-z0-9._/-]*$/.test(subpath)) ||
        typeof conditions !== "object" ||
        conditions === null ||
        typeof conditions.types !== "string"
      ) {
        throw new Error(
          `${manifest.name} export ${subpath} must declare a types target`,
        );
      }
      const absoluteTypes = resolve(
        packagesDirectory,
        packageDirectory.name,
        conditions.types,
      );
      const packageRoot = `${resolve(packagesDirectory, packageDirectory.name)}${sep}`;
      if (
        !absoluteTypes.startsWith(packageRoot) ||
        !absoluteTypes.endsWith(".d.ts")
      ) {
        throw new Error(
          `${manifest.name} export ${subpath} has an unsafe types target`,
        );
      }
      entries.push([
        subpath === "."
          ? manifest.name
          : `${manifest.name}/${subpath.replace(/^\.\//, "")}`,
        relative(repositoryRoot, absoluteTypes).replaceAll("\\", "/"),
      ]);
    }
  }
  return entries.sort(([left], [right]) => left.localeCompare(right));
}

const entries = await discoverPublicEntries();
const packageEntryFiles = new Map(
  entries
    .filter(([name]) => !name.endsWith("/testing"))
    .map(([name, file]) => [name, resolve(repositoryRoot, file)]),
);
const outputDirectory = resolve(repositoryRoot, "docs/api");
const checkOnly = process.argv.includes("--check");
const sourceCache = new Map();
const generatedPageOwnershipMarker =
  "<!-- @pegma/authorization-core:generated-api-doc -->";

function documentationFilename(packageName) {
  const filename = `${packageName
    .replace(/^@pegma\//, "")
    .replaceAll("/", "-")}.md`;
  if (!/^[a-z0-9][a-z0-9._-]*\.md$/.test(filename)) {
    throw new Error(
      `public API name cannot become a safe filename: ${packageName}`,
    );
  }
  return filename;
}

function outputTarget(filename) {
  const target = resolve(outputDirectory, filename);
  if (!target.startsWith(`${outputDirectory}${sep}`)) {
    throw new Error(`generated API output escaped docs/api: ${filename}`);
  }
  return target;
}

async function requireRegularFileOrMissing(target) {
  try {
    const metadata = await lstat(target);
    if (!metadata.isFile()) {
      throw new Error(
        `generated API path is not a regular file: ${relative(
          repositoryRoot,
          target,
        )}`,
      );
    }
  } catch (error) {
    if (error?.code === "ENOENT") return;
    throw error;
  }
}

async function unexpectedMarkdownFiles() {
  let actual = [];
  try {
    actual = await readdir(outputDirectory, { withFileTypes: true });
  } catch (error) {
    if (error?.code === "ENOENT") return [];
    throw error;
  }
  const unexpected = [];
  for (const entry of actual) {
    if (!entry.name.endsWith(".md") || files.has(entry.name)) continue;
    const target = outputTarget(entry.name);
    if (!entry.isFile()) {
      throw new Error(
        `unexpected API documentation path is not a regular file: ${relative(
          repositoryRoot,
          target,
        )}`,
      );
    }
    await requireRegularFileOrMissing(target);
    unexpected.push(target);
  }
  return unexpected;
}

function isGeneratedApiPage(content) {
  return content.startsWith(`${generatedPageOwnershipMarker}\n`);
}

async function source(file) {
  const existing = sourceCache.get(file);
  if (existing !== undefined) return existing;
  const loaded = await readFile(file, "utf8");
  sourceCache.set(file, loaded);
  return loaded;
}

function endOfDeclaration(text, start, kind) {
  if (kind === "interface" || kind === "class") {
    const open = text.indexOf("{", start);
    if (open < 0) throw new Error("declaration has no body");
    let depth = 0;
    for (let index = open; index < text.length; index += 1) {
      if (text[index] === "{") depth += 1;
      if (text[index] === "}") {
        depth -= 1;
        if (depth === 0) {
          return text[index + 1] === ";" ? index + 2 : index + 1;
        }
      }
    }
    throw new Error("declaration body is not balanced");
  }

  let braces = 0;
  let brackets = 0;
  let parentheses = 0;
  for (let index = start; index < text.length; index += 1) {
    if (text[index] === "{") braces += 1;
    if (text[index] === "}") braces -= 1;
    if (text[index] === "[") brackets += 1;
    if (text[index] === "]") brackets -= 1;
    if (text[index] === "(") parentheses += 1;
    if (text[index] === ")") parentheses -= 1;
    if (
      text[index] === ";" &&
      braces === 0 &&
      brackets === 0 &&
      parentheses === 0
    ) {
      return index + 1;
    }
  }
  throw new Error("declaration has no terminating semicolon");
}

function directDeclarations(text) {
  const declarations = new Map();
  const pattern =
    /export\s+(?:declare\s+)?(interface|type|class|function|const)\s+([A-Za-z_$][\w$]*)/g;
  for (const match of text.matchAll(pattern)) {
    const start = match.index;
    const kind = match[1];
    const name = match[2];
    const end = endOfDeclaration(text, start, kind);
    const prefix = text.slice(0, start);
    const nearestCommentStart = prefix.lastIndexOf("/**");
    const commentCandidate =
      nearestCommentStart < 0 ? "" : prefix.slice(nearestCommentStart);
    const commentMatch = commentCandidate.match(/^\/\*\*[\s\S]*?\*\/\s*$/);
    declarations.set(name, {
      kind,
      documentation: commentMatch?.[0].trim() ?? "",
      declaration: text.slice(start, end).trim(),
    });
  }
  return declarations;
}

function namedReexports(text) {
  const exports = [];
  const pattern = /export\s+(?:type\s+)?\{([\s\S]*?)\}\s+from\s+"([^"]+)";/g;
  for (const match of text.matchAll(pattern)) {
    for (const rawItem of match[1].split(",")) {
      const item = rawItem.trim().replace(/^type\s+/, "");
      if (item.length === 0) continue;
      const [importedName, publicName = importedName] = item
        .split(/\s+as\s+/)
        .map((part) => part.trim());
      exports.push({
        importedName,
        publicName,
        specifier: match[2],
      });
    }
  }
  return exports;
}

function resolveSpecifier(fromFile, specifier) {
  if (specifier.startsWith(".")) {
    const base = resolve(dirname(fromFile), specifier);
    return extname(base) === ".js"
      ? `${base.slice(0, -3)}.d.ts`
      : `${base}.d.ts`;
  }
  const packageEntry = packageEntryFiles.get(specifier);
  if (packageEntry === undefined) {
    throw new Error(`API declaration re-exports unknown package ${specifier}`);
  }
  return packageEntry;
}

async function findDeclaration(file, name, visited = new Set()) {
  const key = `${file}:${name}`;
  if (visited.has(key)) {
    throw new Error(`cyclic API re-export while resolving ${name}`);
  }
  visited.add(key);
  const text = await source(file);
  const direct = directDeclarations(text).get(name);
  if (direct !== undefined) return direct;
  const reexport = namedReexports(text).find(
    (candidate) => candidate.publicName === name,
  );
  if (reexport === undefined) {
    throw new Error(
      `public API declaration ${name} could not be resolved from ${relative(
        repositoryRoot,
        file,
      )}`,
    );
  }
  const found = await findDeclaration(
    resolveSpecifier(file, reexport.specifier),
    reexport.importedName,
    visited,
  );
  return {
    ...found,
    declaration: found.declaration.replace(
      new RegExp(`\\b${reexport.importedName}\\b`),
      reexport.publicName,
    ),
  };
}

function publicNames(text) {
  return [
    ...directDeclarations(text).keys(),
    ...namedReexports(text).map(({ publicName }) => publicName),
  ].sort((left, right) => left.localeCompare(right));
}

function renderDocumentation(comment) {
  if (comment.length === 0) return "";
  return comment
    .replace(/^\/\*\*\s?/, "")
    .replace(/\s?\*\/$/, "")
    .split("\n")
    .map((line) => line.replace(/^\s*\*\s?/, ""))
    .join("\n")
    .trim();
}

async function renderEntry(packageName, sourcePath) {
  const absoluteSource = resolve(repositoryRoot, sourcePath);
  const text = await source(absoluteSource);
  const sections = [];
  for (const name of publicNames(text)) {
    const api = await findDeclaration(absoluteSource, name);
    const documentation = renderDocumentation(api.documentation);
    sections.push(
      [
        `## ${name}`,
        "",
        `**Kind:** ${api.kind}`,
        documentation.length === 0 ? "" : `\n${documentation}`,
        "",
        "```ts",
        api.declaration,
        "```",
        "",
      ]
        .filter(
          (line, index, values) => !(line === "" && values[index - 1] === ""),
        )
        .join("\n"),
    );
  }
  return [
    generatedPageOwnershipMarker,
    "",
    `# ${packageName}`,
    "",
    `Generated from the public declaration entry point \`${sourcePath}\`. Internal modules are intentionally excluded.`,
    "",
    ...sections,
    "",
  ].join("\n");
}

const files = new Map();
files.set(
  "README.md",
  await prettier.format(
    [
      generatedPageOwnershipMarker,
      "",
      "# Public API reference",
      "",
      "This reference is generated deterministically from the repository's declared public package entry points. Run `npm run docs:api` to regenerate it and `npm run docs:api:check` to detect drift.",
      "",
      ...entries.map(([packageName]) => {
        const filename = documentationFilename(packageName);
        return `- [\`${packageName}\`](${filename})`;
      }),
      "",
    ].join("\n"),
    { parser: "markdown" },
  ),
);
for (const [packageName, sourcePath] of entries) {
  const filename = documentationFilename(packageName);
  files.set(
    filename,
    await prettier.format(await renderEntry(packageName, sourcePath), {
      parser: "markdown",
    }),
  );
}

const forbiddenInternalNames = [
  "assignmentPointers",
  "authorizationRecords",
  "createAccessGrantIssuerInternal",
  "createAccessGrantVerifierInternal",
  "createJtiReserver",
  "createReplayConsumer",
  "JtiReserver",
  "JwksCache",
  "productionIssuerDependencies",
  "productionVerifierDependencies",
  "ReplayConsumer",
];
const generatedReference = [...files.values()].join("\n");
for (const internalName of forbiddenInternalNames) {
  if (generatedReference.includes(internalName)) {
    throw new Error(
      `generated public API reference leaked internal name ${internalName}`,
    );
  }
}

const drift = [];
for (const [filename, content] of files) {
  const target = outputTarget(filename);
  await requireRegularFileOrMissing(target);
  if (checkOnly) {
    let existing;
    try {
      existing = await readFile(target, "utf8");
    } catch {
      existing = undefined;
    }
    if (existing !== content) drift.push(relative(repositoryRoot, target));
  } else {
    await mkdir(dirname(target), { recursive: true });
    await writeFile(target, content, "utf8");
  }
}

const unexpected = await unexpectedMarkdownFiles();
let removed = 0;
for (const target of unexpected) {
  if (checkOnly) {
    drift.push(relative(repositoryRoot, target));
    continue;
  }
  const content = await readFile(target, "utf8");
  if (isGeneratedApiPage(content)) {
    await unlink(target);
    removed += 1;
  }
}

if (checkOnly && drift.length > 0) {
  throw new Error(
    `Generated API documentation is out of date:\n${drift
      .map((file) => `- ${file}`)
      .join("\n")}\nRun npm run docs:api.`,
  );
}
console.log(
  checkOnly
    ? `API documentation is current (${files.size} files).`
    : `Generated ${files.size} API documentation files${
        removed === 0
          ? ""
          : ` and removed ${removed} obsolete generated page(s)`
      }.`,
);
