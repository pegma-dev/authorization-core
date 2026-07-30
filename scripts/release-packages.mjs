import { createHash, timingSafeEqual } from "node:crypto";
import {
  cp,
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, dirname, join, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const REPOSITORY_URL =
  "git+https://github.com/pegma-dev/authorization-core.git";
const PACKAGE_FILES = [
  "dist/**/*.d.ts",
  "dist/**/*.d.ts.map",
  "dist/**/*.js",
  "dist/**/*.js.map",
];
const NODE_RANGE = ">=22";
const STABLE_SEMVER = /^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)$/u;

export const RELEASE_PACKAGES = [
  {
    directory: "contracts",
    name: "@pegma/authorization-contracts",
    exports: ["."],
    modules: ["index"],
  },
  {
    directory: "auth0",
    name: "@pegma/authorization-auth0",
    exports: ["."],
    modules: ["index"],
  },
  {
    directory: "entra",
    name: "@pegma/authorization-entra",
    exports: ["."],
    modules: ["index"],
  },
  {
    directory: "identity-link",
    name: "@pegma/authorization-identity",
    exports: ["."],
    modules: ["index"],
  },
  {
    directory: "core",
    name: "@pegma/authorization-core",
    exports: [".", "./conformance"],
    modules: ["conformance", "index"],
  },
  {
    directory: "policy",
    name: "@pegma/authorization-policy",
    exports: ["."],
    modules: ["index"],
  },
  {
    directory: "stripe",
    name: "@pegma/authorization-stripe",
    exports: ["."],
    modules: ["index"],
  },
  {
    directory: "storage",
    name: "@pegma/authorization-storage",
    exports: ["."],
    modules: ["collections", "index", "role-store"],
  },
  {
    directory: "admin",
    name: "@pegma/authorization-admin",
    exports: ["."],
    modules: ["index"],
  },
  {
    directory: "tokens",
    name: "@pegma/authorization-tokens",
    exports: [".", "./testing"],
    modules: [
      "index",
      "internal",
      "issuer",
      "jti-reservation",
      "jwks",
      "replay",
      "testing",
      "verifier",
    ],
  },
];

export function releaseImportSpecifiers(definitions = RELEASE_PACKAGES) {
  return definitions.flatMap((definition) =>
    definition.exports.map((exportPath) =>
      exportPath === "."
        ? definition.name
        : `${definition.name}/${exportPath.slice(2)}`,
    ),
  );
}

function packageBootstrapDefinition(config) {
  return Object.freeze({
    ...config,
    definition: RELEASE_PACKAGES.find(({ name }) => name === config.name),
    expectedTarball: `${config.name.slice(1).replace("/", "-")}-${config.version}.tgz`,
  });
}

const IDENTITY_BOOTSTRAP = packageBootstrapDefinition({
  directory: "identity-link",
  name: "@pegma/authorization-identity",
  sourceVersion: "0.1.0",
  version: "0.0.0",
  kind: "authorization-identity-package-bootstrap",
  schemaVersion: 1,
  label: "identity",
  defaultOutput: ".identity-bootstrap",
  manifestFile: "identity-bootstrap-manifest.json",
  verifyPortableProjection(module) {
    const key = module.identityLinkKeyFromVerifiedIdentityClaims({
      issuer: "https://identity.example.test",
      subject: "portable-bootstrap-subject",
      emailVerified: true,
    });
    if (
      !Object.isFrozen(key) ||
      !sameJson(key, {
        issuer: "https://identity.example.test",
        subject: "portable-bootstrap-subject",
      })
    ) {
      fail("identity bootstrap portable ESM projection failed");
    }
  },
  consumerSmokeModule() {
    return [
      'const module = await import("@pegma/authorization-identity");',
      "const result = module.identityLinkKeyFromVerifiedIdentityClaims({",
      '  issuer: "https://identity.example.test",',
      '  subject: "installed-bootstrap-subject",',
      "  emailVerified: true,",
      "});",
      "if (!Object.isFrozen(result) || Object.keys(result).join() !== 'issuer,subject') process.exit(1);",
    ].join("\n");
  },
});

const ENTRA_BOOTSTRAP = packageBootstrapDefinition({
  directory: "entra",
  name: "@pegma/authorization-entra",
  sourceVersion: "0.1.3",
  version: "0.0.0",
  kind: "authorization-entra-package-bootstrap",
  schemaVersion: 1,
  label: "entra",
  defaultOutput: ".entra-bootstrap",
  manifestFile: "entra-bootstrap-manifest.json",
  verifyPortableProjection(module) {
    const key = module.identityLinkKeyFromVerifiedEntraClaims({
      iss: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
      oid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
    });
    if (
      !Object.isFrozen(key) ||
      !sameJson(key, {
        issuer:
          "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",
        subject: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
      })
    ) {
      fail("entra bootstrap portable ESM projection failed");
    }
  },
  consumerSmokeModule() {
    return [
      'const module = await import("@pegma/authorization-entra");',
      "const result = module.identityLinkKeyFromVerifiedEntraClaims({",
      '  iss: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0",',
      '  oid: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",',
      "});",
      "if (!Object.isFrozen(result) || Object.keys(result).join() !== 'issuer,subject') process.exit(1);",
    ].join("\n");
  },
});

export const IDENTITY_BOOTSTRAP_PACKAGE = Object.freeze({
  directory: IDENTITY_BOOTSTRAP.directory,
  name: IDENTITY_BOOTSTRAP.name,
  sourceVersion: IDENTITY_BOOTSTRAP.sourceVersion,
  version: IDENTITY_BOOTSTRAP.version,
});

export const ENTRA_BOOTSTRAP_PACKAGE = Object.freeze({
  directory: ENTRA_BOOTSTRAP.directory,
  name: ENTRA_BOOTSTRAP.name,
  sourceVersion: ENTRA_BOOTSTRAP.sourceVersion,
  version: ENTRA_BOOTSTRAP.version,
});

const INTERNAL_NAMES = new Set(RELEASE_PACKAGES.map(({ name }) => name));
const DEPENDENCY_SECTIONS = [
  "dependencies",
  "devDependencies",
  "optionalDependencies",
  "peerDependencies",
];

function fail(message) {
  throw new Error(message);
}

async function readJson(path) {
  return JSON.parse(await readFile(path, "utf8"));
}

function sameJson(left, right) {
  return JSON.stringify(left) === JSON.stringify(right);
}

function run(command, arguments_, options = {}) {
  const result = spawnSync(command, arguments_, {
    cwd: options.cwd,
    encoding: "utf8",
    env: options.env ?? process.env,
    shell: false,
    stdio: options.capture ? "pipe" : "inherit",
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0 && !options.allowFailure) {
    const detail = [result.stdout, result.stderr].filter(Boolean).join("\n");
    fail(
      `${command} ${arguments_.join(" ")} failed with exit code ${String(result.status)}${detail ? `:\n${detail}` : ""}`,
    );
  }
  return result;
}

function runNpm(arguments_, options = {}) {
  const npmExecPath = process.env.npm_execpath;
  if (npmExecPath !== undefined) {
    return run(process.execPath, [npmExecPath, ...arguments_], options);
  }
  return run("npm", arguments_, options);
}

function requireTrustedPublishingNpm() {
  const version = runNpm(["--version"], { capture: true }).stdout.trim();
  const match = /^(\d+)\.(\d+)\.(\d+)(?:-.+)?$/u.exec(version);
  if (match === null) {
    fail(`could not parse npm version ${version}`);
  }
  const [, majorText, minorText, patchText] = match;
  const [major, minor, patch] = [majorText, minorText, patchText].map(Number);
  if (
    major < 11 ||
    (major === 11 && minor < 5) ||
    (major === 11 && minor === 5 && patch < 1)
  ) {
    fail("trusted publishing requires npm 11.5.1 or newer");
  }
}

function gitCommand() {
  return process.platform === "win32" ? "git.exe" : "git";
}

export function validateReleaseTag(options = {}) {
  const root = resolve(options.root ?? defaultRoot());
  const releaseTag = options.releaseTag ?? process.env.RELEASE_TAG;
  const expectedReleaseCommit =
    options.expectedReleaseCommit ?? process.env.RELEASE_COMMIT;
  if (releaseTag === undefined || !/^v\d+\.\d+\.\d+$/u.test(releaseTag)) {
    fail("a stable release tag is required");
  }
  if (
    expectedReleaseCommit === undefined ||
    !/^[0-9a-f]{40,64}$/u.test(expectedReleaseCommit)
  ) {
    fail("an exact release event commit is required");
  }

  const tagRef = `refs/tags/${releaseTag}`;
  const objectType = run(gitCommand(), ["cat-file", "-t", tagRef], {
    cwd: root,
    capture: true,
    allowFailure: true,
  });
  if (objectType.status !== 0 || objectType.stdout.trim() !== "tag") {
    fail("the release ref must be an annotated tag object");
  }

  const headCommit = run(gitCommand(), ["rev-parse", "HEAD"], {
    cwd: root,
    capture: true,
  }).stdout.trim();
  const tagCommit = run(gitCommand(), ["rev-parse", `${tagRef}^{commit}`], {
    cwd: root,
    capture: true,
  }).stdout.trim();
  if (
    !safeEqual(headCommit, tagCommit) ||
    !safeEqual(headCommit, expectedReleaseCommit)
  ) {
    fail(
      "the release checkout, signed tag target, and release event commit must match",
    );
  }

  const signature = run(gitCommand(), ["verify-tag", "--raw", tagRef], {
    cwd: root,
    capture: true,
    allowFailure: true,
  });
  if (signature.status !== 0) {
    fail("the release tag signature is not valid for an approved signer");
  }
  return { headCommit, releaseTag };
}

function expectedExports(exportNames) {
  return Object.fromEntries(
    exportNames.map((exportName) => {
      const stem = exportName === "." ? "index" : exportName.slice(2);
      return [
        exportName,
        {
          types: `./dist/${stem}.d.ts`,
          import: `./dist/${stem}.js`,
        },
      ];
    }),
  );
}

function validateInternalDependencies(manifest, version, location) {
  for (const section of DEPENDENCY_SECTIONS) {
    const dependencies = manifest[section] ?? {};
    for (const [name, range] of Object.entries(dependencies)) {
      if (INTERNAL_NAMES.has(name) && range !== version) {
        fail(
          `${location} ${section}.${name} must be the common exact version ${version}, found ${String(range)}`,
        );
      }
    }
  }
}

function validateManifest(
  manifest,
  definition,
  version,
  internalDependencyVersion = version,
) {
  const location = `packages/${definition.directory}/package.json`;
  if (manifest.name !== definition.name) {
    fail(`${location} must be named ${definition.name}`);
  }
  if (manifest.version !== version) {
    fail(`${location} must use common version ${version}`);
  }
  if (manifest.private === true) {
    fail(`${location} must be public`);
  }
  if (manifest.license !== "MIT" || manifest.type !== "module") {
    fail(`${location} must be an MIT-licensed ESM package`);
  }
  if (manifest.publishConfig?.access !== "public") {
    fail(`${location} must set publishConfig.access to public`);
  }
  if (manifest.engines?.node !== NODE_RANGE) {
    fail(`${location} must set engines.node to ${NODE_RANGE}`);
  }
  if (!sameJson(manifest.files, PACKAGE_FILES)) {
    fail(`${location} has an unexpected files allowlist`);
  }
  if (!sameJson(manifest.exports, expectedExports(definition.exports))) {
    fail(`${location} has an unexpected exports map`);
  }
  if (
    manifest.repository?.type !== "git" ||
    manifest.repository?.url !== REPOSITORY_URL ||
    manifest.repository?.directory !== `packages/${definition.directory}`
  ) {
    fail(`${location} has unexpected repository metadata`);
  }
  validateInternalDependencies(manifest, internalDependencyVersion, location);
}

async function requirePackageReleaseFiles(root, definition) {
  for (const filename of ["README.md", "LICENSE"]) {
    const path = join(root, "packages", definition.directory, filename);
    const file = await stat(path).catch(() => null);
    if (!file?.isFile()) {
      fail(`packages/${definition.directory}/${filename} is required`);
    }
  }
}

function validateLockEntry(entry, manifest, version, location) {
  if (entry?.name !== manifest.name || entry?.version !== version) {
    fail(`${location} does not match ${manifest.name}@${version}`);
  }
  for (const section of DEPENDENCY_SECTIONS) {
    if (!sameJson(entry[section] ?? {}, manifest[section] ?? {})) {
      fail(`${location} ${section} does not match its package manifest`);
    }
  }
  validateInternalDependencies(entry, version, location);
}

export async function validateRepository(options = {}) {
  const root = resolve(options.root ?? defaultRoot());
  const rootManifest = await readJson(join(root, "package.json"));
  const version = rootManifest.version;
  if (!STABLE_SEMVER.test(version)) {
    fail(
      `root version must be a stable semantic version, found ${String(version)}`,
    );
  }
  if (
    rootManifest.name !== "authorization-core" ||
    rootManifest.private !== true ||
    !sameJson(rootManifest.workspaces, ["packages/*"])
  ) {
    fail("root package must be the private authorization-core workspace");
  }
  if (rootManifest.packageManager !== "npm@11.18.0") {
    fail("root packageManager must pin npm@11.18.0");
  }

  const directories = (
    await readdir(join(root, "packages"), {
      withFileTypes: true,
    })
  )
    .filter((entry) => entry.isDirectory())
    .map((entry) => entry.name)
    .sort();
  const expectedDirectories = RELEASE_PACKAGES.map(
    ({ directory }) => directory,
  ).sort();
  if (!sameJson(directories, expectedDirectories)) {
    fail(
      `public workspace inventory must be exactly ${expectedDirectories.join(", ")}`,
    );
  }

  const lock = await readJson(join(root, "package-lock.json"));
  if (
    lock.lockfileVersion !== 3 ||
    lock.packages?.[""]?.version !== version ||
    lock.packages?.[""]?.name !== rootManifest.name
  ) {
    fail("package-lock root metadata does not match package.json");
  }

  for (const definition of RELEASE_PACKAGES) {
    const manifest = await readJson(
      join(root, "packages", definition.directory, "package.json"),
    );
    validateManifest(manifest, definition, version);
    validateLockEntry(
      lock.packages?.[`packages/${definition.directory}`],
      manifest,
      version,
      `package-lock.json packages/${definition.directory}`,
    );
    await requirePackageReleaseFiles(root, definition);
  }

  const releaseTag = options.releaseTag ?? process.env.RELEASE_TAG;
  if (releaseTag !== undefined && releaseTag !== `v${version}`) {
    fail(`release tag must be v${version}, found ${releaseTag}`);
  }
  const releasePrerelease =
    options.releasePrerelease ?? process.env.RELEASE_PRERELEASE;
  if (releasePrerelease === true || releasePrerelease === "true") {
    fail("prereleases cannot publish packages");
  }
  if (options.requireReleaseTag) {
    validateReleaseTag({
      root,
      releaseTag,
      expectedReleaseCommit: options.expectedReleaseCommit,
    });
  }
  if (options.requireMainAncestor) {
    const result = run(
      gitCommand(),
      ["merge-base", "--is-ancestor", "HEAD", "origin/main"],
      { cwd: root, capture: true, allowFailure: true },
    );
    if (result.status !== 0) {
      fail("the release tag commit must be contained in origin/main");
    }
  }
  if (options.requireClean) {
    const result = run(gitCommand(), ["status", "--porcelain"], {
      cwd: root,
      capture: true,
    });
    if (result.stdout.trim() !== "") {
      fail("release preparation requires a clean checkout");
    }
  }
  return { root, version, releaseTag };
}

function requireManualPackageBootstrap(bootstrap, options = {}) {
  if (
    options.releaseTag !== undefined ||
    options.requireReleaseTag === true ||
    process.env.RELEASE_TAG !== undefined ||
    process.env.GITHUB_EVENT_NAME === "release" ||
    process.env.ACTIONS_ID_TOKEN_REQUEST_URL !== undefined ||
    process.env.ACTIONS_ID_TOKEN_REQUEST_TOKEN !== undefined
  ) {
    fail(
      `the ${bootstrap.label} bootstrap is manual package-name reservation only and refuses release or OIDC authority`,
    );
  }
}

function validatePackageBootstrapDependencies(bootstrap, manifest, location) {
  const expected = {
    "@pegma/authorization-contracts": bootstrap.sourceVersion,
  };
  if (!sameJson(manifest.dependencies, expected)) {
    fail(
      `${location} must depend only on exact @pegma/authorization-contracts@${bootstrap.sourceVersion}`,
    );
  }
  for (const section of [
    "devDependencies",
    "optionalDependencies",
    "peerDependencies",
  ]) {
    if (!sameJson(manifest[section] ?? {}, {})) {
      fail(`${location} must not declare ${section}`);
    }
  }
  if (manifest.scripts?.prepack !== "npm run build") {
    fail(`${location} must build through its prepack script`);
  }
}

async function validatePackageBootstrapRepository(bootstrap, options = {}) {
  requireManualPackageBootstrap(bootstrap, options);
  const validated = await validateRepository(options);
  if (validated.version !== bootstrap.sourceVersion) {
    fail(
      `${bootstrap.label} bootstrap source requires root ${bootstrap.sourceVersion}, found ${validated.version}`,
    );
  }
  if (bootstrap.definition === undefined) {
    fail(
      `${bootstrap.label} bootstrap package is missing from the release inventory`,
    );
  }
  const location = `packages/${bootstrap.directory}/package.json`;
  const manifest = await readJson(join(validated.root, location));
  validatePackageBootstrapDependencies(bootstrap, manifest, location);
  return {
    root: validated.root,
    sourceVersion: validated.version,
    version: bootstrap.version,
  };
}

export async function validateIdentityBootstrapRepository(options = {}) {
  return validatePackageBootstrapRepository(IDENTITY_BOOTSTRAP, options);
}

export async function validateEntraBootstrapRepository(options = {}) {
  return validatePackageBootstrapRepository(ENTRA_BOOTSTRAP, options);
}

function hashTarball(bytes) {
  return {
    integrity: `sha512-${createHash("sha512").update(bytes).digest("base64")}`,
    shasum: createHash("sha1").update(bytes).digest("hex"),
  };
}

function safeEqual(left, right) {
  const leftBytes = Buffer.from(left);
  const rightBytes = Buffer.from(right);
  return (
    leftBytes.length === rightBytes.length &&
    timingSafeEqual(leftBytes, rightBytes)
  );
}

function verifyPackageFiles(definition, files) {
  const paths = files.map(({ path }) => path).sort();
  const expectedPaths = [
    "LICENSE",
    "README.md",
    "package.json",
    ...definition.modules.flatMap((moduleName) => [
      `dist/${moduleName}.d.ts`,
      `dist/${moduleName}.d.ts.map`,
      `dist/${moduleName}.js`,
      `dist/${moduleName}.js.map`,
    ]),
  ].sort();
  if (!sameJson(paths, expectedPaths)) {
    fail(`${definition.name} tarball has an unexpected file inventory`);
  }
  for (const exportName of definition.exports) {
    const stem = exportName === "." ? "index" : exportName.slice(2);
    for (const path of [`dist/${stem}.d.ts`, `dist/${stem}.js`]) {
      if (!paths.includes(path)) {
        fail(`${definition.name} tarball is missing exported file ${path}`);
      }
    }
  }
}

async function verifySourceMaps(tarballRoot, files, packageName) {
  const sourceMaps = files
    .map(({ path }) => path)
    .filter((path) => path.endsWith(".js.map"));
  if (sourceMaps.length === 0) {
    fail(`${packageName} tarball has no source maps`);
  }
  for (const path of sourceMaps) {
    const map = await readJson(join(tarballRoot, path));
    if (!Array.isArray(map.sourcesContent) || map.sourcesContent.length === 0) {
      fail(`${packageName} source map ${path} does not contain inline sources`);
    }
  }
}

async function inspectPackedTarball(tarball, packageRecord) {
  const extractionRoot = await mkdtemp(join(tmpdir(), "authorization-pack-"));
  try {
    run("tar", ["-xzf", tarball, "-C", extractionRoot], { capture: true });
    await verifySourceMaps(
      join(extractionRoot, "package"),
      packageRecord.files,
      packageRecord.name,
    );
  } finally {
    await rm(extractionRoot, { recursive: true, force: true });
  }
}

async function smokeTestTarballs(root, tarballs) {
  const consumerRoot = await mkdtemp(
    join(tmpdir(), "authorization-release-smoke-"),
  );
  try {
    await writeFile(
      join(consumerRoot, "package.json"),
      `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    );
    runNpm(
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", ...tarballs],
      { cwd: consumerRoot },
    );
    const imports = releaseImportSpecifiers();
    const smoke = `await Promise.all(${JSON.stringify(imports)}.map((name) => import(name)));`;
    run(process.execPath, ["--input-type=module", "--eval", smoke], {
      cwd: consumerRoot,
    });
  } finally {
    await rm(consumerRoot, { recursive: true, force: true });
  }
}

async function recordPackedPackage(output, definition, version, packed) {
  if (
    packed?.name !== definition.name ||
    packed?.version !== version ||
    typeof packed.filename !== "string" ||
    !Array.isArray(packed.files)
  ) {
    fail(`npm pack returned invalid metadata for ${definition.name}`);
  }
  verifyPackageFiles(definition, packed.files);
  const tarball = join(output, basename(packed.filename));
  const bytes = await readFile(tarball);
  const hashes = hashTarball(bytes);
  if (
    !safeEqual(hashes.integrity, packed.integrity) ||
    !safeEqual(hashes.shasum, packed.shasum)
  ) {
    fail(`${definition.name} tarball hashes do not match npm pack metadata`);
  }
  const record = {
    name: definition.name,
    version,
    directory: definition.directory,
    tarball: basename(tarball),
    integrity: hashes.integrity,
    shasum: hashes.shasum,
    files: packed.files
      .map(({ path, size }) => ({ path, size }))
      .sort((left, right) => left.path.localeCompare(right.path)),
  };
  await inspectPackedTarball(tarball, record);
  return record;
}

export async function prepareRelease(options = {}) {
  const { root, version, releaseTag } = await validateRepository(options);
  const gitCommit = run(gitCommand(), ["rev-parse", "HEAD"], {
    cwd: root,
    capture: true,
  }).stdout.trim();
  if (!/^[0-9a-f]{40}$/u.test(gitCommit)) {
    fail(`git returned an invalid commit SHA: ${gitCommit}`);
  }
  const output = resolve(root, options.output ?? ".release");
  await mkdir(output, { recursive: true });
  if ((await readdir(output)).length !== 0) {
    fail(`release output directory must be empty: ${output}`);
  }

  runNpm(["run", "build"], { cwd: root });
  const packages = [];
  for (const definition of RELEASE_PACKAGES) {
    const result = runNpm(
      [
        "pack",
        join(root, "packages", definition.directory),
        "--json",
        "--pack-destination",
        output,
      ],
      { cwd: root, capture: true },
    );
    const [packed] = JSON.parse(result.stdout);
    const record = await recordPackedPackage(
      output,
      definition,
      version,
      packed,
    );
    packages.push(record);
  }

  await smokeTestTarballs(
    root,
    packages.map(({ tarball }) => join(output, tarball)),
  );
  const manifest = {
    schemaVersion: 2,
    version,
    gitCommit,
    releaseTag: releaseTag ?? null,
    packages,
  };
  const manifestPath = join(output, "package-manifest.json");
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifestPath, manifest };
}

async function stagePackageBootstrap(bootstrap, root, sourceManifest) {
  const stageRoot = await mkdtemp(
    join(tmpdir(), `authorization-${bootstrap.label}-bootstrap-stage-`),
  );
  const packageRoot = join(stageRoot, "package");
  await mkdir(packageRoot);
  for (const filename of ["README.md", "LICENSE"]) {
    await cp(
      join(root, "packages", bootstrap.directory, filename),
      join(packageRoot, filename),
    );
  }
  await cp(
    join(root, "packages", bootstrap.directory, "dist"),
    join(packageRoot, "dist"),
    { recursive: true },
  );
  const bootstrapManifest = {
    ...sourceManifest,
    version: bootstrap.version,
  };
  validateManifest(
    bootstrapManifest,
    bootstrap.definition,
    bootstrap.version,
    bootstrap.sourceVersion,
  );
  validatePackageBootstrapDependencies(
    bootstrap,
    bootstrapManifest,
    `staged ${bootstrap.label} bootstrap package.json`,
  );
  await writeFile(
    join(packageRoot, "package.json"),
    `${JSON.stringify(bootstrapManifest, null, 2)}\n`,
  );
  return { stageRoot, packageRoot };
}

async function inspectPackageBootstrapTarball(
  bootstrap,
  tarball,
  packageRecord,
) {
  const extractionRoot = await mkdtemp(
    join(tmpdir(), `authorization-${bootstrap.label}-bootstrap-inspect-`),
  );
  try {
    run("tar", ["-xzf", tarball, "-C", extractionRoot], { capture: true });
    const packageRoot = join(extractionRoot, "package");
    const manifest = await readJson(join(packageRoot, "package.json"));
    validateManifest(
      manifest,
      bootstrap.definition,
      bootstrap.version,
      bootstrap.sourceVersion,
    );
    validatePackageBootstrapDependencies(
      bootstrap,
      manifest,
      `packed ${bootstrap.label} bootstrap package.json`,
    );

    const source = await readFile(
      join(packageRoot, "dist", "index.js"),
      "utf8",
    );
    if (
      source.includes("node:") ||
      /\bfrom\s+["']/u.test(source) ||
      source.includes("require(")
    ) {
      fail(
        `${bootstrap.label} bootstrap runtime is not dependency-free portable ESM`,
      );
    }
    const module = await import(
      `data:text/javascript;base64,${Buffer.from(source).toString("base64")}`
    );
    bootstrap.verifyPortableProjection(module);
    verifyPackageFiles(bootstrap.definition, packageRecord.files);
  } finally {
    await rm(extractionRoot, { recursive: true, force: true });
  }
}

async function smokeTestPackageBootstrapTarball(bootstrap, tarball) {
  const consumerRoot = await mkdtemp(
    join(tmpdir(), `authorization-${bootstrap.label}-bootstrap-consumer-`),
  );
  try {
    await writeFile(
      join(consumerRoot, "package.json"),
      `${JSON.stringify({ private: true, type: "module" }, null, 2)}\n`,
    );
    runNpm(
      ["install", "--ignore-scripts", "--no-audit", "--no-fund", tarball],
      { cwd: consumerRoot },
    );
    run(
      process.execPath,
      ["--input-type=module", "--eval", bootstrap.consumerSmokeModule()],
      {
        cwd: consumerRoot,
      },
    );
    runNpm(["audit", "--omit=dev", "--audit-level=high"], {
      cwd: consumerRoot,
    });
  } finally {
    await rm(consumerRoot, { recursive: true, force: true });
  }
}

async function preparePackageBootstrap(bootstrap, options = {}) {
  const { root, sourceVersion, version } =
    await validatePackageBootstrapRepository(bootstrap, options);
  const gitCommit = run(gitCommand(), ["rev-parse", "HEAD"], {
    cwd: root,
    capture: true,
  }).stdout.trim();
  if (!/^[0-9a-f]{40}$/u.test(gitCommit)) {
    fail(`git returned an invalid commit SHA: ${gitCommit}`);
  }
  const output = resolve(root, options.output ?? bootstrap.defaultOutput);
  await mkdir(output, { recursive: true });
  if ((await readdir(output)).length !== 0) {
    fail(
      `${bootstrap.label} bootstrap output directory must be empty: ${output}`,
    );
  }

  runNpm(["run", "build", "--workspace", "@pegma/authorization-contracts"], {
    cwd: root,
  });
  runNpm(["run", "prepack", "--workspace", bootstrap.name], {
    cwd: root,
  });

  const sourceManifest = await readJson(
    join(root, "packages", bootstrap.directory, "package.json"),
  );
  const { stageRoot, packageRoot } = await stagePackageBootstrap(
    bootstrap,
    root,
    sourceManifest,
  );
  let packageRecord;
  try {
    const result = runNpm(
      [
        "pack",
        packageRoot,
        "--ignore-scripts",
        "--json",
        "--pack-destination",
        output,
      ],
      { cwd: root, capture: true },
    );
    const [packed] = JSON.parse(result.stdout);
    packageRecord = await recordPackedPackage(
      output,
      bootstrap.definition,
      version,
      packed,
    );
  } finally {
    await rm(stageRoot, { recursive: true, force: true });
  }

  const tarball = join(output, packageRecord.tarball);
  await inspectPackageBootstrapTarball(bootstrap, tarball, packageRecord);
  await smokeTestPackageBootstrapTarball(bootstrap, tarball);
  const registryIntegrity = queryRegistryIntegrity(packageRecord.name, version);
  const registryState =
    decidePublication(packageRecord.integrity, registryIntegrity) === "skip"
      ? "exact"
      : "absent";
  process.stdout.write(
    `${packageRecord.name}@${version}: ${registryState} before bootstrap\n`,
  );

  const manifest = {
    schemaVersion: bootstrap.schemaVersion,
    kind: bootstrap.kind,
    sourceVersion,
    version,
    gitCommit,
    package: packageRecord,
  };
  const manifestPath = join(output, bootstrap.manifestFile);
  await writeFile(manifestPath, `${JSON.stringify(manifest, null, 2)}\n`);
  return { manifestPath, manifest };
}

export async function prepareIdentityBootstrap(options = {}) {
  return preparePackageBootstrap(IDENTITY_BOOTSTRAP, options);
}

export async function prepareEntraBootstrap(options = {}) {
  return preparePackageBootstrap(ENTRA_BOOTSTRAP, options);
}

export function decidePublication(localIntegrity, registryIntegrity) {
  if (registryIntegrity === null) {
    return "publish";
  }
  if (safeEqual(localIntegrity, registryIntegrity)) {
    return "skip";
  }
  fail("the registry version exists with different tarball integrity");
}

function queryRegistryIntegrity(name, version) {
  const spec = `${name}@${version}`;
  const result = runNpm(["view", spec, "dist.integrity", "--json"], {
    capture: true,
    allowFailure: true,
  });
  if (result.status === 0) {
    const integrity = JSON.parse(result.stdout);
    if (typeof integrity !== "string" || integrity.length === 0) {
      fail(`${spec} exists without dist.integrity`);
    }
    return integrity;
  }
  const output = `${result.stdout}\n${result.stderr}`;
  if (/\bE404\b/u.test(output)) {
    return null;
  }
  fail(`npm registry lookup failed for ${spec}:\n${output.trim()}`);
}

export async function verifyPreparedReleaseManifest(manifestPath) {
  const manifest = await readJson(manifestPath);
  if (
    manifest.schemaVersion !== 2 ||
    !STABLE_SEMVER.test(manifest.version) ||
    !/^[0-9a-f]{40}$/u.test(manifest.gitCommit) ||
    !(
      manifest.releaseTag === null ||
      manifest.releaseTag === `v${manifest.version}`
    ) ||
    !Array.isArray(manifest.packages) ||
    !sameJson(
      manifest.packages.map(({ name }) => name),
      RELEASE_PACKAGES.map(({ name }) => name),
    )
  ) {
    fail("prepared package manifest has an invalid package inventory");
  }
  const currentCommit = run(gitCommand(), ["rev-parse", "HEAD"], {
    cwd: defaultRoot(),
    capture: true,
  }).stdout.trim();
  if (!safeEqual(currentCommit, manifest.gitCommit)) {
    fail("prepared package manifest commit does not match the checkout");
  }
  for (const [index, packageRecord] of manifest.packages.entries()) {
    const definition = RELEASE_PACKAGES[index];
    if (packageRecord.version !== manifest.version) {
      fail(`${packageRecord.name} does not match prepared common version`);
    }
    const expectedTarball = `${definition.name
      .slice(1)
      .replace("/", "-")}-${manifest.version}.tgz`;
    if (
      packageRecord.directory !== definition.directory ||
      packageRecord.tarball !== expectedTarball ||
      typeof packageRecord.integrity !== "string" ||
      typeof packageRecord.shasum !== "string" ||
      !Array.isArray(packageRecord.files)
    ) {
      fail(`${packageRecord.name} has invalid prepared metadata`);
    }
    verifyPackageFiles(definition, packageRecord.files);
    const tarball = resolve(dirname(manifestPath), packageRecord.tarball);
    if (dirname(tarball) !== resolve(dirname(manifestPath))) {
      fail(`${packageRecord.name} tarball must be beside the package manifest`);
    }
    const hashes = hashTarball(await readFile(tarball));
    if (
      !safeEqual(hashes.integrity, packageRecord.integrity) ||
      !safeEqual(hashes.shasum, packageRecord.shasum)
    ) {
      fail(`${packageRecord.name} prepared tarball has changed`);
    }
  }
  return manifest;
}

async function verifyPackageBootstrapManifest(bootstrap, manifestPath) {
  const manifest = await readJson(manifestPath);
  if (
    manifest.schemaVersion !== bootstrap.schemaVersion ||
    manifest.kind !== bootstrap.kind ||
    manifest.sourceVersion !== bootstrap.sourceVersion ||
    manifest.version !== bootstrap.version ||
    !/^[0-9a-f]{40}$/u.test(manifest.gitCommit) ||
    typeof manifest.package !== "object" ||
    manifest.package === null ||
    manifest.package.name !== bootstrap.name ||
    manifest.package.version !== bootstrap.version ||
    manifest.package.directory !== bootstrap.directory
  ) {
    fail(`prepared ${bootstrap.label} bootstrap manifest is invalid`);
  }
  if (bootstrap.definition === undefined) {
    fail(
      `${bootstrap.label} bootstrap package is missing from the release inventory`,
    );
  }
  const packageRecord = manifest.package;
  if (
    packageRecord.tarball !== bootstrap.expectedTarball ||
    typeof packageRecord.integrity !== "string" ||
    typeof packageRecord.shasum !== "string" ||
    !Array.isArray(packageRecord.files)
  ) {
    fail(`prepared ${bootstrap.label} bootstrap package metadata is invalid`);
  }
  verifyPackageFiles(bootstrap.definition, packageRecord.files);
  const currentCommit = run(gitCommand(), ["rev-parse", "HEAD"], {
    cwd: defaultRoot(),
    capture: true,
  }).stdout.trim();
  if (!safeEqual(currentCommit, manifest.gitCommit)) {
    fail(
      `prepared ${bootstrap.label} bootstrap commit does not match the checkout`,
    );
  }
  const tarball = resolve(dirname(manifestPath), packageRecord.tarball);
  if (dirname(tarball) !== resolve(dirname(manifestPath))) {
    fail(`${bootstrap.label} bootstrap tarball must be beside its manifest`);
  }
  const hashes = hashTarball(await readFile(tarball));
  if (
    !safeEqual(hashes.integrity, packageRecord.integrity) ||
    !safeEqual(hashes.shasum, packageRecord.shasum)
  ) {
    fail(`prepared ${bootstrap.label} bootstrap tarball has changed`);
  }
  await inspectPackageBootstrapTarball(bootstrap, tarball, packageRecord);
  return manifest;
}

export async function verifyIdentityBootstrapManifest(manifestPath) {
  return verifyPackageBootstrapManifest(IDENTITY_BOOTSTRAP, manifestPath);
}

export async function verifyEntraBootstrapManifest(manifestPath) {
  return verifyPackageBootstrapManifest(ENTRA_BOOTSTRAP, manifestPath);
}

function wait(milliseconds) {
  Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, milliseconds);
}

function confirmRegistryIntegrity(packageRecord) {
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const registryIntegrity = queryRegistryIntegrity(
      packageRecord.name,
      packageRecord.version,
    );
    if (
      registryIntegrity !== null &&
      safeEqual(packageRecord.integrity, registryIntegrity)
    ) {
      return;
    }
    if (attempt < 5) {
      wait(2 ** attempt * 1000);
    }
  }
  fail(
    `${packageRecord.name}@${packageRecord.version} did not become visible with the prepared integrity`,
  );
}

export async function publishPreparedRelease(options = {}) {
  if (
    process.env.GITHUB_ACTIONS !== "true" ||
    process.env.GITHUB_EVENT_NAME !== "release"
  ) {
    fail("release:publish is restricted to a GitHub release workflow");
  }
  requireTrustedPublishingNpm();
  const manifestPath = resolve(
    options.manifest ?? ".release/package-manifest.json",
  );
  const manifest = await verifyPreparedReleaseManifest(manifestPath);
  const releaseTag = options.releaseTag ?? process.env.RELEASE_TAG;
  const expectedReleaseCommit =
    options.expectedReleaseCommit ?? process.env.RELEASE_COMMIT;
  if (
    releaseTag !== `v${manifest.version}` ||
    manifest.releaseTag !== releaseTag
  ) {
    fail(
      `prepared version and manifest must match release tag v${manifest.version}`,
    );
  }
  if (
    expectedReleaseCommit === undefined ||
    !/^[0-9a-f]{40,64}$/u.test(expectedReleaseCommit) ||
    !safeEqual(manifest.gitCommit, expectedReleaseCommit)
  ) {
    fail("prepared package manifest must match the release event commit");
  }
  for (const packageRecord of manifest.packages) {
    const registryIntegrity = queryRegistryIntegrity(
      packageRecord.name,
      packageRecord.version,
    );
    const decision = decidePublication(
      packageRecord.integrity,
      registryIntegrity,
    );
    if (decision === "skip") {
      process.stdout.write(
        `Verified existing ${packageRecord.name}@${packageRecord.version}; skipping.\n`,
      );
      continue;
    }
    const tarball = resolve(dirname(manifestPath), packageRecord.tarball);
    runNpm(["publish", tarball, "--access", "public", "--provenance"], {
      cwd: dirname(manifestPath),
    });
    confirmRegistryIntegrity(packageRecord);
  }
}

export async function inspectPreparedRegistry(options = {}) {
  const manifestPath = resolve(
    options.manifest ?? ".release/package-manifest.json",
  );
  const manifest = await verifyPreparedReleaseManifest(manifestPath);
  const states = [];
  for (const packageRecord of manifest.packages) {
    const registryIntegrity = queryRegistryIntegrity(
      packageRecord.name,
      packageRecord.version,
    );
    const decision = decidePublication(
      packageRecord.integrity,
      registryIntegrity,
    );
    const state = decision === "skip" ? "exact" : "absent";
    states.push({ name: packageRecord.name, state });
    process.stdout.write(
      `${packageRecord.name}@${packageRecord.version}: ${state}\n`,
    );
  }
  return states;
}

async function inspectPackageBootstrapRegistry(bootstrap, options = {}) {
  requireManualPackageBootstrap(bootstrap, options);
  const manifestPath = resolve(
    options.manifest ?? `${bootstrap.defaultOutput}/${bootstrap.manifestFile}`,
  );
  const manifest = await verifyPackageBootstrapManifest(
    bootstrap,
    manifestPath,
  );
  const packageRecord = manifest.package;
  const registryIntegrity = queryRegistryIntegrity(
    packageRecord.name,
    packageRecord.version,
  );
  const state =
    decidePublication(packageRecord.integrity, registryIntegrity) === "skip"
      ? "exact"
      : "absent";
  process.stdout.write(
    `${packageRecord.name}@${packageRecord.version}: ${state}\n`,
  );
  return { name: packageRecord.name, state };
}

export async function inspectIdentityBootstrapRegistry(options = {}) {
  return inspectPackageBootstrapRegistry(IDENTITY_BOOTSTRAP, options);
}

export async function inspectEntraBootstrapRegistry(options = {}) {
  return inspectPackageBootstrapRegistry(ENTRA_BOOTSTRAP, options);
}

export function parseArguments(arguments_) {
  const options = {};
  for (let index = 0; index < arguments_.length; index += 1) {
    const argument = arguments_[index];
    if (argument === "--") {
      continue;
    }
    if (argument === "--require-main-ancestor") {
      options.requireMainAncestor = true;
      continue;
    }
    if (argument === "--require-clean") {
      options.requireClean = true;
      continue;
    }
    if (argument === "--require-release-tag") {
      options.requireReleaseTag = true;
      continue;
    }
    const key =
      argument === "--root"
        ? "root"
        : argument === "--output"
          ? "output"
          : argument === "--manifest"
            ? "manifest"
            : argument === "--expected-release-commit"
              ? "expectedReleaseCommit"
              : null;
    if (key === null || arguments_[index + 1] === undefined) {
      fail(`unknown or incomplete argument: ${argument}`);
    }
    options[key] = arguments_[index + 1];
    index += 1;
  }
  return options;
}

function defaultRoot() {
  return resolve(dirname(fileURLToPath(import.meta.url)), "..");
}

async function main() {
  const [command, ...arguments_] = process.argv.slice(2);
  const options = parseArguments(arguments_);
  if (command === "check") {
    const { version } = await validateRepository(options);
    process.stdout.write(`Release metadata is valid for ${version}.\n`);
    return;
  }
  if (command === "pack") {
    const { manifestPath } = await prepareRelease(options);
    process.stdout.write(`Prepared release packages at ${manifestPath}.\n`);
    return;
  }
  if (command === "publish") {
    await publishPreparedRelease(options);
    return;
  }
  if (command === "registry-check") {
    await inspectPreparedRegistry(options);
    return;
  }
  if (command === "identity-bootstrap-check") {
    const { sourceVersion, version } =
      await validateIdentityBootstrapRepository(options);
    process.stdout.write(
      `Identity bootstrap metadata is valid for package ${version} from source ${sourceVersion}.\n`,
    );
    return;
  }
  if (command === "identity-bootstrap-pack") {
    const { manifestPath } = await prepareIdentityBootstrap(options);
    process.stdout.write(
      `Prepared identity bootstrap package at ${manifestPath}.\n`,
    );
    return;
  }
  if (command === "identity-bootstrap-registry-check") {
    await inspectIdentityBootstrapRegistry(options);
    return;
  }
  if (command === "entra-bootstrap-check") {
    const { sourceVersion, version } =
      await validateEntraBootstrapRepository(options);
    process.stdout.write(
      `Entra bootstrap metadata is valid for package ${version} from source ${sourceVersion}.\n`,
    );
    return;
  }
  if (command === "entra-bootstrap-pack") {
    const { manifestPath } = await prepareEntraBootstrap(options);
    process.stdout.write(
      `Prepared entra bootstrap package at ${manifestPath}.\n`,
    );
    return;
  }
  if (command === "entra-bootstrap-registry-check") {
    await inspectEntraBootstrapRegistry(options);
    return;
  }
  fail(
    "usage: release-packages.mjs <check|pack|publish|registry-check|identity-bootstrap-check|identity-bootstrap-pack|identity-bootstrap-registry-check|entra-bootstrap-check|entra-bootstrap-pack|entra-bootstrap-registry-check> [options]",
  );
}

const isMain =
  process.argv[1] !== undefined &&
  resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (isMain) {
  await main();
}
