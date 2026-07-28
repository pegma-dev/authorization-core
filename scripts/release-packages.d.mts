export interface ReleasePackageDefinition {
  readonly directory: string;
  readonly name: string;
  readonly exports: readonly string[];
  readonly modules: readonly string[];
}

export interface IdentityBootstrapPackageDefinition {
  readonly directory: "identity-link";
  readonly name: "@pegma/authorization-identity";
  readonly sourceVersion: "0.1.0";
  readonly version: "0.0.0";
}

export interface ValidationOptions {
  readonly root?: string;
  readonly releaseTag?: string;
  readonly releasePrerelease?: boolean | string;
  readonly expectedReleaseCommit?: string;
  readonly requireClean?: boolean;
  readonly requireMainAncestor?: boolean;
  readonly requireReleaseTag?: boolean;
}

export interface ReleaseCommandOptions extends ValidationOptions {
  readonly manifest?: string;
  readonly output?: string;
}

export const RELEASE_PACKAGES: readonly ReleasePackageDefinition[];
export const IDENTITY_BOOTSTRAP_PACKAGE: IdentityBootstrapPackageDefinition;

export function parseArguments(
  arguments_: readonly string[],
): ReleaseCommandOptions;

export function validateRepository(
  options?: ValidationOptions,
): Promise<{ root: string; version: string; releaseTag?: string }>;

export function validateIdentityBootstrapRepository(
  options?: ValidationOptions,
): Promise<{
  root: string;
  sourceVersion: "0.1.0";
  version: "0.0.0";
}>;

export function prepareIdentityBootstrap(
  options?: ReleaseCommandOptions,
): Promise<{ manifestPath: string; manifest: unknown }>;

export function verifyPreparedReleaseManifest(
  manifestPath: string,
): Promise<unknown>;

export function verifyIdentityBootstrapManifest(
  manifestPath: string,
): Promise<unknown>;

export function inspectIdentityBootstrapRegistry(
  options?: ReleaseCommandOptions,
): Promise<{
  name: "@pegma/authorization-identity";
  state: "exact" | "absent";
}>;

export function validateReleaseTag(options?: {
  readonly root?: string;
  readonly releaseTag?: string;
  readonly expectedReleaseCommit?: string;
}): { headCommit: string; releaseTag: string };

export function decidePublication(
  localIntegrity: string,
  registryIntegrity: string | null,
): "publish" | "skip";
