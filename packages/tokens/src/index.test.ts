import { Buffer } from "node:buffer";
import { readFile } from "node:fs/promises";

import {
  createMemoryStore,
  type CollectionDefinition,
  type CollectionStore,
  type Store,
} from "@pegma/storage-core";
import {
  CompactSign,
  exportJWK,
  generateKeyPair,
  type GenerateKeyPairResult,
} from "jose";
import { beforeAll, describe, expect, it } from "vitest";

import {
  ACCESS_GRANT_ALGORITHM,
  ACCESS_GRANT_TYPE,
  accessGrantJtiReservations,
  accessGrantReplayKey,
  accessGrantReplays,
  createAccessGrantJwks,
  parseAccessGrantJwks,
  type AccessGrantIssuer,
  type AccessGrantIssuerConfiguration,
  type SourceAuthorizationSnapshot,
} from "./index.js";
import { JwksCache } from "./jwks.js";
import {
  createTestAccessGrantIssuer,
  createTestAccessGrantVerifier,
} from "./testing.js";

const issuerName = "https://authorization.example.test";
const applicationId = "pegma-production";
const audience = "support-api";
const kid = "key-2026-07-26-primary";
const policyVersion = "2026-07-26.1";
const policyDigest =
  "sha256:ad1b38ea08c91e2e66d6ab4d2f19a70dee7c067ba3c3223a2728f5d2f74a17e3";
const permission = "support.queue.read";
const secondPermission = "support.ticket.reply.any";
const issuedAt = 1_785_087_000;

let keys: GenerateKeyPairResult;

beforeAll(async () => {
  keys = await generateKeyPair("ES256", { extractable: true });
});

function context() {
  return {
    principalId: "principal-001",
    policyVersion,
    roles: ["support_agent"],
    entitlements: [],
    permissions: [permission, secondPermission],
  };
}

function source(
  overrides: Partial<SourceAuthorizationSnapshot> = {},
): SourceAuthorizationSnapshot {
  return {
    applicationId,
    context: context(),
    policyDigest,
    scope: { kind: "application" },
    maximumLifetimeMs: 60_000,
    ...overrides,
  };
}

interface IssuerFixture {
  readonly issuer: AccessGrantIssuer<void>;
  readonly setMonotonic: (value: number) => void;
  readonly setSource: (value: SourceAuthorizationSnapshot) => void;
}

function issuerFixture(
  options: {
    readonly randomBytes32?: () => Uint8Array;
    readonly wallNowEpochMs?: () => number;
    readonly initialMonotonicMs?: number;
    readonly store?: Store;
  } = {},
): IssuerFixture {
  let sourceValue = source();
  let monotonic = options.initialMonotonicMs ?? 1_000;
  let randomCounter = 1;
  const configuration: AccessGrantIssuerConfiguration<void> = {
    issuer: issuerName,
    applicationId,
    kid,
    signingKey: keys.privateKey,
    audiences: {
      [audience]: [permission, secondPermission],
    },
    acceptedPolicies: [{ version: policyVersion, digest: policyDigest }],
    sourceReader: () => sourceValue,
  };
  const issuer = createTestAccessGrantIssuer(
    configuration,
    options.store ?? createMemoryStore(),
    {
      monotonicNowMs: () => monotonic,
      wallNowEpochMs: options.wallNowEpochMs ?? (() => issuedAt * 1_000),
      randomBytes32:
        options.randomBytes32 ??
        (() => new Uint8Array(32).fill(randomCounter++)),
    },
  );
  return {
    issuer,
    setMonotonic: (value) => {
      monotonic = value;
    },
    setSource: (value) => {
      sourceValue = value;
    },
  };
}

async function issue(
  fixture = issuerFixture(),
  requestedPermissions = [permission],
): Promise<string> {
  const read = await fixture.issuer.readSourceAuthorization();
  const bound = fixture.issuer.bindSourceAuthorization(read);
  return fixture.issuer.issue({
    audience,
    requestedPermissions,
    source: bound,
  });
}

async function jwksBody(
  publicKey: CryptoKey = keys.publicKey,
  keyId = kid,
): Promise<string> {
  return JSON.stringify(
    await createAccessGrantJwks([{ kid: keyId, key: publicKey }]),
  );
}

function verifier(
  body: string,
  options: {
    readonly store?: ReturnType<typeof createMemoryStore>;
    readonly verifierNowMs?: number;
    readonly replayNowMs?: number;
    readonly cacheAgeMs?: number;
    readonly jwksNow?: () => number;
    readonly fetch?: () => Promise<{
      body: string;
      finalUrl: string;
    }>;
  } = {},
) {
  return createTestAccessGrantVerifier(
    {
      issuer: issuerName,
      applicationId,
      audience,
      allowedPermissions: [permission, secondPermission],
      acceptedPolicies: [{ version: policyVersion, digest: policyDigest }],
      jwksUrl: "https://authorization.example.test/.well-known/jwks.json",
      jwksCacheAgeMs: options.cacheAgeMs ?? 60_000,
    },
    options.store ?? createMemoryStore(),
    {
      verifierWallNowEpochMs: () =>
        options.verifierNowMs ?? (issuedAt + 1) * 1_000,
      replayStoreNowEpochMs: () =>
        options.replayNowMs ?? (issuedAt + 1) * 1_000,
      jwksMonotonicNowMs: options.jwksNow ?? (() => 0),
      fetchJwks:
        options.fetch ??
        (async () => ({
          body,
          finalUrl: "https://authorization.example.test/.well-known/jwks.json",
        })),
    },
  );
}

type ReplayFault =
  | "outage"
  | "commit-then-throw"
  | "invalid-insert-result"
  | "corrupt-existing-result";

function faultingReplayStore(mode: ReplayFault): {
  readonly store: Store;
  readonly insertCalls: () => number;
} {
  const memory = createMemoryStore();
  let calls = 0;
  const store: Store = {
    collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
      const collection = memory.collection(definition);
      if (definition.name !== accessGrantReplays.name) {
        return collection;
      }
      return new Proxy(collection, {
        get(target, property, receiver) {
          if (property === "insertIfAbsent") {
            return async (value: T) => {
              calls += 1;
              if (mode === "outage") {
                throw new Error("store unavailable");
              }
              if (mode === "commit-then-throw" && calls === 1) {
                await target.insertIfAbsent(value);
                throw new Error("response lost after commit");
              }
              if (mode === "invalid-insert-result") {
                return {
                  inserted: true,
                  value: {
                    ...(value as object),
                    audience: "corrupt-audience",
                  } as T,
                };
              }
              if (mode === "corrupt-existing-result") {
                return {
                  inserted: false,
                  value: {
                    ...(value as object),
                    retainThrough: Number.NaN,
                  } as T,
                };
              }
              return target.insertIfAbsent(value);
            };
          }
          const member = Reflect.get(target, property, receiver) as unknown;
          return typeof member === "function" ? member.bind(target) : member;
        },
      });
    },
  };
  return { store, insertCalls: () => calls };
}

function pausingReplayStore(): {
  readonly store: Store;
  readonly entered: Promise<void>;
  readonly release: () => void;
} {
  const memory = createMemoryStore();
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  const store: Store = {
    collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
      const collection = memory.collection(definition);
      if (definition.name !== accessGrantReplays.name) {
        return collection;
      }
      return new Proxy(collection, {
        get(target, property, receiver) {
          if (property === "insertIfAbsent") {
            return async (value: T) => {
              enter();
              await released;
              return target.insertIfAbsent(value);
            };
          }
          const member = Reflect.get(target, property, receiver) as unknown;
          return typeof member === "function" ? member.bind(target) : member;
        },
      });
    },
  };
  return { store, entered, release };
}

type ReservationFault = "outage" | "commit-then-throw";

function faultingReservationStore(mode: ReservationFault): {
  readonly store: Store;
  readonly insertCalls: () => number;
} {
  const memory = createMemoryStore();
  let calls = 0;
  const store: Store = {
    collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
      const collection = memory.collection(definition);
      if (definition.name !== accessGrantJtiReservations.name) {
        return collection;
      }
      return new Proxy(collection, {
        get(target, property, receiver) {
          if (property === "insertIfAbsent") {
            return async (value: T) => {
              calls += 1;
              if (mode === "outage") {
                throw new Error("reservation unavailable");
              }
              if (calls === 1) {
                await target.insertIfAbsent(value);
                throw new Error("reservation response lost after commit");
              }
              return target.insertIfAbsent(value);
            };
          }
          const member = Reflect.get(target, property, receiver) as unknown;
          return typeof member === "function" ? member.bind(target) : member;
        },
      });
    },
  };
  return { store, insertCalls: () => calls };
}

function pausingReservationStore(): {
  readonly store: Store;
  readonly entered: Promise<void>;
  readonly release: () => void;
} {
  const memory = createMemoryStore();
  let enter!: () => void;
  let release!: () => void;
  const entered = new Promise<void>((resolve) => {
    enter = resolve;
  });
  const released = new Promise<void>((resolve) => {
    release = resolve;
  });
  const store: Store = {
    collection<T>(definition: CollectionDefinition<T>): CollectionStore<T> {
      const collection = memory.collection(definition);
      if (definition.name !== accessGrantJtiReservations.name) {
        return collection;
      }
      return new Proxy(collection, {
        get(target, property, receiver) {
          if (property === "insertIfAbsent") {
            return async (value: T) => {
              enter();
              await released;
              return target.insertIfAbsent(value);
            };
          }
          const member = Reflect.get(target, property, receiver) as unknown;
          return typeof member === "function" ? member.bind(target) : member;
        },
      });
    },
  };
  return { store, entered, release };
}

describe("@pegma/authorization-tokens issuer", () => {
  it("binds a frozen source snapshot and consumes its original deadline", async () => {
    const mutable = context() as {
      principalId: string;
      policyVersion: string;
      roles: string[];
      entitlements: string[];
      permissions: string[];
    };
    const fixture = issuerFixture();
    fixture.setSource(source({ context: mutable }));
    const read = await fixture.issuer.readSourceAuthorization();
    mutable.principalId = "attacker";
    mutable.permissions[0] = "admin.everything";
    fixture.setMonotonic(31_000);
    const compact = await fixture.issuer.issue({
      audience,
      requestedPermissions: [permission],
      source: fixture.issuer.bindSourceAuthorization(read),
    });
    const payload = JSON.parse(
      Buffer.from(compact.split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;

    expect(payload["sub"]).toBe("principal-001");
    expect(payload["permissions"]).toEqual([permission]);
    expect(Number(payload["exp"]) - Number(payload["iat"])).toBe(25);
  });

  it("snapshots every issuer configuration and dependency at construction", async () => {
    const configuredPermissions = [permission];
    const configuredPolicies = [
      { version: policyVersion, digest: policyDigest },
    ];
    const configuration = {
      issuer: issuerName,
      applicationId,
      kid,
      signingKey: keys.privateKey,
      audiences: { [audience]: configuredPermissions },
      acceptedPolicies: configuredPolicies,
      sourceReader: () => source(),
    };
    let randomCounter = 40;
    const dependencies = {
      monotonicNowMs: () => 1_000,
      wallNowEpochMs: () => issuedAt * 1_000,
      randomBytes32: () => new Uint8Array(32).fill(randomCounter++),
    };
    const configured = createTestAccessGrantIssuer<void>(
      configuration,
      createMemoryStore(),
      dependencies,
    );
    const replacement = await generateKeyPair("ES256");
    configuration.issuer = "https://mutated.example.test";
    configuration.applicationId = "mutated-application";
    configuration.kid = "mutated-2026-07-26-key";
    configuration.signingKey = replacement.privateKey;
    configuration.sourceReader = () =>
      source({ applicationId: "mutated-application" });
    configuredPermissions.splice(0, 1, "mutated.permission");
    configuredPolicies[0]!.digest = `sha256:${"0".repeat(64)}`;
    dependencies.monotonicNowMs = () => Number.NaN;
    dependencies.wallNowEpochMs = () => Number.NaN;
    dependencies.randomBytes32 = () => new Uint8Array(31);

    const read = await configured.readSourceAuthorization();
    const compact = await configured.issue({
      audience,
      requestedPermissions: [permission],
      source: configured.bindSourceAuthorization(read),
    });
    const [encodedHeader, encodedPayload] = compact.split(".");
    const header = JSON.parse(
      Buffer.from(encodedHeader!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    const payload = JSON.parse(
      Buffer.from(encodedPayload!, "base64url").toString("utf8"),
    ) as Record<string, unknown>;
    expect(header["kid"]).toBe(kid);
    expect(payload).toMatchObject({
      iss: issuerName,
      application_id: applicationId,
      permissions: [permission],
    });
  });

  it("requires six whole seconds, caps nominal life at thirty, and reads wall time first", async () => {
    const sixSeconds = issuerFixture();
    sixSeconds.setSource(source({ maximumLifetimeMs: 6_000 }));
    const token = await issue(sixSeconds);
    const claims = JSON.parse(
      Buffer.from(token.split(".")[1]!, "base64url").toString("utf8"),
    ) as Record<string, number>;
    expect(claims["exp"]! - claims["iat"]!).toBe(1);

    const tooShort = issuerFixture();
    tooShort.setSource(source({ maximumLifetimeMs: 5_999 }));
    await expect(issue(tooShort)).rejects.toThrow(
      "not enough source authorization lifetime",
    );

    let pausingMonotonic = 0;
    const pausing = createTestAccessGrantIssuer(
      {
        issuer: issuerName,
        applicationId,
        kid,
        signingKey: keys.privateKey,
        audiences: { [audience]: [permission] },
        acceptedPolicies: [{ version: policyVersion, digest: policyDigest }],
        sourceReader: () => source({ maximumLifetimeMs: 6_000 }),
      },
      createMemoryStore(),
      {
        monotonicNowMs: () => pausingMonotonic,
        wallNowEpochMs: () => {
          pausingMonotonic = 5_001;
          return issuedAt * 1_000;
        },
        randomBytes32: () => new Uint8Array(32).fill(1),
      },
    );
    const read = await pausing.readSourceAuthorization(undefined);
    await expect(
      pausing.issue({
        audience,
        requestedPermissions: [permission],
        source: pausing.bindSourceAuthorization(read),
      }),
    ).rejects.toThrow("not enough source authorization lifetime");
  });

  it("rejects organization sources, ungranted permissions, forged capabilities, and repeated identifiers", async () => {
    const organization = issuerFixture();
    organization.setSource(
      source({
        scope: { kind: "organization", organizationId: "organization-001" },
      }),
    );
    await expect(issue(organization)).rejects.toThrow(
      "source authorization binding",
    );

    await expect(
      issue(issuerFixture(), ["support.queue.delete"]),
    ).rejects.toThrow("requested permission");

    const first = issuerFixture();
    const second = issuerFixture();
    const otherRead = await first.issuer.readSourceAuthorization();
    expect(() => second.issuer.bindSourceAuthorization(otherRead)).toThrow(
      "source authorization read is invalid",
    );

    const repeated = issuerFixture({
      randomBytes32: () => new Uint8Array(32).fill(7),
    });
    await issue(repeated);
    await expect(issue(repeated)).rejects.toThrow("already reserved");
  });

  it("reserves identifiers exactly across non-adjacent output and issuer instances", async () => {
    const values = [1, 2, 1];
    let index = 0;
    const fixture = issuerFixture({
      randomBytes32: () => new Uint8Array(32).fill(values[index++]!),
    });
    await expect(issue(fixture)).resolves.toBeDefined();
    await expect(issue(fixture)).resolves.toBeDefined();
    await expect(issue(fixture)).rejects.toThrow("already reserved");

    const sharedStore = createMemoryStore();
    const first = issuerFixture({
      store: sharedStore,
      randomBytes32: () => new Uint8Array(32).fill(91),
    });
    const second = issuerFixture({
      store: sharedStore,
      randomBytes32: () => new Uint8Array(32).fill(91),
    });
    const outcomes = await Promise.allSettled([issue(first), issue(second)]);
    expect(
      outcomes.filter((outcome) => outcome.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      outcomes.filter((outcome) => outcome.status === "rejected"),
    ).toHaveLength(1);
  });

  it("fails closed when identifier reservation is unavailable or ambiguous", async () => {
    const unavailable = faultingReservationStore("outage");
    await expect(
      issue(
        issuerFixture({
          store: unavailable.store,
          randomBytes32: () => new Uint8Array(32).fill(92),
        }),
      ),
    ).rejects.toThrow("reservation failed");
    expect(unavailable.insertCalls()).toBe(1);

    const ambiguous = faultingReservationStore("commit-then-throw");
    await expect(
      issue(
        issuerFixture({
          store: ambiguous.store,
          randomBytes32: () => new Uint8Array(32).fill(93),
        }),
      ),
    ).rejects.toThrow("reservation failed");
    await expect(
      issue(
        issuerFixture({
          store: ambiguous.store,
          randomBytes32: () => new Uint8Array(32).fill(93),
        }),
      ),
    ).rejects.toThrow("already reserved");
    expect(ambiguous.insertCalls()).toBe(2);
  });

  it("terminally invalidates existing evidence when its monotonic domain regresses", async () => {
    const fixture = issuerFixture({ initialMonotonicMs: 100 });
    const read = await fixture.issuer.readSourceAuthorization();
    const capability = fixture.issuer.bindSourceAuthorization(read);
    fixture.setMonotonic(99);
    await expect(fixture.issuer.readSourceAuthorization()).rejects.toThrow(
      "regressed",
    );
    await expect(
      fixture.issuer.issue({
        audience,
        requestedPermissions: [permission],
        source: capability,
      }),
    ).rejects.toThrow("capability is invalid");
    await expect(fixture.issuer.readSourceAuthorization()).rejects.toThrow(
      "domain has failed",
    );
  });

  it("denies an issuance that resumes after terminal monotonic regression", async () => {
    const reservation = pausingReservationStore();
    const fixture = issuerFixture({
      initialMonotonicMs: 1_000,
      randomBytes32: () => new Uint8Array(32).fill(51),
      store: reservation.store,
    });
    const read = await fixture.issuer.readSourceAuthorization();
    const source = fixture.issuer.bindSourceAuthorization(read);
    fixture.setMonotonic(2_000);
    const racedIssue = fixture.issuer.issue({
      audience,
      requestedPermissions: [permission],
      source,
    });

    await reservation.entered;
    fixture.setMonotonic(1_999);
    await expect(fixture.issuer.readSourceAuthorization()).rejects.toThrow(
      "regressed",
    );

    fixture.setMonotonic(2_001);
    reservation.release();
    await expect(racedIssue).rejects.toThrow("domain has failed");
    await expect(fixture.issuer.readSourceAuthorization()).rejects.toThrow(
      "domain has failed",
    );
  });

  it("denies an issuance that signs across a terminal monotonic regression", async () => {
    const samples = [1_000, 2_000, 3_000, 1_999];
    const configured = createTestAccessGrantIssuer<void>(
      {
        issuer: issuerName,
        applicationId,
        kid,
        signingKey: keys.privateKey,
        audiences: { [audience]: [permission] },
        acceptedPolicies: [{ version: policyVersion, digest: policyDigest }],
        sourceReader: () => source(),
      },
      createMemoryStore(),
      {
        monotonicNowMs: () => samples.shift() ?? 4_000,
        wallNowEpochMs: () => issuedAt * 1_000,
        randomBytes32: () => new Uint8Array(32).fill(52),
      },
    );
    const read = await configured.readSourceAuthorization();
    await expect(
      configured.issue({
        audience,
        requestedPermissions: [permission],
        source: configured.bindSourceAuthorization(read),
      }),
    ).rejects.toThrow("regressed");
    await expect(configured.readSourceAuthorization()).rejects.toThrow(
      "domain has failed",
    );
  });

  it("denies an issuance that expires while signing completes", async () => {
    const monotonicSamples = [1_000, 2_000, 3_000, 34_000];
    const wallSamples = [
      issuedAt * 1_000,
      issuedAt * 1_000,
      (issuedAt + 30) * 1_000,
    ];
    const store = createMemoryStore();
    const configured = createTestAccessGrantIssuer<void>(
      {
        issuer: issuerName,
        applicationId,
        kid,
        signingKey: keys.privateKey,
        audiences: { [audience]: [permission] },
        acceptedPolicies: [{ version: policyVersion, digest: policyDigest }],
        sourceReader: () => source(),
      },
      store,
      {
        monotonicNowMs: () => monotonicSamples.shift() ?? 35_000,
        wallNowEpochMs: () => wallSamples.shift() ?? (issuedAt + 30) * 1_000,
        randomBytes32: () => new Uint8Array(32).fill(53),
      },
    );
    const read = await configured.readSourceAuthorization();
    await expect(
      configured.issue({
        audience,
        requestedPermissions: [permission],
        source: configured.bindSourceAuthorization(read),
      }),
    ).rejects.toThrow("expired before issuance completed");

    await expect(
      issue(
        issuerFixture({
          store,
          randomBytes32: () => new Uint8Array(32).fill(53),
        }),
      ),
    ).rejects.toThrow("already reserved");
  });
});

describe("@pegma/authorization-tokens verifier", () => {
  it("verifies ES256 and atomically consumes a grant exactly once", async () => {
    const compact = await issue();
    const body = await jwksBody();
    const store = createMemoryStore();
    const configured = verifier(body, { store });

    await expect(configured.verifyAndConsume(compact)).resolves.toMatchObject({
      issuer: issuerName,
      applicationId,
      audience,
      principalId: "principal-001",
      permissions: [permission],
    });
    await expect(configured.verifyAndConsume(compact)).rejects.toThrow(
      "access grant rejected",
    );
  });

  it("snapshots verifier configuration and dependencies at construction", async () => {
    const compact = await issue();
    const body = await jwksBody();
    const allowedPermissions = [permission];
    const acceptedPolicies = [{ version: policyVersion, digest: policyDigest }];
    const configuration = {
      issuer: issuerName,
      applicationId,
      audience,
      allowedPermissions,
      acceptedPolicies,
      jwksUrl: "https://authorization.example.test/jwks.json",
      jwksCacheAgeMs: 60_000,
    };
    const dependencies = {
      verifierWallNowEpochMs: () => (issuedAt + 1) * 1_000,
      replayStoreNowEpochMs: () => (issuedAt + 1) * 1_000,
      jwksMonotonicNowMs: () => 0,
      fetchJwks: async () => ({
        body,
        finalUrl: "https://authorization.example.test/jwks.json",
      }),
    };
    const configured = createTestAccessGrantVerifier(
      configuration,
      createMemoryStore(),
      dependencies,
    );
    configuration.issuer = "https://mutated.example.test";
    configuration.applicationId = "mutated-application";
    configuration.audience = "mutated-audience";
    configuration.jwksUrl = "https://mutated.example.test/jwks.json";
    configuration.jwksCacheAgeMs = 1;
    allowedPermissions.splice(0, 1, "mutated.permission");
    acceptedPolicies[0]!.digest = `sha256:${"0".repeat(64)}`;
    dependencies.verifierWallNowEpochMs = () => Number.NaN;
    dependencies.replayStoreNowEpochMs = () => Number.NaN;
    dependencies.jwksMonotonicNowMs = () => Number.NaN;
    dependencies.fetchJwks = async () => {
      throw new Error("mutated fetcher");
    };

    await expect(configured.verifyAndConsume(compact)).resolves.toMatchObject({
      issuer: issuerName,
      applicationId,
      audience,
      permissions: [permission],
    });
  });

  it("gives exactly one concurrent consumer the grant", async () => {
    const compact = await issue();
    const configured = verifier(await jwksBody());
    const outcomes = await Promise.allSettled([
      configured.verifyAndConsume(compact),
      configured.verifyAndConsume(compact),
    ]);
    expect(
      outcomes.filter((outcome) => outcome.status === "fulfilled"),
    ).toHaveLength(1);
    expect(
      outcomes.filter((outcome) => outcome.status === "rejected"),
    ).toHaveLength(1);
  });

  it("rejects duplicate, unknown, malformed, noncanonical, and tampered inputs before consumption", async () => {
    const compact = await issue();
    const body = await jwksBody();
    const configured = verifier(body);
    const [encodedHeader, encodedPayload, signature] = compact.split(".");
    const payloadText = Buffer.from(encodedPayload!, "base64url").toString(
      "utf8",
    );
    const duplicatePayload = payloadText.replace(
      `"aud":"${audience}"`,
      `"aud":"${audience}","aud":"${audience}"`,
    );
    const duplicateToken = await new CompactSign(
      new TextEncoder().encode(duplicatePayload),
    )
      .setProtectedHeader({
        alg: ACCESS_GRANT_ALGORITHM,
        kid,
        typ: ACCESS_GRANT_TYPE,
      })
      .sign(keys.privateKey);
    await expect(configured.verifyAndConsume(duplicateToken)).rejects.toThrow(
      "access grant rejected",
    );

    const unknownPayload = payloadText.replace(
      /}$/,
      ',"organization_id":"organization-001"}',
    );
    const unknownToken = await new CompactSign(
      new TextEncoder().encode(unknownPayload),
    )
      .setProtectedHeader({
        alg: ACCESS_GRANT_ALGORITHM,
        kid,
        typ: ACCESS_GRANT_TYPE,
      })
      .sign(keys.privateKey);
    await expect(configured.verifyAndConsume(unknownToken)).rejects.toThrow(
      "access grant rejected",
    );

    const duplicateHeader = Buffer.from(
      `{"alg":"ES256","alg":"ES256","kid":"${kid}","typ":"${ACCESS_GRANT_TYPE}"}`,
    ).toString("base64url");
    await expect(
      configured.verifyAndConsume(
        `${duplicateHeader}.${encodedPayload}.${signature}`,
      ),
    ).rejects.toThrow("access grant rejected");
    await expect(
      configured.verifyAndConsume(
        `${encodedHeader}=.${encodedPayload}.${signature}`,
      ),
    ).rejects.toThrow("access grant rejected");
    await expect(
      configured.verifyAndConsume(`${encodedHeader}.${encodedPayload}.AA`),
    ).rejects.toThrow("access grant rejected");

    const tampered = `${encodedHeader}.${encodedPayload!.slice(0, -1)}A.${signature}`;
    await expect(configured.verifyAndConsume(tampered)).rejects.toThrow(
      "access grant rejected",
    );
  });

  it("enforces exact issuer, application, audience, policy, permission, and zero-leeway time", async () => {
    const compact = await issue();
    const body = await jwksBody();
    await expect(
      verifier(body, {
        verifierNowMs: (issuedAt + 30) * 1_000,
      }).verifyAndConsume(compact),
    ).rejects.toThrow("access grant rejected");

    const wrongPolicy = createTestAccessGrantVerifier(
      {
        issuer: issuerName,
        applicationId,
        audience,
        allowedPermissions: [permission],
        acceptedPolicies: [
          { version: policyVersion, digest: `sha256:${"0".repeat(64)}` },
        ],
        jwksUrl: "https://authorization.example.test/jwks.json",
        jwksCacheAgeMs: 1,
      },
      createMemoryStore(),
      {
        verifierWallNowEpochMs: () => (issuedAt + 1) * 1_000,
        replayStoreNowEpochMs: () => (issuedAt + 1) * 1_000,
        jwksMonotonicNowMs: () => 0,
        fetchJwks: async () => ({
          body,
          finalUrl: "https://authorization.example.test/jwks.json",
        }),
      },
    );
    await expect(wrongPolicy.verifyAndConsume(compact)).rejects.toThrow(
      "access grant rejected",
    );
  });

  it("keeps replay tuple fields structured and rejects an existing corrupt record", async () => {
    const compact = await issue();
    const payload = JSON.parse(
      Buffer.from(compact.split(".")[1]!, "base64url").toString("utf8"),
    ) as { jti: string; exp: number };
    const key = accessGrantReplayKey(
      issuerName,
      applicationId,
      audience,
      payload.jti,
    );
    expect(key.partition).not.toContain(issuerName);

    const store = createMemoryStore();
    await store.collection(accessGrantReplays).put({
      issuer: issuerName,
      applicationId,
      audience,
      jti: payload.jti,
      retainThrough: payload.exp + 4,
    });
    await expect(
      verifier(await jwksBody(), { store }).verifyAndConsume(compact),
    ).rejects.toThrow("access grant rejected");
  });

  it("fails closed with one generic error for replay outage, ambiguity, and corrupt outcomes", async () => {
    const body = await jwksBody();

    const outage = faultingReplayStore("outage");
    await expect(
      verifier(body, { store: outage.store }).verifyAndConsume(await issue()),
    ).rejects.toMatchObject({
      name: "AccessGrantError",
      message: "access grant rejected",
    });

    const ambiguous = faultingReplayStore("commit-then-throw");
    const ambiguousGrant = await issue();
    const ambiguousVerifier = verifier(body, { store: ambiguous.store });
    await expect(
      ambiguousVerifier.verifyAndConsume(ambiguousGrant),
    ).rejects.toMatchObject({
      name: "AccessGrantError",
      message: "access grant rejected",
    });
    await expect(
      ambiguousVerifier.verifyAndConsume(ambiguousGrant),
    ).rejects.toMatchObject({
      name: "AccessGrantError",
      message: "access grant rejected",
    });
    expect(ambiguous.insertCalls()).toBe(2);

    const invalid = faultingReplayStore("invalid-insert-result");
    await expect(
      verifier(body, { store: invalid.store }).verifyAndConsume(await issue()),
    ).rejects.toMatchObject({
      name: "AccessGrantError",
      message: "access grant rejected",
    });

    const corrupt = faultingReplayStore("corrupt-existing-result");
    await expect(
      verifier(body, { store: corrupt.store }).verifyAndConsume(await issue()),
    ).rejects.toMatchObject({
      name: "AccessGrantError",
      message: "access grant rejected",
    });
  });

  it("denies a grant that expires while replay consumption is in flight", async () => {
    const compact = await issue(issuerFixture(), [permission]);
    const body = await jwksBody();
    const replay = pausingReplayStore();
    const verifierOptions = {
      store: replay.store,
      verifierNowMs: issuedAt * 1_000,
      replayNowMs: issuedAt * 1_000,
    };
    const configured = verifier(body, verifierOptions);
    const inFlight = configured.verifyAndConsume(compact);

    await replay.entered;
    verifierOptions.verifierNowMs = (issuedAt + 30) * 1_000;
    replay.release();
    await expect(inFlight).rejects.toThrow("access grant rejected");
    await expect(
      verifier(body, {
        store: replay.store,
        verifierNowMs: issuedAt * 1_000,
        replayNowMs: issuedAt * 1_000,
      }).verifyAndConsume(compact),
    ).rejects.toThrow("access grant rejected");
  });
});

describe("@pegma/authorization-tokens JWKS", () => {
  it("shares refresh, cooldown, strictest age, and terminal clock state across verifiers", async () => {
    let now = 0;
    let fetches = 0;
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const body = await jwksBody();
    const monotonicNow = () => now;
    const fetchJwks = async () => {
      fetches += 1;
      if (fetches === 1) await blocked;
      return {
        body,
        finalUrl: "https://authorization.example.test/.well-known/jwks.json",
      };
    };
    const first = verifier(body, {
      jwksNow: monotonicNow,
      fetch: fetchJwks,
      cacheAgeMs: 60_000,
    });
    const second = verifier(body, {
      jwksNow: monotonicNow,
      fetch: fetchJwks,
      cacheAgeMs: 100,
    });
    const fixture = issuerFixture();
    const invalid = await issue(fixture);
    const [unusedHeader, payload, signature] = invalid.split(".");
    void unusedHeader;
    const unknownHeader = Buffer.from(
      JSON.stringify({
        alg: ACCESS_GRANT_ALGORITHM,
        kid: "random-missing-kid-101",
        typ: ACCESS_GRANT_TYPE,
      }),
    ).toString("base64url");
    const unknown = `${unknownHeader}.${payload}.${signature}`;
    const concurrent = [
      first.verifyAndConsume(unknown),
      second.verifyAndConsume(unknown),
    ];
    release();
    await Promise.allSettled(concurrent);
    expect(fetches).toBe(1);

    now = 1;
    const anotherHeader = Buffer.from(
      JSON.stringify({
        alg: ACCESS_GRANT_ALGORITHM,
        kid: "random-missing-kid-102",
        typ: ACCESS_GRANT_TYPE,
      }),
    ).toString("base64url");
    await expect(
      second.verifyAndConsume(`${anotherHeader}.${payload}.${signature}`),
    ).rejects.toThrow("access grant rejected");
    expect(fetches).toBe(1);

    now = 100;
    await expect(
      first.verifyAndConsume(await issue(fixture)),
    ).resolves.toBeDefined();
    expect(fetches).toBe(2);
    now = 50;
    await expect(second.verifyAndConsume(await issue(fixture))).rejects.toThrow(
      "access grant rejected",
    );
    now = 100;
    await expect(first.verifyAndConsume(await issue(fixture))).rejects.toThrow(
      "access grant rejected",
    );
    expect(fetches).toBe(2);
  });

  it("projects only public key fields and rejects private or unknown material", async () => {
    const document = await createAccessGrantJwks([
      { kid, key: keys.publicKey },
    ]);
    expect(document).toEqual({
      keys: [
        {
          kty: "EC",
          crv: "P-256",
          x: expect.any(String),
          y: expect.any(String),
          use: "sig",
          alg: "ES256",
          kid,
        },
      ],
    });
    await expect(
      createAccessGrantJwks([{ kid, key: keys.privateKey }]),
    ).rejects.toThrow("public P-256");

    const jwk = await exportJWK(keys.publicKey);
    await expect(
      parseAccessGrantJwks(
        JSON.stringify({
          keys: [
            {
              ...jwk,
              use: "sig",
              alg: "ES256",
              kid,
              d: "private-material-is-never-accepted",
            },
          ],
        }),
      ),
    ).rejects.toThrow("exactly");
    await expect(
      parseAccessGrantJwks(
        `{"keys":${JSON.stringify(document.keys)},"keys":[]}`,
      ),
    ).rejects.toThrow("duplicate");
  });

  it("uses strict cache age, bounded issuer-wide misses, rotation replacement, and terminal clock failure", async () => {
    const second = await generateKeyPair("ES256", { extractable: true });
    let now = 0;
    let fetches = 0;
    let body = await jwksBody();
    const cache = new JwksCache({
      issuer: issuerName,
      url: "https://authorization.example.test/jwks.json",
      maxAgeMs: 60_000,
      monotonicNowMs: () => now,
      fetcher: async () => {
        fetches += 1;
        return {
          body,
          finalUrl: "https://authorization.example.test/jwks.json",
        };
      },
    });
    await expect(cache.resolve(kid)).resolves.toBeDefined();
    now = 59_999;
    await expect(cache.resolve(kid)).resolves.toBeDefined();
    expect(fetches).toBe(1);
    now = 60_000;
    await expect(cache.resolve(kid)).resolves.toBeDefined();
    expect(fetches).toBe(2);

    now = 60_001;
    await expect(cache.resolve("missing-key-2026-001")).rejects.toThrow(
      "unknown",
    );
    await expect(cache.resolve("missing-key-2026-002")).rejects.toThrow(
      "unknown",
    );
    expect(fetches).toBe(3);

    body = await jwksBody(second.publicKey, "key-2026-07-26-rotated");
    now = 65_001;
    await expect(
      cache.resolve("key-2026-07-26-rotated"),
    ).resolves.toBeDefined();
    await expect(cache.resolve(kid)).rejects.toThrow("unknown");

    now = 64_000;
    await expect(cache.resolve(kid)).rejects.toThrow("regressed");
    now = 70_000;
    await expect(cache.resolve(kid)).rejects.toThrow("domain has failed");
  });

  it("shares an in-flight refresh and rejects a different-origin final URL", async () => {
    let release!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    let fetches = 0;
    const body = await jwksBody();
    const cache = new JwksCache({
      issuer: issuerName,
      url: "https://authorization.example.test/jwks.json",
      maxAgeMs: 1,
      monotonicNowMs: () => 0,
      fetcher: async () => {
        fetches += 1;
        await blocked;
        return {
          body,
          finalUrl: "https://authorization.example.test/jwks.json",
        };
      },
    });
    const first = cache.resolve(kid);
    const second = cache.resolve(kid);
    release();
    await Promise.all([first, second]);
    expect(fetches).toBe(1);

    const redirected = new JwksCache({
      issuer: issuerName,
      url: "https://authorization.example.test/jwks.json",
      maxAgeMs: 1,
      monotonicNowMs: () => 0,
      fetcher: async () => ({
        body,
        finalUrl: "https://attacker.example.test/jwks.json",
      }),
    });
    await expect(redirected.resolve(kid)).rejects.toThrow("changed origin");
  });

  it("denies an in-flight JWKS refresh after terminal monotonic regression", async () => {
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetchEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let now = 100;
    let fetches = 0;
    const body = await jwksBody();
    const cache = new JwksCache({
      issuer: issuerName,
      url: "https://authorization.example.test/jwks.json",
      maxAgeMs: 1,
      monotonicNowMs: () => now,
      fetcher: async () => {
        fetches += 1;
        entered();
        await blocked;
        return {
          body,
          finalUrl: "https://authorization.example.test/jwks.json",
        };
      },
    });
    const inFlight = cache.resolve(kid);

    await fetchEntered;
    now = 99;
    await expect(cache.resolve(kid)).rejects.toThrow("regressed");
    now = 101;
    release();
    await expect(inFlight).rejects.toThrow("domain has failed");
    await expect(cache.resolve(kid)).rejects.toThrow("domain has failed");
    expect(fetches).toBe(1);
  });

  it("does not consume replay when verifier JWKS refresh loses a terminal race", async () => {
    const compact = await issue();
    const body = await jwksBody();
    const store = createMemoryStore();
    let release!: () => void;
    let entered!: () => void;
    const blocked = new Promise<void>((resolve) => {
      release = resolve;
    });
    const fetchEntered = new Promise<void>((resolve) => {
      entered = resolve;
    });
    let now = 100;
    const configured = verifier(body, {
      store,
      cacheAgeMs: 1,
      jwksNow: () => now,
      fetch: async () => {
        entered();
        await blocked;
        return {
          body,
          finalUrl: "https://authorization.example.test/.well-known/jwks.json",
        };
      },
    });
    const inFlight = configured.verifyAndConsume(compact);

    await fetchEntered;
    now = 99;
    await expect(configured.verifyAndConsume(compact)).rejects.toThrow(
      "access grant rejected",
    );
    now = 101;
    release();
    await expect(inFlight).rejects.toThrow("access grant rejected");

    const fresh = verifier(body, { store });
    await expect(fresh.verifyAndConsume(compact)).resolves.toMatchObject({
      principalId: "principal-001",
    });
  });

  it("starts unknown-kid cooldown before failed initial and stale refreshes", async () => {
    let now = 0;
    let initialFetches = 0;
    const initialFailure = new JwksCache({
      issuer: issuerName,
      url: "https://authorization.example.test/jwks.json",
      maxAgeMs: 60_000,
      monotonicNowMs: () => now,
      fetcher: async () => {
        initialFetches += 1;
        throw new Error("fetch failed");
      },
    });
    await expect(
      initialFailure.resolve("random-missing-kid-001"),
    ).rejects.toThrow("fetch failed");
    now = 1;
    await expect(
      initialFailure.resolve("random-missing-kid-002"),
    ).rejects.toThrow("unknown");
    now = 4_999;
    await expect(
      initialFailure.resolve("random-missing-kid-003"),
    ).rejects.toThrow("unknown");
    expect(initialFetches).toBe(1);
    now = 5_000;
    await expect(
      initialFailure.resolve("random-missing-kid-004"),
    ).rejects.toThrow("fetch failed");
    expect(initialFetches).toBe(2);

    now = 0;
    let staleFetches = 0;
    let failRefresh = false;
    const staleFailure = new JwksCache({
      issuer: issuerName,
      url: "https://authorization.example.test/jwks.json",
      maxAgeMs: 100,
      monotonicNowMs: () => now,
      fetcher: async () => {
        staleFetches += 1;
        if (failRefresh) throw new Error("stale refresh failed");
        return {
          body: await jwksBody(),
          finalUrl: "https://authorization.example.test/jwks.json",
        };
      },
    });
    await staleFailure.resolve(kid);
    failRefresh = true;
    now = 5_000;
    await expect(
      staleFailure.resolve("random-missing-kid-005"),
    ).rejects.toThrow("stale refresh failed");
    now = 5_001;
    await expect(
      staleFailure.resolve("random-missing-kid-006"),
    ).rejects.toThrow("unknown");
    expect(staleFetches).toBe(2);
    now = 10_000;
    await expect(
      staleFailure.resolve("random-missing-kid-007"),
    ).rejects.toThrow("stale refresh failed");
    expect(staleFetches).toBe(3);
  });
});

describe("public-only cross-language vector", () => {
  it("verifies the committed public JWK and compact ES256 grant without private material", async () => {
    const vector = JSON.parse(
      await readFile(
        new URL(
          "../../../tests/fixtures/access-grant-v1-public-vector.json",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as {
      jwks: { keys: unknown[] };
      claims: { exp: number };
      compact: string;
    };
    await expect(
      parseAccessGrantJwks(JSON.stringify(vector.jwks)),
    ).resolves.toEqual(vector.jwks);

    const configured = createTestAccessGrantVerifier(
      {
        issuer: issuerName,
        applicationId,
        audience,
        allowedPermissions: [permission, secondPermission],
        acceptedPolicies: [{ version: policyVersion, digest: policyDigest }],
        jwksUrl: "https://authorization.example.test/vector-jwks.json",
        jwksCacheAgeMs: 60_000,
      },
      createMemoryStore(),
      {
        verifierWallNowEpochMs: () => 2_000_000_001_000,
        replayStoreNowEpochMs: () => 2_000_000_001_000,
        jwksMonotonicNowMs: () => 0,
        fetchJwks: async () => ({
          body: JSON.stringify(vector.jwks),
          finalUrl: "https://authorization.example.test/vector-jwks.json",
        }),
      },
    );
    await expect(
      configured.verifyAndConsume(vector.compact),
    ).resolves.toMatchObject({
      expiresAt: vector.claims.exp,
      principalId: "principal-vector-001",
    });
  });
});
