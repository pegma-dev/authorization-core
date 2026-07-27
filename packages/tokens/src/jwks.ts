import { exportJWK, importJWK } from "jose";

import {
  ACCESS_GRANT_ALGORITHM,
  exactRecord,
  fail,
  isCanonicalBase64Url32,
  isKid,
  JWK_FIELDS,
  MAX_JWKS_CACHE_AGE_MS,
  parseStrictJson,
  UNKNOWN_KID_REFRESH_INTERVAL_MS,
} from "./internal.js";

export interface AccessGrantPublicJwk {
  readonly kty: "EC";
  readonly crv: "P-256";
  readonly x: string;
  readonly y: string;
  readonly use: "sig";
  readonly alg: typeof ACCESS_GRANT_ALGORITHM;
  readonly kid: string;
}

export interface AccessGrantJwks {
  readonly keys: readonly AccessGrantPublicJwk[];
}

export interface AccessGrantPublicKey {
  readonly kid: string;
  readonly key: CryptoKey;
}

export interface JwksFetchResult {
  /** Raw UTF-8 JSON. Raw input is required so duplicate members remain visible. */
  readonly body: string | Uint8Array;
  /** Final URL after any redirect handling. */
  readonly finalUrl: string;
}

export type JwksFetcher = (url: string) => Promise<JwksFetchResult>;

interface ValidatedJwks {
  readonly document: AccessGrantJwks;
  readonly keysByKid: ReadonlyMap<string, CryptoKey>;
}

function keyAlgorithm(key: CryptoKey): EcKeyAlgorithm | undefined {
  const algorithm = key.algorithm;
  return algorithm.name === "ECDSA" && "namedCurve" in algorithm
    ? (algorithm as EcKeyAlgorithm)
    : undefined;
}

function requirePublicP256Key(key: CryptoKey): void {
  const algorithm = keyAlgorithm(key);
  if (
    key.type !== "public" ||
    algorithm?.namedCurve !== "P-256" ||
    !key.usages.includes("verify")
  ) {
    fail("access-grant JWKS requires a public P-256 verification key");
  }
}

function validateJwkShape(value: unknown): AccessGrantPublicJwk {
  const record = exactRecord(value, JWK_FIELDS, "JWK");
  if (
    record["kty"] !== "EC" ||
    record["crv"] !== "P-256" ||
    !isCanonicalBase64Url32(record["x"]) ||
    !isCanonicalBase64Url32(record["y"]) ||
    record["use"] !== "sig" ||
    record["alg"] !== ACCESS_GRANT_ALGORITHM ||
    !isKid(record["kid"])
  ) {
    fail("JWK is not a V1 access-grant public key");
  }
  return Object.freeze({
    kty: "EC",
    crv: "P-256",
    x: record["x"],
    y: record["y"],
    use: "sig",
    alg: ACCESS_GRANT_ALGORITHM,
    kid: record["kid"],
  });
}

async function validateJwks(
  input: string | Uint8Array,
): Promise<ValidatedJwks> {
  const bytes =
    typeof input === "string" ? new TextEncoder().encode(input) : input;
  const parsed = parseStrictJson(bytes, "JWKS");
  const document = exactRecord(parsed, ["keys"], "JWKS");
  if (!Array.isArray(document["keys"])) {
    fail("JWKS keys must be an array");
  }

  const keys: AccessGrantPublicJwk[] = [];
  const keysByKid = new Map<string, CryptoKey>();
  for (const value of document["keys"]) {
    const publicJwk = validateJwkShape(value);
    if (keysByKid.has(publicJwk.kid)) {
      fail("JWKS contains a duplicate kid");
    }
    let key: CryptoKey;
    try {
      key = (await importJWK(publicJwk, ACCESS_GRANT_ALGORITHM)) as CryptoKey;
    } catch (error) {
      fail("JWK contains an invalid P-256 point", { cause: error });
    }
    requirePublicP256Key(key);
    keys.push(publicJwk);
    keysByKid.set(publicJwk.kid, key);
  }
  return {
    document: Object.freeze({ keys: Object.freeze(keys) }),
    keysByKid,
  };
}

/** Parse and fully validate one exact V1 public JWKS document. */
export async function parseAccessGrantJwks(
  input: string | Uint8Array,
): Promise<AccessGrantJwks> {
  return (await validateJwks(input)).document;
}

/**
 * Project host-owned public CryptoKeys into the exact V1 JWKS surface.
 *
 * Private keys are rejected before export and only the seven public profile
 * members are copied into the returned document.
 */
export async function createAccessGrantJwks(
  entries: readonly AccessGrantPublicKey[],
): Promise<AccessGrantJwks> {
  const keys: AccessGrantPublicJwk[] = [];
  const kids = new Set<string>();
  for (const entry of entries) {
    if (!isKid(entry.kid) || kids.has(entry.kid)) {
      fail("access-grant JWKS kid is invalid or repeated");
    }
    requirePublicP256Key(entry.key);
    const exported = await exportJWK(entry.key);
    const projected = validateJwkShape({
      kty: exported.kty,
      crv: exported.crv,
      x: exported.x,
      y: exported.y,
      use: "sig",
      alg: ACCESS_GRANT_ALGORITHM,
      kid: entry.kid,
    });
    keys.push(projected);
    kids.add(entry.kid);
  }
  return Object.freeze({ keys: Object.freeze(keys) });
}

export async function defaultJwksFetcher(
  url: string,
): Promise<JwksFetchResult> {
  const response = await fetch(url, {
    method: "GET",
    redirect: "manual",
    headers: { accept: "application/json" },
  });
  if (!response.ok) {
    fail("JWKS fetch failed");
  }
  return {
    body: new Uint8Array(await response.arrayBuffer()),
    finalUrl: response.url,
  };
}

export interface JwksCacheOptions {
  readonly issuer: string;
  readonly url: string;
  readonly maxAgeMs: number;
  readonly monotonicNowMs: () => number;
  readonly fetcher: JwksFetcher;
}

function canonicalJwksEndpoint(url: string): {
  readonly url: string;
  readonly origin: string;
} {
  let parsed: URL;
  try {
    parsed = new URL(url);
  } catch (error) {
    fail("JWKS URL is invalid", { cause: error });
  }
  if (
    parsed!.protocol !== "https:" ||
    parsed!.username !== "" ||
    parsed!.password !== "" ||
    parsed!.hash !== ""
  ) {
    fail("JWKS URL must be an HTTPS endpoint without credentials or fragment");
  }
  return { url: parsed!.href, origin: parsed!.origin };
}

function requireCacheAge(maxAgeMs: number): void {
  if (
    !Number.isSafeInteger(maxAgeMs) ||
    maxAgeMs < 1 ||
    maxAgeMs > MAX_JWKS_CACHE_AGE_MS
  ) {
    fail("JWKS cache age must be between 1 and 60000 milliseconds");
  }
}

/** Internal issuer-scoped, replace-only V1 JWKS cache. */
export class JwksCache {
  readonly #url: string;
  readonly #origin: string;
  #maxAgeMs: number;
  readonly #monotonicNowMs: () => number;
  readonly #fetcher: JwksFetcher;
  #keys: ReadonlyMap<string, CryptoKey> | undefined;
  #loadedAtMs: number | undefined;
  #lastObservedMs: number | undefined;
  #clockFailed = false;
  #refreshInFlight: Promise<void> | undefined;
  #nextUnknownKidRefreshAtMs: number | undefined;

  constructor(options: JwksCacheOptions) {
    if (options.issuer.length === 0) {
      fail("JWKS issuer must not be empty");
    }
    const endpoint = canonicalJwksEndpoint(options.url);
    requireCacheAge(options.maxAgeMs);
    this.#url = endpoint.url;
    this.#origin = endpoint.origin;
    this.#maxAgeMs = options.maxAgeMs;
    this.#monotonicNowMs = options.monotonicNowMs;
    this.#fetcher = options.fetcher;
  }

  tightenMaxAge(maxAgeMs: number): void {
    requireCacheAge(maxAgeMs);
    this.#maxAgeMs = Math.min(this.#maxAgeMs, maxAgeMs);
  }

  assertActive(): void {
    const now = this.#sample();
    if (
      this.#keys === undefined ||
      this.#loadedAtMs === undefined ||
      now - this.#loadedAtMs >= this.#maxAgeMs
    ) {
      fail("JWKS cache is stale");
    }
  }

  async resolve(kid: string): Promise<CryptoKey> {
    const now = this.#sample();
    const fresh =
      this.#keys !== undefined &&
      this.#loadedAtMs !== undefined &&
      now - this.#loadedAtMs < this.#maxAgeMs;
    const knownBeforeRefresh = this.#keys?.has(kid) === true;
    if (!fresh) {
      if (!knownBeforeRefresh) {
        if (this.#refreshInFlight === undefined) {
          this.#beginUnknownKidRefresh(now);
        }
      }
      await this.#refresh(now);
      this.#requireClockAlive();
    }

    const existing = this.#keys?.get(kid);
    if (existing !== undefined) return existing;

    if (!fresh) {
      if (knownBeforeRefresh) {
        this.#nextUnknownKidRefreshAtMs = now + UNKNOWN_KID_REFRESH_INTERVAL_MS;
      }
      fail("unknown access-grant signing key");
    }

    this.#beginUnknownKidRefresh(now);
    await this.#refresh(now);
    this.#requireClockAlive();
    const refreshed = this.#keys?.get(kid);
    if (refreshed === undefined) {
      fail("unknown access-grant signing key");
    }
    return refreshed;
  }

  #beginUnknownKidRefresh(now: number): void {
    if (
      this.#nextUnknownKidRefreshAtMs !== undefined &&
      now < this.#nextUnknownKidRefreshAtMs
    ) {
      fail("unknown access-grant signing key");
    }

    // Begin the issuer-scoped cooldown before network I/O. Fetch failure must
    // not let attacker-selected kids immediately trigger another request.
    this.#nextUnknownKidRefreshAtMs = now + UNKNOWN_KID_REFRESH_INTERVAL_MS;
  }

  #sample(): number {
    this.#requireClockAlive();
    const now = this.#monotonicNowMs();
    if (
      !Number.isFinite(now) ||
      now < 0 ||
      (this.#lastObservedMs !== undefined && now < this.#lastObservedMs)
    ) {
      this.#clockFailed = true;
      this.#keys = undefined;
      this.#loadedAtMs = undefined;
      fail("JWKS monotonic clock is invalid or regressed");
    }
    this.#lastObservedMs = now;
    return now;
  }

  #requireClockAlive(): void {
    if (this.#clockFailed) {
      fail("JWKS monotonic clock domain has failed");
    }
  }

  async #refresh(now: number): Promise<void> {
    if (this.#refreshInFlight !== undefined) {
      await this.#refreshInFlight;
      return;
    }
    const refresh = this.#load(now);
    this.#refreshInFlight = refresh;
    try {
      await refresh;
    } finally {
      if (this.#refreshInFlight === refresh) {
        this.#refreshInFlight = undefined;
      }
    }
  }

  async #load(now: number): Promise<void> {
    const response = await this.#fetcher(this.#url);
    let finalUrl: URL;
    try {
      finalUrl = new URL(response.finalUrl);
    } catch (error) {
      fail("JWKS fetch returned an invalid final URL", { cause: error });
    }
    if (finalUrl!.origin !== this.#origin) {
      fail("JWKS redirect changed origin");
    }
    const validated = await validateJwks(response.body);
    this.#requireClockAlive();
    this.#keys = validated.keysByKid;
    this.#loadedAtMs = now;
  }
}

const sharedCachesByFetcher = new WeakMap<
  JwksFetcher,
  WeakMap<() => number, Map<string, WeakRef<JwksCache>>>
>();

/**
 * Share issuer/endpoint clock and refresh state without keeping verifier
 * instances or their injected dependencies alive.
 */
export function getSharedJwksCache(options: JwksCacheOptions): JwksCache {
  const endpoint = canonicalJwksEndpoint(options.url);
  let byClock = sharedCachesByFetcher.get(options.fetcher);
  if (byClock === undefined) {
    byClock = new WeakMap();
    sharedCachesByFetcher.set(options.fetcher, byClock);
  }
  let byIssuerAndUrl = byClock.get(options.monotonicNowMs);
  if (byIssuerAndUrl === undefined) {
    byIssuerAndUrl = new Map();
    byClock.set(options.monotonicNowMs, byIssuerAndUrl);
  }
  const registryKey = JSON.stringify([options.issuer, endpoint.url]);
  const existing = byIssuerAndUrl.get(registryKey)?.deref();
  if (existing !== undefined) {
    existing.tightenMaxAge(options.maxAgeMs);
    return existing;
  }
  const created = new JwksCache({ ...options, url: endpoint.url });
  byIssuerAndUrl.set(registryKey, new WeakRef(created));
  return created;
}
