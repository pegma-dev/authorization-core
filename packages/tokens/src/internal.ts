import { base64url } from "jose";

export const ACCESS_GRANT_TYPE = "pegma-access-grant+jwt" as const;
export const ACCESS_GRANT_PROFILE_VERSION = 1 as const;
export const ACCESS_GRANT_ALGORITHM = "ES256" as const;
export const MAX_ACCESS_GRANT_LIFETIME_SECONDS = 30;
export const MAX_NEGATIVE_VERIFIER_OFFSET_SECONDS = 5;
export const MAX_SOURCE_AUTHORIZATION_LIFETIME_MS = 60_000;
export const MAX_JWKS_CACHE_AGE_MS = 60_000;
export const UNKNOWN_KID_REFRESH_INTERVAL_MS = 5_000;

export const HEADER_FIELDS = ["alg", "kid", "typ"] as const;
export const CLAIM_FIELDS = [
  "iss",
  "application_id",
  "aud",
  "sub",
  "exp",
  "iat",
  "jti",
  "profile_version",
  "policy_version",
  "policy_digest",
  "permissions",
] as const;
export const JWK_FIELDS = [
  "kty",
  "crv",
  "x",
  "y",
  "use",
  "alg",
  "kid",
] as const;

const BASE64URL_PATTERN = /^[A-Za-z0-9_-]*$/;
const BASE64URL_32_BYTE_PATTERN = /^[A-Za-z0-9_-]{43}$/;
const ASCII_CONTROL_PATTERN = /[\u0000-\u001F\u007F]/;
const KID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._:-]{15,127}$/;
const PERMISSION_PATTERN =
  /^[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*(?:\.[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*)*$/;
const POLICY_VERSION_PATTERN = /^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/;
const POLICY_DIGEST_PATTERN = /^sha256:[a-f0-9]{64}$/;

export function fail(message: string, options?: { cause?: unknown }): never {
  throw new AccessGrantError(message, options);
}

export class AccessGrantError extends Error {
  constructor(
    message = "access grant rejected",
    options?: { cause?: unknown },
  ) {
    super(message, options);
    this.name = "AccessGrantError";
  }
}

export function isPlainRecord(
  value: unknown,
): value is Readonly<Record<string, unknown>> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

export function exactRecord(
  value: unknown,
  fields: readonly string[],
  kind: string,
): Readonly<Record<string, unknown>> {
  if (!isPlainRecord(value)) {
    fail(`${kind} must be an object`);
  }
  const names = Object.keys(value);
  if (
    names.length !== fields.length ||
    fields.some((field) => !Object.hasOwn(value, field))
  ) {
    fail(`${kind} must contain exactly the V1 fields`);
  }
  return value;
}

export function isKid(value: unknown): value is string {
  return typeof value === "string" && KID_PATTERN.test(value);
}

export function isPolicyVersion(value: unknown): value is string {
  return typeof value === "string" && POLICY_VERSION_PATTERN.test(value);
}

export function isPolicyDigest(value: unknown): value is string {
  return typeof value === "string" && POLICY_DIGEST_PATTERN.test(value);
}

export function isBoundedIdentity(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length > 0 &&
    [...value].length <= 255 &&
    value.trim() === value &&
    !ASCII_CONTROL_PATTERN.test(value)
  );
}

export function isNumericDate(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value > 0;
}

export function isPermission(value: unknown): value is string {
  return (
    typeof value === "string" &&
    value.length <= 255 &&
    PERMISSION_PATTERN.test(value)
  );
}

export function canonicalPermissions(
  values: readonly string[],
): readonly string[] {
  for (const value of values) {
    if (!isPermission(value)) {
      fail("permission is malformed");
    }
  }
  return Object.freeze([...new Set(values)].sort());
}

export function isCanonicalPermissions(
  value: unknown,
): value is readonly string[] {
  if (!Array.isArray(value) || value.length === 0) {
    return false;
  }
  return value.every(
    (permission, index) =>
      isPermission(permission) &&
      (index === 0 || value[index - 1]! < permission),
  );
}

export function decodeCanonicalBase64Url(
  value: string,
  kind: string,
): Uint8Array {
  if (!BASE64URL_PATTERN.test(value)) {
    fail(`${kind} is not canonical base64url`);
  }
  let bytes: Uint8Array;
  try {
    bytes = base64url.decode(value);
  } catch (error) {
    fail(`${kind} is not canonical base64url`, { cause: error });
  }
  if (base64url.encode(bytes!) !== value) {
    fail(`${kind} is not canonical base64url`);
  }
  return bytes;
}

export function isCanonicalBase64Url32(value: unknown): value is string {
  if (typeof value !== "string" || !BASE64URL_32_BYTE_PATTERN.test(value)) {
    return false;
  }
  let decoded: Uint8Array;
  try {
    decoded = base64url.decode(value);
  } catch {
    return false;
  }
  return decoded.length === 32 && base64url.encode(decoded) === value;
}

export function policyPair(version: string, digest: string): string {
  return JSON.stringify([version, digest]);
}

/**
 * Parse JSON while retaining the profile's duplicate-member rejection.
 *
 * JSON.parse cannot expose duplicate object names, so the small recursive
 * parser below checks each object before returning ordinary JSON values.
 */
export function parseStrictJson(bytes: Uint8Array, kind: string): unknown {
  let source: string;
  try {
    source = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch (error) {
    fail(`${kind} is not valid UTF-8 JSON`, { cause: error });
  }
  const parser = new StrictJsonParser(source!, kind);
  return parser.parse();
}

class StrictJsonParser {
  readonly #source: string;
  readonly #kind: string;
  #position = 0;

  constructor(source: string, kind: string) {
    this.#source = source;
    this.#kind = kind;
  }

  parse(): unknown {
    const value = this.#value();
    this.#whitespace();
    if (this.#position !== this.#source.length) {
      this.#invalid();
    }
    return value;
  }

  #value(): unknown {
    this.#whitespace();
    const character = this.#source[this.#position];
    if (character === "{") return this.#object();
    if (character === "[") return this.#array();
    if (character === '"') return this.#string();
    if (character === "t") return this.#literal("true", true);
    if (character === "f") return this.#literal("false", false);
    if (character === "n") return this.#literal("null", null);
    return this.#number();
  }

  #object(): Readonly<Record<string, unknown>> {
    this.#position += 1;
    const result: Record<string, unknown> = Object.create(null) as Record<
      string,
      unknown
    >;
    const names = new Set<string>();
    this.#whitespace();
    if (this.#source[this.#position] === "}") {
      this.#position += 1;
      return result;
    }
    while (true) {
      this.#whitespace();
      if (this.#source[this.#position] !== '"') this.#invalid();
      const name = this.#string();
      if (names.has(name)) {
        fail(`${this.#kind} has a duplicate field`);
      }
      names.add(name);
      this.#whitespace();
      if (this.#source[this.#position] !== ":") this.#invalid();
      this.#position += 1;
      result[name] = this.#value();
      this.#whitespace();
      const next = this.#source[this.#position];
      if (next === "}") {
        this.#position += 1;
        return result;
      }
      if (next !== ",") this.#invalid();
      this.#position += 1;
    }
  }

  #array(): readonly unknown[] {
    this.#position += 1;
    const result: unknown[] = [];
    this.#whitespace();
    if (this.#source[this.#position] === "]") {
      this.#position += 1;
      return result;
    }
    while (true) {
      result.push(this.#value());
      this.#whitespace();
      const next = this.#source[this.#position];
      if (next === "]") {
        this.#position += 1;
        return result;
      }
      if (next !== ",") this.#invalid();
      this.#position += 1;
    }
  }

  #string(): string {
    const start = this.#position;
    this.#position += 1;
    while (this.#position < this.#source.length) {
      const character = this.#source[this.#position]!;
      if (character === '"') {
        this.#position += 1;
        try {
          return JSON.parse(
            this.#source.slice(start, this.#position),
          ) as string;
        } catch (error) {
          fail(`${this.#kind} is invalid JSON`, { cause: error });
        }
      }
      if (character.charCodeAt(0) < 0x20) this.#invalid();
      if (character === "\\") {
        this.#position += 1;
        const escaped = this.#source[this.#position];
        if (escaped === "u") {
          const digits = this.#source.slice(
            this.#position + 1,
            this.#position + 5,
          );
          if (!/^[0-9A-Fa-f]{4}$/.test(digits)) this.#invalid();
          this.#position += 4;
        } else if (escaped === undefined || !'"\\/bfnrt'.includes(escaped)) {
          this.#invalid();
        }
      }
      this.#position += 1;
    }
    return this.#invalid();
  }

  #number(): number {
    const match = /^-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?/.exec(
      this.#source.slice(this.#position),
    );
    if (match === null) return this.#invalid();
    this.#position += match[0].length;
    return Number(match[0]);
  }

  #literal<T>(text: string, value: T): T {
    if (!this.#source.startsWith(text, this.#position)) this.#invalid();
    this.#position += text.length;
    return value;
  }

  #whitespace(): void {
    while (
      this.#source[this.#position] === " " ||
      this.#source[this.#position] === "\t" ||
      this.#source[this.#position] === "\r" ||
      this.#source[this.#position] === "\n"
    ) {
      this.#position += 1;
    }
  }

  #invalid(): never {
    fail(`${this.#kind} is invalid JSON`);
  }
}

export class GuardedMonotonicClock {
  readonly #read: () => number;
  readonly #onFailure: () => void;
  #lastObservedMs: number | undefined;
  #failed = false;

  constructor(read: () => number, onFailure: () => void = () => undefined) {
    this.#read = read;
    this.#onFailure = onFailure;
  }

  sample(): number {
    if (this.#failed) {
      fail("monotonic clock domain has failed");
    }
    const sample = this.#read();
    if (
      !Number.isFinite(sample) ||
      sample < 0 ||
      (this.#lastObservedMs !== undefined && sample < this.#lastObservedMs)
    ) {
      this.#failed = true;
      this.#lastObservedMs = undefined;
      this.#onFailure();
      fail("monotonic clock is invalid or regressed");
    }
    this.#lastObservedMs = sample;
    return sample;
  }
}
