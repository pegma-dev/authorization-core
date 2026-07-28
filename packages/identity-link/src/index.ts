import type {
  IdentityLinkKey,
  PrincipalId,
} from "@pegma/authorization-contracts";

/**
 * The verified first-party identity claims projected by this adapter.
 *
 * This structural contract matches `@pegma/identity` without making either
 * package depend on the other. Email remains identity-side contact evidence
 * and never enters an authorization link key.
 */
export interface VerifiedIdentityClaims {
  readonly issuer: string;
  readonly subject: PrincipalId;
  readonly emailVerified: true;
}

const CLAIM_FIELDS = new Set<PropertyKey>([
  "issuer",
  "subject",
  "emailVerified",
]);
const CONTROL = /[\u0000-\u001F\u007F-\u009F]/u;
const MAX_ISSUER_LENGTH = 1_024;
const MAX_SUBJECT_LENGTH = 512;

function invalidClaims(): TypeError {
  return new TypeError(
    "Verified identity claims must be an exact own-data-only issuer, subject, and emailVerified object",
  );
}

function isWellFormedUnicode(value: string): boolean {
  return !/[\uD800-\uDFFF]/u.test(value);
}

function readDataProperty(
  descriptors: PropertyDescriptorMap,
  name: keyof VerifiedIdentityClaims,
): unknown {
  const descriptorEntry = Object.getOwnPropertyDescriptor(descriptors, name);
  const descriptor = descriptorEntry?.value as PropertyDescriptor | undefined;
  if (
    descriptor === undefined ||
    !Object.hasOwn(descriptor, "value") ||
    descriptor.enumerable !== true
  ) {
    throw invalidClaims();
  }
  return descriptor.value;
}

function boundedIdentifier(value: unknown, maximum: number): string {
  if (
    typeof value !== "string" ||
    value.length > maximum ||
    value.trim().length === 0 ||
    CONTROL.test(value) ||
    !isWellFormedUnicode(value)
  ) {
    throw invalidClaims();
  }
  return value;
}

/**
 * Projects already-verified first-party identity claims into an authorization
 * identity-link key.
 *
 * This function does not authenticate a session or resolve a principal. It
 * accepts only the exact verified-claims shape and deliberately omits contact
 * data and verification evidence from its frozen result. Descriptor validation
 * does not execute ordinary-object getters; portable JavaScript reflection may
 * execute proxy traps, so trusted callers should pass a plain claims snapshot.
 */
export function identityLinkKeyFromVerifiedIdentityClaims(
  claims: VerifiedIdentityClaims,
): IdentityLinkKey {
  if (typeof claims !== "object" || claims === null) {
    throw invalidClaims();
  }

  let prototype: object | null;
  let descriptors: PropertyDescriptorMap;
  try {
    prototype = Object.getPrototypeOf(claims);
    descriptors = Object.getOwnPropertyDescriptors(claims);
  } catch {
    throw invalidClaims();
  }
  if (prototype !== Object.prototype && prototype !== null) {
    throw invalidClaims();
  }

  const keys = Reflect.ownKeys(descriptors);
  if (
    keys.length !== CLAIM_FIELDS.size ||
    keys.some((key) => !CLAIM_FIELDS.has(key))
  ) {
    throw invalidClaims();
  }

  const issuer = boundedIdentifier(
    readDataProperty(descriptors, "issuer"),
    MAX_ISSUER_LENGTH,
  );
  const subject = boundedIdentifier(
    readDataProperty(descriptors, "subject"),
    MAX_SUBJECT_LENGTH,
  );
  if (readDataProperty(descriptors, "emailVerified") !== true) {
    throw invalidClaims();
  }

  return Object.freeze({ issuer, subject });
}
