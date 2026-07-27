import {
  defineCollection,
  type EntityKey,
  type Store,
  type StoredRecord,
} from "@pegma/storage-core";

import {
  encodeStorageKeyPart,
  fail,
  isBoundedIdentity,
  isCanonicalBase64Url32,
  isNumericDate,
} from "./internal.js";

/** One exact V1 grant consumption. Records may safely be retained indefinitely. */
export interface AccessGrantReplayRecord {
  readonly issuer: string;
  readonly applicationId: string;
  readonly audience: string;
  readonly jti: string;
  /** The record must remain present through this NumericDate second. */
  readonly retainThrough: number;
}

function requireStoredString(record: StoredRecord, field: string): string {
  const value = record[field];
  if (typeof value !== "string") {
    fail("access-grant replay record is corrupt");
  }
  return value;
}

function requireStoredNumber(record: StoredRecord, field: string): number {
  const value = record[field];
  if (typeof value !== "number") {
    fail("access-grant replay record is corrupt");
  }
  return value;
}

export function accessGrantReplayKey(
  issuer: string,
  applicationId: string,
  audience: string,
  jti: string,
): EntityKey {
  return {
    partition: `v1-${encodeStorageKeyPart(issuer)}-${encodeStorageKeyPart(applicationId)}-${encodeStorageKeyPart(audience)}`,
    id: jti,
  };
}

/** Declared replay collection. The host supplies the Store implementation. */
export const accessGrantReplays = defineCollection<AccessGrantReplayRecord>({
  name: "authorization_access_grant_replays",
  key: (record) =>
    accessGrantReplayKey(
      record.issuer,
      record.applicationId,
      record.audience,
      record.jti,
    ),
  codec: {
    encode: (record) => ({
      issuer: record.issuer,
      applicationId: record.applicationId,
      audience: record.audience,
      jti: record.jti,
      retainThrough: record.retainThrough,
    }),
    decode: (record) => {
      const decoded = {
        issuer: requireStoredString(record, "issuer"),
        applicationId: requireStoredString(record, "applicationId"),
        audience: requireStoredString(record, "audience"),
        jti: requireStoredString(record, "jti"),
        retainThrough: requireStoredNumber(record, "retainThrough"),
      };
      if (
        decoded.issuer.length === 0 ||
        !isBoundedIdentity(decoded.applicationId) ||
        decoded.audience.length === 0 ||
        !isCanonicalBase64Url32(decoded.jti) ||
        !isNumericDate(decoded.retainThrough)
      ) {
        fail("access-grant replay record is corrupt");
      }
      return decoded;
    },
  },
});

export interface ReplayConsumer {
  consume(record: AccessGrantReplayRecord): Promise<void>;
}

export function createReplayConsumer(
  store: Store,
  replayNowEpochMs: () => number,
): ReplayConsumer {
  const records = store.collection(accessGrantReplays);
  return Object.freeze({
    async consume(record: AccessGrantReplayRecord): Promise<void> {
      const now = replayNowEpochMs();
      if (
        !Number.isFinite(now) ||
        now < 0 ||
        !isNumericDate(record.retainThrough)
      ) {
        fail("replay-store clock or retention is invalid");
      }

      let result;
      try {
        result = await records.insertIfAbsent(record);
      } catch {
        // The backend may have committed before reporting an outage. Retrying
        // then observes the row and denies, so either outcome remains closed.
        fail("access-grant replay store rejected consumption");
      }
      if (!result.inserted) {
        const existing = result.value;
        if (
          existing.issuer !== record.issuer ||
          existing.applicationId !== record.applicationId ||
          existing.audience !== record.audience ||
          existing.jti !== record.jti ||
          !isNumericDate(existing.retainThrough)
        ) {
          fail("access-grant replay record is corrupt");
        }
        fail("access grant was already consumed");
      }
      if (
        result.value.issuer !== record.issuer ||
        result.value.applicationId !== record.applicationId ||
        result.value.audience !== record.audience ||
        result.value.jti !== record.jti ||
        result.value.retainThrough !== record.retainThrough
      ) {
        fail("access-grant replay write result is corrupt");
      }
    },
  });
}
