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
} from "./internal.js";

/** One issuer-owned identifier permanently reserved before signing. */
export interface AccessGrantJtiReservation {
  readonly issuer: string;
  readonly applicationId: string;
  readonly jti: string;
}

export function accessGrantJtiReservationKey(
  issuer: string,
  applicationId: string,
  jti: string,
): EntityKey {
  return {
    partition: `v1-${encodeStorageKeyPart(issuer)}-${encodeStorageKeyPart(applicationId)}`,
    id: jti,
  };
}

function storedString(record: StoredRecord, field: string): string {
  const value = record[field];
  if (typeof value !== "string") {
    fail("access-grant identifier reservation is corrupt");
  }
  return value;
}

/** Declared issuer-side identifier reservation collection. */
export const accessGrantJtiReservations =
  defineCollection<AccessGrantJtiReservation>({
    name: "authorization_access_grant_jti_reservations",
    key: (reservation) =>
      accessGrantJtiReservationKey(
        reservation.issuer,
        reservation.applicationId,
        reservation.jti,
      ),
    codec: {
      encode: (reservation) => ({
        issuer: reservation.issuer,
        applicationId: reservation.applicationId,
        jti: reservation.jti,
      }),
      decode: (record) => {
        const reservation = {
          issuer: storedString(record, "issuer"),
          applicationId: storedString(record, "applicationId"),
          jti: storedString(record, "jti"),
        };
        if (
          reservation.issuer.length === 0 ||
          !isBoundedIdentity(reservation.applicationId) ||
          !isCanonicalBase64Url32(reservation.jti)
        ) {
          fail("access-grant identifier reservation is corrupt");
        }
        return reservation;
      },
    },
  });

export interface JtiReserver {
  reserve(reservation: AccessGrantJtiReservation): Promise<void>;
}

export function createJtiReserver(store: Store): JtiReserver {
  const reservations = store.collection(accessGrantJtiReservations);
  return Object.freeze({
    async reserve(reservation: AccessGrantJtiReservation): Promise<void> {
      let result;
      try {
        result = await reservations.insertIfAbsent(reservation);
      } catch {
        // A write may have committed before its response was lost. Burning the
        // identifier and denying issuance is the only safe interpretation.
        fail("access-grant identifier reservation failed");
      }
      if (!result.inserted) {
        const existing = result.value;
        if (
          existing.issuer !== reservation.issuer ||
          existing.applicationId !== reservation.applicationId ||
          existing.jti !== reservation.jti
        ) {
          fail("access-grant identifier reservation is corrupt");
        }
        fail("access-grant identifier was already reserved");
      }
      if (
        result.value.issuer !== reservation.issuer ||
        result.value.applicationId !== reservation.applicationId ||
        result.value.jti !== reservation.jti
      ) {
        fail("access-grant identifier reservation result is corrupt");
      }
    },
  });
}
