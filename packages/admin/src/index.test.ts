import { describe, expect, it } from "vitest";

import type {
  PrincipalId,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import { createRoleStore } from "@pegma/authorization-storage";
import { createMemoryStore } from "@pegma/storage-core";

import {
  assignmentManagedBy,
  createRoleAdministration,
  ensureSeededAssignment,
  GUARD_COMPENSATION_SYSTEM_ID,
  SEED_SYSTEM_ID,
  type RoleAdministrationStore,
  type RoleHolderIndex,
  type RoleHolderIndexRow,
} from "./index.js";

const APPLICATION: RoleAssignmentScope = Object.freeze({
  kind: "application",
});
const ADMIN = "Admin";
const SUPPORT = "Support";
const alice = "principal-alice" as PrincipalId;
const bob = "principal-bob" as PrincipalId;
const carol = "principal-carol" as PrincipalId;
const operator = Object.freeze({
  kind: "principal",
  principalId: alice,
} as const);

/** Deterministic clock and id source so lifecycle order is explicit. */
function deterministic() {
  let tick = 1_000_000;
  let serial = 0;
  return {
    now: () => (tick += 1_000),
    generateId: () => `id-${String((serial += 1)).padStart(3, "0")}`,
  };
}

/** In-memory holder index following the STORAGE.md recipe (never deletes). */
function memoryHolderIndex(): RoleHolderIndex & {
  readonly rows: RoleHolderIndexRow[];
} {
  const rows: RoleHolderIndexRow[] = [];
  return {
    rows,
    async record(row) {
      if (
        !rows.some(
          (existing) =>
            existing.assignmentId === row.assignmentId &&
            existing.role === row.role,
        )
      ) {
        rows.push(row);
      }
    },
    async listByRole(role) {
      return rows.filter((row) => row.role === role);
    },
  };
}

function world(
  policyOverrides: { oneTimeSystemActors?: ReadonlySet<string> } = {},
) {
  const store = createRoleStore(createMemoryStore(), "admin-tests");
  const holderIndex = memoryHolderIndex();
  const { now, generateId } = deterministic();
  const administration = createRoleAdministration({
    store,
    holderIndex,
    policy: { administratorRole: ADMIN, ...policyOverrides },
    now,
    generateId,
  });
  return { store, holderIndex, administration, now };
}

async function seededAdmin(
  store: RoleAdministrationStore,
  holderIndex: RoleHolderIndex,
  principalId: PrincipalId,
  assignmentId: string,
) {
  expect(
    await ensureSeededAssignment({
      store,
      holderIndex,
      principalId,
      role: ADMIN,
      scope: APPLICATION,
      assignmentId,
      auditEventId: `evt-${assignmentId}`,
      now: () => 1,
    }),
  ).toBe("granted");
}

describe("assignmentManagedBy", () => {
  const policy = {
    administratorRole: ADMIN,
    oneTimeSystemActors: new Set(["nightly-sync"]),
  };

  it("locks ongoing system actors and frees humans and one-time actors", () => {
    expect(
      assignmentManagedBy(
        { grantedBy: { kind: "system", systemId: "entitlement-sync" } },
        policy,
      ),
    ).toBe("system");
    expect(assignmentManagedBy({ grantedBy: operator }, policy)).toBe("human");
    for (const systemId of [
      SEED_SYSTEM_ID,
      GUARD_COMPENSATION_SYSTEM_ID,
      "nightly-sync",
    ]) {
      expect(
        assignmentManagedBy(
          { grantedBy: { kind: "system", systemId } },
          policy,
        ),
      ).toBe("human");
    }
  });
});

describe("assignRole", () => {
  it("assigns with the index row written before the grant", async () => {
    const { administration, holderIndex, store } = world();
    const result = await administration.assignRole({
      principalId: bob,
      role: SUPPORT,
      scope: APPLICATION,
      actor: operator,
    });
    expect(result.status).toBe("assigned");
    const row = holderIndex.rows.find(
      (candidate) => candidate.role === SUPPORT,
    );
    expect(row?.principalId).toBe(bob);
    const stored = await store.getRoleAssignment(row!.assignmentId);
    expect(stored?.assignment.status).toBe("active");
  });

  it("refuses a duplicate active role without writing an index row", async () => {
    const { administration, holderIndex } = world();
    await administration.assignRole({
      principalId: bob,
      role: SUPPORT,
      scope: APPLICATION,
      actor: operator,
    });
    const before = holderIndex.rows.length;
    const duplicate = await administration.assignRole({
      principalId: bob,
      role: SUPPORT,
      scope: APPLICATION,
      actor: operator,
    });
    expect(duplicate.status).toBe("duplicate");
    expect(holderIndex.rows.length).toBe(before);
  });
});

describe("viewGrants", () => {
  it("labels management and self-heals the by-role index", async () => {
    const { administration, holderIndex, store } = world();
    // A grant that never touched the index — the pre-index era shape.
    await store.grantRoleAssignmentWithAudit({
      assignment: {
        id: "preindex-admin",
        principalId: bob,
        role: ADMIN,
        scope: APPLICATION,
        grantedBy: { kind: "system", systemId: "entitlement-sync" },
        grantedAtEpochMs: 1,
        status: "active",
      },
      auditEventId: "evt-preindex-admin",
    });
    expect(await administration.anotherActiveHolderExists(ADMIN, "")).toBe(
      false,
    );
    const grants = await administration.viewGrants(bob, APPLICATION);
    expect(grants).toEqual([expect.objectContaining({ managedBy: "system" })]);
    // The view healed the index; the guard now sees the holder.
    expect(holderIndex.rows).toEqual([
      expect.objectContaining({ assignmentId: "preindex-admin" }),
    ]);
    expect(await administration.anotherActiveHolderExists(ADMIN, "")).toBe(
      true,
    );
  });
});

describe("listHistory", () => {
  it("renders the full lifecycle with revocation evidence, ordered", async () => {
    const { administration, store, holderIndex } = world();
    await seededAdmin(store, holderIndex, bob, "seed-bob");
    await seededAdmin(store, holderIndex, carol, "seed-carol");
    const assigned = await administration.assignRole({
      principalId: bob,
      role: SUPPORT,
      scope: APPLICATION,
      actor: operator,
    });
    expect(assigned.status).toBe("assigned");
    const supportRow = holderIndex.rows.find((row) => row.role === SUPPORT);
    const revoked = await administration.revokeRole({
      assignmentId: supportRow!.assignmentId,
      actor: operator,
      reason: "rotation",
    });
    expect(revoked).toEqual({ status: "revoked", compensated: false });

    const events = await administration.listHistory(bob, APPLICATION);
    expect(events.map((event) => event.kind)).toEqual([
      "granted",
      "granted",
      "revoked",
    ]);
    const last = events.at(-1)!;
    expect(last.reason).toBe("rotation");
    expect(last.actor).toEqual(operator);
  });
});

describe("revokeRole", () => {
  it("maps absence, replay, and system-managed refusal", async () => {
    const { administration, store } = world();
    expect(
      await administration.revokeRole({
        assignmentId: "missing",
        actor: operator,
      }),
    ).toEqual({ status: "not_found" });

    await store.grantRoleAssignmentWithAudit({
      assignment: {
        id: "locked",
        principalId: bob,
        role: SUPPORT,
        scope: APPLICATION,
        grantedBy: { kind: "system", systemId: "entitlement-sync" },
        grantedAtEpochMs: 1,
        status: "active",
      },
      auditEventId: "evt-locked",
    });
    expect(
      await administration.revokeRole({
        assignmentId: "locked",
        actor: operator,
      }),
    ).toEqual({ status: "system_managed" });
  });

  it("refuses to revoke the last active administrator, self or not", async () => {
    const { administration, store, holderIndex } = world();
    await seededAdmin(store, holderIndex, bob, "seed-bob");
    expect(
      await administration.revokeRole({
        assignmentId: "seed-bob",
        actor: operator,
      }),
    ).toEqual({ status: "last_administrator" });

    await seededAdmin(store, holderIndex, carol, "seed-carol");
    expect(
      await administration.revokeRole({
        assignmentId: "seed-bob",
        actor: operator,
      }),
    ).toEqual({ status: "revoked", compensated: false });
    // Now carol is the last again.
    expect(
      await administration.revokeRole({
        assignmentId: "seed-carol",
        actor: operator,
      }),
    ).toEqual({ status: "last_administrator" });
  });

  it("serializes concurrent revocations of the two last administrators", async () => {
    const { administration, store, holderIndex } = world();
    await seededAdmin(store, holderIndex, bob, "seed-bob");
    await seededAdmin(store, holderIndex, carol, "seed-carol");
    const [first, second] = await Promise.all([
      administration.revokeRole({ assignmentId: "seed-bob", actor: operator }),
      administration.revokeRole({
        assignmentId: "seed-carol",
        actor: operator,
      }),
    ]);
    // Exactly one wins; the serialized loser hits the guard, not a race.
    expect([first.status, second.status].sort()).toEqual([
      "last_administrator",
      "revoked",
    ]);
    expect(await administration.anotherActiveHolderExists(ADMIN, "")).toBe(
      true,
    );
  });

  it("compensates when a cross-instance race removes the final administrator", async () => {
    const shared = createRoleStore(createMemoryStore(), "admin-tests");
    const holderIndex = memoryHolderIndex();
    const clockA = deterministic();
    const clockB = deterministic();
    // Instance B is an independent service over the same durable state —
    // in-process serialization cannot see it.
    const instanceB = createRoleAdministration({
      store: shared,
      holderIndex,
      policy: { administratorRole: ADMIN },
      now: clockB.now,
      generateId: () => `b-${clockB.generateId()}`,
    });
    // Instance A's store commits B's competing revoke between A's guard
    // pre-check and A's own revoke — the exact TOCTOU the re-verify exists
    // for.
    let interleaved = false;
    const interleavingStore: RoleAdministrationStore = {
      ...shared,
      revokeRoleAssignmentWithAudit: async (command) => {
        if (!interleaved) {
          interleaved = true;
          expect(
            (
              await instanceB.revokeRole({
                assignmentId: "seed-carol",
                actor: operator,
              })
            ).status,
          ).toBe("revoked");
        }
        return shared.revokeRoleAssignmentWithAudit(command);
      },
    };
    const instanceA = createRoleAdministration({
      store: interleavingStore,
      holderIndex,
      policy: { administratorRole: ADMIN },
      now: clockA.now,
      generateId: () => `a-${clockA.generateId()}`,
    });
    await seededAdmin(shared, holderIndex, bob, "seed-bob");
    await seededAdmin(shared, holderIndex, carol, "seed-carol");

    const result = await instanceA.revokeRole({
      assignmentId: "seed-bob",
      actor: operator,
    });
    expect(result).toEqual({ status: "revoked", compensated: true });

    // The compensation restored the principal A revoked, as a one-time
    // system actor: human-managed, revocable, and visible to the guard.
    const grants = await instanceA.viewGrants(bob, APPLICATION);
    expect(grants).toEqual([
      expect.objectContaining({
        managedBy: "human",
        assignment: expect.objectContaining({
          role: ADMIN,
          grantedBy: {
            kind: "system",
            systemId: GUARD_COMPENSATION_SYSTEM_ID,
          },
        }),
      }),
    ]);
    expect(await instanceA.anotherActiveHolderExists(ADMIN, "")).toBe(true);
  });
});

describe("anotherActiveHolderExists", () => {
  it("verifies candidates against the store: dangling and revoked rows never count", async () => {
    const { administration, holderIndex, store } = world();
    await holderIndex.record({
      principalId: bob,
      assignmentId: "dangling",
      role: ADMIN,
    });
    expect(await administration.anotherActiveHolderExists(ADMIN, "")).toBe(
      false,
    );
    await seededAdmin(store, holderIndex, carol, "seed-carol");
    expect(await administration.anotherActiveHolderExists(ADMIN, "")).toBe(
      true,
    );
    expect(await administration.anotherActiveHolderExists(ADMIN, carol)).toBe(
      false,
    );
  });
});

describe("ensureSeededAssignment", () => {
  it("seeds once; any lifecycle history — including revoked — converges to already", async () => {
    const { administration, store, holderIndex } = world();
    await seededAdmin(store, holderIndex, bob, "seed-bob");
    // Exact manifest retry.
    expect(
      await ensureSeededAssignment({
        store,
        holderIndex,
        principalId: bob,
        role: ADMIN,
        scope: APPLICATION,
        assignmentId: "seed-bob",
        auditEventId: "evt-seed-bob",
      }),
    ).toBe("already");

    await seededAdmin(store, holderIndex, carol, "seed-carol");
    expect(
      await administration.revokeRole({
        assignmentId: "seed-bob",
        actor: operator,
      }),
    ).toEqual({ status: "revoked", compensated: false });
    // Revoked history is durable evidence: a NEW manifest id still refuses.
    expect(
      await ensureSeededAssignment({
        store,
        holderIndex,
        principalId: bob,
        role: ADMIN,
        scope: APPLICATION,
        assignmentId: "seed-bob-second",
        auditEventId: "evt-seed-bob-second",
      }),
    ).toBe("already");
    expect(await store.getRoleAssignment("seed-bob-second")).toBeNull();
  });

  it("seeding one role does not block seeding a different role", async () => {
    const { store, holderIndex } = world();
    await seededAdmin(store, holderIndex, bob, "seed-bob");
    expect(
      await ensureSeededAssignment({
        store,
        holderIndex,
        principalId: bob,
        role: SUPPORT,
        scope: APPLICATION,
        assignmentId: "seed-bob-support",
        auditEventId: "evt-seed-bob-support",
      }),
    ).toBe("granted");
  });
});
