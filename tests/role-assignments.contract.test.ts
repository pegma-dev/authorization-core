import { describe, expect, expectTypeOf, it } from "vitest";

import type {
  AccessContext,
  AccessSubject,
  ActiveRoleAssignment,
  PrincipalId,
  RoleAssignment,
  RoleAssignmentActor,
  RoleAssignmentId,
  RoleAssignmentScope,
  RoleName,
} from "@pegma/authorization-contracts";
import { resolveAccess } from "@pegma/authorization-core";

const principalId = "account_123";
const otherPrincipalId = "account_456";
const organizationId = "organization_alpha";
const otherOrganizationId = "organization_beta";
const supportRole = "support";
const adminRole = "admin";
const otherOrganizationRole = "billing";
const grantor: RoleAssignmentActor = {
  kind: "principal",
  principalId: "account_admin",
};
const lifecycleSystem: RoleAssignmentActor = {
  kind: "system",
  systemId: "role-reconciliation",
};
const applicationScope: RoleAssignmentScope = { kind: "application" };
const organizationScope: RoleAssignmentScope = {
  kind: "organization",
  organizationId,
};

type GrantInput = Omit<ActiveRoleAssignment, "status">;

const scopesEqual = (
  left: RoleAssignmentScope,
  right: RoleAssignmentScope,
): boolean =>
  left.kind === "application"
    ? right.kind === "application"
    : right.kind === "organization" &&
      left.organizationId === right.organizationId;

const actorsEqual = (
  left: RoleAssignmentActor,
  right: RoleAssignmentActor,
): boolean =>
  left.kind === "principal"
    ? right.kind === "principal" && left.principalId === right.principalId
    : right.kind === "system" && left.systemId === right.systemId;

const grantsEqual = (assignment: RoleAssignment, input: GrantInput): boolean =>
  assignment.id === input.id &&
  assignment.principalId === input.principalId &&
  assignment.role === input.role &&
  scopesEqual(assignment.scope, input.scope) &&
  actorsEqual(assignment.grantedBy, input.grantedBy) &&
  assignment.grantedAtEpochMs === input.grantedAtEpochMs;

const requireTimestamp = (value: number, field: string): void => {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error(`${field} must be a non-negative safe integer`);
  }
};

/**
 * Test-local lifecycle fixture. It demonstrates the persistence contract
 * without adding a storage port or mutation service to a public package.
 */
class TestRoleAssignments {
  readonly #assignments = new Map<RoleAssignmentId, RoleAssignment>();

  grant(input: GrantInput): RoleAssignment {
    requireTimestamp(input.grantedAtEpochMs, "grantedAtEpochMs");

    const existing = this.#assignments.get(input.id);
    if (existing !== undefined) {
      if (grantsEqual(existing, input)) {
        return existing;
      }
      throw new Error("assignment ID already records different lifecycle data");
    }

    if (
      [...this.#assignments.values()].some(
        (assignment) =>
          assignment.status === "active" &&
          assignment.principalId === input.principalId &&
          assignment.role === input.role &&
          scopesEqual(assignment.scope, input.scope),
      )
    ) {
      throw new Error("exact principal, role, and scope is already active");
    }

    const assignment: ActiveRoleAssignment = {
      ...input,
      scope: { ...input.scope },
      grantedBy: { ...input.grantedBy },
      status: "active",
    };
    this.#assignments.set(input.id, assignment);
    return assignment;
  }

  revoke(
    expectedAssignmentId: RoleAssignmentId,
    revokedBy: RoleAssignmentActor,
    revokedAtEpochMs: number,
    reason?: string,
  ): RoleAssignment {
    requireTimestamp(revokedAtEpochMs, "revokedAtEpochMs");
    const assignment = this.#assignments.get(expectedAssignmentId);
    if (assignment === undefined || assignment.status !== "active") {
      throw new Error("expected active assignment ID does not exist");
    }
    if (revokedAtEpochMs < assignment.grantedAtEpochMs) {
      throw new Error("revocation cannot precede its grant");
    }

    const revoked: RoleAssignment = {
      ...assignment,
      status: "revoked",
      revokedBy: { ...revokedBy },
      revokedAtEpochMs,
      ...(reason === undefined ? {} : { reason }),
    };
    this.#assignments.set(expectedAssignmentId, revoked);
    return revoked;
  }

  selectActiveRoles(
    selectedPrincipalId: PrincipalId,
    selectedScope: RoleAssignmentScope,
  ): readonly RoleName[] {
    return [...this.#assignments.values()]
      .filter(
        (assignment) =>
          assignment.status === "active" &&
          assignment.principalId === selectedPrincipalId &&
          scopesEqual(assignment.scope, selectedScope),
      )
      .map(({ role }) => role)
      .sort();
  }

  get(id: RoleAssignmentId): RoleAssignment | undefined {
    return this.#assignments.get(id);
  }
}

const grant = (
  id: RoleAssignmentId,
  overrides: Partial<GrantInput> = {},
): GrantInput => ({
  id,
  principalId,
  role: supportRole,
  scope: applicationScope,
  grantedBy: grantor,
  grantedAtEpochMs: 1_700_000_000_000,
  ...overrides,
});

describe("RoleAssignment public contract", () => {
  it("exposes exact discriminated lifecycle states and actor variants", () => {
    expectTypeOf<RoleAssignment["status"]>().toEqualTypeOf<
      "active" | "revoked"
    >();
    expectTypeOf<RoleAssignmentActor["kind"]>().toEqualTypeOf<
      "principal" | "system"
    >();
    expectTypeOf<RoleAssignmentScope["kind"]>().toEqualTypeOf<
      "application" | "organization"
    >();
  });
});

describe("role-assignment lifecycle fixture", () => {
  it("selects only an exact principal, role, and scope tuple", () => {
    const assignments = new TestRoleAssignments();
    assignments.grant(grant("grant_app_support"));
    assignments.grant(
      grant("grant_other_principal", { principalId: otherPrincipalId }),
    );
    assignments.grant(
      grant("grant_other_org", {
        role: adminRole,
        scope: { kind: "organization", organizationId: otherOrganizationId },
      }),
    );

    expect(
      assignments.selectActiveRoles(principalId, applicationScope),
    ).toEqual([supportRole]);
    expect(
      assignments.selectActiveRoles(principalId, organizationScope),
    ).toEqual([]);
  });

  it("composes application and exact-organization roles only after host scope selection", () => {
    const assignments = new TestRoleAssignments();
    assignments.grant(grant("grant_app_support"));
    assignments.grant(
      grant("grant_org_admin", {
        role: adminRole,
        scope: organizationScope,
      }),
    );
    assignments.grant(
      grant("grant_other_org_admin", {
        role: otherOrganizationRole,
        scope: { kind: "organization", organizationId: otherOrganizationId },
      }),
    );

    // The host derived organizationId from the target and validated membership.
    const roles = [
      ...assignments.selectActiveRoles(principalId, applicationScope),
      ...assignments.selectActiveRoles(principalId, organizationScope),
    ];

    expect(roles).toEqual([supportRole, adminRole]);
    expect(roles).not.toContain(otherOrganizationRole);
  });

  it("excludes revoked assignments while preserving immutable grant evidence", () => {
    const assignments = new TestRoleAssignments();
    const original = assignments.grant(grant("grant_then_revoke"));
    const revoked = assignments.revoke(
      original.id,
      lifecycleSystem,
      1_700_000_001_000,
      "staff access removed",
    );

    expect(
      assignments.selectActiveRoles(principalId, applicationScope),
    ).toEqual([]);
    expect(revoked).toEqual({
      ...original,
      status: "revoked",
      revokedBy: lifecycleSystem,
      revokedAtEpochMs: 1_700_000_001_000,
      reason: "staff access removed",
    });
  });

  it("treats an identical grant as idempotent and rejects conflicting duplicates", () => {
    const assignments = new TestRoleAssignments();
    const input = grant("idempotent_grant");

    expect(assignments.grant(input)).toBe(assignments.grant(input));
    expect(() => assignments.grant(grant("different_id"))).toThrow(
      "exact principal, role, and scope is already active",
    );

    const revoked = assignments.revoke(
      input.id,
      lifecycleSystem,
      1_700_000_001_000,
    );
    expect(assignments.grant(input)).toBe(revoked);
    expect(revoked.status).toBe("revoked");
    expect(() =>
      assignments.grant(grant("idempotent_grant", { role: adminRole })),
    ).toThrow("assignment ID already records different lifecycle data");
  });

  it("revokes by exact assignment ID and makes a later regrant ABA-safe", () => {
    const assignments = new TestRoleAssignments();
    assignments.grant(grant("old_assignment"));
    assignments.revoke("old_assignment", grantor, 1_700_000_001_000);
    assignments.grant(
      grant("new_assignment", { grantedAtEpochMs: 1_700_000_002_000 }),
    );

    expect(() =>
      assignments.revoke("old_assignment", lifecycleSystem, 1_700_000_003_000),
    ).toThrow("expected active assignment ID does not exist");
    expect(
      assignments.selectActiveRoles(principalId, applicationScope),
    ).toEqual([supportRole]);
    expect(assignments.get("new_assignment")?.status).toBe("active");
  });

  it("rejects unsafe timestamps and revocation before the grant", () => {
    const assignments = new TestRoleAssignments();

    expect(() =>
      assignments.grant(grant("unsafe_time", { grantedAtEpochMs: 1.5 })),
    ).toThrow("grantedAtEpochMs must be a non-negative safe integer");

    assignments.grant(grant("ordered_time"));
    expect(() =>
      assignments.revoke("ordered_time", lifecycleSystem, 1_699_999_999_999),
    ).toThrow("revocation cannot precede its grant");
  });

  it("keeps actor metadata out of AccessSubject and AccessContext", () => {
    const assignments = new TestRoleAssignments();
    assignments.grant(grant("context_assignment"));
    const subject: AccessSubject = {
      principalId,
      roles: assignments.selectActiveRoles(principalId, applicationScope),
    };
    const context = resolveAccess(subject, {
      version: "role-assignment-contract",
      roles: { support: ["support.queue.read"] },
    });

    expect(subject).toEqual({ principalId, roles: [supportRole] });
    expect(subject).not.toHaveProperty("grantedBy");
    expect(subject).not.toHaveProperty("revokedBy");
    expect(context).toEqual({
      principalId,
      policyVersion: "role-assignment-contract",
      roles: [supportRole],
      entitlements: [],
      permissions: ["support.queue.read"],
    });
    expect(context).not.toHaveProperty("grantedBy");
    expect(context).not.toHaveProperty("revokedBy");
    expectTypeOf(context).toEqualTypeOf<AccessContext>();
  });

  it("keeps unknown roles deny-by-default", () => {
    const assignments = new TestRoleAssignments();
    assignments.grant(grant("unknown_role", { role: "future-unmapped-role" }));

    const context = resolveAccess(
      {
        principalId,
        roles: assignments.selectActiveRoles(principalId, applicationScope),
      },
      {
        version: "unknown-role-contract",
        defaults: ["account.read.own"],
        roles: { support: ["support.queue.read"] },
      },
    );

    expect(context.roles).toEqual(["future-unmapped-role"]);
    expect(context.permissions).toEqual(["account.read.own"]);
  });
});
