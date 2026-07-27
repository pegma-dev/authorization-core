import { createHash } from "node:crypto";

import { AccessGrantError } from "@pegma/authorization-tokens";
import { afterEach, describe, expect, it } from "vitest";

import {
  canonicalizePolicyDocument,
  createReferenceIntegration,
  REFERENCE_POLICY_CANONICAL_JSON,
  REFERENCE_POLICY_DIGEST,
  SYNTHETIC_ADMINISTRATIVE_ACTOR,
  SYNTHETIC_VERIFIED_AUTH0_CLAIMS,
} from "../examples/reference-api/reference-integration.js";

const fixedNow = 1_785_100_000_000;
const runningServers: Array<{ close: () => Promise<unknown> }> = [];

afterEach(async () => {
  await Promise.all(runningServers.splice(0).map((server) => server.close()));
});

describe("Phase 5 reference integration", () => {
  it("binds the accepted policy digest to the exact canonical policy snapshot", () => {
    const recomputed = `sha256:${createHash("sha256")
      .update(REFERENCE_POLICY_CANONICAL_JSON, "utf8")
      .digest("hex")}`;
    expect(REFERENCE_POLICY_DIGEST).toBe(recomputed);

    const changedPolicy = JSON.parse(REFERENCE_POLICY_CANONICAL_JSON) as {
      roles: { administrator: string[] };
    };
    changedPolicy.roles.administrator.push("policy.change.probe");
    const changedDigest = `sha256:${createHash("sha256")
      .update(canonicalizePolicyDocument(changedPolicy), "utf8")
      .digest("hex")}`;
    expect(changedDigest).not.toBe(REFERENCE_POLICY_DIGEST);
  });

  it("serves display-only access and proves reusable allow and deny middleware", async () => {
    const integration = await createReferenceIntegration({
      nowEpochMs: () => fixedNow,
    });
    const running = await integration.start();
    runningServers.push(running);

    const before = integration.getStripeLoadCount();
    const allowed = await fetch(`${running.url}/support/queue`);
    const denied = await fetch(`${running.url}/support/destructive`);
    const accessMe = await fetch(`${running.url}/access/me`);
    const unauthenticatedAdministration = await fetch(
      `${running.url}/admin/role-assignments/grant`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
      },
    );

    expect(allowed.status).toBe(200);
    await expect(allowed.json()).resolves.toEqual({
      status: "support_queue_visible",
    });
    expect(denied.status).toBe(403);
    await expect(denied.json()).resolves.toEqual({
      error: "forbidden",
      permission: "support.ticket.delete.any",
    });
    expect(accessMe.headers.get("cache-control")).toBe("no-store");
    expect(unauthenticatedAdministration.status).toBe(403);
    await expect(accessMe.json()).resolves.toMatchObject({
      displayOnly: true,
      principalId: "principal-reference-001",
      policyVersion: "phase5-reference-1",
    });
    expect(integration.getStripeLoadCount()).toBeGreaterThanOrEqual(before + 3);

    const decisions = integration.logRecords.filter(
      (record) => record.event === "authorization.decision",
    );
    expect(decisions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          permission: "support.queue.read",
          allowed: true,
          reason: "granted",
          scope: {
            kind: "organization",
            organizationId: "organization-reference",
          },
        }),
        expect.objectContaining({
          permission: "support.ticket.delete.any",
          allowed: false,
          reason: "not_granted",
        }),
      ]),
    );
  });

  it("uses only the safe combined mutation API and preserves audited grant/revoke history", async () => {
    const integration = await createReferenceIntegration({
      nowEpochMs: () => fixedNow,
    });
    const assignmentId = "assignment-reference-reviewer";
    const scope = {
      kind: "organization" as const,
      organizationId: "organization-reference",
    };

    const granted = await integration.adminGrantRole(
      SYNTHETIC_ADMINISTRATIVE_ACTOR,
      {
        assignmentId,
        principalId: "principal-reference-001",
        role: "reviewer",
        scope,
        auditEventId: "audit-reference-reviewer-granted",
      },
    );
    expect(granted.status).toBe("granted");

    const revoked = await integration.adminRevokeRole(
      SYNTHETIC_ADMINISTRATIVE_ACTOR,
      {
        assignmentId,
        auditEventId: "audit-reference-reviewer-revoked",
        reason: "example lifecycle completed",
      },
    );
    expect(revoked.status).toBe("revoked");

    const record = await integration.roleStore.getRoleAssignment(assignmentId);
    const history =
      await integration.roleStore.listRoleAssignmentAuditEvents(assignmentId);
    expect(record?.assignment.status).toBe("revoked");
    expect(record?.assignment.grantedBy).toEqual({
      kind: "principal",
      principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
    });
    if (record?.assignment.status === "revoked") {
      expect(record.assignment.revokedBy).toEqual({
        kind: "principal",
        principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
      });
    }
    expect(
      history.map(({ sequence, event }) => [sequence, event.kind, event.id]),
    ).toEqual([
      [1, "granted", "audit-reference-reviewer-granted"],
      [2, "revoked", "audit-reference-reviewer-revoked"],
    ]);
    expect(
      (
        await integration.roleStore.listActiveRoleAssignments(
          "principal-reference-001",
          scope,
        )
      ).some((assignment) => assignment.id === assignmentId),
    ).toBe(false);
  });

  it("binds HTTP role authorization and audit to trusted actor evidence, never request JSON", async () => {
    const integration = await createReferenceIntegration({
      nowEpochMs: () => fixedNow,
      authorizeAdministrativeRequest: async () =>
        SYNTHETIC_ADMINISTRATIVE_ACTOR,
    });
    const running = await integration.start();
    runningServers.push(running);
    const assignmentId = "assignment-reference-http-actor";
    const response = await fetch(
      `${running.url}/admin/role-assignments/grant`,
      {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({
          assignmentId,
          principalId: "principal-reference-001",
          role: "reviewer",
          scope: { kind: "application" },
          auditEventId: "audit-reference-http-actor-granted",
          actorPrincipalId: "request-body-attacker",
        }),
      },
    );

    expect(response.status).toBe(200);
    const record = await integration.roleStore.getRoleAssignment(assignmentId);
    expect(record?.assignment.grantedBy).toEqual({
      kind: "principal",
      principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
    });
    expect(JSON.stringify(record)).not.toContain("request-body-attacker");
    expect(integration.logRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "authorization.decision",
          principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
          permission: "roles.manage",
          allowed: true,
        }),
        expect.objectContaining({
          event: "role_assignment.audit",
          actorPrincipalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
          assignmentId,
        }),
      ]),
    );
  });

  it("emits safe structured logs without credentials or provider facts", async () => {
    const integration = await createReferenceIntegration();
    const grant = await integration.issueApplicationGrant();
    await integration.callProtectedModule(grant);
    await integration.adminGrantRole(SYNTHETIC_ADMINISTRATIVE_ACTOR, {
      assignmentId: "assignment-reference-auditor",
      principalId: "principal-reference-001",
      role: "auditor",
      scope: { kind: "application" },
      auditEventId: "audit-reference-auditor-granted",
    });

    const serialized = JSON.stringify(integration.logRecords);
    expect(serialized).not.toContain(grant);
    expect(serialized).not.toContain("privateKey");
    expect(serialized).not.toContain("signingKey");
    expect(serialized).not.toContain(SYNTHETIC_VERIFIED_AUTH0_CLAIMS.iss);
    expect(serialized).not.toContain(SYNTHETIC_VERIFIED_AUTH0_CLAIMS.sub);
    expect(serialized).not.toContain("feat_synthetic_pro");
    expect(serialized).not.toMatch(/"token"|"compact"|"jti"|"kid"/);
    expect(integration.logRecords).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          event: "access_grant.decision",
          allowed: true,
          permission: "support.module.call",
        }),
        expect.objectContaining({
          event: "role_assignment.audit",
          operation: "grant",
          status: "granted",
        }),
      ]),
    );
  });

  it("publishes public-only JWKS, consumes a grant once, and denies replay", async () => {
    const integration = await createReferenceIntegration();
    const running = await integration.start();
    runningServers.push(running);

    const jwksResponse = await fetch(`${running.url}/.well-known/jwks.json`);
    const jwks = (await jwksResponse.json()) as {
      keys: Array<Record<string, unknown>>;
    };
    expect(jwksResponse.status).toBe(200);
    expect(jwks.keys).toHaveLength(1);
    expect(jwks.keys[0]).not.toHaveProperty("d");

    const compact = await integration.issueApplicationGrant();
    await expect(integration.callProtectedModule(compact)).resolves.toEqual({
      status: "module_action_completed",
      principalId: "principal-reference-001",
    });
    await expect(
      integration.callProtectedModule(compact),
    ).rejects.toBeInstanceOf(AccessGrantError);
  });
});
