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
    let nowEpochMs = fixedNow;
    const integration = await createReferenceIntegration({
      nowEpochMs: () => nowEpochMs,
    });
    const scope = {
      kind: "organization" as const,
      organizationId: "organization-reference",
    };
    const grantCommand = {
      idempotencyKey: "grant-reviewer-v1",
      principalId: "principal-reference-001",
      role: "reviewer",
      scope,
    };
    const concurrentGrantResults = await Promise.all([
      integration.adminGrantRole(SYNTHETIC_ADMINISTRATIVE_ACTOR, grantCommand),
      integration.adminGrantRole(SYNTHETIC_ADMINISTRATIVE_ACTOR, grantCommand),
    ]);
    expect(concurrentGrantResults.map(({ status }) => status).sort()).toEqual([
      "granted",
      "unchanged",
    ]);
    const granted = concurrentGrantResults.find(
      ({ status }) => status === "granted",
    );
    const concurrentGrantRetry = concurrentGrantResults.find(
      ({ status }) => status === "unchanged",
    );
    if (granted === undefined || concurrentGrantRetry === undefined) {
      throw new Error("concurrent grant did not settle idempotently");
    }
    expect(concurrentGrantRetry.assignmentId).toBe(granted.assignmentId);
    expect(concurrentGrantRetry.auditEventId).toBe(granted.auditEventId);

    nowEpochMs += 1_000;
    const grantRetry = await integration.adminGrantRole(
      SYNTHETIC_ADMINISTRATIVE_ACTOR,
      grantCommand,
    );
    expect(grantRetry.status).toBe("unchanged");
    expect(grantRetry.assignmentId).toBe(granted.assignmentId);
    expect(grantRetry.auditEventId).toBe(granted.auditEventId);

    const revokeCommand = {
      idempotencyKey: "revoke-reviewer-v1",
      assignmentId: granted.assignmentId,
      reason: "example lifecycle completed",
    };
    const concurrentRevokeResults = await Promise.all([
      integration.adminRevokeRole(
        SYNTHETIC_ADMINISTRATIVE_ACTOR,
        revokeCommand,
      ),
      integration.adminRevokeRole(
        SYNTHETIC_ADMINISTRATIVE_ACTOR,
        revokeCommand,
      ),
    ]);
    expect(concurrentRevokeResults.map(({ status }) => status).sort()).toEqual([
      "revoked",
      "unchanged",
    ]);
    const revoked = concurrentRevokeResults.find(
      ({ status }) => status === "revoked",
    );
    const concurrentRevokeRetry = concurrentRevokeResults.find(
      ({ status }) => status === "unchanged",
    );
    if (revoked === undefined || concurrentRevokeRetry === undefined) {
      throw new Error("concurrent revoke did not settle idempotently");
    }
    expect(concurrentRevokeRetry.assignmentId).toBe(revoked.assignmentId);
    expect(concurrentRevokeRetry.auditEventId).toBe(revoked.auditEventId);

    nowEpochMs += 1_000;
    const revokeRetry = await integration.adminRevokeRole(
      SYNTHETIC_ADMINISTRATIVE_ACTOR,
      revokeCommand,
    );
    expect(revokeRetry.status).toBe("unchanged");
    expect(revokeRetry.assignmentId).toBe(revoked.assignmentId);
    expect(revokeRetry.auditEventId).toBe(revoked.auditEventId);

    const record = await integration.roleStore.getRoleAssignment(
      granted.assignmentId,
    );
    const history = await integration.roleStore.listRoleAssignmentAuditEvents(
      granted.assignmentId,
    );
    expect(record?.assignment.status).toBe("revoked");
    expect(record?.assignment.grantedAtEpochMs).toBe(fixedNow);
    expect(record?.assignment.grantedBy).toEqual({
      kind: "principal",
      principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
    });
    if (record?.assignment.status === "revoked") {
      expect(record.assignment.revokedBy).toEqual({
        kind: "principal",
        principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
      });
      expect(record.assignment.revokedAtEpochMs).toBe(fixedNow + 1_000);
      expect(record.assignment.reason).toBe("example lifecycle completed");
    }
    expect(
      history.map(({ sequence, event }) => [sequence, event.kind, event.id]),
    ).toEqual([
      [1, "granted", granted.auditEventId],
      [2, "revoked", revoked.auditEventId],
    ]);

    const regranted = await integration.adminGrantRole(
      SYNTHETIC_ADMINISTRATIVE_ACTOR,
      { ...grantCommand, idempotencyKey: "grant-reviewer-v2" },
    );
    expect(regranted.status).toBe("granted");
    expect(regranted.assignmentId).not.toBe(granted.assignmentId);
    await expect(
      integration.adminRevokeRole(
        SYNTHETIC_ADMINISTRATIVE_ACTOR,
        revokeCommand,
      ),
    ).resolves.toMatchObject({
      status: "unchanged",
      assignmentId: granted.assignmentId,
      auditEventId: revoked.auditEventId,
    });
    await expect(
      integration.adminGrantRole(SYNTHETIC_ADMINISTRATIVE_ACTOR, grantCommand),
    ).resolves.toMatchObject({
      status: "conflict",
      assignmentId: granted.assignmentId,
      auditEventId: granted.auditEventId,
    });
    expect(
      (
        await integration.roleStore.listActiveRoleAssignments(
          "principal-reference-001",
          scope,
        )
      ).map((assignment) => assignment.id),
    ).toContain(regranted.assignmentId);
  });

  it("rejects caller lifecycle IDs and binds HTTP mutation evidence to the trusted actor", async () => {
    const integration = await createReferenceIntegration({
      nowEpochMs: () => fixedNow,
      authorizeAdministrativeRequest: async () =>
        SYNTHETIC_ADMINISTRATIVE_ACTOR,
    });
    const running = await integration.start();
    runningServers.push(running);
    const rejected = await fetch(
      `${running.url}/admin/role-assignments/grant`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "http-actor-rejected-v1",
        },
        body: JSON.stringify({
          principalId: "principal-reference-001",
          role: "reviewer",
          scope: { kind: "application" },
          assignmentId: "assignment-request-body-attacker",
          auditEventId: "audit-reference-http-actor-granted",
          actorPrincipalId: "request-body-attacker",
        }),
      },
    );
    expect(rejected.status).toBe(400);
    await expect(rejected.json()).resolves.toEqual({
      error: "invalid_command",
    });
    await expect(
      integration.roleStore.getRoleAssignment(
        "assignment-request-body-attacker",
      ),
    ).resolves.toBeNull();

    const response = await fetch(
      `${running.url}/admin/role-assignments/grant`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "http-actor-grant-v1",
        },
        body: JSON.stringify({
          principalId: "principal-reference-001",
          role: "reviewer",
          scope: { kind: "application" },
        }),
      },
    );
    expect(response.status).toBe(200);
    const responseBody = (await response.json()) as {
      assignmentId: string;
      auditEventId: string;
      status: string;
    };
    expect(responseBody.status).toBe("granted");
    expect(responseBody.assignmentId).not.toBe(
      "assignment-request-body-attacker",
    );
    expect(responseBody.auditEventId).not.toBe(
      "audit-reference-http-actor-granted",
    );
    const record = await integration.roleStore.getRoleAssignment(
      responseBody.assignmentId,
    );
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
          assignmentId: responseBody.assignmentId,
        }),
      ]),
    );

    const exactRetry = await fetch(
      `${running.url}/admin/role-assignments/grant`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "http-actor-grant-v1",
        },
        body: JSON.stringify({
          principalId: "principal-reference-001",
          role: "reviewer",
          scope: { kind: "application" },
        }),
      },
    );
    expect(exactRetry.status).toBe(200);
    await expect(exactRetry.json()).resolves.toMatchObject({
      status: "unchanged",
      assignmentId: responseBody.assignmentId,
      auditEventId: responseBody.auditEventId,
    });

    const crossOperationReuse = await fetch(
      `${running.url}/admin/role-assignments/revoke`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "http-actor-grant-v1",
        },
        body: JSON.stringify({
          assignmentId: responseBody.assignmentId,
        }),
      },
    );
    expect(crossOperationReuse.status).toBe(409);

    const mismatchedRetry = await fetch(
      `${running.url}/admin/role-assignments/grant`,
      {
        method: "POST",
        headers: {
          "content-type": "application/json",
          "idempotency-key": "http-actor-grant-v1",
        },
        body: JSON.stringify({
          principalId: "principal-reference-001",
          role: "different-role",
          scope: { kind: "application" },
        }),
      },
    );
    expect(mismatchedRetry.status).toBe(409);
  });

  it("emits safe structured logs without credentials or provider facts", async () => {
    const integration = await createReferenceIntegration();
    const grant = await integration.issueApplicationGrant();
    await integration.callProtectedModule(grant);
    await integration.adminGrantRole(SYNTHETIC_ADMINISTRATIVE_ACTOR, {
      idempotencyKey: "grant-auditor-v1",
      principalId: "principal-reference-001",
      role: "auditor",
      scope: { kind: "application" },
    });

    const serialized = JSON.stringify(integration.logRecords);
    expect(serialized).not.toContain(grant);
    expect(serialized).not.toContain("privateKey");
    expect(serialized).not.toContain("signingKey");
    expect(serialized).not.toContain(SYNTHETIC_VERIFIED_AUTH0_CLAIMS.iss);
    expect(serialized).not.toContain(SYNTHETIC_VERIFIED_AUTH0_CLAIMS.sub);
    expect(serialized).not.toContain("feat_synthetic_pro");
    expect(serialized).not.toContain("grant-auditor-v1");
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

  it("publishes public-only JWKS, issues and consumes on one injected clock, and denies replay", async () => {
    const integration = await createReferenceIntegration({
      nowEpochMs: () => fixedNow,
    });
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
