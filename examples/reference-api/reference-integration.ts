/**
 * Complete, deliberately ordinary Phase 5 integration example.
 *
 * NON-PRODUCTION: identity and billing inputs are synthetic, and every Store
 * is in-memory. The Auth0-shaped claims are treated as already verified only
 * to demonstrate the post-verification projection. No token verification,
 * webhook handling, durable persistence, or production key management is
 * implemented here.
 */
import { createHash, webcrypto } from "node:crypto";
import {
  createServer,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { pathToFileURL } from "node:url";

import { identityLinkKeyFromVerifiedAuth0Claims } from "@pegma/authorization-auth0";
import type {
  AccessContext,
  ActiveRoleAssignment,
  RoleAssignmentScope,
} from "@pegma/authorization-contracts";
import { decideAccess, resolveAccess } from "@pegma/authorization-core";
import { parsePolicy } from "@pegma/authorization-policy";
import { createInMemoryStorageAdapter } from "@pegma/authorization-storage";
import {
  createStripeEntitlementAdapter,
  type StripePersistedEntitlementState,
} from "@pegma/authorization-stripe";
import {
  AccessGrantError,
  createAccessGrantIssuer,
  createAccessGrantJwks,
} from "@pegma/authorization-tokens";
import { createTestAccessGrantVerifier } from "@pegma/authorization-tokens/testing";
import { createMemoryStore } from "@pegma/storage-core";

type LogRecord = Readonly<Record<string, unknown>>;

export interface ReferenceIntegrationOptions {
  readonly nowEpochMs?: () => number;
  readonly logSink?: (record: LogRecord) => void;
  readonly authorizeAdministrativeRequest?: (
    request: IncomingMessage,
  ) =>
    | TrustedAdministrativeActor
    | null
    | Promise<TrustedAdministrativeActor | null>;
}

/**
 * Exact host principal established by trusted request authentication.
 *
 * The administration request body is never a source of this evidence.
 */
export interface TrustedAdministrativeActor {
  readonly principalId: string;
}

export interface AdminGrantRoleCommand {
  readonly assignmentId: string;
  readonly principalId: string;
  readonly role: string;
  readonly scope: RoleAssignmentScope;
  readonly auditEventId: string;
}

export interface AdminRevokeRoleCommand {
  readonly assignmentId: string;
  readonly auditEventId: string;
  readonly reason?: string;
}

interface TargetAccess {
  readonly context: AccessContext;
  readonly scope: RoleAssignmentScope;
  readonly target: {
    readonly id: string;
    readonly organizationId: string;
    readonly ownerPrincipalId: string;
  };
}

interface PermissionMiddlewareOptions {
  readonly permission: string;
  readonly resolveRequestAccess: (
    request: IncomingMessage,
  ) => Promise<TargetAccess>;
  readonly log: (record: LogRecord) => void;
  readonly protectedHandler: (
    request: IncomingMessage,
    response: ServerResponse,
    access: TargetAccess,
  ) => void | Promise<void>;
}

export const REFERENCE_APPLICATION_ID = "reference-saas";
export const REFERENCE_ISSUER = "https://authorization.example.test";
export const REFERENCE_JWKS_URL =
  "https://authorization.example.test/.well-known/jwks.json";
export const REFERENCE_AUDIENCE = "support-module";
export const SYNTHETIC_VERIFIED_AUTH0_CLAIMS = Object.freeze({
  iss: "https://synthetic-tenant.example.test/",
  sub: "auth0|synthetic-account",
});
export const SYNTHETIC_ADMINISTRATIVE_ACTOR = Object.freeze({
  principalId: "principal-reference-admin-002",
});

const PRINCIPAL_ID = "principal-reference-001";
const ORGANIZATION_ID = "organization-reference";
const TARGET_ID = "ticket-reference-001";
const SIGNING_KEY_ID = "phase5-reference-key-2026-07";
const MAX_STRIPE_STATE_AGE_MS = 15 * 60 * 1_000;
const ROLE_AUTHORIZATION_LIFETIME_MS = 60_000;
const MODULE_PERMISSION = "support.module.call";

/**
 * Canonicalize the JSON data model with lexicographically sorted object keys.
 *
 * Production hosts should version and review their own equivalent procedure
 * and bind the resulting digest to every policy and deployment input that can
 * affect authorization.
 */
export function canonicalizePolicyDocument(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string") return JSON.stringify(value);
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new TypeError("policy documents require finite JSON numbers");
    }
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map(canonicalizePolicyDocument).join(",")}]`;
  }
  if (typeof value === "object") {
    const prototype = Object.getPrototypeOf(value);
    if (prototype !== Object.prototype && prototype !== null) {
      throw new TypeError("policy documents require ordinary JSON objects");
    }
    return `{${Object.keys(value)
      .sort()
      .map(
        (key) =>
          `${JSON.stringify(key)}:${canonicalizePolicyDocument(
            (value as Record<string, unknown>)[key],
          )}`,
      )
      .join(",")}}`;
  }
  throw new TypeError("policy documents must contain only JSON values");
}

export const REFERENCE_POLICY_DOCUMENT = Object.freeze({
  schemaVersion: 1,
  version: "phase5-reference-1",
  defaults: Object.freeze(["account.read.own"]),
  roles: Object.freeze({
    administrator: Object.freeze(["roles.manage", MODULE_PERMISSION]),
    support_agent: Object.freeze([
      "support.queue.read",
      "support.ticket.reply.any",
    ]),
  }),
  entitlements: Object.freeze({
    "plan.pro": Object.freeze(["support.ticket.create"]),
  }),
});
export const REFERENCE_POLICY_CANONICAL_JSON = canonicalizePolicyDocument(
  REFERENCE_POLICY_DOCUMENT,
);
export const REFERENCE_POLICY_DIGEST = `sha256:${createHash("sha256")
  .update(REFERENCE_POLICY_CANONICAL_JSON, "utf8")
  .digest("hex")}`;

// Parse the exact reviewed bytes whose digest is accepted by issuer/verifier.
const policy = parsePolicy(JSON.parse(REFERENCE_POLICY_CANONICAL_JSON));

const syntheticTargets = new Map([
  [
    TARGET_ID,
    Object.freeze({
      id: TARGET_ID,
      organizationId: ORGANIZATION_ID,
      ownerPrincipalId: PRINCIPAL_ID,
    }),
  ],
]);
const syntheticMemberships = new Set([
  JSON.stringify([PRINCIPAL_ID, ORGANIZATION_ID]),
]);

const writeJson = (
  response: ServerResponse,
  status: number,
  value: unknown,
) => {
  response.writeHead(status, {
    "cache-control": "no-store",
    "content-type": "application/json; charset=utf-8",
  });
  response.end(JSON.stringify(value));
};

const readJson = async (
  request: IncomingMessage,
): Promise<Record<string, unknown>> => {
  const chunks: Uint8Array[] = [];
  for await (const chunk of request) chunks.push(chunk);
  if (chunks.length === 0) return {};
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
};

const safeScope = (scope: RoleAssignmentScope): RoleAssignmentScope =>
  scope.kind === "application"
    ? { kind: "application" }
    : { kind: "organization", organizationId: scope.organizationId };

/**
 * Create reusable allow/deny middleware for Node's built-in HTTP server.
 *
 * The middleware resolves trusted facts on every request, records one safe
 * structured decision, and invokes the protected handler only when allowed.
 */
export const createPermissionMiddleware =
  ({
    permission,
    resolveRequestAccess,
    log,
    protectedHandler,
  }: PermissionMiddlewareOptions) =>
  async (request: IncomingMessage, response: ServerResponse) => {
    const access = await resolveRequestAccess(request);
    const decision = decideAccess(access.context, permission);
    log({
      event: "authorization.decision",
      applicationId: REFERENCE_APPLICATION_ID,
      principalId: access.context.principalId,
      policyVersion: access.context.policyVersion,
      targetId: access.target.id,
      scope: safeScope(access.scope),
      permission: decision.permission,
      allowed: decision.allowed,
      reason: decision.reason,
    });
    if (!decision.allowed) {
      writeJson(response, 403, {
        error: "forbidden",
        permission: decision.permission,
      });
      return;
    }
    await protectedHandler(request, response, access);
  };

/**
 * Build the reference host and protected module.
 *
 * All dependencies are public package entry points. The testing subpath is
 * used only for in-process HTTPS JWKS injection; production must construct
 * `createAccessGrantVerifier` with a real fixed HTTPS endpoint.
 */
export async function createReferenceIntegration(
  options: ReferenceIntegrationOptions = {},
) {
  const nowEpochMs = options.nowEpochMs ?? (() => Date.now());
  const logRecords: LogRecord[] = [];
  const log = (record: LogRecord) => {
    const detached: LogRecord = Object.freeze(structuredClone(record));
    logRecords.push(detached);
    options.logSink?.(detached);
  };
  let stripeLoads = 0;

  // NON-PRODUCTION: this read-only seed stands in for durable host identity
  // linking. The input below is synthetic and not a verified token.
  const roleStore = createInMemoryStorageAdapter({
    identityLinks: [
      {
        key: {
          issuer: SYNTHETIC_VERIFIED_AUTH0_CLAIMS.iss,
          subject: SYNTHETIC_VERIFIED_AUTH0_CLAIMS.sub,
        },
        principalId: PRINCIPAL_ID,
      },
    ],
  });

  // NON-PRODUCTION: this Map stands in for host-persisted, webhook/reconciled
  // billing state. It never implies that Authorization Core verifies Stripe
  // webhooks or owns billing persistence.
  const syntheticPersistedStripeState = new Map<
    string,
    StripePersistedEntitlementState
  >([
    [
      PRINCIPAL_ID,
      {
        principalId: PRINCIPAL_ID,
        refreshedAtEpochMs: nowEpochMs(),
        facts: {
          mode: "feature",
          activeFeatureIds: ["feat_synthetic_pro"],
        },
      },
    ],
    [
      SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
      {
        principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
        refreshedAtEpochMs: nowEpochMs(),
        facts: {
          mode: "feature",
          activeFeatureIds: [],
        },
      },
    ],
  ]);
  const stripe = createStripeEntitlementAdapter(
    [
      {
        kind: "feature",
        id: "feat_synthetic_pro",
        entitlements: ["plan.pro"],
      },
    ],
    {
      async loadPersistedEntitlementState(principalId) {
        stripeLoads += 1;
        const state = syntheticPersistedStripeState.get(principalId);
        if (state === undefined) {
          throw new Error("persisted entitlement state is missing");
        }
        return structuredClone(state);
      },
    },
    MAX_STRIPE_STATE_AGE_MS,
    nowEpochMs,
  );

  const grantSeed = async (
    assignment: ActiveRoleAssignment,
    auditEventId: string,
  ) => {
    const result = await roleStore.grantRoleAssignmentWithAudit({
      assignment,
      auditEventId,
    });
    if (result.status !== "granted" && result.status !== "unchanged") {
      throw new Error(`reference seed grant failed: ${result.reason}`);
    }
  };
  const createdAt = nowEpochMs();
  await grantSeed(
    {
      id: "assignment-reference-administrator",
      principalId: PRINCIPAL_ID,
      role: "administrator",
      scope: { kind: "application" },
      grantedBy: { kind: "system", systemId: "reference-seed" },
      grantedAtEpochMs: createdAt,
      status: "active",
    },
    "audit-reference-administrator-granted",
  );
  await grantSeed(
    {
      id: "assignment-reference-administrative-actor",
      principalId: SYNTHETIC_ADMINISTRATIVE_ACTOR.principalId,
      role: "administrator",
      scope: { kind: "application" },
      grantedBy: { kind: "system", systemId: "reference-seed" },
      grantedAtEpochMs: createdAt,
      status: "active",
    },
    "audit-reference-administrative-actor-granted",
  );
  await grantSeed(
    {
      id: "assignment-reference-support",
      principalId: PRINCIPAL_ID,
      role: "support_agent",
      scope: { kind: "organization", organizationId: ORGANIZATION_ID },
      grantedBy: { kind: "system", systemId: "reference-seed" },
      grantedAtEpochMs: createdAt,
      status: "active",
    },
    "audit-reference-support-granted",
  );

  const resolvePrincipal = async (
    verifiedClaims: Readonly<{ iss: string; sub: string }>,
  ) => {
    // The host must perform real Auth0 verification before this projection.
    const identityKey = identityLinkKeyFromVerifiedAuth0Claims(verifiedClaims);
    const principalId = await roleStore.resolvePrincipalId(identityKey);
    if (principalId === null)
      throw new Error("verified identity is not linked");
    return principalId;
  };

  const resolveApplicationAccessForPrincipal = async (principalId: string) => {
    const assignments = await roleStore.listActiveRoleAssignments(principalId, {
      kind: "application",
    });
    const entitlements = await stripe.resolveEntitlements({ principalId });
    return resolveAccess(
      {
        principalId,
        roles: assignments.map((assignment) => assignment.role),
        entitlements,
      },
      policy,
    );
  };
  const resolveApplicationAccess = async (
    verifiedClaims: Readonly<{ iss: string; sub: string }>,
  ) =>
    resolveApplicationAccessForPrincipal(
      await resolvePrincipal(verifiedClaims),
    );

  const resolveTargetAccess = async (
    verifiedClaims: Readonly<{ iss: string; sub: string }>,
    targetId: string,
  ): Promise<TargetAccess> => {
    const principalId = await resolvePrincipal(verifiedClaims);
    const target = syntheticTargets.get(targetId);
    if (target === undefined) throw new Error("target was not found");

    // The organization comes from the authoritative target, never a role,
    // access context, token, or untrusted organization selector.
    const membershipKey = JSON.stringify([principalId, target.organizationId]);
    if (!syntheticMemberships.has(membershipKey)) {
      throw new Error("principal is not a current organization member");
    }
    const scope = {
      kind: "organization",
      organizationId: target.organizationId,
    } as const;
    const [applicationAssignments, organizationAssignments, entitlements] =
      await Promise.all([
        roleStore.listActiveRoleAssignments(principalId, {
          kind: "application",
        }),
        roleStore.listActiveRoleAssignments(principalId, scope),
        stripe.resolveEntitlements({ principalId }),
      ]);
    const context = resolveAccess(
      {
        principalId,
        roles: [...applicationAssignments, ...organizationAssignments].map(
          (assignment) => assignment.role,
        ),
        entitlements,
      },
      policy,
    );
    return Object.freeze({ context, scope, target });
  };

  const authorizeRoleAdministration = async (
    actor: TrustedAdministrativeActor,
  ) => {
    const context = await resolveApplicationAccessForPrincipal(
      actor.principalId,
    );
    const decision = decideAccess(context, "roles.manage");
    log({
      event: "authorization.decision",
      applicationId: REFERENCE_APPLICATION_ID,
      principalId: context.principalId,
      policyVersion: context.policyVersion,
      scope: { kind: "application" },
      permission: decision.permission,
      allowed: decision.allowed,
      reason: decision.reason,
    });
    if (!decision.allowed) throw new Error("role administration denied");
    return context.principalId;
  };

  const grantRoleAsAuthorizedActor = async (
    actorPrincipalId: string,
    {
      assignmentId,
      principalId,
      role,
      scope,
      auditEventId,
    }: AdminGrantRoleCommand,
  ) => {
    const result = await roleStore.grantRoleAssignmentWithAudit({
      assignment: {
        id: assignmentId,
        principalId,
        role,
        scope,
        grantedBy: { kind: "principal", principalId: actorPrincipalId },
        grantedAtEpochMs: nowEpochMs(),
        status: "active",
      },
      auditEventId,
    });
    log({
      event: "role_assignment.audit",
      applicationId: REFERENCE_APPLICATION_ID,
      operation: "grant",
      actorPrincipalId,
      assignmentId,
      auditEventId,
      principalId,
      role,
      scope: safeScope(scope),
      status: result.status,
      ...(result.status === "conflict" ? { reason: result.reason } : {}),
      ...(result.status === "granted" || result.status === "unchanged"
        ? {
            auditSequence: result.auditRecord.sequence,
            auditKind: result.auditRecord.event.kind,
          }
        : {}),
    });
    return result;
  };

  const adminGrantRole = async (
    actor: TrustedAdministrativeActor,
    command: AdminGrantRoleCommand,
  ) =>
    grantRoleAsAuthorizedActor(
      await authorizeRoleAdministration(actor),
      command,
    );

  const revokeRoleAsAuthorizedActor = async (
    actorPrincipalId: string,
    { assignmentId, auditEventId, reason }: AdminRevokeRoleCommand,
  ) => {
    const existing = await roleStore.getRoleAssignment(assignmentId);
    if (existing === null) return Object.freeze({ status: "not_found" });
    const result = await roleStore.revokeRoleAssignmentWithAudit({
      assignmentId,
      expectedConcurrencyToken: existing.concurrencyToken,
      revokedBy: { kind: "principal", principalId: actorPrincipalId },
      revokedAtEpochMs: nowEpochMs(),
      ...(reason === undefined ? {} : { reason }),
      auditEventId,
    });
    log({
      event: "role_assignment.audit",
      applicationId: REFERENCE_APPLICATION_ID,
      operation: "revoke",
      actorPrincipalId,
      assignmentId,
      auditEventId,
      status: result.status,
      ...(result.status === "conflict" ? { reason: result.reason } : {}),
      ...(result.status === "revoked" || result.status === "unchanged"
        ? {
            auditSequence: result.auditRecord.sequence,
            auditKind: result.auditRecord.event.kind,
          }
        : {}),
    });
    return result;
  };

  const adminRevokeRole = async (
    actor: TrustedAdministrativeActor,
    command: AdminRevokeRoleCommand,
  ) =>
    revokeRoleAsAuthorizedActor(
      await authorizeRoleAdministration(actor),
      command,
    );

  // Runtime-generated P-256 material: no private key is committed or logged.
  const generatedKeys = await webcrypto.subtle.generateKey(
    { name: "ECDSA", namedCurve: "P-256" },
    true,
    ["sign", "verify"],
  );
  const privateKey = generatedKeys.privateKey as unknown as CryptoKey;
  const publicKey = generatedKeys.publicKey as unknown as CryptoKey;
  const jwks = await createAccessGrantJwks([
    { kid: SIGNING_KEY_ID, key: publicKey },
  ]);
  const issuerStore = createMemoryStore();
  const issuer = createAccessGrantIssuer(
    {
      issuer: REFERENCE_ISSUER,
      applicationId: REFERENCE_APPLICATION_ID,
      kid: SIGNING_KEY_ID,
      signingKey: privateKey,
      audiences: { [REFERENCE_AUDIENCE]: [MODULE_PERMISSION] },
      acceptedPolicies: [
        { version: policy.version, digest: REFERENCE_POLICY_DIGEST },
      ],
      sourceReader: async (
        verifiedClaims: Readonly<{ iss: string; sub: string }>,
      ) => ({
        applicationId: REFERENCE_APPLICATION_ID,
        context: await resolveApplicationAccess(verifiedClaims),
        policyDigest: REFERENCE_POLICY_DIGEST,
        scope: { kind: "application" },
        maximumLifetimeMs: ROLE_AUTHORIZATION_LIFETIME_MS,
      }),
    },
    issuerStore,
  );

  // LOCAL TEST/DEMO ONLY: production uses createAccessGrantVerifier and fetches
  // the immutable fixed HTTPS URL. This injected fetch never weakens that API.
  const verifier = createTestAccessGrantVerifier(
    {
      issuer: REFERENCE_ISSUER,
      applicationId: REFERENCE_APPLICATION_ID,
      audience: REFERENCE_AUDIENCE,
      allowedPermissions: [MODULE_PERMISSION],
      acceptedPolicies: [
        { version: policy.version, digest: REFERENCE_POLICY_DIGEST },
      ],
      jwksUrl: REFERENCE_JWKS_URL,
      jwksCacheAgeMs: 60_000,
    },
    createMemoryStore(),
    {
      verifierWallNowEpochMs: nowEpochMs,
      replayStoreNowEpochMs: nowEpochMs,
      jwksMonotonicNowMs: () => performance.now(),
      fetchJwks: async () => ({
        body: JSON.stringify(jwks),
        finalUrl: REFERENCE_JWKS_URL,
      }),
    },
  );

  const issueApplicationGrant = async () => {
    const read = await issuer.readSourceAuthorization(
      SYNTHETIC_VERIFIED_AUTH0_CLAIMS,
    );
    const source = issuer.bindSourceAuthorization(read);
    return issuer.issue({
      audience: REFERENCE_AUDIENCE,
      requestedPermissions: [MODULE_PERMISSION],
      source,
    });
  };

  const callProtectedModule = async (compactGrant: string) => {
    let verified;
    try {
      verified = await verifier.verifyAndConsume(compactGrant);
    } catch (error) {
      if (error instanceof AccessGrantError) {
        log({
          event: "access_grant.denied",
          applicationId: REFERENCE_APPLICATION_ID,
          audience: REFERENCE_AUDIENCE,
          reason: "verification_or_replay_failed",
        });
      }
      throw error;
    }
    const decision = {
      allowed: verified.permissions.includes(MODULE_PERMISSION),
      permission: MODULE_PERMISSION,
      reason: verified.permissions.includes(MODULE_PERMISSION)
        ? "granted"
        : "not_granted",
    };
    log({
      event: "access_grant.decision",
      applicationId: verified.applicationId,
      audience: verified.audience,
      principalId: verified.principalId,
      policyVersion: verified.policyVersion,
      permission: decision.permission,
      allowed: decision.allowed,
      reason: decision.reason,
    });
    if (!decision.allowed) throw new AccessGrantError();
    return Object.freeze({
      status: "module_action_completed",
      principalId: verified.principalId,
    });
  };

  const resolveHttpAccess = async (request: IncomingMessage) => {
    const url = new URL(request.url ?? "/", "http://reference.invalid");
    return resolveTargetAccess(
      SYNTHETIC_VERIFIED_AUTH0_CLAIMS,
      url.searchParams.get("targetId") ?? TARGET_ID,
    );
  };
  const allowMiddleware = createPermissionMiddleware({
    permission: "support.queue.read",
    resolveRequestAccess: resolveHttpAccess,
    log,
    protectedHandler: async (_request, response) =>
      writeJson(response, 200, { status: "support_queue_visible" }),
  });
  const denyMiddleware = createPermissionMiddleware({
    permission: "support.ticket.delete.any",
    resolveRequestAccess: resolveHttpAccess,
    log,
    protectedHandler: async (_request, response) =>
      writeJson(response, 200, { status: "unexpected" }),
  });

  const requestHandler = async (
    request: IncomingMessage,
    response: ServerResponse,
  ) => {
    try {
      const url = new URL(request.url ?? "/", "http://reference.invalid");
      if (request.method === "GET" && url.pathname === "/access/me") {
        const access = await resolveHttpAccess(request);
        // Display-only convenience output. It is never accepted back as
        // authority and may be filtered further by a real product.
        writeJson(response, 200, {
          displayOnly: true,
          principalId: access.context.principalId,
          policyVersion: access.context.policyVersion,
          permissions: access.context.permissions.filter(
            (permission) =>
              permission === "account.read.own" ||
              permission === "support.queue.read" ||
              permission === "support.ticket.create" ||
              permission === "support.ticket.reply.any",
          ),
        });
        return;
      }
      if (request.method === "GET" && url.pathname === "/support/queue") {
        await allowMiddleware(request, response);
        return;
      }
      if (request.method === "GET" && url.pathname === "/support/destructive") {
        await denyMiddleware(request, response);
        return;
      }
      if (
        request.method === "GET" &&
        url.pathname === "/.well-known/jwks.json"
      ) {
        writeJson(response, 200, jwks);
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/admin/role-assignments/grant"
      ) {
        const actor =
          options.authorizeAdministrativeRequest === undefined
            ? null
            : await options.authorizeAdministrativeRequest(request);
        if (actor === null) {
          writeJson(response, 403, { error: "forbidden" });
          return;
        }
        let actorPrincipalId: string;
        try {
          actorPrincipalId = await authorizeRoleAdministration(actor);
        } catch {
          writeJson(response, 403, { error: "forbidden" });
          return;
        }
        const command = (await readJson(
          request,
        )) as unknown as AdminGrantRoleCommand;
        writeJson(
          response,
          200,
          await grantRoleAsAuthorizedActor(actorPrincipalId, command),
        );
        return;
      }
      if (
        request.method === "POST" &&
        url.pathname === "/admin/role-assignments/revoke"
      ) {
        const actor =
          options.authorizeAdministrativeRequest === undefined
            ? null
            : await options.authorizeAdministrativeRequest(request);
        if (actor === null) {
          writeJson(response, 403, { error: "forbidden" });
          return;
        }
        let actorPrincipalId: string;
        try {
          actorPrincipalId = await authorizeRoleAdministration(actor);
        } catch {
          writeJson(response, 403, { error: "forbidden" });
          return;
        }
        const command = (await readJson(
          request,
        )) as unknown as AdminRevokeRoleCommand;
        writeJson(
          response,
          200,
          await revokeRoleAsAuthorizedActor(actorPrincipalId, command),
        );
        return;
      }
      writeJson(response, 404, { error: "not_found" });
    } catch {
      writeJson(response, 500, { error: "request_failed_closed" });
    }
  };

  return Object.freeze({
    policy,
    jwks,
    logRecords,
    roleStore,
    resolveApplicationAccess,
    resolveTargetAccess,
    adminGrantRole,
    adminRevokeRole,
    issueApplicationGrant,
    callProtectedModule,
    getStripeLoadCount: () => stripeLoads,
    async start(port = 0) {
      const server = createServer((request, response) => {
        void requestHandler(request, response);
      });
      await new Promise<void>((resolve, reject) => {
        server.once("error", reject);
        server.listen(port, "127.0.0.1", resolve);
      });
      const address = server.address();
      if (address === null || typeof address === "string") {
        throw new Error("reference server did not expose a TCP address");
      }
      return Object.freeze({
        url: `http://127.0.0.1:${address.port}`,
        close: () =>
          new Promise<void>((resolve, reject) =>
            server.close((error) =>
              error === undefined ? resolve() : reject(error),
            ),
          ),
      });
    },
  });
}

async function runDemo() {
  const integration = await createReferenceIntegration();
  if (process.argv.includes("--serve")) {
    const running = await integration.start(3000);
    console.log(
      JSON.stringify({
        status: "reference_api_listening",
        url: running.url,
        warning:
          "NON-PRODUCTION: synthetic inputs and ephemeral memory storage",
      }),
    );
    return;
  }

  const running = await integration.start();
  try {
    const allowed = await fetch(`${running.url}/support/queue`);
    const denied = await fetch(`${running.url}/support/destructive`);
    const me = await fetch(`${running.url}/access/me`);
    const compactGrant = await integration.issueApplicationGrant();
    const moduleResult = await integration.callProtectedModule(compactGrant);
    let replayDenied = false;
    try {
      await integration.callProtectedModule(compactGrant);
    } catch (error) {
      replayDenied = error instanceof AccessGrantError;
    }
    console.log(
      JSON.stringify(
        {
          warning:
            "NON-PRODUCTION: synthetic provider inputs and ephemeral memory storage",
          allowStatus: allowed.status,
          denyStatus: denied.status,
          accessMe: await me.json(),
          moduleResult,
          replayDenied,
          logs: integration.logRecords,
        },
        null,
        2,
      ),
    );
  } finally {
    await running.close();
  }
}

if (
  process.argv[1] !== undefined &&
  import.meta.url === pathToFileURL(process.argv[1]).href
) {
  await runDemo();
}
