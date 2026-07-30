/**
 * HTTP-neutral audited role administration for Authorization Core hosts.
 *
 * Extracted from the two reference hosts per `docs/ADMINISTRATION.md`. The
 * service owns grants rendering with an explicit management policy, audited
 * assign, audited revoke with the last-administrator guard, per-principal
 * lifecycle history, and the one-time seed helper. The HOST owns the HTTP
 * envelope, UI, principal lookup, rate limiting, and the authorization of
 * the service's own callers — nothing here re-checks permissions.
 */
import type {
  ActiveRoleAssignment,
  PrincipalId,
  RoleAssignmentActor,
  RoleAssignmentScope,
  RoleName,
} from "@pegma/authorization-contracts";
import type {
  AuditedRoleAssignmentMutationStore,
  RoleAssignmentReader,
  VersionedRoleAssignment,
} from "@pegma/authorization-storage";

/** The store surface the service needs: reads plus audited mutations. */
export interface RoleAdministrationStore
  extends RoleAssignmentReader, AuditedRoleAssignmentMutationStore {}

/** One superset row in the host's by-role holder index. */
export interface RoleHolderIndexRow {
  readonly principalId: PrincipalId;
  readonly assignmentId: string;
  readonly role: RoleName;
}

/**
 * The host-provided by-role index (`docs/STORAGE.md` recipe): rows are
 * written BEFORE grants, never deleted, and verified against the
 * authoritative store on every read. The index may over-report; it must
 * never under-report a grant that exists.
 */
export interface RoleHolderIndex {
  readonly record: (row: RoleHolderIndexRow) => Promise<void>;
  readonly listByRole: (
    role: RoleName,
  ) => Promise<readonly RoleHolderIndexRow[]>;
}

/** System actor written by the guard's post-revoke compensation grant. */
export const GUARD_COMPENSATION_SYSTEM_ID = "last-administrator-guard";

/** Default system actor for `ensureSeededAssignment`. */
export const SEED_SYSTEM_ID = "bootstrap";

/**
 * Explicit management policy. Assignments granted by system actors are
 * locked (`managedBy: "system"`) unless the actor is declared ONE-TIME
 * here: a one-time actor writes once and never touches the assignment
 * again, so the record is human-managed like any operator grant. The seed
 * and guard-compensation actors are one-time by definition and are always
 * included.
 */
export interface RoleManagementPolicy {
  /** The role the last-administrator guard protects. */
  readonly administratorRole: RoleName;
  /** Additional host-declared one-time system actor ids. */
  readonly oneTimeSystemActors?: ReadonlySet<string>;
}

/** Who may edit an assignment through the administration surface. */
export type ManagedBy = "system" | "human";

/** One active assignment with its management label. */
export interface AdministeredAssignment {
  readonly assignment: ActiveRoleAssignment;
  readonly managedBy: ManagedBy;
}

/** One rendered lifecycle event for the per-principal history view. */
export interface RoleAdministrationEvent {
  readonly assignmentId: string;
  readonly role: RoleName;
  readonly kind: "granted" | "revoked";
  readonly actor: RoleAssignmentActor;
  readonly atEpochMs: number;
  readonly reason?: string;
}

/** Command for an audited operator grant. */
export interface AssignRoleCommand {
  readonly principalId: PrincipalId;
  readonly role: RoleName;
  readonly scope: RoleAssignmentScope;
  readonly actor: RoleAssignmentActor;
}

/** Result of one audited operator grant. */
export type AssignRoleResult =
  | Readonly<{
      readonly status: "assigned";
      readonly record: VersionedRoleAssignment<ActiveRoleAssignment>;
    }>
  | Readonly<{ readonly status: "duplicate" }>
  | Readonly<{ readonly status: "conflict" }>;

/** Command for an audited operator revocation. */
export interface RevokeRoleCommand {
  readonly assignmentId: string;
  readonly actor: RoleAssignmentActor;
  readonly reason?: string;
}

/**
 * Result of one audited operator revocation.
 *
 * `compensated` reports that the post-revoke re-verification found no
 * active administrator remaining (a concurrent revoke on another instance
 * won its race) and the guard wrote a compensation grant restoring the
 * revoked principal. See "What the guard does NOT promise" in
 * `docs/ADMINISTRATION.md` for the honest limits of this treatment.
 */
export type RevokeRoleResult =
  | Readonly<{
      readonly status: "revoked";
      readonly compensated: boolean;
    }>
  | Readonly<{ readonly status: "not_found" }>
  | Readonly<{ readonly status: "already_revoked" }>
  | Readonly<{ readonly status: "system_managed" }>
  | Readonly<{ readonly status: "last_administrator" }>
  | Readonly<{ readonly status: "conflict" }>;

/** Constructor options for {@link createRoleAdministration}. */
export interface RoleAdministrationOptions {
  readonly store: RoleAdministrationStore;
  readonly holderIndex: RoleHolderIndex;
  readonly policy: RoleManagementPolicy;
  /** Epoch-milliseconds clock; injectable for deterministic tests. */
  readonly now?: () => number;
  /** Fresh opaque id source for grants and audit events. */
  readonly generateId?: () => string;
}

/** The administration service. One instance per application; host-gated. */
export interface RoleAdministration {
  readonly viewGrants: (
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ) => Promise<readonly AdministeredAssignment[]>;
  readonly listHistory: (
    principalId: PrincipalId,
    scope: RoleAssignmentScope,
  ) => Promise<readonly RoleAdministrationEvent[]>;
  readonly assignRole: (
    command: AssignRoleCommand,
  ) => Promise<AssignRoleResult>;
  readonly revokeRole: (
    command: RevokeRoleCommand,
  ) => Promise<RevokeRoleResult>;
  readonly anotherActiveHolderExists: (
    role: RoleName,
    excludingPrincipalId: PrincipalId | "",
  ) => Promise<boolean>;
}

const alwaysOneTime = new Set([GUARD_COMPENSATION_SYSTEM_ID, SEED_SYSTEM_ID]);

/**
 * Management label for one assignment under one policy. Grants by humans
 * are human-managed; grants by system actors are locked unless the actor
 * is one-time (the seed and guard-compensation actors always are).
 */
export function assignmentManagedBy(
  assignment: Pick<ActiveRoleAssignment, "grantedBy">,
  policy: RoleManagementPolicy,
): ManagedBy {
  const grantedBy = assignment.grantedBy;
  if (grantedBy.kind !== "system") {
    return "human";
  }
  return alwaysOneTime.has(grantedBy.systemId) ||
    (policy.oneTimeSystemActors?.has(grantedBy.systemId) ?? false)
    ? "human"
    : "system";
}

/** Options for {@link ensureSeededAssignment}. */
export interface EnsureSeededAssignmentOptions {
  readonly store: RoleAdministrationStore;
  /** When provided, the superset row is recorded before the grant. */
  readonly holderIndex?: RoleHolderIndex;
  readonly principalId: PrincipalId;
  readonly role: RoleName;
  readonly scope: RoleAssignmentScope;
  /**
   * Fresh opaque assignment id from the host's ceremony manifest, retained
   * there for retries. NOT derived from the principal or role
   * (`docs/ROLE_ASSIGNMENTS.md`); an exact replay is the store's ordinary
   * `unchanged`, and the history check below converges even a lost
   * manifest.
   */
  readonly assignmentId: string;
  /** Audit event id, equally fresh and manifest-retained. */
  readonly auditEventId: string;
  readonly systemId?: string;
  readonly now?: () => number;
}

/**
 * Seed one role for one principal, ONCE PER PRINCIPAL, EVER: any existing
 * assignment record for the role — active or revoked, whatever its
 * provenance — is durable already-seeded evidence, so a deliberate
 * revocation is never resurrected by a lingering seed input. The ceremony
 * in `docs/ADMINISTRATOR_BOOTSTRAP.md` decides whether and for whom to
 * call this; the helper is a pure function over the ports.
 */
export async function ensureSeededAssignment(
  options: EnsureSeededAssignmentOptions,
): Promise<"granted" | "already"> {
  const { store, holderIndex, principalId, role, scope } = options;
  const history = await store.listRoleAssignments(principalId, scope);
  if (history.some((assignment) => assignment.role === role)) {
    return "already";
  }
  if (holderIndex !== undefined) {
    await holderIndex.record({
      principalId,
      assignmentId: options.assignmentId,
      role,
    });
  }
  const result = await store.grantRoleAssignmentWithAudit({
    assignment: {
      id: options.assignmentId,
      principalId,
      role,
      scope,
      grantedBy: {
        kind: "system",
        systemId: options.systemId ?? SEED_SYSTEM_ID,
      },
      grantedAtEpochMs: (options.now ?? Date.now)(),
      status: "active",
    },
    auditEventId: options.auditEventId,
  });
  return result.status === "granted" ? "granted" : "already";
}

/** Creates the administration service over host-owned ports. */
export function createRoleAdministration(
  options: RoleAdministrationOptions,
): RoleAdministration {
  const { store, holderIndex, policy } = options;
  const now = options.now ?? (() => Date.now());
  const generateId = options.generateId ?? (() => crypto.randomUUID());

  const anotherActiveHolderExists = async (
    role: RoleName,
    excludingPrincipalId: PrincipalId | "",
  ): Promise<boolean> => {
    const candidates = await holderIndex.listByRole(role);
    for (const candidate of candidates) {
      if (candidate.principalId === excludingPrincipalId) {
        continue;
      }
      // Rows are candidates only; the authoritative store decides.
      const current = await store.getRoleAssignment(candidate.assignmentId);
      if (
        current !== null &&
        current.assignment.status === "active" &&
        current.assignment.role === role &&
        current.assignment.principalId === candidate.principalId
      ) {
        return true;
      }
    }
    return false;
  };

  // Revocations are serialized in-process so two concurrent revokes of the
  // two last administrators cannot interleave past the guard. The chain
  // never rejects: each task's failure belongs to its own caller.
  let revokeChain: Promise<unknown> = Promise.resolve();
  const serialized = <T>(task: () => Promise<T>): Promise<T> => {
    const next = revokeChain.then(task, task);
    revokeChain = next.catch(() => undefined);
    return next;
  };

  const revokeRole = (command: RevokeRoleCommand): Promise<RevokeRoleResult> =>
    serialized(async () => {
      const current = await store.getRoleAssignment(command.assignmentId);
      if (current === null) {
        return { status: "not_found" };
      }
      if (current.assignment.status === "revoked") {
        return { status: "already_revoked" };
      }
      const assignment = current.assignment;
      if (assignmentManagedBy(assignment, policy) === "system") {
        return { status: "system_managed" };
      }
      const guarded = assignment.role === policy.administratorRole;
      if (
        guarded &&
        !(await anotherActiveHolderExists(
          assignment.role,
          assignment.principalId,
        ))
      ) {
        return { status: "last_administrator" };
      }
      const revoked = await store.revokeRoleAssignmentWithAudit({
        assignmentId: assignment.id,
        expectedConcurrencyToken: current.concurrencyToken,
        revokedBy: command.actor,
        revokedAtEpochMs: now(),
        ...(command.reason === undefined ? {} : { reason: command.reason }),
        auditEventId: generateId(),
      });
      if (revoked.status === "not_found") {
        return { status: "not_found" };
      }
      if (revoked.status === "conflict") {
        return { status: "conflict" };
      }
      if (!guarded) {
        return { status: "revoked", compensated: false };
      }
      // Re-verify after the commit: a concurrent revoke on ANOTHER instance
      // may have removed the holder the pre-check relied on. If no active
      // administrator remains, restore the principal just revoked with a
      // one-time system actor (human-managed, revocable). The residual
      // crash window and its documented recovery live in
      // docs/ADMINISTRATION.md.
      if (await anotherActiveHolderExists(assignment.role, "")) {
        return { status: "revoked", compensated: false };
      }
      const compensationId = generateId();
      await holderIndex.record({
        principalId: assignment.principalId,
        assignmentId: compensationId,
        role: assignment.role,
      });
      await store.grantRoleAssignmentWithAudit({
        assignment: {
          id: compensationId,
          principalId: assignment.principalId,
          role: assignment.role,
          scope: assignment.scope,
          grantedBy: {
            kind: "system",
            systemId: GUARD_COMPENSATION_SYSTEM_ID,
          },
          grantedAtEpochMs: now(),
          status: "active",
        },
        auditEventId: generateId(),
      });
      return { status: "revoked", compensated: true };
    });

  const service: RoleAdministration = {
    async viewGrants(principalId, scope) {
      const active = await store.listActiveRoleAssignments(principalId, scope);
      // Self-heal the superset: an assignment the store reports but the
      // index misses (a grant that predates the index) is re-recorded so
      // the guard's by-role candidate set converges. Idempotent puts.
      for (const assignment of active) {
        await holderIndex.record({
          principalId,
          assignmentId: assignment.id,
          role: assignment.role,
        });
      }
      return active.map((assignment) => ({
        assignment,
        managedBy: assignmentManagedBy(assignment, policy),
      }));
    },

    async listHistory(principalId, scope) {
      const held = await store.listRoleAssignments(principalId, scope);
      const events: RoleAdministrationEvent[] = [];
      for (const assignment of held) {
        events.push({
          assignmentId: assignment.id,
          role: assignment.role,
          kind: "granted",
          actor: assignment.grantedBy,
          atEpochMs: assignment.grantedAtEpochMs,
        });
        if (assignment.status === "revoked") {
          events.push({
            assignmentId: assignment.id,
            role: assignment.role,
            kind: "revoked",
            actor: assignment.revokedBy,
            atEpochMs: assignment.revokedAtEpochMs,
            ...(assignment.reason === undefined
              ? {}
              : { reason: assignment.reason }),
          });
        }
      }
      events.sort((left, right) => left.atEpochMs - right.atEpochMs);
      return events;
    },

    async assignRole(command) {
      const active = await store.listActiveRoleAssignments(
        command.principalId,
        command.scope,
      );
      // Pre-check so a routine duplicate never writes an index row; the
      // store's active-tuple guarantee still decides races past this.
      if (active.some((assignment) => assignment.role === command.role)) {
        return { status: "duplicate" };
      }
      const assignmentId = generateId();
      await holderIndex.record({
        principalId: command.principalId,
        assignmentId,
        role: command.role,
      });
      const result = await store.grantRoleAssignmentWithAudit({
        assignment: {
          id: assignmentId,
          principalId: command.principalId,
          role: command.role,
          scope: command.scope,
          grantedBy: command.actor,
          grantedAtEpochMs: now(),
          status: "active",
        },
        auditEventId: generateId(),
      });
      if (result.status === "granted") {
        return { status: "assigned", record: result.record };
      }
      if (result.status === "conflict" && result.reason === "active_tuple") {
        return { status: "duplicate" };
      }
      return { status: "conflict" };
    },

    revokeRole,
    anotherActiveHolderExists,
  };
  return Object.freeze(service);
}
