import fc from "fast-check";
import { describe, expect, it } from "vitest";

import type { AccessPolicy, AccessSubject } from "./index.js";
import {
  resolveAccess,
  resolveAccessWithDiagnostics,
  serializeAccessContext,
} from "./index.js";

const DEFAULT_RUNS = 500;
const environment =
  (
    globalThis as typeof globalThis & {
      readonly process?: {
        readonly env?: Readonly<Record<string, string | undefined>>;
      };
    }
  ).process?.env ?? {};
const PROPERTY_SEEDS = {
  canonicalOutput: 0x1a2b_3c4d,
  equivalentInputs: 0x2b3c_4d5e,
  unknownFacts: 0x3c4d_5e6f,
  prototypeKeys: 0x4d5e_6f70,
  stableSerialization: 0x5e6f_7081,
} as const;

const prototypeSensitiveNames = [
  "__proto__",
  "constructor",
  "prototype",
  "toString",
  "hasOwnProperty",
] as const;

type Assignment = readonly [name: string, permissions: readonly string[]];

interface ResolverModel {
  readonly principalId: string;
  readonly version: string;
  readonly defaults: readonly string[];
  readonly roles: readonly Assignment[];
  readonly entitlements: readonly Assignment[];
  readonly roleFacts: readonly string[];
  readonly entitlementFacts: readonly string[];
  readonly selectOddRoles: boolean;
  readonly selectOddEntitlements: boolean;
}

function optionalInteger(name: string): number | undefined {
  const raw = environment[name];
  if (raw === undefined || raw.length === 0) {
    return undefined;
  }

  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed)) {
    throw new Error(`${name} must be a safe integer`);
  }

  return parsed;
}

function propertyParameters(defaultSeed: number) {
  const configuredRuns = optionalInteger("PEGMA_FC_RUNS");
  if (configuredRuns !== undefined && configuredRuns < 1) {
    throw new Error("PEGMA_FC_RUNS must be greater than zero");
  }

  const path = environment.PEGMA_FC_PATH;

  return {
    seed: optionalInteger("PEGMA_FC_SEED") ?? defaultSeed,
    numRuns: configuredRuns ?? DEFAULT_RUNS,
    ...(path === undefined || path.length === 0 ? {} : { path }),
  };
}

function canonical(values: readonly string[]): readonly string[] {
  return [...new Set(values)].sort();
}

function toRecord(
  assignments: readonly Assignment[],
): Readonly<Record<string, readonly string[]>> {
  const record = Object.create(null) as Record<string, readonly string[]>;

  for (const [name, permissions] of assignments) {
    record[name] = permissions;
  }

  return record;
}

function selectedNames(
  assignments: readonly Assignment[],
  selectOdd: boolean,
): readonly string[] {
  return assignments
    .filter((_, index) => index % 2 === (selectOdd ? 1 : 0))
    .map(([name]) => name);
}

function subjectFor(model: ResolverModel): AccessSubject {
  return {
    principalId: model.principalId,
    roles: [
      ...model.roleFacts,
      ...selectedNames(model.roles, model.selectOddRoles),
    ],
    entitlements: [
      ...model.entitlementFacts,
      ...selectedNames(model.entitlements, model.selectOddEntitlements),
    ],
  };
}

function policyFor(
  model: ResolverModel,
  roles = model.roles,
  entitlements = model.entitlements,
  defaults = model.defaults,
): AccessPolicy {
  return {
    version: model.version,
    defaults,
    roles: toRecord(roles),
    entitlements: toRecord(entitlements),
  };
}

function expectedPermissions(
  model: ResolverModel,
  subject: AccessSubject,
): readonly string[] {
  const subjectRoles = new Set(subject.roles ?? []);
  const subjectEntitlements = new Set(subject.entitlements ?? []);
  const permissions = [...model.defaults];

  for (const [name, grants] of model.roles) {
    if (subjectRoles.has(name)) {
      permissions.push(...grants);
    }
  }

  for (const [name, grants] of model.entitlements) {
    if (subjectEntitlements.has(name)) {
      permissions.push(...grants);
    }
  }

  return canonical(permissions);
}

function expectedUnknown(
  values: readonly string[],
  assignments: readonly Assignment[],
): readonly string[] {
  const policyNames = new Set(assignments.map(([name]) => name));
  return canonical(values.filter((name) => !policyNames.has(name)));
}

function duplicateAndReverse(values: readonly string[]): readonly string[] {
  return [...values, ...values].reverse();
}

function reorderAssignments(
  assignments: readonly Assignment[],
): readonly Assignment[] {
  return [...assignments]
    .reverse()
    .map(([name, permissions]) => [name, duplicateAndReverse(permissions)]);
}

function unknownNames(
  candidates: readonly string[],
  assignments: readonly Assignment[],
): readonly string[] {
  const policyNames = new Set(assignments.map(([name]) => name));

  return candidates.map((candidate, index) => {
    let unknown = candidate;
    while (policyNames.has(unknown)) {
      unknown = `${unknown}\u0000${index}`;
    }
    return unknown;
  });
}

function inheritedRecord(
  name: string,
  permissions: readonly string[],
): Record<string, readonly string[]> {
  const prototype = Object.create(null) as Record<string, readonly string[]>;
  Object.defineProperty(prototype, name, {
    configurable: true,
    enumerable: true,
    value: permissions,
  });
  return Object.create(prototype) as Record<string, readonly string[]>;
}

function withOwnAssignment(
  record: Record<string, readonly string[]>,
  name: string,
  permissions: readonly string[],
): Readonly<Record<string, readonly string[]>> {
  Object.defineProperty(record, name, {
    configurable: true,
    enumerable: true,
    value: permissions,
  });
  return record;
}

const opaqueNameArbitrary = fc.oneof(
  fc.constantFrom(...prototypeSensitiveNames),
  fc.string({ maxLength: 24 }),
);

const permissionArbitrary = fc.oneof(
  fc.constantFrom(
    "account.read.own",
    "support.queue.read",
    "support.ticket.reply.any",
    "planner.desktop.use",
  ),
  fc
    .tuple(
      fc.constantFrom("account", "support", "planner", "feature"),
      fc.nat({ max: 100_000 }),
      fc.constantFrom("read", "write", "use", "manage"),
    )
    .map(([resource, identifier, action]) => {
      return `${resource}.${identifier}.${action}`;
    }),
);

const grantsArbitrary = fc.array(permissionArbitrary, { maxLength: 8 });

const assignmentsArbitrary = fc.uniqueArray(
  fc.tuple(opaqueNameArbitrary, grantsArbitrary),
  {
    maxLength: 6,
    selector: ([name]) => name,
  },
);

const resolverModelArbitrary: fc.Arbitrary<ResolverModel> = fc.record({
  principalId: fc
    .string({ maxLength: 24 })
    .map((value) => `principal:${value}`),
  version: fc.string({ maxLength: 24 }).map((value) => `version:${value}`),
  defaults: grantsArbitrary,
  roles: assignmentsArbitrary,
  entitlements: assignmentsArbitrary,
  roleFacts: fc.array(opaqueNameArbitrary, { maxLength: 8 }),
  entitlementFacts: fc.array(opaqueNameArbitrary, { maxLength: 8 }),
  selectOddRoles: fc.boolean(),
  selectOddEntitlements: fc.boolean(),
});

describe("resolveAccess properties", () => {
  it("matches an independent canonical oracle deterministically", () => {
    fc.assert(
      fc.property(resolverModelArbitrary, (model) => {
        const subject = subjectFor(model);
        const policy = policyFor(model);
        const expected = {
          principalId: model.principalId,
          policyVersion: model.version,
          roles: canonical(subject.roles ?? []),
          entitlements: canonical(subject.entitlements ?? []),
          permissions: expectedPermissions(model, subject),
        };

        expect(resolveAccess(subject, policy)).toEqual(expected);
        expect(resolveAccess(subject, policy)).toEqual(expected);
        expect(resolveAccessWithDiagnostics(subject, policy)).toEqual({
          context: expected,
          diagnostics: {
            unknownRoles: expectedUnknown(subject.roles ?? [], model.roles),
            unknownEntitlements: expectedUnknown(
              subject.entitlements ?? [],
              model.entitlements,
            ),
          },
        });
      }),
      propertyParameters(PROPERTY_SEEDS.canonicalOutput),
    );
  });

  it("is invariant to permutations, map order, and duplicates", () => {
    fc.assert(
      fc.property(resolverModelArbitrary, (model) => {
        const subject = subjectFor(model);
        const baseline = resolveAccessWithDiagnostics(
          subject,
          policyFor(model),
        );
        const equivalentSubject = {
          principalId: subject.principalId,
          roles: duplicateAndReverse(subject.roles ?? []),
          entitlements: duplicateAndReverse(subject.entitlements ?? []),
        };
        const equivalentPolicy = policyFor(
          model,
          reorderAssignments(model.roles),
          reorderAssignments(model.entitlements),
          duplicateAndReverse(model.defaults),
        );

        expect(
          resolveAccessWithDiagnostics(equivalentSubject, equivalentPolicy),
        ).toEqual(baseline);
      }),
      propertyParameters(PROPERTY_SEEDS.equivalentInputs),
    );
  });

  it("grants no permissions when arbitrary unknown facts are added", () => {
    fc.assert(
      fc.property(
        resolverModelArbitrary,
        fc.array(opaqueNameArbitrary, { maxLength: 8 }),
        fc.array(opaqueNameArbitrary, { maxLength: 8 }),
        (model, roleCandidates, entitlementCandidates) => {
          const subject = subjectFor(model);
          const policy = policyFor(model);
          const baseline = resolveAccessWithDiagnostics(subject, policy);
          const extraRoles = unknownNames(roleCandidates, model.roles);
          const extraEntitlements = unknownNames(
            entitlementCandidates,
            model.entitlements,
          );
          const withUnknownFacts = resolveAccessWithDiagnostics(
            {
              principalId: subject.principalId,
              roles: [...(subject.roles ?? []), ...extraRoles],
              entitlements: [
                ...(subject.entitlements ?? []),
                ...extraEntitlements,
              ],
            },
            policy,
          );

          expect(withUnknownFacts.context.permissions).toEqual(
            baseline.context.permissions,
          );
          expect(withUnknownFacts.context.roles).toEqual(
            canonical([...(subject.roles ?? []), ...extraRoles]),
          );
          expect(withUnknownFacts.context.entitlements).toEqual(
            canonical([...(subject.entitlements ?? []), ...extraEntitlements]),
          );
          expect(withUnknownFacts.diagnostics).toEqual({
            unknownRoles: expectedUnknown(
              [...(subject.roles ?? []), ...extraRoles],
              model.roles,
            ),
            unknownEntitlements: expectedUnknown(
              [...(subject.entitlements ?? []), ...extraEntitlements],
              model.entitlements,
            ),
          });
        },
      ),
      propertyParameters(PROPERTY_SEEDS.unknownFacts),
    );
  });

  it("ignores inherited prototype-sensitive keys and honors own keys", () => {
    fc.assert(
      fc.property(
        fc.constantFrom(...prototypeSensitiveNames),
        fc.constantFrom(...prototypeSensitiveNames),
        fc.nat({ max: 100_000 }),
        (roleName, entitlementName, identifier) => {
          const defaults = [`default.${identifier}.read`];
          const inheritedRoleGrants = [`inherited.${identifier}.role`];
          const inheritedEntitlementGrants = [
            `inherited.${identifier}.entitlement`,
          ];
          const ownRoleGrants = [`own.${identifier}.role`];
          const ownEntitlementGrants = [`own.${identifier}.entitlement`];
          const inheritedRoles = inheritedRecord(roleName, inheritedRoleGrants);
          const inheritedEntitlements = inheritedRecord(
            entitlementName,
            inheritedEntitlementGrants,
          );
          const subject = {
            principalId: `principal:${identifier}`,
            roles: [roleName],
            entitlements: [entitlementName],
          };

          const inheritedOnly = resolveAccess(subject, {
            version: `version:${identifier}`,
            defaults,
            roles: inheritedRoles,
            entitlements: inheritedEntitlements,
          });

          expect(inheritedOnly.permissions).toEqual(defaults);
          expect(inheritedOnly.permissions).not.toContain(
            inheritedRoleGrants[0],
          );
          expect(inheritedOnly.permissions).not.toContain(
            inheritedEntitlementGrants[0],
          );

          const withOwnKeys = resolveAccess(subject, {
            version: `version:${identifier}`,
            defaults,
            roles: withOwnAssignment(inheritedRoles, roleName, ownRoleGrants),
            entitlements: withOwnAssignment(
              inheritedEntitlements,
              entitlementName,
              ownEntitlementGrants,
            ),
          });

          expect(withOwnKeys.permissions).toEqual(
            canonical([...defaults, ...ownRoleGrants, ...ownEntitlementGrants]),
          );
        },
      ),
      propertyParameters(PROPERTY_SEEDS.prototypeKeys),
    );
  });

  it("serializes equivalent resolved inputs to identical JSON", () => {
    fc.assert(
      fc.property(resolverModelArbitrary, (model) => {
        const subject = subjectFor(model);
        const baseline = resolveAccess(subject, policyFor(model));
        const equivalent = resolveAccess(
          {
            principalId: subject.principalId,
            roles: duplicateAndReverse(subject.roles ?? []),
            entitlements: duplicateAndReverse(subject.entitlements ?? []),
          },
          policyFor(
            model,
            reorderAssignments(model.roles),
            reorderAssignments(model.entitlements),
            duplicateAndReverse(model.defaults),
          ),
        );

        expect(serializeAccessContext(equivalent)).toBe(
          serializeAccessContext(baseline),
        );
        expect(JSON.parse(serializeAccessContext(baseline))).toEqual(baseline);
      }),
      propertyParameters(PROPERTY_SEEDS.stableSerialization),
    );
  });
});
