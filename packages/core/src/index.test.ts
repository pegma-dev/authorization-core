import { describe, expect, it } from "vitest";

import {
  decideAccess,
  hasPermission,
  resolveAccess,
  resolveAccessWithDiagnostics,
  serializeAccessContext,
} from "./index.js";
import type { AccessContext } from "./index.js";

const policy = {
  version: "test-1",
  defaults: ["account.read.own"],
  roles: {
    support: [
      "support.queue.read",
      "support.ticket.reply.any",
      "account.read.own",
    ],
    admin: ["access.roles.manage"],
  },
  entitlements: {
    "plan.pro": ["support.ticket.create", "support.ticket.read.own"],
    "plan.advisor": [
      "support.ticket.create",
      "support.ticket.read.own",
      "advisor.features.use",
    ],
  },
} as const;

describe("resolveAccess", () => {
  it("combines and deduplicates defaults, roles, and entitlements", () => {
    const context = resolveAccess(
      {
        principalId: "principal-1",
        roles: ["support", "support"],
        entitlements: ["plan.pro"],
      },
      policy,
    );

    expect(context).toEqual({
      principalId: "principal-1",
      policyVersion: "test-1",
      roles: ["support"],
      entitlements: ["plan.pro"],
      permissions: [
        "account.read.own",
        "support.queue.read",
        "support.ticket.create",
        "support.ticket.read.own",
        "support.ticket.reply.any",
      ],
    });
  });

  it("models a RetireGolden account with paid and staff access", () => {
    // RetireGolden owns this boundary translation. This fixture assumes the
    // product has already collapsed provider lifecycle state into an
    // active-or-absent tier.
    const account = {
      accountId: "f8ea9308-1bdb-49b0-89a9-eef2af28eb6b",
      subject: "auth0|retiregolden-test-account",
      resolvedTier: "advisor",
    } as const;
    const assignedStaffRoles = ["admin"] as const;
    const activeEntitlement = `plan.${account.resolvedTier}` as const;

    const context = resolveAccess(
      {
        principalId: account.accountId,
        roles: assignedStaffRoles,
        entitlements: [activeEntitlement],
      },
      policy,
    );

    expect(context.principalId).toBe(account.accountId);
    expect(context.principalId).not.toBe(account.subject);
    expect(context.roles).toEqual(["admin"]);
    expect(context.entitlements).toEqual(["plan.advisor"]);
    expect(hasPermission(context, "access.roles.manage")).toBe(true);
    expect(hasPermission(context, "advisor.features.use")).toBe(true);
    expect(decideAccess(context, "support.queue.read")).toEqual({
      allowed: false,
      permission: "support.queue.read",
      reason: "not_granted",
    });
  });

  it("retains unknown facts but grants nothing from them", () => {
    const context = resolveAccess(
      {
        principalId: "principal-3",
        roles: ["unknown-role"],
        entitlements: ["unknown-entitlement"],
      },
      policy,
    );

    expect(context.roles).toEqual(["unknown-role"]);
    expect(context.entitlements).toEqual(["unknown-entitlement"]);
    expect(context.permissions).toEqual(["account.read.own"]);
    expect(decideAccess(context, "support.queue.read")).toEqual({
      allowed: false,
      permission: "support.queue.read",
      reason: "not_granted",
    });
  });

  it("treats inherited policy keys as unknown facts", () => {
    const context = resolveAccess(
      {
        principalId: "principal-prototype-names",
        roles: ["constructor", "__proto__"],
        entitlements: ["toString", "hasOwnProperty"],
      },
      policy,
    );

    expect(context.roles).toEqual(["__proto__", "constructor"]);
    expect(context.entitlements).toEqual(["hasOwnProperty", "toString"]);
    expect(context.permissions).toEqual(["account.read.own"]);
  });

  it("rejects empty identifiers and permission names", () => {
    expect(() => resolveAccess({ principalId: " " }, policy)).toThrowError(
      "principalId must not be empty",
    );

    const context = resolveAccess({ principalId: "principal-4" }, policy);
    expect(() => hasPermission(context, "")).toThrowError(
      "permission must not be empty",
    );
  });
});

describe("resolveAccessWithDiagnostics", () => {
  it("reports canonical unknown facts without changing the access context", () => {
    const subject = {
      principalId: "principal-diagnostics",
      roles: ["unknown-z", "support", "unknown-a", "unknown-z", "plan.pro"],
      entitlements: ["support", "plan.pro", "unknown-entitlement"],
    } as const;

    const resolution = resolveAccessWithDiagnostics(subject, policy);

    expect(resolution.context).toEqual(resolveAccess(subject, policy));
    expect(resolution.context.permissions).toEqual([
      "account.read.own",
      "support.queue.read",
      "support.ticket.create",
      "support.ticket.read.own",
      "support.ticket.reply.any",
    ]);
    expect(resolution.diagnostics).toEqual({
      unknownRoles: ["plan.pro", "unknown-a", "unknown-z"],
      unknownEntitlements: ["support", "unknown-entitlement"],
    });
  });

  it("treats own empty assignments as known and missing maps as unknown", () => {
    const knownEmpty = resolveAccessWithDiagnostics(
      {
        principalId: "principal-empty",
        roles: ["observer"],
        entitlements: ["plan.free"],
      },
      {
        version: "empty-1",
        defaults: ["account.read.own"],
        roles: { observer: [] },
        entitlements: { "plan.free": [] },
      },
    );
    const missingMaps = resolveAccessWithDiagnostics(
      {
        principalId: "principal-missing",
        roles: ["observer"],
        entitlements: ["plan.free"],
      },
      { version: "missing-1", defaults: ["account.read.own"] },
    );

    expect(knownEmpty.diagnostics).toEqual({
      unknownRoles: [],
      unknownEntitlements: [],
    });
    expect(knownEmpty.context.permissions).toEqual(["account.read.own"]);
    expect(missingMaps.diagnostics).toEqual({
      unknownRoles: ["observer"],
      unknownEntitlements: ["plan.free"],
    });
    expect(missingMaps.context.permissions).toEqual(["account.read.own"]);
  });

  it("ignores inherited prototype keys and recognizes explicit own keys", () => {
    const rolePrototype = { constructor: ["inherited.role"] };
    const entitlementPrototype = { toString: ["inherited.entitlement"] };
    const roles = Object.create(rolePrototype) as Record<
      string,
      readonly string[]
    >;
    const entitlements = Object.create(entitlementPrototype) as Record<
      string,
      readonly string[]
    >;
    Object.defineProperty(roles, "__proto__", {
      enumerable: true,
      value: ["own.role"],
    });
    Object.defineProperty(entitlements, "hasOwnProperty", {
      enumerable: true,
      value: ["own.entitlement"],
    });

    const resolution = resolveAccessWithDiagnostics(
      {
        principalId: "principal-prototypes",
        roles: ["constructor", "__proto__"],
        entitlements: ["toString", "hasOwnProperty"],
      },
      {
        version: "prototype-1",
        roles,
        entitlements,
      },
    );

    expect(resolution.context.permissions).toEqual([
      "own.entitlement",
      "own.role",
    ]);
    expect(resolution.diagnostics).toEqual({
      unknownRoles: ["constructor"],
      unknownEntitlements: ["toString"],
    });
  });

  it("returns a deeply frozen resolution, including empty diagnostics", () => {
    const resolution = resolveAccessWithDiagnostics(
      { principalId: "principal-frozen" },
      { version: "frozen-1" },
    );

    expect(Object.isFrozen(resolution)).toBe(true);
    expect(Object.isFrozen(resolution.context)).toBe(true);
    expect(Object.isFrozen(resolution.context.roles)).toBe(true);
    expect(Object.isFrozen(resolution.context.entitlements)).toBe(true);
    expect(Object.isFrozen(resolution.context.permissions)).toBe(true);
    expect(Object.isFrozen(resolution.diagnostics)).toBe(true);
    expect(Object.isFrozen(resolution.diagnostics.unknownRoles)).toBe(true);
    expect(Object.isFrozen(resolution.diagnostics.unknownEntitlements)).toBe(
      true,
    );
    expect(
      Reflect.set(resolution.diagnostics, "unknownRoles", ["changed"]),
    ).toBe(false);
  });
});

describe("serializeAccessContext", () => {
  it("emits the five access-context fields in stable compact JSON", () => {
    const context = resolveAccess(
      {
        principalId: "principal-serialization",
        roles: ["support"],
        entitlements: ["plan.pro"],
      },
      policy,
    );

    expect(serializeAccessContext(context)).toBe(
      '{"principalId":"principal-serialization","policyVersion":"test-1","roles":["support"],"entitlements":["plan.pro"],"permissions":["account.read.own","support.queue.read","support.ticket.create","support.ticket.read.own","support.ticket.reply.any"]}',
    );
  });

  it("keeps empty arrays and round-trips escaped and Unicode strings", () => {
    const empty = resolveAccess(
      { principalId: "principal-empty" },
      { version: "empty-1" },
    );
    const loneSurrogate = "\ud800";
    const context: AccessContext = {
      principalId: 'principal-"quoted"\n',
      policyVersion: "version-雪-😀",
      roles: ["back\\slash", loneSurrogate],
      entitlements: [],
      permissions: ["feature.read\town"],
    };

    expect(serializeAccessContext(empty)).toBe(
      '{"principalId":"principal-empty","policyVersion":"empty-1","roles":[],"entitlements":[],"permissions":[]}',
    );
    expect(JSON.parse(serializeAccessContext(context))).toEqual(context);
    expect(serializeAccessContext(context)).toContain("\\ud800");
  });

  it("projects fresh data so extra fields and hostile toJSON hooks are ignored", () => {
    const roles = ["support"];
    Object.defineProperty(roles, "toJSON", {
      value: () => ["admin"],
    });
    const context = {
      principalId: "principal-projected",
      policyVersion: "projected-1",
      roles,
      entitlements: ["plan.pro"],
      permissions: ["account.read.own"],
      diagnostics: { unknownRoles: ["admin"] },
      toJSON: () => ({ principalId: "attacker-controlled" }),
    };

    expect(serializeAccessContext(context)).toBe(
      '{"principalId":"principal-projected","policyVersion":"projected-1","roles":["support"],"entitlements":["plan.pro"],"permissions":["account.read.own"]}',
    );
  });

  it("ignores inherited object and array toJSON hooks", () => {
    const context = resolveAccess(
      {
        principalId: "principal-inherited-hooks",
        roles: ["support"],
        entitlements: ["plan.pro"],
      },
      policy,
    );
    const expected =
      '{"principalId":"principal-inherited-hooks","policyVersion":"test-1","roles":["support"],"entitlements":["plan.pro"],"permissions":["account.read.own","support.queue.read","support.ticket.create","support.ticket.read.own","support.ticket.reply.any"]}';
    const objectDescriptor = Object.getOwnPropertyDescriptor(
      Object.prototype,
      "toJSON",
    );
    const arrayDescriptor = Object.getOwnPropertyDescriptor(
      Array.prototype,
      "toJSON",
    );
    let objectHookCalled = false;
    let arrayHookCalled = false;
    let serialized: string | undefined;

    try {
      Object.defineProperty(Object.prototype, "toJSON", {
        configurable: true,
        value: () => {
          objectHookCalled = true;
          return { principalId: "object-prototype" };
        },
      });
      Object.defineProperty(Array.prototype, "toJSON", {
        configurable: true,
        value: () => {
          arrayHookCalled = true;
          return ["array-prototype"];
        },
      });

      serialized = serializeAccessContext(context);
    } finally {
      if (objectDescriptor === undefined) {
        Reflect.deleteProperty(Object.prototype, "toJSON");
      } else {
        Object.defineProperty(Object.prototype, "toJSON", objectDescriptor);
      }
      if (arrayDescriptor === undefined) {
        Reflect.deleteProperty(Array.prototype, "toJSON");
      } else {
        Object.defineProperty(Array.prototype, "toJSON", arrayDescriptor);
      }
    }

    expect(serialized).toBe(expected);
    expect(objectHookCalled).toBe(false);
    expect(arrayHookCalled).toBe(false);
  });

  it("does not mutate the context or its arrays", () => {
    const context = resolveAccess(
      {
        principalId: "principal-immutable",
        roles: ["support"],
        entitlements: ["plan.pro"],
      },
      policy,
    );
    const before = {
      principalId: context.principalId,
      policyVersion: context.policyVersion,
      roles: [...context.roles],
      entitlements: [...context.entitlements],
      permissions: [...context.permissions],
    };

    serializeAccessContext(context);

    expect(context).toEqual(before);
    expect(Object.isFrozen(context)).toBe(true);
    expect(Object.isFrozen(context.roles)).toBe(true);
    expect(Object.isFrozen(context.entitlements)).toBe(true);
    expect(Object.isFrozen(context.permissions)).toBe(true);
  });

  it("rejects malformed contexts without invoking accessors", () => {
    const malformed = (value: unknown) => {
      return () => serializeAccessContext(value as AccessContext);
    };
    const sparseRoles = new Array<string>(1);
    let contextAccessorRead = false;
    const contextAccessor = {
      get principalId() {
        contextAccessorRead = true;
        return "principal-accessor";
      },
      policyVersion: "accessor-1",
      roles: [],
      entitlements: [],
      permissions: [],
    };
    let arrayAccessorRead = false;
    const accessorRoles: string[] = [];
    Object.defineProperty(accessorRoles, 0, {
      enumerable: true,
      get() {
        arrayAccessorRead = true;
        return "support";
      },
    });

    expect(malformed(null)).toThrowError("context must be an object");
    expect(
      malformed({
        principalId: " ",
        policyVersion: "version-1",
        roles: [],
        entitlements: [],
        permissions: [],
      }),
    ).toThrowError("principalId must not be empty");
    expect(
      malformed({
        principalId: "principal-1",
        policyVersion: 1,
        roles: [],
        entitlements: [],
        permissions: [],
      }),
    ).toThrowError("policyVersion must be a string");
    expect(
      malformed({
        principalId: "principal-1",
        policyVersion: "version-1",
        roles: sparseRoles,
        entitlements: [],
        permissions: [],
      }),
    ).toThrowError("roles must be a dense array of strings");
    expect(malformed(contextAccessor)).toThrowError(
      "principalId must be an own data property",
    );
    expect(contextAccessorRead).toBe(false);
    expect(
      malformed({
        principalId: "principal-1",
        policyVersion: "version-1",
        roles: accessorRoles,
        entitlements: [],
        permissions: [],
      }),
    ).toThrowError("roles must be a dense array of strings");
    expect(arrayAccessorRead).toBe(false);
  });
});
