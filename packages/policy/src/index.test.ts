import { describe, expect, it } from "vitest";

import { resolveAccess } from "@pegma/authorization-core";

import {
  MAX_PERMISSION_NAME_LENGTH,
  MAX_POLICY_VERSION_LENGTH,
  MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH,
  parsePolicy,
  PERMISSION_NAME_PATTERN_SOURCE,
  POLICY_SCHEMA_VERSION,
  POLICY_VERSION_PATTERN_SOURCE,
  PolicyValidationError,
  validatePolicy,
} from "./index.js";

function diagnosticsFor(input: unknown) {
  const result = validatePolicy(input);
  expect(result.valid).toBe(false);
  if (result.valid) {
    throw new Error("Expected policy validation to fail");
  }
  return result.diagnostics;
}

function diagnosticCodes(input: unknown) {
  return diagnosticsFor(input).map((diagnostic) => diagnostic.code);
}

describe("PolicyDocumentV1", () => {
  it("accepts and freezes a minimal policy", () => {
    const policy = parsePolicy({ schemaVersion: 1, version: "v1" });

    expect(policy).toEqual({ schemaVersion: 1, version: "v1" });
    expect(policy.schemaVersion).toBe(POLICY_SCHEMA_VERSION);
    expect(Object.isFrozen(policy)).toBe(true);
  });

  it("accepts a full JSON-compatible policy and preserves its version", () => {
    const input = {
      schemaVersion: 1,
      version: "Release_2026-07.24",
      defaults: ["account.read_own"],
      roles: {
        "Support Team": ["support.ticket_reply.any"],
      },
      entitlements: {
        "Plan/Advisor": ["advisor.client-list.read"],
      },
    };

    const policy = parsePolicy(input);

    expect(policy.version).toBe("Release_2026-07.24");
    expect(policy.defaults).toEqual(["account.read_own"]);
    expect(policy.roles?.["Support Team"]).toEqual([
      "support.ticket_reply.any",
    ]);
    expect(policy.entitlements?.["Plan/Advisor"]).toEqual([
      "advisor.client-list.read",
    ]);
  });

  it("round-trips through JSON", () => {
    const source = {
      schemaVersion: 1,
      version: "2026-07-24",
      defaults: ["account.read.own"],
      roles: { support: ["support.queue.read"] },
      entitlements: { "plan.pro": ["planner.desktop.use"] },
    };

    const first = parsePolicy(JSON.parse(JSON.stringify(source)));
    const second = parsePolicy(JSON.parse(JSON.stringify(first)));

    expect(second).toEqual(first);
  });

  it("integrates with core while allowing cross-source overlap", () => {
    const policy = parsePolicy({
      schemaVersion: 1,
      version: "integration-1",
      defaults: ["account.read.own"],
      roles: {
        support: ["account.read.own", "support.queue.read"],
      },
      entitlements: {
        "plan.pro": ["account.read.own", "planner.desktop.use"],
      },
    });

    const context = resolveAccess(
      {
        principalId: "account-1",
        roles: ["support"],
        entitlements: ["plan.pro"],
      },
      policy,
    );

    expect(context.policyVersion).toBe("integration-1");
    expect(context.permissions).toEqual([
      "account.read.own",
      "planner.desktop.use",
      "support.queue.read",
    ]);
  });

  it("supports a fail-closed startup boundary", () => {
    let resolverReached = false;
    const startHost = (input: unknown) => {
      const policy = parsePolicy(input);
      resolverReached = true;
      return resolveAccess({ principalId: "account-1" }, policy);
    };

    expect(() =>
      startHost({
        schemaVersion: 1,
        version: "boot-1",
        defaults: ["Account.Read"],
      }),
    ).toThrow(PolicyValidationError);
    expect(resolverReached).toBe(false);
  });
});

describe("version semantics", () => {
  it("exports the documented patterns and accepts exact boundary values", () => {
    const longestVersion = `V${"a".repeat(MAX_POLICY_VERSION_LENGTH - 1)}`;
    const longestPermission = "a".repeat(MAX_PERMISSION_NAME_LENGTH);

    expect(new RegExp(POLICY_VERSION_PATTERN_SOURCE).test(longestVersion)).toBe(
      true,
    );
    expect(
      new RegExp(PERMISSION_NAME_PATTERN_SOURCE).test(longestPermission),
    ).toBe(true);
    expect(
      parsePolicy({
        schemaVersion: 1,
        version: longestVersion,
        defaults: [longestPermission],
      }).version,
    ).toBe(longestVersion);
  });

  it.each([
    "",
    " version",
    "version ",
    "version/1",
    `v${"a".repeat(MAX_POLICY_VERSION_LENGTH)}`,
  ])("rejects malformed policy version %j", (version) => {
    expect(diagnosticCodes({ schemaVersion: 1, version })).toContain(
      "invalid_policy_version",
    );
  });

  it("keeps versions opaque, case-sensitive, and verbatim", () => {
    const upper = parsePolicy({ schemaVersion: 1, version: "Release-A" });
    const lower = parsePolicy({ schemaVersion: 1, version: "release-a" });

    expect(upper.version).toBe("Release-A");
    expect(lower.version).toBe("release-a");
    expect(upper.version).not.toBe(lower.version);
  });

  it("keeps exported pattern sources detached from live validation controls", () => {
    const versionPattern = new RegExp(POLICY_VERSION_PATTERN_SOURCE);
    const permissionPattern = new RegExp(PERMISSION_NAME_PATTERN_SOURCE);

    versionPattern.compile(".*");
    permissionPattern.test = () => true;

    expect(
      diagnosticCodes({
        schemaVersion: 1,
        version: "bad/version",
        defaults: ["account.*"],
      }),
    ).toEqual(["invalid_policy_version", "malformed_permission"]);
  });
});

describe("permission-name grammar", () => {
  it.each([
    "read",
    "account.read.own",
    "support.ticket-reply.any",
    "support.ticket_reply.read_own",
    "v2.feature3.use",
  ])("accepts %s", (permission) => {
    expect(() =>
      parsePolicy({
        schemaVersion: 1,
        version: "grammar-1",
        defaults: [permission],
      }),
    ).not.toThrow();
  });

  it.each([
    "",
    " ",
    "Account.read",
    "1account.read",
    ".account.read",
    "account.read.",
    "account..read",
    "account.-read",
    "account.read-",
    "account.--read",
    "account._read",
    "account.read_",
    "account.__read",
    "account read",
    "account/read",
    "account:read",
    "account.*",
    "áccount.read",
    "a".repeat(MAX_PERMISSION_NAME_LENGTH + 1),
  ])("rejects malformed permission %j", (permission) => {
    const codes = diagnosticCodes({
      schemaVersion: 1,
      version: "grammar-1",
      defaults: [permission],
    });
    expect(
      codes.includes("empty_name") || codes.includes("malformed_permission"),
    ).toBe(true);
  });
});

describe("strict document validation", () => {
  it.each([null, [], "policy", 1, true])(
    "rejects non-object root %j",
    (input) => {
      expect(diagnosticCodes(input)).toContain("invalid_type");
    },
  );

  it("requires schemaVersion and version", () => {
    const diagnostics = diagnosticsFor({});
    expect(diagnostics).toMatchObject([
      { code: "missing_field", path: "/schemaVersion" },
      { code: "missing_field", path: "/version" },
    ]);
  });

  it.each([
    [{ schemaVersion: "1", version: "v1" }, "invalid_type"],
    [{ schemaVersion: 2, version: "v1" }, "unsupported_schema_version"],
    [{ schemaVersion: 1, version: 1 }, "invalid_type"],
  ] as const)("rejects malformed required fields", (input, code) => {
    expect(diagnosticCodes(input)).toContain(code);
  });

  it("rejects unknown V1 fields in deterministic name order", () => {
    const diagnostics = diagnosticsFor({
      schemaVersion: 1,
      version: "v1",
      zebra: true,
      alpha: true,
    });

    expect(diagnostics).toMatchObject([
      { code: "unknown_field", path: "/alpha" },
      { code: "unknown_field", path: "/zebra" },
    ]);
  });

  it("never returns a partial policy alongside diagnostics", () => {
    const result = validatePolicy({
      schemaVersion: 1,
      version: "v1",
      defaults: ["valid.read", "INVALID"],
    });

    expect(result.valid).toBe(false);
    expect("policy" in result).toBe(false);
  });

  it.each([
    ["defaults", {}],
    ["roles", []],
    ["entitlements", "plan.pro"],
  ])("rejects wrong %s section type", (field, value) => {
    expect(
      diagnosticCodes({
        schemaVersion: 1,
        version: "v1",
        [field]: value,
      }),
    ).toContain("invalid_type");
  });

  it("rejects wrong grant-list and item types", () => {
    const diagnostics = diagnosticsFor({
      schemaVersion: 1,
      version: "v1",
      defaults: ["account.read", 42],
      roles: { support: "support.read" },
    });

    expect(diagnostics).toMatchObject([
      { code: "invalid_type", path: "/defaults/1" },
      { code: "invalid_type", path: "/roles/support" },
    ]);
  });

  it("rejects sparse arrays", () => {
    const sparse: unknown[] = ["account.read"];
    sparse.length = 2;

    expect(
      diagnosticCodes({
        schemaVersion: 1,
        version: "v1",
        defaults: sparse,
      }),
    ).toContain("invalid_structure");
  });

  it("rejects symbols, accessors, inherited values, and custom prototypes", () => {
    const symbolDocument = { schemaVersion: 1, version: "v1" };
    Object.defineProperty(symbolDocument, Symbol("extra"), { value: true });

    const accessorDocument: Record<string, unknown> = { schemaVersion: 1 };
    Object.defineProperty(accessorDocument, "version", {
      enumerable: true,
      get: () => "v1",
    });

    const inheritedDocument = Object.assign(
      Object.create({ defaults: ["inherited.read"] }),
      { schemaVersion: 1, version: "v1" },
    );
    const nullPrototypeDocument = Object.assign(Object.create(null), {
      schemaVersion: 1,
      version: "v1",
    });

    for (const input of [
      symbolDocument,
      accessorDocument,
      inheritedDocument,
      nullPrototypeDocument,
    ]) {
      expect(diagnosticCodes(input)).toContain("invalid_structure");
    }
  });
});

describe("host-owned role and entitlement names", () => {
  it("preserves opaque exact names", () => {
    const policy = parsePolicy({
      schemaVersion: 1,
      version: "names-1",
      roles: {
        "Support/Admin_Équipe": ["support.read"],
      },
      entitlements: {
        "SKU:Pro/Annual": ["planner.use"],
      },
    });

    expect(Object.keys(policy.roles ?? {})).toEqual(["Support/Admin_Équipe"]);
    expect(Object.keys(policy.entitlements ?? {})).toEqual(["SKU:Pro/Annual"]);
  });

  it.each(["", " padded", "padded ", "line\nbreak", "x".repeat(256)])(
    "rejects invalid role name %j",
    (name) => {
      const roles = Object.fromEntries([[name, ["support.read"]]]);
      const codes = diagnosticCodes({
        schemaVersion: 1,
        version: "names-1",
        roles,
      });
      expect(
        codes.includes("empty_name") || codes.includes("invalid_name"),
      ).toBe(true);
    },
  );

  it.each(["", "\ttab", "tab\t", "delete\u007fkey", "x".repeat(256)])(
    "rejects invalid entitlement name %j",
    (name) => {
      const entitlements = Object.fromEntries([[name, ["planner.use"]]]);
      const codes = diagnosticCodes({
        schemaVersion: 1,
        version: "names-1",
        entitlements,
      });
      expect(
        codes.includes("empty_name") || codes.includes("invalid_name"),
      ).toBe(true);
    },
  );

  it("accepts the maximum host-name length", () => {
    const name = "x".repeat(MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH);
    const policy = parsePolicy({
      schemaVersion: 1,
      version: "names-1",
      roles: { [name]: ["support.read"] },
    });

    expect(Object.hasOwn(policy.roles ?? {}, name)).toBe(true);
  });

  it("counts host-name limits in Unicode code points", () => {
    const maximumName = "😀".repeat(MAX_ROLE_OR_ENTITLEMENT_NAME_LENGTH);
    const oversizedName = `${maximumName}😀`;

    expect(() =>
      parsePolicy({
        schemaVersion: 1,
        version: "names-1",
        roles: { [maximumName]: ["support.read"] },
      }),
    ).not.toThrow();

    expect(
      diagnosticCodes({
        schemaVersion: 1,
        version: "names-1",
        roles: { [oversizedName]: ["support.read"] },
      }),
    ).toContain("invalid_name");
  });
});

describe("duplicate grants", () => {
  it.each([
    {
      defaults: ["account.read", "account.read"],
    },
    {
      roles: { support: ["support.read", "support.read"] },
    },
    {
      entitlements: { "plan.pro": ["planner.use", "planner.use"] },
    },
  ])("rejects a duplicate within one grant list", (section) => {
    const diagnostics = diagnosticsFor({
      schemaVersion: 1,
      version: "duplicates-1",
      ...section,
    });

    expect(diagnostics.some(({ code }) => code === "duplicate_grant")).toBe(
      true,
    );
  });

  it("reports duplicate locations with RFC 6901 pointers", () => {
    const diagnostics = diagnosticsFor({
      schemaVersion: 1,
      version: "duplicates-1",
      roles: {
        "team/a~b": ["support.read", "support.read"],
      },
    });

    expect(diagnostics).toContainEqual({
      code: "duplicate_grant",
      path: "/roles/team~1a~0b/1",
      relatedPath: "/roles/team~1a~0b/0",
      message: "A grant list must not contain duplicate permissions.",
    });
  });

  it("allows the same permission across independent grant sources", () => {
    const result = validatePolicy({
      schemaVersion: 1,
      version: "duplicates-1",
      defaults: ["account.read"],
      roles: { support: ["account.read"] },
      entitlements: { "plan.pro": ["account.read"] },
    });

    expect(result.valid).toBe(true);
  });
});

describe("safe immutable output", () => {
  it("reconstructs prototype-sensitive keys without pollution", () => {
    const source = JSON.parse(`{
      "schemaVersion": 1,
      "version": "safe-1",
      "roles": {
        "__proto__": ["safe.proto"],
        "constructor": ["safe.constructor"],
        "prototype": ["safe.prototype"],
        "toString": ["safe.to-string"]
      }
    }`) as unknown;

    const policy = parsePolicy(source);

    expect(Object.getPrototypeOf(policy.roles)).toBeNull();
    expect(Object.keys(policy.roles ?? {}).sort()).toEqual([
      "__proto__",
      "constructor",
      "prototype",
      "toString",
    ]);
    expect(policy.roles?.["__proto__"]).toEqual(["safe.proto"]);
    expect(({} as { polluted?: unknown }).polluted).toBeUndefined();
  });

  it("returns a detached deeply frozen copy", () => {
    const input = {
      schemaVersion: 1,
      version: "freeze-1",
      defaults: ["account.read"],
      roles: { support: ["support.read"] },
    };
    const policy = parsePolicy(input);

    input.version = "mutated";
    input.defaults.push("account.write");
    input.roles.support.push("support.write");

    expect(policy.version).toBe("freeze-1");
    expect(policy.defaults).toEqual(["account.read"]);
    expect(policy.roles?.support).toEqual(["support.read"]);
    expect(Object.isFrozen(policy)).toBe(true);
    expect(Object.isFrozen(policy.defaults)).toBe(true);
    expect(Object.isFrozen(policy.roles)).toBe(true);
    expect(Object.isFrozen(policy.roles?.support)).toBe(true);
    expect(Reflect.set(policy, "version", "changed")).toBe(false);
  });

  it("returns frozen deterministic diagnostics", () => {
    const first = {
      schemaVersion: 1,
      version: "v1",
      roles: {
        zeta: ["Zeta.read", "Zeta.read"],
        alpha: ["Alpha.read"],
      },
    };
    const second = {
      version: "v1",
      schemaVersion: 1,
      roles: {
        alpha: ["Alpha.read"],
        zeta: ["Zeta.read", "Zeta.read"],
      },
    };

    const firstDiagnostics = diagnosticsFor(first);
    const secondDiagnostics = diagnosticsFor(second);

    expect(firstDiagnostics).toEqual(secondDiagnostics);
    expect(Object.isFrozen(firstDiagnostics)).toBe(true);
    expect(
      firstDiagnostics.every((diagnostic) => Object.isFrozen(diagnostic)),
    ).toBe(true);
  });

  it("attaches structured diagnostics to PolicyValidationError", () => {
    try {
      parsePolicy({
        schemaVersion: 1,
        version: "v1",
        defaults: ["INVALID"],
      });
      throw new Error("Expected parsePolicy to throw");
    } catch (error) {
      expect(error).toBeInstanceOf(PolicyValidationError);
      expect((error as PolicyValidationError).diagnostics).toMatchObject([
        { code: "malformed_permission", path: "/defaults/0" },
      ]);
    }
  });
});
