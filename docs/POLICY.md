# Policy documents

`@pegma/authorization-policy` validates application-owned policy before it reaches the
resolver. Validation belongs on the trusted server startup path: a host should
stop booting when its policy is invalid rather than discover a configuration
error during an authorization request.

```ts
import { readFile } from "node:fs/promises";

import { resolveAccess } from "@pegma/authorization-core";
import {
  parsePolicy,
  PolicyValidationError,
} from "@pegma/authorization-policy";

let policy;
try {
  const source = await readFile("./access-policy.json", "utf8");
  policy = parsePolicy(JSON.parse(source));
} catch (error) {
  if (error instanceof PolicyValidationError) {
    for (const diagnostic of error.diagnostics) {
      console.error(diagnostic.code, diagnostic.path, diagnostic.message);
    }
  }
  throw error;
}

const context = resolveAccess(
  { principalId: "account_123", roles: ["support"] },
  policy,
);
```

`parsePolicy` accepts an already decoded value. JSON syntax errors remain the
responsibility of `JSON.parse`; document-shape errors produce deterministic
Authorization Core diagnostics. `validatePolicy` provides the same checks as a
nonthrowing discriminated result when a host wants to render or aggregate
diagnostics before failing startup.

## V1 document

```json
{
  "schemaVersion": 1,
  "version": "2026-07-24",
  "defaults": ["account.read.own"],
  "roles": {
    "support": ["support.queue.read", "support.ticket.reply.any"]
  },
  "entitlements": {
    "plan.pro": ["support.ticket.create", "support.ticket.read.own"]
  }
}
```

`schemaVersion` and `version` have separate purposes:

- `schemaVersion` identifies the serialized document shape. V1 requires the
  number `1`, rejects unknown fields, and fails closed on any other schema
  version.
- `version` is the host application's policy revision. It is preserved
  verbatim in the resolved access context and compared only by exact,
  case-sensitive equality. Authorization Core assigns it no semantic-version, date, or
  ordering meaning. A host should change it whenever permission-granting
  behavior changes.

A policy version is 1–128 ASCII characters and matches:

```text
^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$
```

The `defaults`, `roles`, and `entitlements` sections are optional. Present
sections must use arrays and objects exactly as shown; `null`, sparse arrays,
accessors, inherited configuration, custom prototypes, symbols, and non-JSON
values are rejected. Successful validation returns a detached, deeply frozen
copy so later mutation of the decoded input cannot change authorization
behavior.

## Permission names

Permission names contain 1–255 ASCII characters and consist of one or more
dot-separated segments. Each segment:

1. begins with a lowercase ASCII letter;
2. continues with lowercase ASCII letters or digits; and
3. may contain additional alphanumeric groups separated by one hyphen or
   underscore.

The equivalent segment grammar is:

```text
[a-z][a-z0-9]*(?:[-_][a-z0-9]+)*
```

Examples:

```text
account.read.own
support.ticket-reply.any
advisor.client_list.read
```

Wildcards, whitespace, uppercase letters, Unicode, empty segments, and
leading, trailing, or consecutive separators are invalid. Permission strings
belong to the host; Authorization Core validates their syntax but does not assign
global meanings to their segments.

Role and entitlement names are opaque, exact, case-sensitive host identifiers.
Authorization Core does not impose the permission grammar on them. V1 rejects an empty
name, surrounding whitespace, ASCII control characters, or a name longer than
255 Unicode code points, and otherwise preserves the name without
normalization.

For application-level vocabulary, exact-match behavior, compatibility effects,
and staged rename guidance, see the
[permission naming and compatibility guide](PERMISSIONS.md).

## Duplicate grants

A single grant list must not repeat a permission. This applies independently to
the defaults list and to each role or entitlement list.

The same permission may be granted by different sources. For example, a
default, a staff role, and a paid entitlement may all grant
`account.read.own`; the additive resolver intentionally combines and
deduplicates those independent grants.

V1 validates an already decoded value. It does not claim to detect duplicate
object members that a JSON parser has already collapsed.

## Diagnostics and fail-closed behavior

Every diagnostic has a stable `code`, an RFC 6901 JSON Pointer `path`, and a
human-readable `message`. A duplicate also identifies the first occurrence
with `relatedPath`. Diagnostics are ordered deterministically and frozen.

Validation never returns a partial policy. `validatePolicy` returns either a
valid immutable document or diagnostics; `parsePolicy` throws
`PolicyValidationError` when diagnostics exist. Hosts should treat either JSON
syntax failure or policy validation failure as a startup failure.

Policy validation diagnostics describe invalid configuration and should fail
startup. Unknown roles and entitlements supplied later in an access subject
are a different, informational signal: they remain harmless in Core and grant
nothing.

Hosts that want this runtime observability can opt into
`resolveAccessWithDiagnostics`:

```ts
import { resolveAccessWithDiagnostics } from "@pegma/authorization-core";

const resolution = resolveAccessWithDiagnostics(
  {
    principalId: "account_123",
    roles: ["support", "renamed-role"],
    entitlements: ["plan.pro", "retired-plan"],
  },
  policy,
);

// {
//   unknownRoles: ["renamed-role"],
//   unknownEntitlements: ["retired-plan"]
// }
console.log(resolution.diagnostics);
```

`resolution.context` is exactly the access context that `resolveAccess` would
return. Diagnostic names are deduplicated, sorted, and deeply frozen. A role or
entitlement is known only when its policy map contains an own property for that
exact name; an own property with an empty grant list is still known. Role and
entitlement namespaces are independent.

Core does not log automatically or assign severity to runtime diagnostics.
They do not fail startup, change a permission decision, or become permission
inputs. Hosts may aggregate or log them at a trusted server boundary, taking
care not to expose staff or unreleased-feature names to clients.
