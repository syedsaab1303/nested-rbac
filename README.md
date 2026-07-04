# nested-rbac

> Lightweight, **Zanzibar/ReBAC-inspired** hierarchical RBAC for **Express + TypeScript**.
> A role granted on a parent resource automatically applies to every child beneath it —
> without the infrastructure of a full FGA engine.

[![CI](https://github.com/syedsaab1303/nested-rbac/actions/workflows/ci.yml/badge.svg)](https://github.com/syedsaab1303/nested-rbac/actions)
[![npm](https://img.shields.io/npm/v/nested-rbac.svg)](https://www.npmjs.com/package/nested-rbac)
![types](https://img.shields.io/badge/types-included-blue)

## Why?

Most RBAC libraries model **flat** roles: a user is an `admin`, or not. Real systems are
usually **nested**:

```
organization → team → project → resource
```

Granting someone a role on an _organization_ should implicitly let them act on every
_team_, _project_ and _resource_ underneath it — without re-assigning the role at every
level. `nested-rbac` models exactly this: **permissions flow downward through the
hierarchy.**

Full Zanzibar-style engines (OpenFGA, SpiceDB, Permify) solve this at massive scale, but
require a separate service and a relationship graph. `nested-rbac` captures the same core
idea in a tiny, dependency-free library you can drop into any Node app.

## Install

```bash
npm install nested-rbac
```

`express` is an optional peer dependency — only needed if you use the middleware.

## Quickstart

```ts
import { RBAC, expressRBAC } from "nested-rbac";

// 1. Describe your hierarchy and roles.
const rbac = new RBAC({
  hierarchy: ["organization", "team", "project", "resource"],
  roles: {
    owner: ["*"],                                   // everything
    editor: ["project:read", "project:write"],
    billing: ["billing:*"],                         // any billing action
    viewer: ["project:read"],
  },
});

// 2. Wire it to your app's data.
const authorize = expressRBAC(rbac, {
  getAssignments: (req) => req.user.assignments,    // from your auth middleware
  getAncestors: (resource) => resolveAncestors(resource), // parent → root, from your DB
});

// 3. Guard routes.
app.get(
  "/projects/:id/settings",
  authorize({
    permission: "project:read",
    resource: (req) => ({ type: "project", id: req.params.id }),
  }),
  getSettingsHandler,
);
```

A user who is `editor` on `organization O1` passes this check for any project under `O1`,
because the role is inherited down the chain.

## Permissions & wildcards

Permissions follow a `"<domain>:<action>"` convention. Two wildcards exist:

| Pattern       | Grants                                |
| ------------- | ------------------------------------- |
| `"*"`         | every permission                      |
| `"billing:*"` | every action in the `billing` domain  |

### Deny rules

A leading `"!"` makes a permission an explicit **deny** that overrides any
matching grant — **deny always wins**, and honours the same wildcards.

```ts
const rbac = new RBAC({
  hierarchy: ["organization", "project"],
  roles: {
    owner: ["*"],
    restricted: ["project:read", "project:write", "!project:write"], // can read, never write
  },
});
```

Denies can also be attached per-assignment (see below), e.g. an org `owner`
who is nonetheless blocked from one action on a specific project.

### Direct (ad-hoc) permission grants

An assignment can carry `permissions` directly instead of (or alongside) a
`role` — handy for one-off grants without defining a whole role:

```ts
const assignments = [
  { role: "viewer", resource: { type: "project", id: "P1" } },
  { permissions: ["billing:export", "!billing:delete"], resource: { type: "project", id: "P1" } },
];
```

### Inspecting effective permissions

`listPermissions(...)` returns the resolved grant/deny patterns for a target —
useful for sending a capability list to a frontend:

```ts
rbac.listPermissions(assignments, { type: "project", id: "P1" }, ancestors);
// => { granted: ["billing:export", "project:read"], denied: ["billing:delete"] }
```

## Programmatic checks (no Express)

```ts
rbac.can(
  assignments,                              // RoleAssignment[]
  "project:write",                          // required permission
  { type: "resource", id: "R1" },           // target
  [{ type: "project", id: "P1" }],          // ancestors (parent → root)
); // => boolean
```

## API

### `new RBAC(options)`

| Option      | Type                            | Description                              |
| ----------- | ------------------------------- | ---------------------------------------- |
| `hierarchy` | `string[]`                      | Resource types, broadest ancestor first. |
| `roles`     | `Record<string, Permission[]>`  | Role name → permissions it grants.       |

Methods: `can(...)`, `permissionsFor(...)`, `listPermissions(...)`, `levelOf(type)`.

### `expressRBAC(rbac, options)`

Returns an `authorize(rule)` factory producing Express middleware.

| Option           | Type                                            | Description                                   |
| ---------------- | ----------------------------------------------- | --------------------------------------------- |
| `getAssignments` | `(req) => RoleAssignment[] \| Promise<...>`     | Read the caller's assignments.                |
| `getAncestors`   | `(resource) => ResourceRef[] \| Promise<...>`   | Resolve ancestor chain. Omit for flat checks. |
| `onDenied`       | `(req, res) => void`                            | Custom `403` handler.                         |

## License

MIT
