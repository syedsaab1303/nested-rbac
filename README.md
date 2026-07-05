# nested-rbac

> Lightweight, **Zanzibar/ReBAC-inspired** hierarchical RBAC for **Node.js, Express & TypeScript**.
> A role granted on a parent resource automatically applies to every child beneath it —
> without the infrastructure of a full FGA engine.

[![npm version](https://img.shields.io/npm/v/nested-rbac.svg?color=cb3837&logo=npm)](https://www.npmjs.com/package/nested-rbac)
[![npm downloads](https://img.shields.io/npm/dm/nested-rbac.svg?color=cb3837)](https://www.npmjs.com/package/nested-rbac)
[![CI](https://github.com/syedsaab1303/nested-rbac/actions/workflows/ci.yml/badge.svg)](https://github.com/syedsaab1303/nested-rbac/actions)
[![minzipped size](https://img.shields.io/bundlephobia/minzip/nested-rbac?color=blue)](https://bundlephobia.com/package/nested-rbac)
[![types included](https://img.shields.io/badge/types-included-blue)](https://www.typescriptlang.org/)
[![license](https://img.shields.io/npm/l/nested-rbac.svg?color=blue)](./LICENSE)

- 🌳 **Hierarchical** — grant a role once on a parent; it cascades to every descendant.
- 🪶 **Tiny & zero-dependency** — pure logic you can drop into any Node app.
- 🧩 **Framework-agnostic core** + an optional thin **Express** middleware.
- 🔧 **Wildcards & deny rules** — `"billing:*"`, global `"*"`, and `"!action"` (deny always wins).
- 🟦 **TypeScript-first** — full type declarations shipped; dual **ESM + CJS**.

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

## How inheritance works

To check a permission on a target, the engine gathers the target node **plus all of its
ancestors**, then unions the permissions from any role assigned on any of those nodes:

```
organization "acme"   ← Priya is "owner" here
        │
      team "eng"
        │
   project "web"       ← Rahul is "editor" here
        │
    task "homepage"    ← check: can Rahul delete this?
```

Rahul was never assigned a role on the task itself — but `editor` on the parent `web`
project **inherits down**, so he's allowed. Priya's org-level `owner` reaches every task
in the whole tree. Nobody re-assigns roles at each level.

## When should I use this?

|                                       | Flat RBAC<br>(CASL, accesscontrol) | **nested-rbac**       | Zanzibar / FGA<br>(OpenFGA, SpiceDB) |
| ------------------------------------- | ---------------------------------- | --------------------- | ------------------------------------ |
| Resource-hierarchy inheritance        | ❌ do it by hand                    | ✅ built-in            | ✅ built-in                           |
| Infrastructure                        | none (in-process)                  | **none (in-process)** | separate service + datastore         |
| Setup cost                            | low                                | **low**               | high                                 |
| Runtime dependencies                  | varies                             | **zero**              | client + server                      |
| Cross-tree / graph relationships      | ❌                                  | ❌                     | ✅                                    |
| Scale                                 | single app                         | single app            | billions of objects                  |
| Best for                              | simple flat roles                  | **nested SaaS resources** | large-scale, complex relations   |

**Sweet spot:** a multi-tenant app (`org → team → project → …`) that needs inheritance,
but doesn't want to deploy and operate a full authorization service.

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

> ⚠️ **Security note:** always enforce authorization on the server. `listPermissions`
> is great for showing/hiding UI in your web or mobile client, but the real `can(...)`
> check must run on your backend — never trust the client.

## Programmatic checks (no Express)

```ts
rbac.can(
  assignments,                              // RoleAssignment[]
  "project:write",                          // required permission
  { type: "resource", id: "R1" },           // target
  [{ type: "project", id: "P1" }],          // ancestors (parent → root)
); // => boolean
```

## Performance

The `can()` check is pure in-memory set logic: it gathers the target plus its ancestors,
unions the permissions from any matching assignment, and matches with `O(1)` set lookups.
Hierarchy **depth barely matters** — it only adds a few entries to the ancestor array.

Measured on Node 24 (`node benchmark/bench.mjs`):

| Scenario                              | Throughput            |
| ------------------------------------- | --------------------- |
| depth 4, 1 assignment (inherited)     | ~1,360,000 checks/sec |
| depth 12, 1 assignment (deep)         | ~1,070,000 checks/sec |
| depth 4, 101 assignments              | ~196,000 checks/sec   |

So the engine itself is never the bottleneck. **The real cost is the `getAncestors`
lookup you supply**, which runs on every check. A naive resolver that walks one level per
query turns a single check into N round-trips (a classic N+1). Instead:

- Resolve the **whole chain in one query** — a recursive CTE (`WITH RECURSIVE …`), a
  stored **materialized path** (`/org/team/project` on each row), or a **closure table**.
- **Memoize per request** so repeated checks on related resources don't re-hit the DB.
  The library ships a helper for this:

```ts
import { memoizeAncestors } from "nested-rbac";

// Create a fresh cache per request (otherwise you risk stale hierarchy data).
app.use((req, _res, next) => {
  req.getAncestors = memoizeAncestors((r) => db.getAncestorChain(r));
  next();
});
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

### `memoizeAncestors(resolve)`

Wraps a `getAncestors` resolver with a cache so repeated lookups for the same resource
don't re-hit your database. Create one **per request** (or per batch job) to avoid stale
data — see [Performance](#performance).

## Contributing

Issues and PRs are welcome — see [CONTRIBUTING.md](./CONTRIBUTING.md). If `nested-rbac` is
useful to you, a ⭐ on [GitHub](https://github.com/syedsaab1303/nested-rbac) helps others
find it.

## License

MIT © [syedsaab1303](https://github.com/syedsaab1303)
