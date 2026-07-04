/**
 * Comprehensive scenario suite (50+ cases) exercising nested-rbac across
 * realistic SaaS situations and edge cases. Modelled on a hierarchy:
 *
 *   organization → team → project → resource
 *
 * Run with: npm test
 */
import { describe, expect, it, vi } from "vitest";
import { RBAC, expressRBAC } from "../src/index.js";
import type { ResourceRef, RoleAssignment } from "../src/index.js";

const rbac = new RBAC({
  hierarchy: ["organization", "team", "project", "resource"],
  roles: {
    owner: ["*"],
    admin: ["project:read", "project:write", "project:delete", "member:manage"],
    editor: ["project:read", "project:write"],
    viewer: ["project:read"],
    billing: ["billing:read", "billing:export", "billing:*"],
    auditor: ["*", "!project:write", "!project:delete"], // can see all, change nothing
    contractor: ["project:read", "project:write", "!billing:*"],
  },
});

// Canonical nodes used across scenarios.
const ORG: ResourceRef = { type: "organization", id: "acme" };
const TEAM: ResourceRef = { type: "team", id: "eng" };
const PROJECT: ResourceRef = { type: "project", id: "website" };
const RESOURCE: ResourceRef = { type: "resource", id: "deploy-config" };

// Full ancestor chains (parent → root) for each node.
const ancOfResource: ResourceRef[] = [PROJECT, TEAM, ORG];
const ancOfProject: ResourceRef[] = [TEAM, ORG];
const ancOfTeam: ResourceRef[] = [ORG];

// A sibling branch, to prove isolation.
const OTHER_TEAM: ResourceRef = { type: "team", id: "design" };
const OTHER_PROJECT: ResourceRef = { type: "project", id: "marketing" };

// ---------------------------------------------------------------------------
describe("1. Direct grants on the target node", () => {
  it("01 viewer on project can read it", () => {
    const a: RoleAssignment[] = [{ role: "viewer", resource: PROJECT }];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(true);
  });

  it("02 viewer on project cannot write it", () => {
    const a: RoleAssignment[] = [{ role: "viewer", resource: PROJECT }];
    expect(rbac.can(a, "project:write", PROJECT)).toBe(false);
  });

  it("03 editor on project can read and write", () => {
    const a: RoleAssignment[] = [{ role: "editor", resource: PROJECT }];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(true);
    expect(rbac.can(a, "project:write", PROJECT)).toBe(true);
  });

  it("04 editor cannot delete (not granted)", () => {
    const a: RoleAssignment[] = [{ role: "editor", resource: PROJECT }];
    expect(rbac.can(a, "project:delete", PROJECT)).toBe(false);
  });

  it("05 admin can delete and manage members", () => {
    const a: RoleAssignment[] = [{ role: "admin", resource: PROJECT }];
    expect(rbac.can(a, "project:delete", PROJECT)).toBe(true);
    expect(rbac.can(a, "member:manage", PROJECT)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe("2. Hierarchical inheritance (parent → descendants)", () => {
  it("06 owner on org inherits to a resource 3 levels down", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: ORG }];
    expect(rbac.can(a, "project:write", RESOURCE, ancOfResource)).toBe(true);
  });

  it("07 editor on team inherits to a project", () => {
    const a: RoleAssignment[] = [{ role: "editor", resource: TEAM }];
    expect(rbac.can(a, "project:write", PROJECT, ancOfProject)).toBe(true);
  });

  it("08 editor on project inherits to a resource", () => {
    const a: RoleAssignment[] = [{ role: "editor", resource: PROJECT }];
    expect(rbac.can(a, "project:read", RESOURCE, ancOfResource)).toBe(true);
  });

  it("09 admin on org inherits delete down to resource", () => {
    const a: RoleAssignment[] = [{ role: "admin", resource: ORG }];
    expect(rbac.can(a, "project:delete", RESOURCE, ancOfResource)).toBe(true);
  });

  it("10 inheritance only flows down, never up", () => {
    // role granted on the deep resource must NOT grant on its parent project
    const a: RoleAssignment[] = [{ role: "owner", resource: RESOURCE }];
    expect(rbac.can(a, "project:write", PROJECT, ancOfProject)).toBe(false);
  });

  it("11 child role does not leak to the org root", () => {
    const a: RoleAssignment[] = [{ role: "admin", resource: PROJECT }];
    expect(rbac.can(a, "project:read", ORG)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe("3. Sibling / branch isolation", () => {
  it("12 role on one team does not apply to a sibling team", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: TEAM }];
    expect(rbac.can(a, "project:read", OTHER_TEAM, [ORG])).toBe(false);
  });

  it("13 role on one project does not apply to a sibling project", () => {
    const a: RoleAssignment[] = [{ role: "editor", resource: PROJECT }];
    expect(rbac.can(a, "project:read", OTHER_PROJECT, [TEAM, ORG])).toBe(false);
  });

  it("14 but a common ancestor (org) covers both branches", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: ORG }];
    expect(rbac.can(a, "project:read", OTHER_PROJECT, [OTHER_TEAM, ORG])).toBe(
      true,
    );
    expect(rbac.can(a, "project:read", PROJECT, ancOfProject)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe("4. Wildcards", () => {
  it("15 global '*' grants any permission", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: PROJECT }];
    expect(rbac.can(a, "anything:at:all", PROJECT)).toBe(true);
    expect(rbac.can(a, "project:delete", PROJECT)).toBe(true);
  });

  it("16 domain wildcard grants every action in that domain", () => {
    const a: RoleAssignment[] = [{ role: "billing", resource: PROJECT }];
    expect(rbac.can(a, "billing:read", PROJECT)).toBe(true);
    expect(rbac.can(a, "billing:refund", PROJECT)).toBe(true);
  });

  it("17 domain wildcard does NOT cross domains", () => {
    const a: RoleAssignment[] = [{ role: "billing", resource: PROJECT }];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(false);
  });

  it("18 domain wildcard requires a domain-qualified permission", () => {
    const a: RoleAssignment[] = [
      { permissions: ["billing:*"], resource: PROJECT },
    ];
    // "billing" has no ':' separator → not matched by "billing:*"
    expect(rbac.can(a, "billing", PROJECT)).toBe(false);
    expect(rbac.can(a, "billing:read", PROJECT)).toBe(true);
  });

  it("19 inherited global wildcard still wins down the tree", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: ORG }];
    expect(rbac.can(a, "secret:action", RESOURCE, ancOfResource)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
describe("5. Deny rules ('!') — deny always wins", () => {
  it("20 explicit deny overrides a same-set grant", () => {
    const a: RoleAssignment[] = [
      { permissions: ["project:write", "!project:write"], resource: PROJECT },
    ];
    expect(rbac.can(a, "project:write", PROJECT)).toBe(false);
  });

  it("21 auditor sees everything but cannot write/delete", () => {
    const a: RoleAssignment[] = [{ role: "auditor", resource: PROJECT }];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(true);
    expect(rbac.can(a, "billing:read", PROJECT)).toBe(true);
    expect(rbac.can(a, "project:write", PROJECT)).toBe(false);
    expect(rbac.can(a, "project:delete", PROJECT)).toBe(false);
  });

  it("22 deny beats an inherited '*' from an ancestor", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: ORG },
      { permissions: ["!project:delete"], resource: ORG },
    ];
    expect(rbac.can(a, "project:write", RESOURCE, ancOfResource)).toBe(true);
    expect(rbac.can(a, "project:delete", RESOURCE, ancOfResource)).toBe(false);
  });

  it("23 domain-wide deny (!billing:*) blocks the whole domain", () => {
    const a: RoleAssignment[] = [{ role: "contractor", resource: PROJECT }];
    expect(rbac.can(a, "billing:read", PROJECT)).toBe(false);
    expect(rbac.can(a, "billing:export", PROJECT)).toBe(false);
    expect(rbac.can(a, "project:read", PROJECT)).toBe(true);
  });

  it("24 deny on an ancestor cascades to descendants", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: ORG },
      { permissions: ["!secret:read"], resource: TEAM },
    ];
    expect(rbac.can(a, "secret:read", RESOURCE, ancOfResource)).toBe(false);
  });

  it("25 a deny in a sibling branch does NOT affect this branch", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: ORG },
      { permissions: ["!project:write"], resource: OTHER_TEAM },
    ];
    // our resource is under TEAM/eng, deny was on design → no effect
    expect(rbac.can(a, "project:write", RESOURCE, ancOfResource)).toBe(true);
  });

  it("26 specific deny does not block a different action in the domain", () => {
    const a: RoleAssignment[] = [
      { role: "owner", permissions: ["!project:delete"], resource: PROJECT },
    ];
    expect(rbac.can(a, "project:delete", PROJECT)).toBe(false);
    expect(rbac.can(a, "project:write", PROJECT)).toBe(true);
  });

  it("27 global deny grant interplay: '!*' would block everything", () => {
    const a: RoleAssignment[] = [
      { permissions: ["*", "!*"], resource: PROJECT },
    ];
    // denied has "*", satisfies() returns true for any → blocked
    expect(rbac.can(a, "anything", PROJECT)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe("6. Direct / ad-hoc permissions", () => {
  it("28 assignment with permissions and no role works", () => {
    const a: RoleAssignment[] = [
      { permissions: ["report:generate"], resource: PROJECT },
    ];
    expect(rbac.can(a, "report:generate", PROJECT)).toBe(true);
  });

  it("29 role + ad-hoc permissions combine on one assignment", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", permissions: ["project:export"], resource: PROJECT },
    ];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(true);
    expect(rbac.can(a, "project:export", PROJECT)).toBe(true);
  });

  it("30 ad-hoc permissions inherit from an ancestor", () => {
    const a: RoleAssignment[] = [
      { permissions: ["billing:export"], resource: ORG },
    ];
    expect(rbac.can(a, "billing:export", RESOURCE, ancOfResource)).toBe(true);
  });

  it("31 empty permissions array grants nothing", () => {
    const a: RoleAssignment[] = [{ permissions: [], resource: PROJECT }];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe("7. Multiple assignments accumulate", () => {
  it("32 permissions from two roles on different nodes both apply", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", resource: PROJECT },
      { role: "billing", resource: ORG },
    ];
    expect(rbac.can(a, "project:read", RESOURCE, ancOfResource)).toBe(true);
    expect(rbac.can(a, "billing:read", RESOURCE, ancOfResource)).toBe(true);
  });

  it("33 two roles on the same node union their permissions", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", resource: PROJECT },
      { role: "billing", resource: PROJECT },
    ];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(true);
    expect(rbac.can(a, "billing:export", PROJECT)).toBe(true);
  });

  it("34 a deny in any applicable assignment overrides grants in others", () => {
    const a: RoleAssignment[] = [
      { role: "editor", resource: PROJECT },
      { permissions: ["!project:write"], resource: ORG },
    ];
    expect(rbac.can(a, "project:write", RESOURCE, ancOfResource)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe("8. Edge cases & robustness", () => {
  it("35 empty assignment list denies everything", () => {
    expect(rbac.can([], "project:read", PROJECT)).toBe(false);
  });

  it("36 unknown role contributes no permissions", () => {
    const a: RoleAssignment[] = [
      { role: "nonexistent", resource: PROJECT },
    ];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(false);
  });

  it("37 unknown role mixed with valid ad-hoc still grants the ad-hoc", () => {
    const a: RoleAssignment[] = [
      { role: "ghost", permissions: ["project:read"], resource: PROJECT },
    ];
    expect(rbac.can(a, "project:read", PROJECT)).toBe(true);
  });

  it("38 missing ancestors (flat check) prevents inheritance", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: ORG }];
    // no ancestors passed → org assignment is not 'applicable' to resource
    expect(rbac.can(a, "project:read", RESOURCE)).toBe(false);
  });

  it("39 same type, different id is not the same node", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: { type: "project", id: "website" } },
    ];
    const other: ResourceRef = { type: "project", id: "blog" };
    expect(rbac.can(a, "project:read", other)).toBe(false);
  });

  it("40 same id, different type is not the same node", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: { type: "team", id: "x" } },
    ];
    const other: ResourceRef = { type: "project", id: "x" };
    expect(rbac.can(a, "project:read", other)).toBe(false);
  });

  it("41 permission matching is case-sensitive", () => {
    const a: RoleAssignment[] = [{ role: "viewer", resource: PROJECT }];
    expect(rbac.can(a, "Project:Read", PROJECT)).toBe(false);
  });

  it("42 a permission with no domain separator only matches exactly", () => {
    const a: RoleAssignment[] = [
      { permissions: ["ping"], resource: PROJECT },
    ];
    expect(rbac.can(a, "ping", PROJECT)).toBe(true);
    expect(rbac.can(a, "ping:pong", PROJECT)).toBe(false);
  });

  it("43 levelOf reports positions and -1 for unknown", () => {
    expect(rbac.levelOf("organization")).toBe(0);
    expect(rbac.levelOf("team")).toBe(1);
    expect(rbac.levelOf("project")).toBe(2);
    expect(rbac.levelOf("resource")).toBe(3);
    expect(rbac.levelOf("galaxy")).toBe(-1);
  });

  it("44 constructor copies options (external mutation is ignored)", () => {
    const opts = {
      hierarchy: ["a", "b"],
      roles: { r: ["x:read"] as string[] },
    };
    const engine = new RBAC(opts);
    opts.roles.r.push("x:write"); // mutate the original after construction
    const a: RoleAssignment[] = [
      { role: "r", resource: { type: "a", id: "1" } },
    ];
    expect(engine.can(a, "x:write", { type: "a", id: "1" })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
describe("9. permissionsFor & listPermissions", () => {
  it("45 permissionsFor returns the raw granted set (no denies applied)", () => {
    const a: RoleAssignment[] = [{ role: "editor", resource: PROJECT }];
    const set = rbac.permissionsFor(a, PROJECT);
    expect(set.has("project:read")).toBe(true);
    expect(set.has("project:write")).toBe(true);
    expect(set.has("project:delete")).toBe(false);
  });

  it("46 listPermissions returns sorted granted + denied", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", resource: PROJECT },
      { permissions: ["report:run", "!project:delete"], resource: ORG },
    ];
    const result = rbac.listPermissions(a, RESOURCE, ancOfResource);
    expect(result.granted).toEqual(["project:read", "report:run"]);
    expect(result.denied).toEqual(["project:delete"]);
  });

  it("47 listPermissions yields empty arrays when nothing applies", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: OTHER_PROJECT },
    ];
    expect(rbac.listPermissions(a, RESOURCE, ancOfResource)).toEqual({
      granted: [],
      denied: [],
    });
  });

  it("48 listPermissions de-duplicates overlapping grants", () => {
    const a: RoleAssignment[] = [
      { permissions: ["x:read", "x:read"], resource: PROJECT },
      { permissions: ["x:read"], resource: PROJECT },
    ];
    expect(rbac.listPermissions(a, PROJECT).granted).toEqual(["x:read"]);
  });
});

// ---------------------------------------------------------------------------
describe("10. Express middleware (expressRBAC)", () => {
  const engine = new RBAC({
    hierarchy: ["organization", "project"],
    roles: { owner: ["*"], viewer: ["project:read"] },
  });

  function mockRes() {
    const res: any = {};
    res.statusCode = 200;
    res.body = undefined;
    res.status = vi.fn((code: number) => {
      res.statusCode = code;
      return res;
    });
    res.json = vi.fn((payload: any) => {
      res.body = payload;
      return res;
    });
    return res;
  }

  it("49 calls next() when the caller is authorized", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: (req: any) => req.user.assignments,
    });
    const handler = authorize({
      permission: "project:read",
      resource: (req: any) => ({ type: "project", id: req.params.id }),
    });
    const req: any = {
      params: { id: "website" },
      user: {
        assignments: [
          { role: "viewer", resource: { type: "project", id: "website" } },
        ],
      },
    };
    const res = mockRes();
    const next = vi.fn();
    await handler(req, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect(res.status).not.toHaveBeenCalled();
  });

  it("50 responds 403 when the caller lacks the permission", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: (req: any) => req.user.assignments,
    });
    const handler = authorize({
      permission: "project:write",
      resource: (req: any) => ({ type: "project", id: req.params.id }),
    });
    const req: any = {
      params: { id: "website" },
      user: {
        assignments: [
          { role: "viewer", resource: { type: "project", id: "website" } },
        ],
      },
    };
    const res = mockRes();
    const next = vi.fn();
    await handler(req, res, next);
    expect(next).not.toHaveBeenCalled();
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body).toEqual({ error: "Forbidden", permission: "project:write" });
  });

  it("51 uses getAncestors so inherited roles authorize", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: (req: any) => req.user.assignments,
      getAncestors: () => [{ type: "organization", id: "acme" }],
    });
    const handler = authorize({
      permission: "project:write",
      resource: (req: any) => ({ type: "project", id: req.params.id }),
    });
    const req: any = {
      params: { id: "website" },
      user: {
        assignments: [
          { role: "owner", resource: { type: "organization", id: "acme" } },
        ],
      },
    };
    const res = mockRes();
    const next = vi.fn();
    await handler(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("52 custom onDenied handler is used instead of the default 403", async () => {
    const onDenied = vi.fn((_req: any, res: any) => {
      res.status(401).json({ error: "nope" });
    });
    const authorize = expressRBAC(engine, {
      getAssignments: () => [],
      onDenied,
    });
    const handler = authorize({
      permission: "project:read",
      resource: () => ({ type: "project", id: "x" }),
    });
    const res = mockRes();
    const next = vi.fn();
    await handler({} as any, res, next);
    expect(onDenied).toHaveBeenCalledOnce();
    expect(res.statusCode).toBe(401);
  });

  it("53 forwards errors to next(err) when a resolver throws", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: () => {
        throw new Error("db down");
      },
    });
    const handler = authorize({
      permission: "project:read",
      resource: () => ({ type: "project", id: "x" }),
    });
    const res = mockRes();
    const next = vi.fn();
    await handler({} as any, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect((next.mock.calls[0][0] as Error).message).toBe("db down");
  });

  it("54 supports async getAssignments returning a promise", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: async () => [
        { role: "viewer", resource: { type: "project", id: "website" } },
      ],
    });
    const handler = authorize({
      permission: "project:read",
      resource: (req: any) => ({ type: "project", id: req.params.id }),
    });
    const req: any = { params: { id: "website" } };
    const res = mockRes();
    const next = vi.fn();
    await handler(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });
});
