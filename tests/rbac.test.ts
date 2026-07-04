import { describe, expect, it } from "vitest";
import { RBAC } from "../src/rbac.js";
import type { ResourceRef, RoleAssignment } from "../src/types.js";

const rbac = new RBAC({
  hierarchy: ["organization", "team", "project", "resource"],
  roles: {
    owner: ["*"],
    admin: ["project:read", "project:write", "member:manage"],
    editor: ["project:read", "project:write"],
    viewer: ["project:read"],
    billing: ["billing:*"],
  },
});

// A resource and its full ancestor chain (parent -> root).
const resource: ResourceRef = { type: "resource", id: "R1" };
const ancestorsOfR1: ResourceRef[] = [
  { type: "project", id: "P1" },
  { type: "team", id: "T1" },
  { type: "organization", id: "O1" },
];

describe("hierarchical RBAC", () => {
  it("grants when the role is assigned on the target itself", () => {
    const a: RoleAssignment[] = [{ role: "viewer", resource }];
    expect(rbac.can(a, "project:read", resource)).toBe(true);
  });

  it("inherits a permission granted on an ancestor", () => {
    const a: RoleAssignment[] = [
      { role: "editor", resource: { type: "project", id: "P1" } },
    ];
    expect(rbac.can(a, "project:write", resource, ancestorsOfR1)).toBe(true);
  });

  it("inherits all the way down from the organization root", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: { type: "organization", id: "O1" } },
    ];
    expect(rbac.can(a, "project:write", resource, ancestorsOfR1)).toBe(true);
  });

  it("denies when no applicable node carries the role", () => {
    const a: RoleAssignment[] = [
      { role: "editor", resource: { type: "project", id: "P2" } },
    ];
    expect(rbac.can(a, "project:write", resource, ancestorsOfR1)).toBe(false);
  });

  it("denies a permission the assigned role does not grant", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", resource: { type: "project", id: "P1" } },
    ];
    expect(rbac.can(a, "project:write", resource, ancestorsOfR1)).toBe(false);
  });

  it("honours the global wildcard (*)", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: { type: "organization", id: "O1" } },
    ];
    expect(rbac.can(a, "anything:goes", resource, ancestorsOfR1)).toBe(true);
  });

  it("honours a domain wildcard (billing:*)", () => {
    const a: RoleAssignment[] = [
      { role: "billing", resource: { type: "project", id: "P1" } },
    ];
    const target: ResourceRef = { type: "project", id: "P1" };
    expect(rbac.can(a, "billing:read", target)).toBe(true);
    expect(rbac.can(a, "billing:export", target)).toBe(true);
    expect(rbac.can(a, "project:read", target)).toBe(false);
  });

  it("combines permissions from multiple applicable roles", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", resource },
      { role: "billing", resource: { type: "project", id: "P1" } },
    ];
    expect(rbac.can(a, "project:read", resource, ancestorsOfR1)).toBe(true);
    expect(rbac.can(a, "billing:read", resource, ancestorsOfR1)).toBe(true);
  });

  it("exposes the hierarchy level of a type", () => {
    expect(rbac.levelOf("organization")).toBe(0);
    expect(rbac.levelOf("resource")).toBe(3);
    expect(rbac.levelOf("unknown")).toBe(-1);
  });
});

describe("direct permission grants", () => {
  it("grants ad-hoc permissions carried by an assignment (no role)", () => {
    const a: RoleAssignment[] = [
      { permissions: ["project:read"], resource },
    ];
    expect(rbac.can(a, "project:read", resource)).toBe(true);
    expect(rbac.can(a, "project:write", resource)).toBe(false);
  });

  it("inherits ad-hoc permissions from an ancestor", () => {
    const a: RoleAssignment[] = [
      {
        permissions: ["billing:export"],
        resource: { type: "organization", id: "O1" },
      },
    ];
    expect(rbac.can(a, "billing:export", resource, ancestorsOfR1)).toBe(true);
  });

  it("combines a role and ad-hoc permissions on the same assignment", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", permissions: ["project:write"], resource },
    ];
    expect(rbac.can(a, "project:read", resource)).toBe(true);
    expect(rbac.can(a, "project:write", resource)).toBe(true);
  });
});

describe("deny rules", () => {
  const denyRbac = new RBAC({
    hierarchy: ["organization", "team", "project", "resource"],
    roles: {
      owner: ["*"],
      restricted: ["project:read", "project:write", "!project:write"],
    },
  });

  it("an explicit deny overrides a matching grant", () => {
    const a: RoleAssignment[] = [{ role: "restricted", resource }];
    expect(denyRbac.can(a, "project:read", resource)).toBe(true);
    expect(denyRbac.can(a, "project:write", resource)).toBe(false);
  });

  it("deny wins even over a global wildcard grant", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: { type: "organization", id: "O1" } },
      {
        permissions: ["!project:delete"],
        resource: { type: "organization", id: "O1" },
      },
    ];
    expect(denyRbac.can(a, "project:read", resource, ancestorsOfR1)).toBe(true);
    expect(denyRbac.can(a, "project:delete", resource, ancestorsOfR1)).toBe(
      false,
    );
  });

  it("honours a domain-wide deny (!billing:*)", () => {
    const a: RoleAssignment[] = [
      { role: "owner", permissions: ["!billing:*"], resource },
    ];
    expect(denyRbac.can(a, "billing:read", resource)).toBe(false);
    expect(denyRbac.can(a, "billing:export", resource)).toBe(false);
    expect(denyRbac.can(a, "project:read", resource)).toBe(true);
  });
});

describe("listPermissions", () => {
  it("returns the resolved grant and deny patterns, sorted", () => {
    const a: RoleAssignment[] = [
      { role: "viewer", resource },
      {
        role: "billing",
        permissions: ["!billing:export"],
        resource: { type: "project", id: "P1" },
      },
    ];
    expect(rbac.listPermissions(a, resource, ancestorsOfR1)).toEqual({
      granted: ["billing:*", "project:read"],
      denied: ["billing:export"],
    });
  });

  it("returns empty arrays when nothing applies", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: { type: "project", id: "P2" } },
    ];
    expect(rbac.listPermissions(a, resource, ancestorsOfR1)).toEqual({
      granted: [],
      denied: [],
    });
  });
});
