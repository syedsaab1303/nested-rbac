/**
 * Second scenario suite (50 cases) — DIFFERENT conditions from scenarios.test.ts:
 * deeper/odd-shaped hierarchies, multi-colon permission formats, layered deny
 * combinations, multi-tenant isolation, and async middleware error paths.
 *
 * Run with: npm test
 */
import { describe, expect, it, vi } from "vitest";
import { RBAC, expressRBAC } from "../src/index.js";
import type { ResourceRef, RoleAssignment } from "../src/index.js";

const ref = (type: string, id: string): ResourceRef => ({ type, id });

// ---------------------------------------------------------------------------
// A. Deep & oddly-shaped hierarchies
// ---------------------------------------------------------------------------
describe("A. Hierarchy shapes & depth", () => {
  const deep = new RBAC({
    hierarchy: ["l0", "l1", "l2", "l3", "l4"],
    roles: { root: ["*"], mid: ["data:read"] },
  });
  const L = (n: number) => ref(`l${n}`, "x");
  const ancOf = (n: number) =>
    Array.from({ length: n }, (_, i) => L(n - 1 - i)); // parent → root

  it("01 root on l0 inherits 4 levels down to l4", () => {
    const a: RoleAssignment[] = [{ role: "root", resource: L(0) }];
    expect(deep.can(a, "data:write", L(4), ancOf(4))).toBe(true);
  });

  it("02 mid on l2 grants down to l4", () => {
    const a: RoleAssignment[] = [{ role: "mid", resource: L(2) }];
    expect(deep.can(a, "data:read", L(4), ancOf(4))).toBe(true);
  });

  it("03 mid on l2 does NOT grant up to l1", () => {
    const a: RoleAssignment[] = [{ role: "mid", resource: L(2) }];
    expect(deep.can(a, "data:read", L(1), ancOf(1))).toBe(false);
  });

  it("04 mid on l3 does NOT grant to l2 (sibling-up)", () => {
    const a: RoleAssignment[] = [{ role: "mid", resource: L(3) }];
    expect(deep.can(a, "data:read", L(2), ancOf(2))).toBe(false);
  });

  it("05 role on l1 inherits skipping a level to l3", () => {
    const a: RoleAssignment[] = [{ role: "mid", resource: L(1) }];
    expect(deep.can(a, "data:read", L(3), ancOf(3))).toBe(true);
  });

  it("06 levelOf reports the deepest index", () => {
    expect(deep.levelOf("l4")).toBe(4);
    expect(deep.levelOf("l0")).toBe(0);
  });

  it("07 single-level (flat) hierarchy still works on the node itself", () => {
    const flat = new RBAC({
      hierarchy: ["doc"],
      roles: { viewer: ["doc:read"] },
    });
    const a: RoleAssignment[] = [{ role: "viewer", resource: ref("doc", "1") }];
    expect(flat.can(a, "doc:read", ref("doc", "1"))).toBe(true);
    expect(flat.can(a, "doc:read", ref("doc", "2"))).toBe(false);
  });

  it("08 empty roles map: a role name resolves to nothing", () => {
    const bare = new RBAC({ hierarchy: ["x"], roles: {} });
    const a: RoleAssignment[] = [{ role: "anything", resource: ref("x", "1") }];
    expect(bare.can(a, "x:read", ref("x", "1"))).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// B. Permission string formats & wildcard nuances
// ---------------------------------------------------------------------------
describe("B. Permission formats & wildcards", () => {
  const node = ref("svc", "1");
  const make = (perms: string[]): RoleAssignment[] => [
    { permissions: perms, resource: node },
  ];
  const fmt = new RBAC({ hierarchy: ["svc"], roles: {} });

  it("09 exact multi-colon permission matches itself", () => {
    expect(fmt.can(make(["report:export:pdf"]), "report:export:pdf", node)).toBe(
      true,
    );
  });

  it("10 multi-colon is exact: a sibling action is not granted", () => {
    expect(fmt.can(make(["report:export:pdf"]), "report:export:csv", node)).toBe(
      false,
    );
  });

  it("11 domain wildcard splits on the FIRST colon (covers deep perms)", () => {
    expect(fmt.can(make(["report:*"]), "report:export:pdf", node)).toBe(true);
  });

  it("12 domain wildcard covers a shallow action too", () => {
    expect(fmt.can(make(["report:*"]), "report:view", node)).toBe(true);
  });

  it("13 nested wildcard 'report:export:*' does NOT cover 'report:export:pdf'", () => {
    // documented limitation: only the first-colon domain wildcard is honoured
    expect(fmt.can(make(["report:export:*"]), "report:export:pdf", node)).toBe(
      false,
    );
  });

  it("14 a domain deny '!report:*' blocks even a deep action", () => {
    const a: RoleAssignment[] = [
      { permissions: ["report:export:pdf", "!report:*"], resource: node },
    ];
    expect(fmt.can(a, "report:export:pdf", node)).toBe(false);
  });

  it("15 global wildcard grants a colon-less permission", () => {
    expect(fmt.can(make(["*"]), "ping", node)).toBe(true);
  });

  it("16 global wildcard even grants an empty-string permission", () => {
    expect(fmt.can(make(["*"]), "", node)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// C. Layered deny combinations
// ---------------------------------------------------------------------------
describe("C. Layered deny combinations", () => {
  const biz = new RBAC({
    hierarchy: ["org", "dept", "team"],
    roles: {
      super: ["*"],
      finance: ["billing:*", "report:read"],
      temp: ["billing:*", "!billing:refund"],
    },
  });
  const ORG = ref("org", "o1");
  const DEPT = ref("dept", "d1");
  const TEAM = ref("team", "t1");
  const TEAM2 = ref("team", "t2");
  const ancTeam = [DEPT, ORG];

  it("17 temp can read within a granted domain", () => {
    const a: RoleAssignment[] = [{ role: "temp", resource: TEAM }];
    expect(biz.can(a, "billing:read", TEAM)).toBe(true);
  });

  it("18 specific deny overrides the domain grant", () => {
    const a: RoleAssignment[] = [{ role: "temp", resource: TEAM }];
    expect(biz.can(a, "billing:refund", TEAM)).toBe(false);
  });

  it("19 deny is surgical: other domain actions still allowed", () => {
    const a: RoleAssignment[] = [{ role: "temp", resource: TEAM }];
    expect(biz.can(a, "billing:export", TEAM)).toBe(true);
  });

  it("20 ad-hoc domain deny carves a hole in a global grant", () => {
    const a: RoleAssignment[] = [
      { role: "super", permissions: ["!billing:*"], resource: TEAM },
    ];
    expect(biz.can(a, "billing:read", TEAM)).toBe(false);
    expect(biz.can(a, "project:read", TEAM)).toBe(true);
  });

  it("21 deny on a mid-ancestor cascades to descendants", () => {
    const a: RoleAssignment[] = [
      { role: "super", resource: ORG },
      { permissions: ["!billing:refund"], resource: DEPT },
    ];
    expect(biz.can(a, "billing:refund", TEAM, ancTeam)).toBe(false);
    expect(biz.can(a, "billing:read", TEAM, ancTeam)).toBe(true);
  });

  it("22 a deny on one team does not leak to a sibling team", () => {
    const a: RoleAssignment[] = [
      { role: "super", resource: ORG },
      { permissions: ["!data:write"], resource: TEAM },
    ];
    expect(biz.can(a, "data:write", TEAM, ancTeam)).toBe(false);
    expect(biz.can(a, "data:write", TEAM2, ancTeam)).toBe(true);
  });

  it("23 multiple denies accumulate independently", () => {
    const a: RoleAssignment[] = [
      { role: "super", permissions: ["!a:read", "!b:read"], resource: TEAM },
    ];
    expect(biz.can(a, "a:read", TEAM)).toBe(false);
    expect(biz.can(a, "b:read", TEAM)).toBe(false);
    expect(biz.can(a, "c:read", TEAM)).toBe(true);
  });

  it("24 a deny that matches nothing is harmless", () => {
    const a: RoleAssignment[] = [
      { role: "super", permissions: ["!ghost:action"], resource: TEAM },
    ];
    expect(biz.can(a, "real:thing", TEAM)).toBe(true);
  });

  it("25 grant and deny of the same exact permission → denied", () => {
    const a: RoleAssignment[] = [
      { permissions: ["x:do", "!x:do"], resource: TEAM },
    ];
    expect(biz.can(a, "x:do", TEAM)).toBe(false);
  });

  it("26 domain deny overrides an exact grant in that domain", () => {
    const a: RoleAssignment[] = [
      { permissions: ["x:do", "!x:*"], resource: TEAM },
    ];
    expect(biz.can(a, "x:do", TEAM)).toBe(false);
  });

  it("27 exact deny carves one action out of a domain grant", () => {
    const a: RoleAssignment[] = [
      { permissions: ["x:*", "!x:do"], resource: TEAM },
    ];
    expect(biz.can(a, "x:do", TEAM)).toBe(false);
    expect(biz.can(a, "x:other", TEAM)).toBe(true);
  });

  it("28 deny + wildcard on same ancestor cascades the hole down", () => {
    const a: RoleAssignment[] = [
      { role: "super", permissions: ["!secret:*"], resource: ORG },
    ];
    expect(biz.can(a, "secret:read", TEAM, ancTeam)).toBe(false);
    expect(biz.can(a, "public:read", TEAM, ancTeam)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// D. Multi-tenant isolation & accumulation
// ---------------------------------------------------------------------------
describe("D. Multi-tenant isolation & accumulation", () => {
  const saas = new RBAC({
    hierarchy: ["tenant", "workspace", "board"],
    roles: {
      owner: ["*"],
      member: ["board:read", "board:comment"],
      guest: ["board:read"],
    },
  });
  const TA = ref("tenant", "A");
  const TB = ref("tenant", "B");
  const WS = ref("workspace", "W1");
  const BOARD = ref("board", "B1");
  const ancBoardA = [WS, TA];

  it("29 owner in tenant A has full power on its boards", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: TA }];
    expect(saas.can(a, "board:delete", BOARD, ancBoardA)).toBe(true);
  });

  it("30 owner in tenant A has nothing in tenant B", () => {
    const a: RoleAssignment[] = [{ role: "owner", resource: TA }];
    expect(saas.can(a, "board:read", BOARD, [WS, TB])).toBe(false);
  });

  it("31 two tenant roles coexist without bleeding", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: TA },
      { role: "guest", resource: TB },
    ];
    expect(saas.can(a, "board:delete", BOARD, [WS, TA])).toBe(true); // A: owner
    expect(saas.can(a, "board:delete", BOARD, [WS, TB])).toBe(false); // B: guest
    expect(saas.can(a, "board:read", BOARD, [WS, TB])).toBe(true); // B: guest read
  });

  it("32 same role assigned twice is idempotent", () => {
    const a: RoleAssignment[] = [
      { role: "member", resource: WS },
      { role: "member", resource: WS },
    ];
    expect(saas.can(a, "board:comment", BOARD, ancBoardA)).toBe(true);
  });

  it("33 role at ancestor + extra role at target accumulate", () => {
    const a: RoleAssignment[] = [
      { role: "guest", resource: TA },
      { role: "member", resource: BOARD },
    ];
    expect(saas.can(a, "board:read", BOARD, ancBoardA)).toBe(true);
    expect(saas.can(a, "board:comment", BOARD, ancBoardA)).toBe(true);
  });

  it("34 grant at target + deny at ancestor → deny wins", () => {
    const a: RoleAssignment[] = [
      { role: "member", resource: BOARD },
      { permissions: ["!board:comment"], resource: TA },
    ];
    expect(saas.can(a, "board:comment", BOARD, ancBoardA)).toBe(false);
    expect(saas.can(a, "board:read", BOARD, ancBoardA)).toBe(true);
  });

  it("35 a deny in a different tenant does not apply", () => {
    const a: RoleAssignment[] = [
      { role: "owner", resource: TA },
      { permissions: ["!board:delete"], resource: TB },
    ];
    expect(saas.can(a, "board:delete", BOARD, ancBoardA)).toBe(true);
  });

  it("36 ancestor order does not matter (membership, not sequence)", () => {
    const a: RoleAssignment[] = [{ role: "member", resource: TA }];
    expect(saas.can(a, "board:read", BOARD, [TA, WS])).toBe(true);
    expect(saas.can(a, "board:read", BOARD, [WS, TA])).toBe(true);
  });

  it("37 duplicate ancestors are harmless", () => {
    const a: RoleAssignment[] = [{ role: "member", resource: WS }];
    expect(saas.can(a, "board:read", BOARD, [WS, WS, TA])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// E. listPermissions & permissionsFor under varied inputs
// ---------------------------------------------------------------------------
describe("E. listPermissions & permissionsFor", () => {
  const eng = new RBAC({
    hierarchy: ["org", "team"],
    roles: {
      temp: ["billing:*", "report:read", "!billing:refund"],
      lead: ["team:manage"],
    },
  });
  const ORG = ref("org", "o1");
  const TEAM = ref("team", "t1");
  const ancTeam = [ORG];

  it("38 permissionsFor returns raw grants incl. wildcards (no denies)", () => {
    const set = eng.permissionsFor([{ role: "temp", resource: TEAM }], TEAM);
    expect(set.has("billing:*")).toBe(true);
    expect(set.has("report:read")).toBe(true);
    expect(set.has("billing:refund")).toBe(false); // deny is not a grant
  });

  it("39 listPermissions splits granted vs denied", () => {
    const r = eng.listPermissions([{ role: "temp", resource: TEAM }], TEAM);
    expect(r.granted).toEqual(["billing:*", "report:read"]);
    expect(r.denied).toEqual(["billing:refund"]);
  });

  it("40 listPermissions output is alphabetically sorted", () => {
    const a: RoleAssignment[] = [
      { permissions: ["z:a", "a:z", "m:m"], resource: TEAM },
    ];
    expect(eng.listPermissions(a, TEAM).granted).toEqual(["a:z", "m:m", "z:a"]);
  });

  it("41 listPermissions de-dups perms inherited from multiple levels", () => {
    const a: RoleAssignment[] = [
      { permissions: ["report:read"], resource: ORG },
      { permissions: ["report:read"], resource: TEAM },
    ];
    expect(eng.listPermissions(a, TEAM, ancTeam).granted).toEqual([
      "report:read",
    ]);
  });

  it("42 listPermissions merges grants across the ancestor chain", () => {
    const a: RoleAssignment[] = [
      { role: "lead", resource: ORG },
      { permissions: ["report:read"], resource: TEAM },
    ];
    expect(eng.listPermissions(a, TEAM, ancTeam).granted).toEqual([
      "report:read",
      "team:manage",
    ]);
  });

  it("43 listPermissions is empty for an unrelated branch", () => {
    const a: RoleAssignment[] = [
      { role: "lead", resource: ref("team", "other") },
    ];
    expect(eng.listPermissions(a, TEAM, ancTeam)).toEqual({
      granted: [],
      denied: [],
    });
  });
});

// ---------------------------------------------------------------------------
// F. Express middleware — async paths & error handling
// ---------------------------------------------------------------------------
describe("F. Express middleware edge paths", () => {
  const engine = new RBAC({
    hierarchy: ["org", "project"],
    roles: { owner: ["*"], viewer: ["project:read"] },
  });

  function mockRes() {
    const res: any = { statusCode: 200, body: undefined };
    res.status = vi.fn((c: number) => {
      res.statusCode = c;
      return res;
    });
    res.json = vi.fn((p: any) => {
      res.body = p;
      return res;
    });
    return res;
  }

  it("44 async getAncestors enables inherited authorization", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: () => [
        { role: "owner", resource: ref("org", "acme") },
      ],
      getAncestors: async () => [ref("org", "acme")],
    });
    const handler = authorize({
      permission: "project:write",
      resource: (req: any) => ref("project", req.params.id),
    });
    const req: any = { params: { id: "p1" } };
    const res = mockRes();
    const next = vi.fn();
    await handler(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("45 a throwing getAncestors is forwarded to next(err)", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: () => [{ role: "owner", resource: ref("org", "a") }],
      getAncestors: async () => {
        throw new Error("ancestor lookup failed");
      },
    });
    const handler = authorize({
      permission: "project:read",
      resource: () => ref("project", "p1"),
    });
    const res = mockRes();
    const next = vi.fn();
    await handler({} as any, res, next);
    expect(next).toHaveBeenCalledOnce();
    expect((next.mock.calls[0][0] as Error).message).toBe(
      "ancestor lookup failed",
    );
  });

  it("46 an async resource resolver is awaited", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: () => [
        { role: "viewer", resource: ref("project", "p1") },
      ],
    });
    const handler = authorize({
      permission: "project:read",
      resource: async (req: any) => ref("project", req.params.id),
    });
    const req: any = { params: { id: "p1" } };
    const res = mockRes();
    const next = vi.fn();
    await handler(req, res, next);
    expect(next).toHaveBeenCalledOnce();
  });

  it("47 default denial returns 403 with the permission name", async () => {
    const authorize = expressRBAC(engine, { getAssignments: () => [] });
    const handler = authorize({
      permission: "project:read",
      resource: () => ref("project", "p1"),
    });
    const res = mockRes();
    const next = vi.fn();
    await handler({} as any, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.body).toEqual({ error: "Forbidden", permission: "project:read" });
    expect(next).not.toHaveBeenCalled();
  });

  it("48 custom onDenied replaces the default response", async () => {
    const onDenied = vi.fn((_req: any, res: any) =>
      res.status(418).json({ tea: true }),
    );
    const authorize = expressRBAC(engine, {
      getAssignments: () => [],
      onDenied,
    });
    const handler = authorize({
      permission: "project:read",
      resource: () => ref("project", "p1"),
    });
    const res = mockRes();
    const next = vi.fn();
    await handler({} as any, res, next);
    expect(res.statusCode).toBe(418);
    expect(next).not.toHaveBeenCalled();
  });

  it("49 async getAssignments resolving to [] denies", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: async () => [],
    });
    const handler = authorize({
      permission: "project:read",
      resource: () => ref("project", "p1"),
    });
    const res = mockRes();
    const next = vi.fn();
    await handler({} as any, res, next);
    expect(res.status).toHaveBeenCalledWith(403);
  });

  it("50 one authorize factory drives two routes independently", async () => {
    const authorize = expressRBAC(engine, {
      getAssignments: () => [
        { role: "viewer", resource: ref("project", "p1") },
      ],
    });
    const target = (req: any) => ref("project", req.params.id);
    const readH = authorize({ permission: "project:read", resource: target });
    const delH = authorize({ permission: "project:delete", resource: target });

    const req: any = { params: { id: "p1" } };
    const rRes = mockRes();
    const rNext = vi.fn();
    await readH(req, rRes, rNext);
    expect(rNext).toHaveBeenCalledOnce(); // viewer can read

    const dRes = mockRes();
    const dNext = vi.fn();
    await delH(req, dRes, dNext);
    expect(dRes.status).toHaveBeenCalledWith(403); // viewer cannot delete
    expect(dNext).not.toHaveBeenCalled();
  });
});
