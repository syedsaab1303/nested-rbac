import type {
  Permission,
  RBACOptions,
  ResourceRef,
  RoleAssignment,
} from "./types.js";

const keyOf = (r: ResourceRef): string => `${r.type}:${r.id}`;

/**
 * Does a permission pattern set satisfy the required permission?
 * Honours the `*` (global) and `<domain>:*` (per-domain) wildcards.
 */
function satisfies(patterns: Set<Permission>, required: Permission): boolean {
  if (patterns.has("*")) return true;
  if (patterns.has(required)) return true;
  const sep = required.indexOf(":");
  if (sep > -1) {
    const domain = required.slice(0, sep);
    if (patterns.has(`${domain}:*`)) return true;
  }
  return false;
}

/** The effective grant/deny patterns resolved for a target. */
export interface ResolvedPermissions {
  /** Positive permission patterns the user holds (may include wildcards). */
  granted: Permission[];
  /** Deny patterns that override grants (may include wildcards). */
  denied: Permission[];
}

/**
 * A framework-agnostic, hierarchical RBAC engine.
 *
 * Roles are assigned to a user at a node in the hierarchy. A role granted on a
 * parent node is **inherited** by every descendant node — so an `owner` on an
 * `organization` is implicitly an `owner` on every `team`, `project` and
 * `resource` beneath it, without any extra assignment.
 *
 * Permissions can also be granted ad-hoc per assignment (see
 * {@link RoleAssignment.permissions}), and any permission prefixed with `"!"`
 * is an explicit **deny** that overrides matching grants.
 *
 * @example
 * ```ts
 * const rbac = new RBAC({
 *   hierarchy: ["organization", "team", "project", "resource"],
 *   roles: {
 *     owner: ["*"],
 *     editor: ["project:read", "project:write"],
 *     viewer: ["project:read"],
 *     restricted: ["project:read", "!project:delete"], // deny wins
 *   },
 * });
 * ```
 */
export class RBAC {
  readonly hierarchy: readonly string[];
  private readonly roles: Record<string, Permission[]>;

  constructor(options: RBACOptions) {
    this.hierarchy = [...options.hierarchy];
    // Deep-copy each role's permission list so post-construction mutation of
    // the caller's options object cannot alter this engine's behaviour.
    this.roles = {};
    for (const [name, perms] of Object.entries(options.roles)) {
      this.roles[name] = [...perms];
    }
  }

  /** Position of a resource type in the hierarchy (0 = root), or `-1` if unknown. */
  levelOf(type: string): number {
    return this.hierarchy.indexOf(type);
  }

  /**
   * Internal: resolve grant/deny pattern sets for `target`, gathering every
   * assignment that applies to the target itself or one of its `ancestors`.
   * A permission prefixed with `"!"` is routed to the deny set.
   */
  private collect(
    assignments: RoleAssignment[],
    target: ResourceRef,
    ancestors: ResourceRef[],
  ): { granted: Set<Permission>; denied: Set<Permission> } {
    const applicable = new Set<string>([
      keyOf(target),
      ...ancestors.map(keyOf),
    ]);
    const granted = new Set<Permission>();
    const denied = new Set<Permission>();

    const add = (perm: Permission): void => {
      if (perm.startsWith("!")) denied.add(perm.slice(1));
      else granted.add(perm);
    };

    for (const a of assignments) {
      if (!applicable.has(keyOf(a.resource))) continue;
      if (a.role) for (const p of this.roles[a.role] ?? []) add(p);
      if (a.permissions) for (const p of a.permissions) add(p);
    }
    return { granted, denied };
  }

  /**
   * Resolve the effective **positive** permission set a user has on `target`,
   * given that resource's ancestor chain. Any role (or ad-hoc permissions)
   * assigned on `target` itself **or** on one of its `ancestors` contributes.
   *
   * Note: this returns grants only. Use {@link RBAC.listPermissions} for a
   * deny-aware breakdown, or {@link RBAC.can} for an authoritative check.
   */
  permissionsFor(
    assignments: RoleAssignment[],
    target: ResourceRef,
    ancestors: ResourceRef[] = [],
  ): Set<Permission> {
    return this.collect(assignments, target, ancestors).granted;
  }

  /**
   * Return the full resolved permission picture for `target` — useful for
   * sending a capability list to a frontend. Both arrays are sorted for
   * stable output and may contain wildcard patterns.
   */
  listPermissions(
    assignments: RoleAssignment[],
    target: ResourceRef,
    ancestors: ResourceRef[] = [],
  ): ResolvedPermissions {
    const { granted, denied } = this.collect(assignments, target, ancestors);
    return {
      granted: [...granted].sort(),
      denied: [...denied].sort(),
    };
  }

  /**
   * Returns `true` if the user (via `assignments`) holds `permission` on
   * `target`, accounting for roles inherited from `ancestors`. An explicit
   * deny (`"!..."`) that matches the permission always overrides any grant.
   */
  can(
    assignments: RoleAssignment[],
    permission: Permission,
    target: ResourceRef,
    ancestors: ResourceRef[] = [],
  ): boolean {
    const { granted, denied } = this.collect(assignments, target, ancestors);
    if (satisfies(denied, permission)) return false;
    return satisfies(granted, permission);
  }
}
