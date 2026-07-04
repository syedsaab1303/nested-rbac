/**
 * A permission string. Convention: `"<domain>:<action>"`, e.g. `"project:read"`.
 * Two wildcards are supported:
 *   - `"*"`          — grants everything
 *   - `"billing:*"`  — grants every action within the `billing` domain
 *
 * A leading `"!"` turns a permission into an explicit **deny** that overrides
 * any grant for the matching permission(s), e.g. `"!project:delete"` or
 * `"!billing:*"`. Deny always wins, and honours the same wildcards.
 */
export type Permission = string;

/** A pointer to a single node in your resource hierarchy. */
export interface ResourceRef {
  /** The resource type, e.g. `"project"`. Should be one of the `hierarchy` levels. */
  type: string;
  /** The unique id of this resource instance. */
  id: string;
}

/**
 * Binds permissions to a user at a specific node in the hierarchy. Supply a
 * `role` (resolved via the `roles` map), an ad-hoc list of `permissions`, or
 * both — whatever is present contributes to the effective set. The grant
 * inherits to every descendant of `resource`.
 */
export interface RoleAssignment {
  /** A role name that exists in the `roles` map. */
  role?: string;
  /**
   * Ad-hoc permissions granted directly by this assignment, without going
   * through the `roles` map. Supports the same wildcards and `"!"` deny prefix.
   */
  permissions?: Permission[];
  /** The node this role was granted on (the role inherits to all descendants). */
  resource: ResourceRef;
}

/** Configuration for an {@link RBAC} instance. */
export interface RBACOptions {
  /**
   * The resource hierarchy, ordered from the broadest ancestor to the
   * narrowest child, e.g. `["organization", "team", "project", "resource"]`.
   */
  hierarchy: string[];
  /** Map of role name → the permissions that role grants. */
  roles: Record<string, Permission[]>;
}
