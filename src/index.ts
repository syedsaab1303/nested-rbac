export { RBAC } from "./rbac.js";
export type { ResolvedPermissions } from "./rbac.js";
export { expressRBAC } from "./middleware.js";
export { memoizeAncestors } from "./memoize.js";

export type {
  Permission,
  ResourceRef,
  RoleAssignment,
  RBACOptions,
} from "./types.js";
export type { MiddlewareOptions, AuthorizeRule } from "./middleware.js";
