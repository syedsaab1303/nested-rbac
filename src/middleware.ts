import type { NextFunction, Request, RequestHandler, Response } from "express";
import type { ResourceRef, RoleAssignment } from "./types.js";
import type { RBAC } from "./rbac.js";

/** Wiring that tells the middleware how to read your app's data. */
export interface MiddlewareOptions {
  /**
   * Extract the caller's role assignments from the request — typically from
   * `req.user` after your auth middleware has run.
   */
  getAssignments: (
    req: Request,
  ) => RoleAssignment[] | Promise<RoleAssignment[]>;
  /**
   * Resolve the ancestor chain (immediate parent up to the root) for a
   * resource. This is app/DB-specific, so you supply it. Omit it for flat
   * (non-inherited) checks.
   */
  getAncestors?: (
    resource: ResourceRef,
  ) => ResourceRef[] | Promise<ResourceRef[]>;
  /** Custom denial handler. Defaults to a `403` JSON response. */
  onDenied?: (req: Request, res: Response) => void;
}

/** Describes what a single guarded route requires. */
export interface AuthorizeRule {
  /** The permission the caller must hold, e.g. `"project:read"`. */
  permission: string;
  /** Derive the target resource from the request (e.g. from route params). */
  resource: (req: Request) => ResourceRef | Promise<ResourceRef>;
}

/**
 * Build an `authorize(rule)` factory bound to an {@link RBAC} instance.
 *
 * @example
 * ```ts
 * const authorize = expressRBAC(rbac, {
 *   getAssignments: (req) => req.user.assignments,
 *   getAncestors: (r) => resolveAncestorsFromDb(r),
 * });
 *
 * app.get(
 *   "/projects/:id/settings",
 *   authorize({
 *     permission: "project:read",
 *     resource: (req) => ({ type: "project", id: req.params.id }),
 *   }),
 *   handler,
 * );
 * ```
 */
export function expressRBAC(rbac: RBAC, options: MiddlewareOptions) {
  const { getAssignments, getAncestors, onDenied } = options;

  return function authorize(rule: AuthorizeRule): RequestHandler {
    return async (req: Request, res: Response, next: NextFunction) => {
      try {
        const target = await rule.resource(req);
        const assignments = await getAssignments(req);
        const ancestors = getAncestors ? await getAncestors(target) : [];

        if (rbac.can(assignments, rule.permission, target, ancestors)) {
          return next();
        }

        if (onDenied) return onDenied(req, res);
        res
          .status(403)
          .json({ error: "Forbidden", permission: rule.permission });
      } catch (err) {
        next(err);
      }
    };
  };
}
