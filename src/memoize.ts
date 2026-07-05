import type { ResourceRef } from "./types.js";

const keyOf = (r: ResourceRef): string => `${r.type}:${r.id}`;

/**
 * Wrap a `getAncestors` resolver with a cache so repeated lookups for the same
 * resource don't re-hit your database within a single unit of work.
 *
 * The cache lives for the lifetime of the returned function, so **create one
 * per request (or per batch job)** — e.g. inside a request-scoped middleware —
 * to avoid serving stale hierarchy data across requests. Concurrent lookups for
 * the same resource share a single in-flight promise.
 *
 * @example
 * ```ts
 * app.use((req, _res, next) => {
 *   // fresh cache per request
 *   req.getAncestors = memoizeAncestors((r) => db.getAncestorChain(r));
 *   next();
 * });
 * ```
 */
export function memoizeAncestors(
  resolve: (resource: ResourceRef) => ResourceRef[] | Promise<ResourceRef[]>,
): (resource: ResourceRef) => Promise<ResourceRef[]> {
  const cache = new Map<string, Promise<ResourceRef[]>>();
  return (resource: ResourceRef): Promise<ResourceRef[]> => {
    const key = keyOf(resource);
    let hit = cache.get(key);
    if (!hit) {
      hit = Promise.resolve(resolve(resource));
      cache.set(key, hit);
    }
    return hit;
  };
}
