import { describe, expect, it, vi } from "vitest";
import { memoizeAncestors } from "../src/memoize.js";
import type { ResourceRef } from "../src/types.js";

const project: ResourceRef = { type: "project", id: "P1" };
const otherProject: ResourceRef = { type: "project", id: "P2" };
const chain: ResourceRef[] = [{ type: "organization", id: "O1" }];

describe("memoizeAncestors", () => {
  it("calls the underlying resolver only once per resource", async () => {
    const resolver = vi.fn((_r: ResourceRef) => chain);
    const memo = memoizeAncestors(resolver);

    await memo(project);
    await memo(project);
    await memo(project);

    expect(resolver).toHaveBeenCalledTimes(1);
  });

  it("returns the resolved ancestor chain", async () => {
    const memo = memoizeAncestors(() => chain);
    await expect(memo(project)).resolves.toEqual(chain);
  });

  it("caches per distinct resource key", async () => {
    const resolver = vi.fn((_r: ResourceRef) => chain);
    const memo = memoizeAncestors(resolver);

    await memo(project);
    await memo(otherProject);
    await memo(project);

    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it("works with an async resolver and shares the in-flight promise", async () => {
    const resolver = vi.fn(async (_r: ResourceRef) => chain);
    const memo = memoizeAncestors(resolver);

    // fire concurrently before the first resolves
    const [a, b] = await Promise.all([memo(project), memo(project)]);

    expect(resolver).toHaveBeenCalledTimes(1);
    expect(a).toEqual(chain);
    expect(b).toEqual(chain);
  });
});
