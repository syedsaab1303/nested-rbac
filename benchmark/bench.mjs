// Micro-benchmark for the core `can()` check.
//
// It answers the question raised on the launch post: how does the engine behave
// as the hierarchy gets deep and checks land on hot request paths? The check is
// pure in-memory set logic, so the numbers below reflect the engine ONLY — your
// real-world latency is dominated by the `getAncestors` DB lookup you supply.
//
//   npm run build && node benchmark/bench.mjs
import { RBAC } from "../dist/index.js";

const rbac = new RBAC({
  hierarchy: ["organization", "team", "project", "resource"],
  roles: {
    owner: ["*"],
    editor: ["resource:read", "resource:write", "resource:delete"],
    viewer: ["resource:read"],
  },
});

const target = { type: "resource", id: "R1" };

// A realistic shallow chain (parent -> root).
const shallow = [
  { type: "project", id: "P1" },
  { type: "team", id: "T1" },
  { type: "organization", id: "O1" },
];
const shallowRoot = [{ role: "owner", resource: { type: "organization", id: "O1" } }];

// A deep chain (12 levels) with the role assigned on the far root.
const deep = Array.from({ length: 12 }, (_, i) => ({ type: `level${i}`, id: `N${i}` }));
const deepRoot = [{ role: "owner", resource: deep[deep.length - 1] }];

// Many assignments (100 unrelated + 1 that matches at the root).
const many = Array.from({ length: 100 }, (_, i) => ({
  role: "viewer",
  resource: { type: "project", id: `PX${i}` },
}));
many.push({ role: "owner", resource: { type: "organization", id: "O1" } });

function bench(label, fn, seconds = 2) {
  for (let i = 0; i < 50_000; i++) fn(); // warm up the JIT
  const start = process.hrtime.bigint();
  const endAt = start + BigInt(seconds) * 1_000_000_000n;
  let ops = 0;
  while (process.hrtime.bigint() < endAt) {
    fn();
    ops++;
  }
  const elapsedNs = Number(process.hrtime.bigint() - start);
  const perSec = Math.round(ops / (elapsedNs / 1e9));
  const nsPerOp = (elapsedNs / ops).toFixed(0);
  console.log(
    `${label.padEnd(42)} ${perSec.toLocaleString().padStart(15)} ops/sec   (~${nsPerOp} ns/op)`,
  );
}

console.log(`\nnested-rbac core can() benchmark  —  Node ${process.version}\n`);
bench("depth 4,  1 assignment  (inherited)", () =>
  rbac.can(shallowRoot, "resource:write", target, shallow),
);
bench("depth 12, 1 assignment  (deep inherited)", () =>
  rbac.can(deepRoot, "resource:write", target, deep),
);
bench("depth 4,  101 assignments", () =>
  rbac.can(many, "resource:write", target, shallow),
);
console.log("\nNote: this measures the engine only. In production the cost is the");
console.log("getAncestors() DB lookup — resolve the whole chain in one query.\n");
