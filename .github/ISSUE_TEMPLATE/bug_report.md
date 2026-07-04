---
name: Bug report
about: Something isn't behaving the way you expected
title: "[Bug] "
labels: bug
---

**What happened**
A clear description of the bug.

**Minimal reproduction**
Please share the smallest example that shows the problem:

```ts
const rbac = new RBAC({
  hierarchy: [/* ... */],
  roles: {/* ... */},
});

const assignments = [/* ... */];

rbac.can(assignments, "permission", target, ancestors);
// expected: true, got: false
```

**Expected behaviour**
What you expected to happen.

**Actual behaviour**
What actually happened.

**Environment**
- nested-rbac version:
- Node version:
- Using the Express middleware? yes / no
