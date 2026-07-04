# Contributing to nested-rbac

Thanks for your interest in improving `nested-rbac`! Contributions of all sizes are
welcome — bug reports, docs fixes, tests, and features.

## Getting started

```bash
# 1. Fork and clone the repo
git clone https://github.com/<your-username>/nested-rbac.git
cd nested-rbac

# 2. Install dependencies
npm install

# 3. Run the checks
npm run typecheck   # tsc --noEmit
npm test            # vitest run
npm run build       # tsup -> dist/
```

## Ground rules

- **Keep it dependency-free at runtime.** The core must not add runtime dependencies;
  `express` stays an optional peer dependency.
- **Every behaviour change needs a test.** Add or update tests in `tests/` so the
  permission logic stays fully covered.
- **Don't break the public API** without discussion — open an issue first for anything
  that changes exported types or method signatures.
- **Stay TypeScript-strict.** `npm run typecheck` must pass with no errors.

## Submitting a change

1. Create a branch: `git checkout -b fix/short-description`.
2. Make your change and add tests.
3. Ensure `npm run typecheck && npm test && npm run build` all pass.
4. Open a pull request describing **what** changed and **why**.

## Reporting bugs

Please include a minimal reproduction: the `hierarchy` + `roles` you configured, the
`assignments`, the `can(...)` / route call you made, what you expected, and what happened.

## Ideas / discussion

Not sure if something fits? Open an issue and let's talk it through before you build it.
