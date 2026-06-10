# Agent Development Notes

This package is intended to stay small, dependency-light, and easy to run with
`npx`.

## Product Boundary

- Build a local helper for humans who run `npm audit fix` manually.
- Do not try to replace Dependabot, Renovate, or CI audit policy tools.
- Prefer output that can be pasted directly into `git commit` or written with
  `--message-file`.
- Keep the generated message factual: package, dependency kind, severity,
  vulnerable range, old version, new version, advisory title, and advisory URL.

## CLI Contract

The primary command is:

```sh
npm-audit-fix-message --fix
```

It should:

1. capture `npm audit --json` before changes,
2. capture the current lockfile before changes,
3. run `npm audit fix`,
4. compare old and new lockfiles,
5. print a version-aware commit message.

The secondary command is:

```sh
npm-audit-fix-message --audit <file>
```

It should generate the same message from saved `npm audit --json` or relevant
`npm audit --verbose` text output.

## Implementation Preferences

- Keep runtime dependencies at zero unless a dependency removes real complexity.
- Prefer Node standard library APIs.
- Keep parsing functions pure and exported so tests can exercise them directly.
- Avoid network calls except the `npm audit` and `npm audit fix` commands the
  user explicitly requested through the CLI mode.
- Treat `npm audit --json` non-zero exit status as expected when vulnerabilities
  are present; use stdout JSON if it exists.
- Do not mutate project files other than the changes caused by `npm audit fix`
  and an explicit `--message-file` target.

## Testing

Use `node:test` with fixture-sized objects rather than network-dependent tests.
Cover at least:

- `npm audit --json` parsing,
- `npm audit --verbose` text parsing,
- lockfile version diffing,
- formatted commit-message output,
- argument validation for mutually exclusive modes.

When changing CLI behavior, update `README.md` and `docs/design.md` if the user
workflow or product boundary changes.
