# npm-audit-fix-message

Generate version-aware commit messages for `npm audit fix` changes.

This is a small dependency-free CLI for the case where a human runs
`npm audit fix` locally and wants a commit message similar to a
dependency-update bot PR:

```text
build: update vulnerable npm packages

- fixture-parser (dev; critical; 1.1.0 - 1.8.3; 1.8.3 -> 1.8.4)
  - Fixture parser mishandles quoted input - https://github.com/advisories/GHSA-aaaa-bbbb-cccc
  - via package.json: apps/gui devDependency fixture-tool (2.3.1 -> 2.4.0)
```

## Usage

Run the whole flow:

```sh
npx npm-audit-fix-message --fix
```

That command:

1. runs `npm audit --json` and keeps the pre-fix result in memory,
2. reads the current `package-lock.json`,
3. runs `npm audit fix`,
4. compares the old and new lockfiles,
5. prints a commit message to stdout.

Because this mode runs `npm audit fix`, it can modify `package-lock.json` and
possibly `package.json`, depending on what npm decides is needed. Run it from
the project you want to update, preferably with a clean working tree so the
resulting lockfile changes are easy to review.

If `npm audit fix` applies some lockfile updates but exits non-zero because
other vulnerabilities remain, this command still prints a commit message for
the actual lockfile changes and writes a warning to stderr. Remaining
vulnerabilities are not listed as fixed. The full `npm audit fix` report is
suppressed so the generated commit message stays easy to copy; run `npm audit`
afterward to inspect the remaining issues. To
avoid claiming unresolved advisories were fixed, `--fix` also checks post-fix
audit output and omits advisory URLs that are still reported as vulnerable.

Generate from a saved audit output:

```sh
npm audit --json > tmp/npm-audit-before.json
npm audit fix
npx npm-audit-fix-message --audit tmp/npm-audit-before.json
```

`--audit` accepts either `npm audit --json` output or the relevant text block
from `npm audit --verbose`.

Write the generated message to a file as well as stdout:

```sh
npx npm-audit-fix-message --audit tmp/npm-audit-before.json --message-file .git/COMMIT_EDITMSG
```

## Options

- `--fix`: run `npm audit --json`, then `npm audit fix`, then generate output.
- `--audit <file>`: read saved audit output instead of running audit.
- `--base <rev>`: revision used to read the old lockfile when not using `--fix`.
  Defaults to `HEAD`.
- `--lockfile <path>`: lockfile path. Defaults to `package-lock.json`.
- `--message-file <path>`: also write the generated message to a file.

## Limits

- This tool is not a replacement for Dependabot, Renovate, or CI audit policy.
- It only compares npm lockfiles and audit output.
- It reports packages that both changed in the lockfile and had concrete
  advisory entries in the pre-fix audit output.
- It omits audit graph nodes that only point to other vulnerable packages.
- When possible, it lists package.json or workspace package.json dependencies
  that pull in the fixed package as nested `via package.json` lines. If that
  direct dependency's installed lockfile version changed, the line includes its
  old and new versions.
- If `npm audit fix` exits non-zero after changing the lockfile, `--fix`
  treats the changed packages as a partial success and warns that issues may
  remain. It omits advisories that are still present in post-fix audit output.
- It does not print npm's full audit report. If `npm audit fix` fails without
  lockfile changes, the error includes npm's stderr when available and otherwise
  asks you to run `npm audit` for details.
- `npm audit --json` can exit non-zero when vulnerabilities are present; this is
  expected, and the CLI uses the JSON output when npm provides it.
