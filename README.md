# npm-audit-fix-message

Generate version-aware commit messages for `npm audit fix` changes.

This is a small dependency-free CLI for the case where a human runs
`npm audit fix` locally and wants a commit message similar to a
dependency-update bot PR:

```text
build: update vulnerable npm packages

- fixture-parser (dev; critical; 1.1.0 - 1.8.3; 1.8.3 -> 1.8.4)
  - Fixture parser mishandles quoted input - https://github.com/advisories/GHSA-aaaa-bbbb-cccc
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
- It reports packages that both changed in the lockfile and appeared in the
  pre-fix audit output.
- `npm audit --json` can exit non-zero when vulnerabilities are present; this is
  expected, and the CLI uses the JSON output when npm provides it.
