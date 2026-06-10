# npm-audit-fix-message

Generate version-aware commit messages for `npm audit fix` changes.

This is a small CLI for the case where a human runs `npm audit fix` locally and
wants a commit message similar to a dependency-update bot PR:

```text
build: update vulnerable npm packages

- shell-quote (dev; critical; 1.1.0 - 1.8.3; 1.8.3 -> 1.8.4)
  - shell-quote quote() does not escape newlines in object .op values - https://github.com/advisories/GHSA-w7jw-789q-3m8p
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

Generate from a saved audit output:

```sh
npm audit --json > tmp/npm-audit-before.json
npm audit fix
npx npm-audit-fix-message --audit tmp/npm-audit-before.json
```

`--audit` accepts either `npm audit --json` output or the relevant text block
from `npm audit --verbose`.

## Options

- `--fix`: run `npm audit --json`, then `npm audit fix`, then generate output.
- `--audit <file>`: read saved audit output instead of running audit.
- `--base <rev>`: revision used to read the old lockfile when not using `--fix`.
  Defaults to `HEAD`.
- `--lockfile <path>`: lockfile path. Defaults to `package-lock.json`.
- `--message-file <path>`: also write the generated message to a file.

## Status

This directory is a temporary package-development starting point. The package
name, public API, and output details are still open for iteration.
