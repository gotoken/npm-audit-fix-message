# Design Notes

## Problem

`npm audit fix` updates lockfiles, but the resulting commit message often loses
the security context:

- affected package,
- dependency kind (`prod` or `dev`),
- advisory severity,
- vulnerable version range,
- old version and fixed version,
- advisory title and URL.

Dependabot and Renovate solve this by opening dependency-update PRs. This CLI is
for the smaller local workflow where a developer runs `npm audit fix` manually
but still wants a useful commit message.

## Proposed CLI Shape

```sh
npx npm-audit-fix-message --fix
```

Primary behavior:

1. capture `npm audit --json` before any fix,
2. capture the current lockfile,
3. run `npm audit fix`,
4. compare the old and new lockfiles,
5. match changed packages to pre-fix advisories,
6. print a commit message.

Secondary behavior:

```sh
npx npm-audit-fix-message --audit tmp/npm-audit-before.json
```

This supports users who already saved audit output or want to inspect/edit the
input before generating the message.

## Output Format

```text
build: update vulnerable npm packages

- <package> (<prod|dev>; <severity>; <vulnerable-range>; <from> -> <to>)
  - <advisory title> - <advisory URL>
```

This intentionally resembles dependency-update commit messages while staying
plain enough to paste into `git commit`.

## Non-goals

- Replacing Dependabot, Renovate, or audit policy tools.
- Maintaining allowlists.
- Deciding whether a vulnerability is acceptable.
- Running forced major updates beyond what `npm audit fix` chooses.

## Open Questions

- Should the default subject be configurable?
- Should `--fix` write `.git/COMMIT_EDITMSG` or only an explicit
  `--message-file`?
- Should package managers other than npm be supported later?
- Should workspaces be grouped in the output?
