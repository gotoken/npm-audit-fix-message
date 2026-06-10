import assert from "node:assert/strict";
import test from "node:test";

import {
  changedPackages,
  formatCommitMessage,
  parseArgs,
  parseAuditOutput,
} from "../src/index.mjs";

test("parseArgs supports fix mode", () => {
  assert.deepEqual(parseArgs(["--fix", "--message-file", "msg.txt"]), {
    auditPath: undefined,
    base: "HEAD",
    fix: true,
    lockfile: "package-lock.json",
    messageFile: "msg.txt",
  });
});

test("formats a commit message from npm audit --json output", () => {
  const audit = parseAuditOutput(
    JSON.stringify({
      vulnerabilities: {
        "fixture-runner": {
          name: "fixture-runner",
          severity: "critical",
          range: "<2.4.0",
          via: [
            {
              title: "Fixture runner allows unsafe file access",
              url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
            },
            {
              title: "Fixture runner mishandles project configuration",
              url: "https://github.com/advisories/GHSA-1111-2222-3333",
            },
          ],
        },
      },
    }),
  );
  const changes = changedPackages(
    {
      packages: {
        "node_modules/fixture-runner": { version: "2.3.1", dev: true },
      },
    },
    {
      packages: {
        "node_modules/fixture-runner": { version: "2.4.0", dev: true },
      },
    },
  );

  assert.equal(
    formatCommitMessage(audit, changes),
    [
      "build: update vulnerable npm packages",
      "",
      "- fixture-runner (dev; critical; <2.4.0; 2.3.1 -> 2.4.0)",
      "  - Fixture runner allows unsafe file access - https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
      "  - Fixture runner mishandles project configuration - https://github.com/advisories/GHSA-1111-2222-3333",
      "",
    ].join("\n"),
  );
});

test("formats a commit message from npm audit --verbose text output", () => {
  const audit = parseAuditOutput(`
fixture-parser  1.1.0 - 1.8.3
Severity: critical
Fixture parser mishandles quoted input - https://github.com/advisories/GHSA-aaaa-bbbb-cccc
Fixture parser allows unsafe token expansion - https://github.com/advisories/GHSA-4444-5555-6666
`);
  const changes = changedPackages(
    {
      packages: {
        "node_modules/fixture-parser": { version: "1.8.3", dev: true },
      },
    },
    {
      packages: {
        "node_modules/fixture-parser": { version: "1.8.4", dev: true },
      },
    },
  );

  assert.equal(
    formatCommitMessage(audit, changes),
    [
      "build: update vulnerable npm packages",
      "",
      "- fixture-parser (dev; critical; 1.1.0 - 1.8.3; 1.8.3 -> 1.8.4)",
      "  - Fixture parser mishandles quoted input - https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      "  - Fixture parser allows unsafe token expansion - https://github.com/advisories/GHSA-4444-5555-6666",
      "",
    ].join("\n"),
  );
});
