import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  changedPackages,
  collectAuditInputs,
  collectFixInputs,
  formatCommitMessage,
  generateMessage,
  generateMessageFromInputs,
  parseAuditJson,
  parseArgs,
  parseAuditOutput,
  sanitizeCommitField,
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

test("parseArgs rejects invalid option combinations", () => {
  assert.throws(
    () => parseArgs(["--fix", "--audit", "audit.json"]),
    /Use either --fix or --audit/,
  );
  assert.throws(() => parseArgs(["--unknown"]), /Unknown option/);
  assert.throws(() => parseArgs(["--audit"]), /Missing value/);
  assert.throws(
    () => parseArgs(["--message-file"]),
    /Missing value/,
  );
  assert.throws(
    () => parseArgs([]),
    /Missing required option/,
  );
});

test("parseArgs allows help without a mode", () => {
  assert.equal(parseArgs(["--help"]).help, true);
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

test("generateMessageFromInputs formats from raw audit and lock objects", () => {
  const message = generateMessageFromInputs({
    auditRaw: JSON.stringify({
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
          ],
        },
      },
    }),
    oldLock: {
      packages: {
        "node_modules/fixture-runner": { version: "2.3.1", dev: true },
      },
    },
    newLock: {
      packages: {
        "node_modules/fixture-runner": { version: "2.4.0", dev: true },
      },
    },
  });

  assert.equal(
    message,
    [
      "build: update vulnerable npm packages",
      "",
      "- fixture-runner (dev; critical; <2.4.0; 2.3.1 -> 2.4.0)",
      "  - Fixture runner allows unsafe file access - https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
      "",
    ].join("\n"),
  );
});

test("parseAuditJson ignores string via entries and keeps empty advisories", () => {
  const advisories = parseAuditJson({
    vulnerabilities: {
      "fixture-parser": {
        name: "fixture-parser",
        severity: "high",
        range: "<1.8.4",
        via: [
          "transitive-parent",
          {
            title: "Fixture parser mishandles quoted input",
            url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
          },
        ],
      },
      "fixture-empty": {
        name: "fixture-empty",
        severity: "moderate",
        range: "<2.0.0",
        via: [],
      },
    },
  });

  assert.deepEqual(advisories.get("fixture-parser"), {
    name: "fixture-parser",
    severity: "high",
    range: "<1.8.4",
    advisories: [
      {
        title: "Fixture parser mishandles quoted input",
        url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      },
    ],
  });
  assert.deepEqual(advisories.get("fixture-empty"), {
    name: "fixture-empty",
    severity: "moderate",
    range: "<2.0.0",
    advisories: [],
  });
});

test("sanitizeCommitField removes terminal and bidi control sequences", () => {
  assert.equal(
    sanitizeCommitField(
      [
        "safe",
        "\x1B[2J",
        "screen",
        "\x1B]52;c;Y2xpcGJvYXJkLXBheWxvYWQ=\x07",
        "clipboard",
        "\u202E",
        "bidi",
        "\x00",
        "nul",
      ].join(""),
    ),
    "safescreenclipboardbidinul",
  );
});

test("formatCommitMessage strips control characters from generated fields", () => {
  const advisories = new Map([
    [
      "fixture-runner",
      {
        name: "fixture-runner",
        severity: "critical\x1B[31m",
        range: "<2.4.0\u202E",
        advisories: [
          {
            title: "Clear terminal\x1B[2J and set clipboard\x1B]52;c;QQ==\x07",
            url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz\x1B[?1049h",
          },
        ],
      },
    ],
  ]);
  const changes = new Map([
    [
      "fixture-runner",
      {
        name: "fixture-runner",
        from: "2.3.1",
        to: "2.4.0",
        kind: "dev\u202E",
      },
    ],
  ]);
  const message = formatCommitMessage(advisories, changes);

  assert.equal(
    message,
    [
      "build: update vulnerable npm packages",
      "",
      "- fixture-runner (dev; critical; <2.4.0; 2.3.1 -> 2.4.0)",
      "  - Clear terminal and set clipboard - https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
      "",
    ].join("\n"),
  );
  assert.doesNotMatch(message, /[\x00-\x09\x0B-\x1F\x7F-\x9F]/u);
  assert.doesNotMatch(message, /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/u);
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

test("changedPackages handles scoped packages and dependency kind", () => {
  const changes = changedPackages(
    {
      packages: {
        "node_modules/@scope/fixture": { version: "1.0.0" },
        "node_modules/dev-fixture": { version: "2.0.0", dev: true },
      },
    },
    {
      packages: {
        "node_modules/@scope/fixture": { version: "1.0.1" },
        "node_modules/dev-fixture": { version: "2.1.0", dev: true },
      },
    },
  );

  assert.deepEqual(changes.get("@scope/fixture"), {
    name: "@scope/fixture",
    from: "1.0.0",
    to: "1.0.1",
    kind: "prod",
  });
  assert.deepEqual(changes.get("dev-fixture"), {
    name: "dev-fixture",
    from: "2.0.0",
    to: "2.1.0",
    kind: "dev",
  });
});

test("changedPackages handles duplicate package names and unchanged packages", () => {
  const changes = changedPackages(
    {
      packages: {
        "node_modules/fixture": { version: "1.0.0" },
        "node_modules/parent/node_modules/fixture": { version: "1.5.0" },
        "node_modules/unchanged": { version: "3.0.0" },
      },
    },
    {
      packages: {
        "node_modules/fixture": { version: "1.0.0" },
        "node_modules/parent/node_modules/fixture": { version: "1.5.1" },
        "node_modules/unchanged": { version: "3.0.0" },
      },
    },
  );

  assert.deepEqual(changes.get("fixture"), {
    name: "fixture",
    from: "1.5.0",
    to: "1.5.1",
    kind: "prod",
  });
  assert.equal(changes.has("unchanged"), false);
});

test("collectFixInputs captures audit and lockfiles around npm audit fix", () => {
  const calls = [];
  const oldLock = {
    packages: {
      "node_modules/fixture-runner": { version: "2.3.1", dev: true },
    },
  };
  const newLock = {
    packages: {
      "node_modules/fixture-runner": { version: "2.4.0", dev: true },
    },
  };
  const inputs = collectFixInputs(
    { lockfile: "package-lock.json" },
    {
      cwd: () => "/work/project",
      readJson: (filePath) => {
        calls.push(`readJson:${filePath}`);
        return calls.filter((call) => call.startsWith("readJson")).length === 1
          ? oldLock
          : newLock;
      },
      resolvePath: (...parts) => parts.join("/"),
      runAuditFix: () => calls.push("runAuditFix"),
      runAuditJson: () => {
        calls.push("runAuditJson");
        return '{"vulnerabilities":{}}';
      },
    },
  );

  assert.deepEqual(inputs, {
    auditRaw: '{"vulnerabilities":{}}',
    oldLock,
    newLock,
  });
  assert.deepEqual(calls, [
    "runAuditJson",
    "readJson:/work/project/package-lock.json",
    "runAuditFix",
    "readJson:/work/project/package-lock.json",
  ]);
});

test("collectAuditInputs reads saved audit output and git base lockfile", () => {
  const oldLock = {
    packages: {
      "node_modules/fixture-runner": { version: "2.3.1", dev: true },
    },
  };
  const newLock = {
    packages: {
      "node_modules/fixture-runner": { version: "2.4.0", dev: true },
    },
  };
  const inputs = collectAuditInputs(
    {
      auditPath: "tmp/audit.json",
      base: "HEAD~1",
      lockfile: "package-lock.json",
    },
    {
      cwd: () => "/work/project",
      exists: (filePath) => filePath === "tmp/audit.json",
      readGitJsonFile: (revision, filePath) => {
        assert.equal(revision, "HEAD~1");
        assert.equal(filePath, "package-lock.json");
        return oldLock;
      },
      readJson: (filePath) => {
        assert.equal(filePath, "/work/project/package-lock.json");
        return newLock;
      },
      readText: (filePath) => {
        assert.equal(filePath, "tmp/audit.json");
        return '{"vulnerabilities":{}}';
      },
      resolvePath: (...parts) => parts.join("/"),
    },
  );

  assert.deepEqual(inputs, {
    auditRaw: '{"vulnerabilities":{}}',
    oldLock,
    newLock,
  });
});

test("collectAuditInputs rejects missing audit file", () => {
  assert.throws(
    () =>
      collectAuditInputs(
        {
          auditPath: "missing.json",
          base: "HEAD",
          lockfile: "package-lock.json",
        },
        { exists: () => false },
      ),
    /Audit output file does not exist/,
  );
});

test("generateMessage uses the selected input collection path", () => {
  const message = generateMessage(
    {
      auditPath: "tmp/audit.json",
      base: "HEAD",
      fix: false,
      lockfile: "package-lock.json",
    },
    {
      cwd: () => "/work/project",
      exists: () => true,
      readGitJsonFile: () => ({
        packages: {
          "node_modules/fixture-runner": { version: "2.3.1", dev: true },
        },
      }),
      readJson: () => ({
        packages: {
          "node_modules/fixture-runner": { version: "2.4.0", dev: true },
        },
      }),
      readText: () =>
        JSON.stringify({
          vulnerabilities: {
            "fixture-runner": {
              name: "fixture-runner",
              severity: "critical",
              range: "<2.4.0",
              via: [{ title: "Fixture runner allows unsafe file access" }],
            },
          },
        }),
      resolvePath: (...parts) => parts.join("/"),
    },
  );

  assert.equal(
    message,
    [
      "build: update vulnerable npm packages",
      "",
      "- fixture-runner (dev; critical; <2.4.0; 2.3.1 -> 2.4.0)",
      "  - Fixture runner allows unsafe file access",
      "",
    ].join("\n"),
  );
});

test("CLI prints help", (context) => {
  const result = spawnSync(
    process.execPath,
    ["bin/npm-audit-fix-message.mjs", "--help"],
    { encoding: "utf8" },
  );

  if (result.error?.code === "EPERM") {
    context.skip("child process execution is blocked in this environment");
    return;
  }

  assert.equal(result.status, 0);
  assert.match(result.stdout, /npm-audit-fix-message --fix/);
  assert.equal(result.stderr, "");
});
