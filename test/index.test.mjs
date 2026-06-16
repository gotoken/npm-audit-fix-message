import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import test from "node:test";

import {
  collectAuditInputs,
  collectFixInputs,
  generateMessage,
  parseArgs,
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
