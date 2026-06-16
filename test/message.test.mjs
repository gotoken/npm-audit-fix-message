import assert from "node:assert/strict";
import test from "node:test";

import { parseAuditOutput } from "../src/audit.mjs";
import { changedPackages } from "../src/lockfile.mjs";
import {
  formatCommitMessage,
  generateMessageFromInputs,
  sanitizeCommitField,
} from "../src/message.mjs";

test("formatCommitMessage formats npm audit --json changes", () => {
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

test("formatCommitMessage formats npm audit --verbose text changes", () => {
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
