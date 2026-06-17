import assert from "node:assert/strict";
import test from "node:test";

import { parseAuditOutput } from "../src/audit.mjs";
import { changedPackages } from "../src/lockfile.mjs";
import {
  fixedAdvisoriesByPackage,
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

test("generateMessageFromInputs omits advisories still present after fix", () => {
  const message = generateMessageFromInputs({
    auditRaw: JSON.stringify({
      vulnerabilities: {
        "fixed-fixture": {
          name: "fixed-fixture",
          severity: "high",
          range: "<1.0.1",
          via: [
            {
              title: "Fixed fixture vulnerability",
              url: "https://github.com/advisories/GHSA-fixed-fixture",
            },
          ],
        },
        "still-vulnerable-fixture": {
          name: "still-vulnerable-fixture",
          severity: "critical",
          range: "<3.0.0",
          via: [
            {
              title: "Still vulnerable fixture vulnerability",
              url: "https://github.com/advisories/GHSA-still-vulnerable",
            },
          ],
        },
      },
    }),
    auditAfterRaw: JSON.stringify({
      vulnerabilities: {
        "still-vulnerable-fixture": {
          name: "still-vulnerable-fixture",
          severity: "critical",
          range: "<3.0.0",
          via: [
            {
              title: "Still vulnerable fixture vulnerability",
              url: "https://github.com/advisories/GHSA-still-vulnerable",
            },
          ],
        },
      },
    }),
    oldLock: {
      packages: {
        "node_modules/fixed-fixture": { version: "1.0.0" },
        "node_modules/still-vulnerable-fixture": { version: "2.0.0" },
      },
    },
    newLock: {
      packages: {
        "node_modules/fixed-fixture": { version: "1.0.1" },
        "node_modules/still-vulnerable-fixture": { version: "2.0.1" },
      },
    },
  });

  assert.equal(
    message,
    [
      "build: update vulnerable npm packages",
      "",
      "- fixed-fixture (prod; high; <1.0.1; 1.0.0 -> 1.0.1)",
      "  - Fixed fixture vulnerability - https://github.com/advisories/GHSA-fixed-fixture",
      "",
    ].join("\n"),
  );
});

test("generateMessageFromInputs keeps only fixed advisories for a package", () => {
  const message = generateMessageFromInputs({
    auditRaw: JSON.stringify({
      vulnerabilities: {
        "mixed-fixture": {
          name: "mixed-fixture",
          severity: "high",
          range: "<2.0.0",
          via: [
            {
              title: "Fixed mixed fixture vulnerability",
              url: "https://github.com/advisories/GHSA-fixed-mixed",
            },
            {
              title: "Remaining mixed fixture vulnerability",
              url: "https://github.com/advisories/GHSA-remaining-mixed",
            },
          ],
        },
      },
    }),
    auditAfterRaw: JSON.stringify({
      vulnerabilities: {
        "mixed-fixture": {
          name: "mixed-fixture",
          severity: "high",
          range: "<2.0.0",
          via: [
            {
              title: "Remaining mixed fixture vulnerability",
              url: "https://github.com/advisories/GHSA-remaining-mixed",
            },
          ],
        },
      },
    }),
    oldLock: {
      packages: {
        "node_modules/mixed-fixture": { version: "1.0.0" },
      },
    },
    newLock: {
      packages: {
        "node_modules/mixed-fixture": { version: "1.0.1" },
      },
    },
  });

  assert.equal(
    message,
    [
      "build: update vulnerable npm packages",
      "",
      "- mixed-fixture (prod; high; <2.0.0; 1.0.0 -> 1.0.1)",
      "  - Fixed mixed fixture vulnerability - https://github.com/advisories/GHSA-fixed-mixed",
      "",
    ].join("\n"),
  );
});

test("generateMessageFromInputs shows direct package.json requesters", () => {
  const message = generateMessageFromInputs({
    auditRaw: JSON.stringify({
      vulnerabilities: {
        "vulnerable-fixture": {
          name: "vulnerable-fixture",
          severity: "high",
          range: "<1.0.1",
          via: [
            {
              title: "Vulnerable fixture advisory",
              url: "https://github.com/advisories/GHSA-requester-test",
            },
          ],
        },
        "chain-fixture": {
          name: "chain-fixture",
          severity: "high",
          range: "*",
          via: ["vulnerable-fixture"],
        },
      },
    }),
    auditAfterRaw: JSON.stringify({ vulnerabilities: {} }),
    oldLock: {
      packages: {
        "": { dependencies: { "direct-fixture": "^1.0.0" } },
        "node_modules/direct-fixture": {
          version: "1.0.0",
          dependencies: { "vulnerable-fixture": "^1.0.0" },
        },
        "node_modules/vulnerable-fixture": { version: "1.0.0" },
      },
    },
    newLock: {
      packages: {
        "": { dependencies: { "direct-fixture": "^1.0.0" } },
        "node_modules/direct-fixture": {
          version: "1.1.0",
          dependencies: { "vulnerable-fixture": "^1.0.0" },
        },
        "node_modules/vulnerable-fixture": { version: "1.0.1" },
      },
    },
  });

  assert.equal(
    message,
    [
      "build: update vulnerable npm packages",
      "",
      "- vulnerable-fixture (prod; high; <1.0.1; 1.0.0 -> 1.0.1)",
      "  - Vulnerable fixture advisory - https://github.com/advisories/GHSA-requester-test",
      "  - via package.json: root dependency direct-fixture (1.0.0 -> 1.1.0)",
      "",
    ].join("\n"),
  );
  assert.doesNotMatch(message, /chain-fixture/);
});

test("fixedAdvisoriesByPackage removes remaining advisory URLs", () => {
  const advisories = new Map([
    [
      "mixed-fixture",
      {
        name: "mixed-fixture",
        advisories: [
          {
            title: "Fixed mixed fixture vulnerability",
            url: "https://github.com/advisories/GHSA-fixed-mixed",
          },
          {
            title: "Remaining mixed fixture vulnerability",
            url: "https://github.com/advisories/GHSA-remaining-mixed",
          },
        ],
      },
    ],
  ]);
  const remaining = new Map([
    [
      "mixed-fixture",
      {
        name: "mixed-fixture",
        advisories: [
          {
            title: "Remaining mixed fixture vulnerability",
            url: "https://github.com/advisories/GHSA-remaining-mixed",
          },
        ],
      },
    ],
  ]);

  assert.deepEqual([...fixedAdvisoriesByPackage(advisories, remaining)], [
    [
      "mixed-fixture",
      {
        name: "mixed-fixture",
        advisories: [
          {
            title: "Fixed mixed fixture vulnerability",
            url: "https://github.com/advisories/GHSA-fixed-mixed",
          },
        ],
      },
    ],
  ]);
});

test("fixedAdvisoriesByPackage scopes title fallback by package name", () => {
  const advisories = new Map([
    [
      "fixed-fixture",
      {
        name: "fixed-fixture",
        advisories: [{ title: "Shared advisory title" }],
      },
    ],
  ]);
  const remaining = new Map([
    [
      "remaining-fixture",
      {
        name: "remaining-fixture",
        advisories: [{ title: "Shared advisory title" }],
      },
    ],
  ]);

  assert.deepEqual([...fixedAdvisoriesByPackage(advisories, remaining)], [
    [
      "fixed-fixture",
      {
        name: "fixed-fixture",
        advisories: [{ title: "Shared advisory title" }],
      },
    ],
  ]);
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

test("sanitizeCommitField removes OSC sequences terminated by BEL or string terminator", () => {
  assert.equal(
    sanitizeCommitField("before\x1B]52;c;Y2xpcGJvYXJk\x07after"),
    "beforeafter",
  );
  assert.equal(
    sanitizeCommitField("before\x1B]0;window title\x1B\\after"),
    "beforeafter",
  );
});

test("sanitizeCommitField removes CSI and simple ESC sequences", () => {
  assert.equal(sanitizeCommitField("red\x1B[31mtext\x1B[0m"), "redtext");
  assert.equal(sanitizeCommitField("reset\x1Bcafter"), "resetafter");
});

test("sanitizeCommitField removes raw controls and bidi overrides", () => {
  assert.equal(sanitizeCommitField("line\nbreak\ttext"), "linebreaktext");
  assert.equal(sanitizeCommitField("abc\u202Edef\u2069ghi"), "abcdefghi");
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
