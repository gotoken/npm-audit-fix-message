import assert from "node:assert/strict";
import test from "node:test";

import { parseAuditJson, parseAuditOutput } from "../src/audit.mjs";

test("parseAuditJson ignores string-only via entries", () => {
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
      "fixture-chain": {
        name: "fixture-chain",
        severity: "moderate",
        range: "*",
        via: ["fixture-parser"],
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
  assert.equal(advisories.has("fixture-empty"), false);
  assert.equal(advisories.has("fixture-chain"), false);
});

test("parseAuditOutput parses npm audit --json output", () => {
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
          ],
        },
      },
    }),
  );

  assert.deepEqual(audit.get("fixture-runner"), {
    name: "fixture-runner",
    severity: "critical",
    range: "<2.4.0",
    advisories: [
      {
        title: "Fixture runner allows unsafe file access",
        url: "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
      },
    ],
  });
});

test("parseAuditOutput parses npm audit --verbose text output", () => {
  const audit = parseAuditOutput(`
fixture-parser  1.1.0 - 1.8.3
Severity: critical
Fixture parser mishandles quoted input - https://github.com/advisories/GHSA-aaaa-bbbb-cccc
Fixture parser allows unsafe token expansion - https://github.com/advisories/GHSA-4444-5555-6666
fixture-chain  *
Severity: moderate
`);

  assert.deepEqual(audit.get("fixture-parser"), {
    name: "fixture-parser",
    range: "1.1.0 - 1.8.3",
    severity: "critical",
    advisories: [
      {
        title: "Fixture parser mishandles quoted input",
        url: "https://github.com/advisories/GHSA-aaaa-bbbb-cccc",
      },
      {
        title: "Fixture parser allows unsafe token expansion",
        url: "https://github.com/advisories/GHSA-4444-5555-6666",
      },
    ],
  });
  assert.equal(audit.has("fixture-chain"), false);
});
