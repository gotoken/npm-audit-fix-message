import { parseAuditOutput } from "./audit.mjs";
import {
  changedPackages,
  directDependencyRequestersForChanges,
} from "./lockfile.mjs";

const OSC_SEQUENCE = /\x1B\][^\x07\x1B]*(?:\x07|\x1B\\)/gu;
const CSI_SEQUENCE = /\x1B\[[0-?]*[ -/]*[@-~]/gu;
const ESCAPE_SEQUENCE = /\x1B[ -/]*[@-~]/gu;
const C0_C1_CONTROL = /[\x00-\x1F\x7F-\x9F]/gu;
const BIDI_CONTROL = /[\u061C\u200E\u200F\u202A-\u202E\u2066-\u2069]/gu;

export function sanitizeCommitField(value) {
  // This is defensive stripping for commit-message fields, not a full terminal
  // parser. Remove known terminal and text-direction controls, then remove any
  // remaining raw control bytes so untrusted audit text cannot affect display.
  return String(value)
    .replace(OSC_SEQUENCE, "")
    .replace(CSI_SEQUENCE, "")
    .replace(ESCAPE_SEQUENCE, "")
    .replace(C0_C1_CONTROL, "")
    .replace(BIDI_CONTROL, "");
}

function advisoryKey(advisory) {
  return advisory?.url || advisory?.title;
}

function remainingAdvisoryKeys(remainingAdvisories) {
  if (!remainingAdvisories) {
    return new Set();
  }

  return new Set(
    [...remainingAdvisories.values()]
      .flatMap((advisory) => advisory.advisories)
      .map(advisoryKey)
      .filter(Boolean),
  );
}

export function fixedAdvisoriesByPackage(
  advisoriesByPackage,
  remainingAdvisories,
) {
  const remainingKeys = remainingAdvisoryKeys(remainingAdvisories);
  if (remainingKeys.size === 0) {
    return advisoriesByPackage;
  }

  const fixedAdvisories = new Map();

  for (const [name, advisory] of advisoriesByPackage) {
    const fixedVia = advisory.advisories.filter((via) => {
      const key = advisoryKey(via);
      return key ? !remainingKeys.has(key) : true;
    });

    if (advisory.advisories.length > 0 && fixedVia.length === 0) {
      continue;
    }

    fixedAdvisories.set(name, {
      ...advisory,
      advisories: fixedVia,
    });
  }

  return fixedAdvisories;
}

function requesterKindLabel(kind) {
  if (kind === "prod") {
    return "dependency";
  }

  return `${kind}Dependency`;
}

function formatRequester(requester) {
  const manifest =
    requester.manifestPath === "." ? "root" : requester.manifestPath;
  const versionChange =
    requester.from && requester.to ? ` (${requester.from} -> ${requester.to})` : "";
  return `${manifest} ${requesterKindLabel(requester.kind)} ${
    requester.name
  }${versionChange}`;
}

export function formatCommitMessage(
  advisoriesByPackage,
  changes,
  requestersByPackage = new Map(),
) {
  const changedVulnerablePackages = [...changes.values()].filter((change) =>
    advisoriesByPackage.has(change.name),
  );

  if (changedVulnerablePackages.length === 0) {
    throw new Error("No changed packages matched the audit output.");
  }

  changedVulnerablePackages.sort((left, right) =>
    left.name.localeCompare(right.name),
  );

  const lines = ["build: update vulnerable npm packages", ""];

  for (const change of changedVulnerablePackages) {
    const advisory = advisoriesByPackage.get(change.name);
    const fields = [
      change.kind,
      advisory.severity,
      advisory.range,
      `${change.from} -> ${change.to}`,
    ]
      .filter(Boolean)
      .map(sanitizeCommitField);

    lines.push(`- ${sanitizeCommitField(change.name)} (${fields.join("; ")})`);

    for (const via of advisory.advisories) {
      const suffix = via.url ? ` - ${sanitizeCommitField(via.url)}` : "";
      lines.push(`  - ${sanitizeCommitField(via.title)}${suffix}`);
    }

    for (const requester of requestersByPackage.get(change.name) ?? []) {
      lines.push(
        `  - via package.json: ${sanitizeCommitField(
          formatRequester(requester),
        )}`,
      );
    }
  }

  return `${lines.join("\n")}\n`;
}

export function generateMessageFromInputs({
  auditAfterRaw,
  auditRaw,
  oldLock,
  newLock,
}) {
  const advisories = fixedAdvisoriesByPackage(
    parseAuditOutput(auditRaw),
    auditAfterRaw ? parseAuditOutput(auditAfterRaw) : undefined,
  );
  const changes = changedPackages(oldLock, newLock);
  const requesters = directDependencyRequestersForChanges(
    oldLock,
    newLock,
    changes,
  );

  return formatCommitMessage(advisories, changes, requesters);
}
