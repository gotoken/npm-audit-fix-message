import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

const DEFAULT_LOCKFILE = "package-lock.json";

export function parseArgs(argv) {
  const options = {
    auditPath: undefined,
    base: "HEAD",
    fix: false,
    lockfile: DEFAULT_LOCKFILE,
    messageFile: undefined,
  };

  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    const next = argv[index + 1];

    if (arg === "--fix") {
      options.fix = true;
    } else if (arg === "--audit" || arg === "-a") {
      options.auditPath = requireValue(arg, next);
      index += 1;
    } else if (arg === "--base" || arg === "-b") {
      options.base = requireValue(arg, next);
      index += 1;
    } else if (arg === "--lockfile") {
      options.lockfile = requireValue(arg, next);
      index += 1;
    } else if (arg === "--message-file") {
      options.messageFile = requireValue(arg, next);
      index += 1;
    } else if (arg === "--help" || arg === "-h") {
      options.help = true;
    } else {
      throw new Error(`Unknown option: ${arg}`);
    }
  }

  if (options.fix && options.auditPath) {
    throw new Error("Use either --fix or --audit, not both.");
  }

  return options;
}

function requireValue(option, value) {
  if (!value || value.startsWith("-")) {
    throw new Error(`Missing value for ${option}`);
  }

  return value;
}

export function helpText() {
  return [
    "Usage:",
    "  npm-audit-fix-message --fix",
    "  npm-audit-fix-message --audit <audit-before-file>",
    "",
    "Options:",
    "  --fix                  Run npm audit --json, npm audit fix, then generate",
    "  -a, --audit <file>     Saved npm audit --json or npm audit --verbose output",
    "  -b, --base <rev>       Revision to compare package-lock.json against",
    "                         when not using --fix (default: HEAD)",
    "      --lockfile <file>  Lockfile path (default: package-lock.json)",
    "      --message-file <file>",
    "                         Also write the generated commit message to a file",
    "  -h, --help             Show this help",
  ].join("\n");
}

export function parseAuditOutput(raw) {
  const trimmed = raw.trim();
  if (!trimmed) {
    return new Map();
  }

  try {
    return parseAuditJson(JSON.parse(trimmed));
  } catch {
    return parseAuditText(trimmed);
  }
}

export function parseAuditJson(audit) {
  const advisoriesByPackage = new Map();
  const vulnerabilities = audit?.vulnerabilities ?? {};

  for (const vulnerability of Object.values(vulnerabilities)) {
    if (!vulnerability?.name) {
      continue;
    }

    const advisories = [];
    for (const via of vulnerability.via ?? []) {
      if (!via || typeof via !== "object") {
        continue;
      }

      advisories.push({
        title: via.title ?? via.name ?? vulnerability.name,
        url: via.url,
      });
    }

    advisoriesByPackage.set(vulnerability.name, {
      name: vulnerability.name,
      severity: vulnerability.severity,
      range: vulnerability.range,
      advisories,
    });
  }

  return advisoriesByPackage;
}

export function parseAuditText(raw) {
  const advisoriesByPackage = new Map();
  const lines = raw.split(/\r?\n/);
  let current;

  for (const line of lines) {
    const packageMatch = line.match(/^(\S+)\s{2,}(.+)$/);
    if (packageMatch && !line.startsWith("Severity:")) {
      current = {
        name: packageMatch[1],
        range: packageMatch[2].trim(),
        advisories: [],
      };
      advisoriesByPackage.set(current.name, current);
      continue;
    }

    if (!current) {
      continue;
    }

    const severityMatch = line.match(/^Severity:\s+(\S+)/);
    if (severityMatch) {
      current.severity = severityMatch[1];
      continue;
    }

    const advisoryMatch = line.match(/^\s*(.+?)\s+-\s+(https?:\/\/\S+)\s*$/);
    if (advisoryMatch) {
      current.advisories.push({
        title: advisoryMatch[1].trim(),
        url: advisoryMatch[2],
      });
    }
  }

  return advisoriesByPackage;
}

export function packageNameFromLockPath(lockPath) {
  const marker = "node_modules/";
  const index = lockPath.lastIndexOf(marker);
  if (index === -1) {
    return undefined;
  }

  return lockPath.slice(index + marker.length);
}

export function packageKind(entry) {
  return entry?.dev ? "dev" : "prod";
}

export function packageEntriesByName(lock) {
  const entries = new Map();

  for (const [lockPath, entry] of Object.entries(lock?.packages ?? {})) {
    const name = packageNameFromLockPath(lockPath);
    if (!name || !entry?.version) {
      continue;
    }

    if (!entries.has(name)) {
      entries.set(name, []);
    }

    entries.get(name).push({ lockPath, entry });
  }

  return entries;
}

export function changedPackages(oldLock, newLock) {
  const oldEntries = packageEntriesByName(oldLock);
  const newEntries = packageEntriesByName(newLock);
  const changes = new Map();

  for (const [name, nextEntries] of newEntries) {
    const previousEntries = oldEntries.get(name) ?? [];

    for (const next of nextEntries) {
      const previous =
        previousEntries.find((entry) => entry.lockPath === next.lockPath) ??
        previousEntries.find(
          (entry) => entry.entry.version !== next.entry.version,
        );

      if (!previous || previous.entry.version === next.entry.version) {
        continue;
      }

      changes.set(name, {
        name,
        from: previous.entry.version,
        to: next.entry.version,
        kind: packageKind(next.entry),
      });
      break;
    }
  }

  return changes;
}

export function formatCommitMessage(advisoriesByPackage, changes) {
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
    ].filter(Boolean);

    lines.push(`- ${change.name} (${fields.join("; ")})`);

    for (const via of advisory.advisories) {
      const suffix = via.url ? ` - ${via.url}` : "";
      lines.push(`  - ${via.title}${suffix}`);
    }
  }

  return `${lines.join("\n")}\n`;
}

export function readJsonFile(filePath) {
  return JSON.parse(readFileSync(filePath, "utf8"));
}

export function readGitJson(revision, filePath) {
  const result = spawnSync("git", ["show", `${revision}:${filePath}`], {
    encoding: "utf8",
  });

  if (result.status !== 0) {
    throw new Error(
      `Failed to read ${filePath} from ${revision}: ${result.stderr.trim()}`,
    );
  }

  return JSON.parse(result.stdout);
}

export function runNpmAuditJson() {
  const result = spawnSync("npm", ["audit", "--json"], {
    encoding: "utf8",
    env: process.env,
    stdio: ["ignore", "pipe", "pipe"],
  });

  if (!result.stdout?.trim()) {
    throw new Error(
      result.stderr.trim() || "npm audit --json produced no JSON",
    );
  }

  return result.stdout;
}

export function runNpmAuditFix() {
  const result = spawnSync("npm", ["audit", "fix"], {
    encoding: "utf8",
    env: process.env,
    stdio: "inherit",
  });

  if (result.status !== 0) {
    throw new Error("npm audit fix failed.");
  }
}

export function generateMessage(options) {
  const lockfilePath = path.resolve(process.cwd(), options.lockfile);

  let auditRaw;
  let oldLock;

  if (options.fix) {
    auditRaw = runNpmAuditJson();
    oldLock = readJsonFile(lockfilePath);
    runNpmAuditFix();
  } else {
    if (!options.auditPath) {
      throw new Error("Missing required option: --fix or --audit <file>");
    }

    if (!existsSync(options.auditPath)) {
      throw new Error(`Audit output file does not exist: ${options.auditPath}`);
    }

    auditRaw = readFileSync(options.auditPath, "utf8");
    oldLock = readGitJson(options.base, options.lockfile);
  }

  const newLock = readJsonFile(lockfilePath);
  const advisories = parseAuditOutput(auditRaw);
  const changes = changedPackages(oldLock, newLock);

  return formatCommitMessage(advisories, changes);
}

export function main() {
  let options;
  try {
    options = parseArgs(process.argv.slice(2));
  } catch (error) {
    console.error(error.message);
    console.error("");
    console.error(helpText());
    process.exit(1);
  }

  if (options.help) {
    console.log(helpText());
    return;
  }

  try {
    const message = generateMessage(options);
    if (options.messageFile) {
      writeFileSync(options.messageFile, message);
    }
    process.stdout.write(message);
  } catch (error) {
    console.error(error.message);
    process.exit(1);
  }
}
