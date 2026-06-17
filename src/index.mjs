import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
import path from "node:path";
import process from "node:process";

import { generateMessageFromInputs } from "./message.mjs";
import { changedPackages } from "./lockfile.mjs";

export {
  parseAuditJson,
  parseAuditOutput,
  parseAuditText,
} from "./audit.mjs";
export {
  changedPackages,
  directDependencyRequestersByName,
  directDependencyRequestersForChanges,
  packageEntriesByName,
  packageKind,
  packageNameFromLockPath,
} from "./lockfile.mjs";
export {
  formatCommitMessage,
  fixedAdvisoriesByPackage,
  generateMessageFromInputs,
  sanitizeCommitField,
} from "./message.mjs";

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

  if (!options.help && !options.fix && !options.auditPath) {
    throw new Error("Missing required option: --fix or --audit <file>");
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
    env: process.env,
    stdio: ["ignore", "ignore", "ignore"],
  });

  if (result.error) {
    throw new Error(`npm audit fix failed: ${result.error.message}`);
  }

  return {
    signal: result.signal,
    status: result.status,
  };
}

function auditFixFailed(result) {
  return (result?.status ?? 0) !== 0 || Boolean(result?.signal);
}

function auditFixExitDescription(result) {
  if (result?.signal) {
    return `signal ${result.signal}`;
  }

  return `status ${result?.status ?? "unknown"}`;
}

export function collectFixInputs(options, helpers = {}) {
  const {
    cwd = process.cwd,
    readJson = readJsonFile,
    resolvePath = path.resolve,
    runAuditFix = runNpmAuditFix,
    runAuditJson = runNpmAuditJson,
    warn = console.error,
  } = helpers;
  const lockfilePath = resolvePath(cwd(), options.lockfile);
  const auditRaw = runAuditJson();
  const oldLock = readJson(lockfilePath);
  const fixResult = runAuditFix() ?? { status: 0 };
  const newLock = readJson(lockfilePath);
  let auditAfterRaw;

  if (auditFixFailed(fixResult)) {
    const changes = changedPackages(oldLock, newLock);

    if (changes.size === 0) {
      throw new Error("npm audit fix failed.");
    }

    warn(
      [
        `Warning: npm audit fix exited with ${auditFixExitDescription(
          fixResult,
        )} after applying lockfile changes.`,
        "Some vulnerabilities may remain; run npm audit to review them.",
        "",
      ].join("\n"),
    );

    auditAfterRaw = runAuditJson();
  }

  return {
    ...(auditAfterRaw ? { auditAfterRaw } : {}),
    auditRaw,
    oldLock,
    newLock,
  };
}

export function collectAuditInputs(options, helpers = {}) {
  const {
    cwd = process.cwd,
    exists = existsSync,
    readGitJsonFile = readGitJson,
    readJson = readJsonFile,
    readText = (filePath) => readFileSync(filePath, "utf8"),
    resolvePath = path.resolve,
  } = helpers;

  if (!exists(options.auditPath)) {
    throw new Error(`Audit output file does not exist: ${options.auditPath}`);
  }

  return {
    auditRaw: readText(options.auditPath),
    oldLock: readGitJsonFile(options.base, options.lockfile),
    newLock: readJson(resolvePath(cwd(), options.lockfile)),
  };
}

export function collectMessageInputs(options, helpers = {}) {
  return options.fix
    ? collectFixInputs(options, helpers)
    : collectAuditInputs(options, helpers);
}

export function generateMessage(options, helpers = {}) {
  return generateMessageFromInputs(collectMessageInputs(options, helpers));
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
