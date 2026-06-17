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

    if (advisories.length === 0) {
      continue;
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

  for (const [name, advisory] of advisoriesByPackage) {
    if (advisory.advisories.length === 0) {
      advisoriesByPackage.delete(name);
    }
  }

  return advisoriesByPackage;
}
