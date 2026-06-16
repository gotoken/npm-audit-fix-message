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
