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

function manifestDependencyEntries(entry) {
  return [
    ["dependencies", "prod"],
    ["devDependencies", "dev"],
    ["optionalDependencies", "optional"],
  ].flatMap(([field, kind]) =>
    Object.keys(entry?.[field] ?? {}).map((name) => ({ kind, name })),
  );
}

function packageDependencyNames(entry) {
  return Object.keys({
    ...(entry?.dependencies ?? {}),
    ...(entry?.optionalDependencies ?? {}),
  });
}

function resolveDependencyPath(packages, fromPath, name) {
  let basePath = fromPath;

  while (true) {
    const dependencyPath = basePath
      ? `${basePath}/node_modules/${name}`
      : `node_modules/${name}`;

    if (packages[dependencyPath]) {
      return dependencyPath;
    }

    const nestedIndex = basePath.lastIndexOf("/node_modules/");
    if (nestedIndex !== -1) {
      basePath = basePath.slice(0, nestedIndex);
      continue;
    }

    if (basePath) {
      basePath = "";
      continue;
    }

    return undefined;
  }
}

function isManifestPath(lockPath) {
  return lockPath === "" || !lockPath.includes("node_modules");
}

function collectDirectDependencyRequesters(oldLock, newLock, lockPaths) {
  const oldPackages = oldLock?.packages ?? {};
  const packages = newLock?.packages ?? {};
  const reverseDependencies = new Map();
  const directDependencies = [];
  const requesters = new Map();
  const targetPaths = new Set(lockPaths);

  for (const [lockPath, entry] of Object.entries(packages)) {
    for (const name of packageDependencyNames(entry)) {
      const dependencyPath = resolveDependencyPath(packages, lockPath, name);
      if (!dependencyPath) {
        continue;
      }

      if (!reverseDependencies.has(dependencyPath)) {
        reverseDependencies.set(dependencyPath, []);
      }
      reverseDependencies.get(dependencyPath).push(lockPath);
    }

    if (!isManifestPath(lockPath)) {
      continue;
    }

    for (const dependency of manifestDependencyEntries(entry)) {
      const dependencyPath = resolveDependencyPath(
        packages,
        lockPath,
        dependency.name,
      );

      if (dependencyPath) {
        const previousVersion = oldPackages[dependencyPath]?.version;
        const nextVersion = packages[dependencyPath]?.version;
        directDependencies.push({
          ...dependency,
          lockPath: dependencyPath,
          manifestPath: lockPath || ".",
          ...(previousVersion &&
          nextVersion &&
          previousVersion !== nextVersion
            ? { from: previousVersion, to: nextVersion }
            : {}),
        });
      }
    }
  }

  for (const lockPath of targetPaths) {
    const packageName = packageNameFromLockPath(lockPath);
    if (!packageName) {
      continue;
    }

    const queue = [lockPath];
    const seen = new Set(queue);
    const found = new Map();

    for (let index = 0; index < queue.length; index += 1) {
      const currentPath = queue[index];

      for (const dependency of directDependencies) {
        if (dependency.lockPath !== currentPath) {
          continue;
        }

        found.set(
          `${dependency.manifestPath}\0${dependency.kind}\0${dependency.name}`,
          {
            ...(dependency.from && dependency.to
              ? { from: dependency.from, to: dependency.to }
              : {}),
            kind: dependency.kind,
            manifestPath: dependency.manifestPath,
            name: dependency.name,
          },
        );
      }

      for (const parentPath of reverseDependencies.get(currentPath) ?? []) {
        if (!seen.has(parentPath)) {
          seen.add(parentPath);
          queue.push(parentPath);
        }
      }
    }

    if (!requesters.has(packageName)) {
      requesters.set(packageName, []);
    }

    requesters.get(packageName).push(...found.values());
  }

  for (const [name, values] of requesters) {
    requesters.set(
      name,
      values.sort(
        (left, right) =>
          left.manifestPath.localeCompare(right.manifestPath) ||
          left.name.localeCompare(right.name) ||
          left.kind.localeCompare(right.kind),
      ),
    );
  }

  return requesters;
}

export function directDependencyRequestersByName(lock) {
  return collectDirectDependencyRequesters(
    lock,
    lock,
    Object.keys(lock?.packages ?? {}),
  );
}

export function directDependencyRequestersForChanges(oldLock, newLock, changes) {
  return collectDirectDependencyRequesters(
    oldLock,
    newLock,
    [...changes.values()].map((change) => change.lockPath).filter(Boolean),
  );
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

      const change = {
        name,
        from: previous.entry.version,
        to: next.entry.version,
        kind: packageKind(next.entry),
      };
      Object.defineProperty(change, "lockPath", {
        enumerable: false,
        value: next.lockPath,
      });
      changes.set(name, change);
      break;
    }
  }

  return changes;
}
