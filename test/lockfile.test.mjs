import assert from "node:assert/strict";
import test from "node:test";

import {
  changedPackages,
  directDependencyRequestersForChanges,
} from "../src/lockfile.mjs";

test("changedPackages handles scoped packages and dependency kind", () => {
  const changes = changedPackages(
    {
      packages: {
        "node_modules/@scope/fixture": { version: "1.0.0" },
        "node_modules/dev-fixture": { version: "2.0.0", dev: true },
      },
    },
    {
      packages: {
        "node_modules/@scope/fixture": { version: "1.0.1" },
        "node_modules/dev-fixture": { version: "2.1.0", dev: true },
      },
    },
  );

  assert.deepEqual(changes.get("@scope/fixture"), {
    name: "@scope/fixture",
    from: "1.0.0",
    to: "1.0.1",
    kind: "prod",
  });
  assert.deepEqual(changes.get("dev-fixture"), {
    name: "dev-fixture",
    from: "2.0.0",
    to: "2.1.0",
    kind: "dev",
  });
});

test("changedPackages handles duplicate package names and unchanged packages", () => {
  const changes = changedPackages(
    {
      packages: {
        "node_modules/fixture": { version: "1.0.0" },
        "node_modules/parent/node_modules/fixture": { version: "1.5.0" },
        "node_modules/unchanged": { version: "3.0.0" },
      },
    },
    {
      packages: {
        "node_modules/fixture": { version: "1.0.0" },
        "node_modules/parent/node_modules/fixture": { version: "1.5.1" },
        "node_modules/unchanged": { version: "3.0.0" },
      },
    },
  );

  assert.deepEqual(changes.get("fixture"), {
    name: "fixture",
    from: "1.5.0",
    to: "1.5.1",
    kind: "prod",
  });
  assert.equal(changes.has("unchanged"), false);
});

test("directDependencyRequestersForChanges finds package.json requesters", () => {
  const oldLock = {
    packages: {
      "": { dependencies: { "direct-prod": "^1.0.0" } },
      "apps/gui": { devDependencies: { "direct-dev": "^2.0.0" } },
      "node_modules/direct-prod": {
        version: "1.0.0",
        dependencies: { "vulnerable-fixture": "^1.0.0" },
      },
      "apps/gui/node_modules/direct-dev": {
        version: "2.0.0",
        dependencies: { "vulnerable-fixture": "^1.0.0" },
      },
      "node_modules/vulnerable-fixture": { version: "1.0.0" },
      "apps/gui/node_modules/vulnerable-fixture": { version: "1.0.0" },
    },
  };
  const newLock = {
    packages: {
      ...oldLock.packages,
      "node_modules/vulnerable-fixture": { version: "1.0.1" },
      "apps/gui/node_modules/vulnerable-fixture": { version: "1.0.0" },
    },
  };
  const changes = changedPackages(oldLock, newLock);
  const requesters = directDependencyRequestersForChanges(
    oldLock,
    newLock,
    changes,
  );

  assert.deepEqual(requesters.get("vulnerable-fixture"), [
    {
      kind: "prod",
      manifestPath: ".",
      name: "direct-prod",
    },
  ]);
});

test("directDependencyRequestersForChanges includes changed direct package versions", () => {
  const oldLock = {
    packages: {
      "": { devDependencies: { "direct-dev": "^2.0.0" } },
      "node_modules/direct-dev": {
        version: "2.0.0",
        dependencies: { "vulnerable-fixture": "^1.0.0" },
      },
      "node_modules/vulnerable-fixture": { version: "1.0.0" },
    },
  };
  const newLock = {
    packages: {
      "": { devDependencies: { "direct-dev": "^2.0.0" } },
      "node_modules/direct-dev": {
        version: "2.1.0",
        dependencies: { "vulnerable-fixture": "^1.0.0" },
      },
      "node_modules/vulnerable-fixture": { version: "1.0.1" },
    },
  };
  const changes = changedPackages(oldLock, newLock);
  const requesters = directDependencyRequestersForChanges(
    oldLock,
    newLock,
    changes,
  );

  assert.deepEqual(requesters.get("vulnerable-fixture"), [
    {
      from: "2.0.0",
      kind: "dev",
      manifestPath: ".",
      name: "direct-dev",
      to: "2.1.0",
    },
  ]);
});

test("directDependencyRequestersForChanges keeps multiple requesters for one lock path", () => {
  const oldLock = {
    packages: {
      "": { dependencies: { "shared-direct": "^1.0.0" } },
      "apps/api": { dependencies: { "shared-direct": "^1.0.0" } },
      "node_modules/shared-direct": {
        version: "1.0.0",
        dependencies: { "vulnerable-fixture": "^1.0.0" },
      },
      "node_modules/vulnerable-fixture": { version: "1.0.0" },
    },
  };
  const newLock = {
    packages: {
      ...oldLock.packages,
      "node_modules/vulnerable-fixture": { version: "1.0.1" },
    },
  };
  const changes = changedPackages(oldLock, newLock);
  const requesters = directDependencyRequestersForChanges(
    oldLock,
    newLock,
    changes,
  );

  assert.deepEqual(requesters.get("vulnerable-fixture"), [
    {
      kind: "prod",
      manifestPath: ".",
      name: "shared-direct",
    },
    {
      kind: "prod",
      manifestPath: "apps/api",
      name: "shared-direct",
    },
  ]);
});
