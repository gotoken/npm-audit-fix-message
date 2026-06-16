import assert from "node:assert/strict";
import test from "node:test";

import { changedPackages } from "../src/lockfile.mjs";

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
