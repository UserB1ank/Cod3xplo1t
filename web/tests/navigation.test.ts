import test from "node:test";
import assert from "node:assert/strict";
import { readRoute, routeHash } from "../src/workbench.ts";

test("unselected project functions retain their requested destination", () => {
  for (const view of ["overview", "tasks", "sources", "knowledge", "findings", "reports", "artifacts", "plugins", "workflows", "settings"]) {
    const route = { view, selecting: true };
    assert.deepEqual(readRoute(routeHash(route)), route);
    assert.equal(routeHash(route), `#/workspace/${view}`);
  }
});

test("configuration subpages have stable routes while legacy links remain readable", () => {
  for (const section of ["models", "storage"] as const) {
    const route = { view: "configuration", section };
    assert.deepEqual(readRoute(routeHash(route)), route);
  }
  assert.deepEqual(readRoute("#/settings"), { view: "settings" });
  assert.deepEqual(readRoute("#/storage"), { view: "storage" });
  assert.deepEqual(readRoute("#/workspace/unknown"), { view: "projects" });
});
