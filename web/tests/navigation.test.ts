import test from "node:test";
import assert from "node:assert/strict";
import { readRoute, routeHash } from "../src/workbench.ts";

test("unselected project functions retain their requested destination", () => {
  for (const view of [
    "overview",
    "tasks",
    "sources",
    "knowledge",
    "findings",
    "reports",
    "artifacts",
    "plugins",
    "workflows",
    "settings",
  ]) {
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

test("opening a project starts at its overview and preserves an explicit destination", async () => {
  const { projectDestination, primaryNavigation } = await import(
    "../src/navigation.ts"
  );
  assert.deepEqual(projectDestination("project-a"), {
    project: "project-a",
    view: "overview",
  });
  assert.deepEqual(
    projectDestination("project-a", { view: "paths", selecting: true }),
    { project: "project-a", view: "paths" },
  );
  assert.deepEqual(readRoute("#/projects/project-a"), {
    project: "project-a",
    view: "overview",
  });
  assert.deepEqual(
    primaryNavigation.map((item) => item.id),
    ["overview", "knowledge", "paths", "assistant", "findings", "reports"],
  );
  for (const view of ["paths", "assistant"]) {
    assert.deepEqual(readRoute(routeHash({ project: "project-a", view })), {
      project: "project-a",
      view,
    });
    assert.deepEqual(readRoute(routeHash({ view, selecting: true })), {
      view,
      selecting: true,
    });
  }
  assert.deepEqual(readRoute("#/projects/project-a/tasks"), {
    project: "project-a",
    view: "tasks",
  });
});
