import test from "node:test";
import assert from "node:assert/strict";
import {
  canStart,
  gradeCounts,
  initialFindings,
  initialPlugins,
  initialStorage,
  initialTasks,
  initialWorkflow,
  validateManifest,
  validateSource,
  validateStorage,
  validateWorkflow,
  workflowOrder,
} from "../src/prototype/model.ts";

test("source types have explicit snapshot semantics and reject traversal and embedded credentials", () => {
  assert.deepEqual(validateSource("local_folder", "/repos/service", ""), []);
  assert.ok(validateSource("local_folder", "/repos/../outside", "").length);
  assert.ok(validateSource("local_folder", "/repos/service", "main").length);
  assert.deepEqual(
    validateSource(
      "git_repository",
      "https://forge.example.invalid/service.git",
      "main",
    ),
    [],
  );
  assert.ok(
    validateSource(
      "git_repository",
      "https://user:fixture@forge.example.invalid/service.git",
      "main",
    ).length,
  );
});
test("workflow dependencies are topologically ordered and type checked", () => {
  assert.deepEqual(validateWorkflow(initialWorkflow, initialPlugins), []);
  assert.equal(
    workflowOrder(initialWorkflow).length,
    initialWorkflow.nodes.length,
  );
  const cyclic = structuredClone(initialWorkflow);
  cyclic.nodes[0].needs = ["report"];
  assert.ok(
    validateWorkflow(cyclic, initialPlugins).some((e) => e.includes("循环")),
  );
  assert.deepEqual(workflowOrder(cyclic), []);
  const missing = structuredClone(initialWorkflow);
  missing.nodes.find((n) => n.id === "normalize")!.needs = ["parse"];
  assert.ok(
    validateWorkflow(missing, initialPlugins).some((e) =>
      e.includes("scanner.alerts"),
    ),
  );
  const missingVersion = structuredClone(initialWorkflow);
  missingVersion.nodes[0].plugin_version = "99.0.0";
  assert.ok(
    validateWorkflow(missingVersion, initialPlugins).some((e) =>
      e.includes("未注册"),
    ),
  );
});
test("plugin manifests declare read-only scope and explicit execution entrypoints", () => {
  assert.deepEqual(validateManifest(initialPlugins[0]), []);
  const external = structuredClone(initialPlugins[0]);
  external.runtime = { kind: "process" };
  assert.ok(validateManifest(external).some((e) => e.includes("入口")));
  assert.ok(
    validateManifest({
      ...initialPlugins[0],
      permissions: { network: "none", source_write: true },
    }).length,
  );
});
test("task concurrency and verdict counts preserve independent state", () => {
  const tasks = structuredClone(initialTasks);
  assert.equal(canStart(tasks[2], tasks, 1), false);
  assert.equal(canStart(tasks[2], tasks, 4), true);
  assert.equal(canStart({ ...tasks[2], archived: true }, tasks, 4), false);
  assert.deepEqual(gradeCounts(initialFindings, "task-pay-api"), {
    high: 0,
    medium: 0,
    low: 0,
  });
  assert.deepEqual(gradeCounts(initialFindings, "task-edge"), {
    high: 1,
    medium: 0,
    low: 0,
  });
  const task = structuredClone(initialTasks[2]);
  const template = structuredClone(initialWorkflow);
  template.nodes.splice(0, 1);
  assert.equal(task.workflow.nodes.length, 7);
});
test("storage adapters validate structure without claiming to connect", () => {
  assert.deepEqual(validateStorage(initialStorage), []);
  assert.ok(
    validateStorage({
      ...initialStorage,
      metadata: { ...initialStorage.metadata, port: 99999 },
    }).length,
  );
  assert.ok(
    validateStorage({
      ...initialStorage,
      metadata: { ...initialStorage.metadata, driver: "custom" },
    }).length,
  );
  assert.ok(
    validateStorage({
      ...initialStorage,
      artifacts: {
        driver: "s3",
        endpoint: "https://user:fixture@store.example.invalid",
        bucket: "reports",
      },
    }).length,
  );
});
