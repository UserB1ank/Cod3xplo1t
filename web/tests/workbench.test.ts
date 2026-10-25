import test from "node:test";
import assert from "node:assert/strict";
import {
  latestSnapshot,
  readRoute,
  routeHash,
  sourceNetworkError,
  taskGradeCounts,
  taskState,
  type Task,
  type ProjectFinding,
} from "../src/workbench.ts";
import { ApiClient } from "../src/api.ts";

test("project and task routes preserve opaque identifiers and reject malformed hashes", () => {
  const route = { project: "project/a", task: "audit:one", view: "findings" };
  assert.deepEqual(readRoute(routeHash(route)), route);
  assert.deepEqual(readRoute("#/projects/%GG/tasks"), { view: "projects" });
});
test("active calls remain visible when scheduling is paused", () => {
  const task = {
    paused: true,
    status: "READY",
    path_count: 2,
    counts_by_status: { ANALYZING: 1, QUEUED: 1 },
  } as unknown as Task;
  assert.equal(taskState(task), "RUNNING");
  task.counts_by_status = { QUEUED: 2 };
  assert.equal(taskState(task), "PAUSED");
});
test("workflow task state follows pause and cancellation controls", () => {
  const task = { workflow_status: "PAUSED" } as Task;
  assert.equal(taskState(task), "PAUSED");
  for (const status of ["PAUSING", "CANCELLING"]) {
    task.workflow_status = status;
    assert.equal(taskState(task), "RUNNING");
  }
});
test("only confirmed findings contribute to per-task grades", () => {
  const findings = [
    {
      severity: "high",
      status: "confirmed",
      sources: [{ task_id: "one" }, { task_id: "two" }],
    },
    { severity: "high", status: "candidate", sources: [{ task_id: "one" }] },
    { severity: "low", status: "confirmed", sources: [{ task_id: "other" }] },
  ] as ProjectFinding[];
  assert.deepEqual(taskGradeCounts(findings, "one"), {
    high: 1,
    medium: 0,
    low: 0,
  });
});
test("API rejects credential-bearing origins and refuses redirects", async () => {
  assert.throws(
    () =>
      new ApiClient({
        base: "https://user:secret@example.invalid/api",
        token: "",
      }),
  );
  let request: RequestInit | undefined;
  const api = new ApiClient({ base: "/api", token: "fixture-only" }, (async (
    _url: unknown,
    options: RequestInit,
  ) => {
    request = options;
    return new Response("{}");
  }) as typeof fetch);
  await api.get("/projects");
  assert.equal(request?.redirect, "error");
  assert.equal(
    new Headers(request?.headers).get("Authorization"),
    "Bearer fixture-only",
  );
  await assert.rejects(() => api.get("//other.invalid"));
});
test("latest snapshot is selected without mutating server data", () => {
  const snapshots = [
    { snapshot_id: "old", created_at: "2024-01-01" },
    { snapshot_id: "new", created_at: "2024-02-01" },
  ];
  assert.equal(latestSnapshot(snapshots as never).snapshot_id, "new");
  assert.equal(snapshots[0].snapshot_id, "old");
});

test("API maps actionable 403 codes instead of blaming permissions", async () => {
  const forbidden = (code: string) =>
    new ApiClient(
      { base: "/api", token: "" },
      async () =>
        new Response(JSON.stringify({ code, error: "server detail" }), {
          status: 403,
          headers: { "Content-Type": "application/json" },
        }),
    );
  await assert.rejects(
    () => forbidden("network_disabled").get("/projects"),
    /远程 Git 访问未启用/,
  );
  await assert.rejects(
    () => forbidden("origin_forbidden").get("/projects"),
    /请求来源无效/,
  );
  await assert.rejects(
    () => forbidden("git_access_denied").get("/projects"),
    /Git 仓库访问被拒绝/,
  );
  await assert.rejects(
    () => forbidden("forbidden").get("/projects"),
    /没有执行该操作的权限/,
  );
});

test("remote sources are blocked before a project is created when network is off", () => {
  assert.match(
    sourceNetworkError("git_repository", "https://example.invalid/repo.git", false),
    /远程 Git 访问未启用/,
  );
  assert.match(
    sourceNetworkError("legacy_auto", "ssh://example.invalid/repo.git", false),
    /远程 Git 访问未启用/,
  );
  assert.equal(
    sourceNetworkError("git_repository", "https://example.invalid/repo.git", true),
    "",
  );
  assert.equal(sourceNetworkError("local_folder", "/repos/service", false), "");
});

test("completed tasks show a completed control instead of an active pause toggle", async () => {
  const { taskSchedulingControl } = await import("../src/workbench.ts");
  const task = { paused: false, status: "READY", path_count: 4, counts_by_status: { CONCLUDED: 4 } } as Task;
  assert.equal(taskSchedulingControl(task).state, "complete");
  assert.equal(taskSchedulingControl(task).enabled, false);
  task.counts_by_status = { HYPOTHESIS_FORMED: 4 };
  assert.equal(taskSchedulingControl(task).state, "complete");
  task.paused = true;
  assert.equal(taskSchedulingControl(task).state, "complete");
  task.paused = false;
  task.counts_by_status = { QUEUED: 4 };
  assert.equal(taskSchedulingControl(task).state, "pause");
  assert.equal(taskSchedulingControl(task).enabled, true);
  task.paused = true;
  assert.equal(taskSchedulingControl(task).state, "resume");
  task.workflow_status = "RUNNING";
  assert.equal(taskSchedulingControl(task).enabled, false);
});

test("cancelled paths remain stopped instead of being labelled completed", async () => {
  const { taskSchedulingControl } = await import("../src/workbench.ts");
  const task = { paused: true, status: "READY", path_count: 4, counts_by_status: { CANCELLED: 4 } } as Task;
  assert.equal(taskState(task), "CANCELLED");
  assert.equal(taskSchedulingControl(task).label, "已停止");
  assert.equal(taskSchedulingControl(task).enabled, false);
});

test("completed partial graph preparation is distinct from blocked review", () => {
  const task = { workflow_status: "PARTIAL", path_count: 100 } as Task;
  assert.equal(taskState(task), "PARTIAL");
});
