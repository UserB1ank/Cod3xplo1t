import test from "node:test";
import assert from "node:assert/strict";
import {
  latestSnapshot,
  readRoute,
  routeHash,
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
