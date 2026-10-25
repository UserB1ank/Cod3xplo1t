import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api.ts";
import { pathStopMessage, stopProjectPaths, projectPathStopStatus, type PathStopResult } from "../src/project-path-controls.ts";

test("bulk path stop uses project-scoped API and reports pending execution truthfully", async () => {
  const calls: string[] = [];
  const pending: PathStopResult = { api_version: "codexploit/v1", project_id: "p/1", state: "STOPPING", cancelled_paths: 4, paused_tasks: 1, remaining_paths: 0, pending_agent_runs: 1, pending_verification_runs: 0, pending_workflows: 0, errors: [] };
  const api = new ApiClient({base: "/api", token: ""}, async (url, options) => {
    calls.push(`${options?.method || "GET"} ${url}`);
    return Response.json(pending);
  });
  const result = await stopProjectPaths(api, "p/1");
  assert.match(pathStopMessage(result), /1 个 Agent 运行/);
  assert.doesNotMatch(pathStopMessage(result), /均已结束/);
  await projectPathStopStatus(api, "p/1");
  assert.deepEqual(calls, ["POST /api/v1/projects/p%2F1/stop-paths", "GET /api/v1/projects/p%2F1/stop-paths"]);
  assert.match(pathStopMessage({...pending, state: "PARTIAL"}), /部分停止操作失败/);
});

test("project deletion conflict points to stopping paths instead of raw storage detail", async () => {
  const api = new ApiClient({base: "/api", token: ""}, async () => Response.json({code: "project_active_work", error: "storage: conflicting record"}, {status: 409}));
  await assert.rejects(() => api.deleteProject("project"), /停止所有路径/);
});
