import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api.ts";
import type { Task } from "../src/workbench.ts";

test("archiving a completed task closes scheduling and uses the returned version", async () => {
  const { organizeTask } = await import("../src/task-actions.ts");
  const requests: { url: string; method?: string; version: string | null }[] = [];
  const api = new ApiClient({ base: "/api", token: "" }, async (url, options) => {
    requests.push({ url: String(url), method: options?.method, version: new Headers(options?.headers).get("If-Match") });
    return new Response("{}", { headers: { ETag: '"task-v2"' } });
  });
  await organizeTask(api, "project", { audit_id: "audit", etag: '"task-v1"', paused: false } as Task, { archived: true });
  assert.deepEqual(requests, [
    { url: "/api/tasks/audit/pause", method: "POST", version: '"task-v1"' },
    { url: "/api/projects/project/tasks/audit", method: "PATCH", version: '"task-v2"' },
  ]);
});
