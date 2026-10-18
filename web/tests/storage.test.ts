import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api.ts";
import { readRoute, routeHash } from "../src/workbench.ts";
import { readStorageStatus } from "../src/storageData.ts";

test("storage page preserves its route and displays a real unavailable probe", async () => {
  assert.deepEqual(readRoute(routeHash({ view: "storage" })), {
    view: "storage",
  });
  const status = {
    api_version: "codexploit/v1",
    driver: "postgres",
    profile: "catalog",
    readiness: "unavailable",
    durable: true,
    schema_version: "unknown",
    capabilities: { projects: true, tasks: false },
    locations: {
      catalog: "postgres",
      artifact_content: "workspace",
      accounts: "workspace",
      model_settings: "workspace",
    },
  };
  const client = new ApiClient(
    { base: "/api", token: "" },
    async (input, options) => {
      assert.equal(input, "/api/v1/storage/status");
      assert.equal(options?.cache, "no-store");
      return new Response(JSON.stringify(status), { status: 503 });
    },
  );
  assert.deepEqual(await readStorageStatus(client), status);
  const denied = new ApiClient(
    { base: "/api", token: "" },
    async () => new Response("{}", { status: 403 }),
  );
  await assert.rejects(() => readStorageStatus(denied), /权限/);
});
