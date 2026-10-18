import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api.ts";
import {
  preparePublication,
  readRevisionDirectory,
} from "../src/knowledgeData.ts";

test("publication uses the authoritative head and revision selection loads every page", async () => {
  const requests: string[] = [];
  const client = new ApiClient({ base: "/api", token: "" }, async (input) => {
    const url = String(input);
    requests.push(url);
    if (url.includes("limit=1&"))
      return new Response(
        JSON.stringify({
          head_revision: "rev-301",
          revisions: [{ revision: "rev-1" }],
          next_cursor: "older-page",
        }),
      );
    const second = url.includes("cursor=page-2");
    return new Response(
      JSON.stringify({
        head_revision: "rev-301",
        revisions: [{ revision: second ? "rev-301" : "rev-1" }],
        next_cursor: second ? "" : "page-2",
      }),
    );
  });
  const request = await preparePublication(
    client,
    "project-a",
    "snapshot-a",
    "invocation-a",
    "batch-a",
  );
  assert.equal(request.base_revision, "rev-301");
  assert.equal(request.batch_id, "batch-a");
  const directory = await readRevisionDirectory(
    client,
    "project-a",
    "snapshot-a",
  );
  assert.deepEqual(
    directory.revisions.map((r) => r.revision),
    ["rev-1", "rev-301"],
  );
  assert.equal(requests.length, 3);
  const broken = new ApiClient(
    { base: "/api", token: "" },
    async () => new Response(JSON.stringify({ revisions: [] })),
  );
  await assert.rejects(
    () => preparePublication(broken, "p", "s", "i", "b"),
    /head/,
  );
});
