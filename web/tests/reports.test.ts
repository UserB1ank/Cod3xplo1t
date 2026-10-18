import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api.ts";
import { readVerifiedReport } from "../src/report-client.ts";
import type { ArtifactRef } from "../src/Artifacts.tsx";

test("report download authenticates and refuses corrupt or incomplete bytes", async () => {
  const bytes = new TextEncoder().encode("fixed report");
  const hash = [...new Uint8Array(await crypto.subtle.digest("SHA-256", bytes))]
    .map((n) => n.toString(16).padStart(2, "0"))
    .join("");
  const ref = {
    id: "artifact-report",
    kind: "report.document",
    sha256: hash,
    bytes: bytes.length,
    scope: {
      project_id: "project-one",
      source_id: "source-one",
      snapshot_id: "snapshot-one",
    },
  } as ArtifactRef;
  let content = bytes;
  let request: RequestInit | undefined;
  let address = "";
  const api = new ApiClient({ base: "/api", token: "fixture-only" }, (async (
    url: unknown,
    options: RequestInit,
  ) => {
    address = String(url);
    request = options;
    return new Response(content);
  }) as typeof fetch);
  assert.deepEqual(await readVerifiedReport(api, ref), bytes);
  assert.equal(
    new Headers(request?.headers).get("Authorization"),
    "Bearer fixture-only",
  );
  assert.ok(
    address.startsWith(
      "/api/v1/projects/project-one/snapshots/snapshot-one/artifacts/artifact-report/content",
    ),
  );
  content = new TextEncoder().encode("wrong report");
  await assert.rejects(readVerifiedReport(api, ref), /摘要/);
  content = bytes.slice(0, 4);
  await assert.rejects(readVerifiedReport(api, ref), /长度/);
  await assert.rejects(
    readVerifiedReport(api, { ...ref, bytes: 65 * 1048576 }),
    /预算/,
  );
});
