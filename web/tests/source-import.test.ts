import test from "node:test";
import assert from "node:assert/strict";
import { ApiClient } from "../src/api.ts";

test("source uploads preserve binary bytes, authentication and abort signal", async () => {
  let request: RequestInit | undefined;
  const api = new ApiClient({ base: "/api", token: "synthetic-upload-test" }, async (_url, options) => {
    request = options;
    return new Response("{}");
  });
  const archive = new Blob([new Uint8Array([0x50, 0x4b, 0, 0xff])]);
  const controller = new AbortController();
  await api.response("/v1/projects/fixture/imports/src-fixture?format=zip", {
    method: "POST", body: archive, signal: controller.signal,
    headers: { "Content-Type": "application/zip" },
  });
  assert.equal(request?.body, archive);
  assert.equal(request?.signal, controller.signal);
  assert.equal(new Headers(request?.headers).get("Content-Type"), "application/zip");
  assert.equal(new Headers(request?.headers).get("Authorization"), "Bearer synthetic-upload-test");
  assert.equal(request?.redirect, "error");
});
