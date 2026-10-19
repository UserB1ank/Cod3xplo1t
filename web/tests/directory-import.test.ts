import test from "node:test";
import assert from "node:assert/strict";
import { prepareDirectory, importDirectory } from "../src/directory-import.ts";
import { ApiClient } from "../src/api.ts";

function selected(path: string, content: string) {
  const file = new File([content], path.split("/").at(-1)!);
  Object.defineProperty(file, "webkitRelativePath", { value: path });
  return file;
}

test("directory selection screens sensitive bytes before transmission and keeps relative paths", async () => {
  const selection = await prepareDirectory([selected("local-root/internal/服务 main.go", "package service\n"), selected("local-root/.env", "SYNTHETIC_ONLY=1"), selected("local-root/node_modules/noise.js", "ignored")]);
  assert.equal(selection.manifest.files.length, 1);
  assert.equal(selection.manifest.files[0].path, "internal/服务 main.go");
  assert.equal(selection.manifest.files[0].size, 16);
  assert.match(selection.manifest.files[0].sha256, /^[a-f0-9]{64}$/);
  // A generated directory is recorded once, not once per file; a sensitive file is
  // still named individually.
  assert.deepEqual(selection.manifest.excluded, ["node_modules", ".env"]);
  assert.equal(selection.summary.excludedFiles, 2);
  assert.deepEqual(selection.summary.directories, [{ path: "node_modules", files: 1 }]);
  const api = new ApiClient({ base: "/api", token: "synthetic-test" }, async (_url, options) => {
    assert.equal(new Headers(options?.headers).has("Content-Type"), false);
    const body = options?.body as FormData;
    assert.equal(body.getAll("files").length, 1);
    assert.equal((body.get("files") as File).name, "internal/服务 main.go");
    assert.equal(body.get("manifest"), JSON.stringify(selection.manifest));
    return new Response("{}");
  });
  await importDirectory(api, "project", "source", "Directory", selection, false);
});

test("empty, filtered, conflicting, over-budget and cancelled directory reads fail before upload", async () => {
  await assert.rejects(prepareDirectory([]), /为空/);
  await assert.rejects(prepareDirectory([selected("root/.env", "synthetic")]), /全部被过滤/);
  await assert.rejects(prepareDirectory([selected("root/a.go", "a"), selected("root/A.go", "b")]), /重名/);
  const large = selected("root/large.go", "x");
  Object.defineProperty(large, "size", { value: 4 * 1024 * 1024 + 1 });
  await assert.rejects(prepareDirectory([large]), /单文件/);
  const controller = new AbortController(); controller.abort();
  await assert.rejects(prepareDirectory([selected("root/main.go", "package main")], controller.signal), { name: "AbortError" });
});

test("generated directories are collapsed instead of counted per file", async () => {
  // The reported bug: a repository with fewer than a hundred source files produced
  // tens of thousands of exclusion records because every file under node_modules
  // and .git was listed, and the file cap counted them too.
  const files: File[] = [];
  for (let i = 0; i < 12000; i++) files.push(selected(`root/node_modules/pkg/f${i}.js`, ""));
  for (let i = 0; i < 40; i++) files.push(selected(`root/.git/objects/ab/f${i}`, ""));
  for (let i = 0; i < 90; i++) files.push(selected(`root/internal/f${i}.go`, "package internal\n"));

  const selection = await prepareDirectory(files);
  assert.equal(selection.files.length, 90);
  assert.deepEqual(selection.manifest.excluded.sort(), [".git", "node_modules"]);
  assert.equal(selection.summary.excludedFiles, 12040);
  assert.equal(selection.summary.excludedDirectoryCount, 2);
  assert.deepEqual(selection.summary.directories, [
    { path: "node_modules", files: 12000 },
    { path: ".git", files: 40 },
  ]);
});

test("the upload cap counts included files, not generated ones", async () => {
  const included = Array.from({ length: 10001 }, (_, i) => selected(`root/f${i}.go`, "x"));
  await assert.rejects(prepareDirectory(included), /10000/);
  const withNoise = [...Array.from({ length: 10001 }, (_, i) => selected(`root/f${i}.go`, "x")), ...Array.from({ length: 5000 }, (_, i) => selected(`root/vendor/f${i}.go`, ""))];
  await assert.rejects(prepareDirectory(withNoise), /10000/);
});
