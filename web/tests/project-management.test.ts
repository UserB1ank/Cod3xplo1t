import test from "node:test";
import assert from "node:assert/strict";
import {
  canStartAnalysis,
  effectiveProjectInput,
  formatBytes,
  projectInputLabel,
  projectInputSourceLabel,
  projectInputState,
} from "../src/project-management.ts";
import type { ProjectInput } from "../src/types.ts";

function input(overrides: Partial<ProjectInput> = {}): ProjectInput {
  return {
    project_id: "proj-one",
    state: "importing",
    version: 1,
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:00Z",
    files: 0,
    bytes: 0,
    ...overrides,
  };
}

test("a missing input is a legacy project, not an empty ready one", () => {
  assert.equal(projectInputState(undefined), "legacy");
  assert.equal(projectInputLabel(undefined), "旧多来源项目");
  assert.equal(canStartAnalysis(undefined), false);
  assert.match(projectInputSourceLabel(undefined), /旧项目/);
});

test("ready input is the only state that may start analysis", () => {
  const ready = input({ state: "ready", snapshot_id: "snap-one", files: 3, bytes: 2048 });
  assert.equal(projectInputState(ready), "ready");
  assert.equal(canStartAnalysis(ready), true);
  assert.match(projectInputSourceLabel(ready), /3 个文件/);
  for (const state of ["importing", "failed", "legacy"] as const) {
    assert.equal(canStartAnalysis(input({ state })), false);
  }
});

test("an interrupted import is presented as failed after the stale window", () => {
  const stale = input({
    state: "importing",
    source_id: "src-one",
    source_name: "source.zip",
    updated_at: "2026-01-01T00:00:00Z",
  });
  const now = Date.parse("2026-01-01T00:06:00Z");
  assert.equal(effectiveProjectInput(stale, now)?.state, "failed");
  assert.equal(effectiveProjectInput(stale, now)?.failure_code, "import_interrupted");
  assert.equal(effectiveProjectInput(stale, Date.parse("2026-01-01T00:04:00Z"))?.state, "importing");
  assert.equal(projectInputState(stale), "failed");
  assert.match(projectInputSourceLabel(effectiveProjectInput(stale, now)), /导入已中断/);
});

test("failed input keeps the real server reason instead of a demo success", () => {
  const failed = input({ state: "failed", failure_message: "源码上传未完成，请重试" });
  assert.equal(projectInputLabel(failed), "源码导入失败");
  assert.equal(projectInputSourceLabel(failed), "源码上传未完成，请重试");
  assert.equal(canStartAnalysis(failed), false);
});

test("byte labels are bounded and readable", () => {
  assert.equal(formatBytes(0), "0 B");
  assert.equal(formatBytes(512), "512 B");
  assert.equal(formatBytes(2048), "2.0 KiB");
  assert.equal(formatBytes(10 * 1024 * 1024), "10 MiB");
});
