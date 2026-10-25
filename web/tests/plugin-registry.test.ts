import test from "node:test";
import assert from "node:assert/strict";
import { stageInputs } from "../src/plugin-registry.ts";

test("stage input selection pins an explicit artifact and rejects ambiguity", () => {
  const scope = {
    project_id: "project",
    source_id: "source",
    snapshot_id: "snapshot",
  };
  const first = {
    id: "source-a",
    kind: "source.snapshot",
    schema_id: "codexploit/source-tar/v1",
    scope,
  };
  const second = { ...first, id: "source-b" };
  const operation = {
    inputs: [
      {
        name: "source",
        kind: first.kind,
        schema_id: first.schema_id,
        cardinality: "one",
        required: true,
      },
    ],
  };
  assert.throws(() => stageInputs(operation, [first, second], {}), /选择/);
  assert.deepEqual(
    stageInputs(operation, [first, second], { source: "source-b" }),
    { inputs: [second], input_ports: ["source"] },
  );
  assert.throws(
    () => stageInputs(operation, [first], { source: "missing" }),
    /选择/,
  );
});

import {
  pluginGroups,
  registryState,
  filterPlugins,
} from "../src/plugin-registry.ts";
import type { RegistryRecord } from "../src/plugin-registry.ts";

test("catalog groups versions without turning registration into installed readiness", () => {
  const record = (version: string, executable = false): RegistryRecord => ({
    manifest: {
      api_version: "codexploit/plugin/v2",
      id: "example.parser",
      version,
      name: "Parser",
      runtime: { kind: "process" },
    },
    stages: ["parse"],
    package_digest: "a".repeat(64),
    manifest_digest: "b".repeat(64),
    installed: executable,
    executable,
  });
  const historical = record("1.9.0", true),
    newest = record("1.10.0");
  const groups = pluginGroups([newest, historical]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].current.manifest.version, "1.9.0");
  assert.deepEqual(
    groups[0].versions.map((row) => row.manifest.version),
    ["1.10.0", "1.9.0"],
  );
  assert.equal(registryState(newest).key, "uninstalled");
  const pending = filterPlugins(groups, {
    query: "",
    stage: "",
    state: "uninstalled",
  });
  assert.equal(pending.length, 1);
  assert.equal(pending[0].current.manifest.version, "1.10.0");
  assert.equal(
    filterPlugins(groups, {
      query: "example.parser",
      stage: "parse",
      state: "ready",
    }).length,
    1,
  );
  assert.equal(
    filterPlugins(groups, { query: "", stage: "scan", state: "" }).length,
    0,
  );
});

import { invocationCoverageText } from "../src/plugin-registry.ts";

test("failed or unknown coverage never appears as a completed zero-count analysis", () => {
  assert.equal(
    invocationCoverageText("FAILED", undefined, {
      input_files: 0,
      parsed_files: 0,
      partial_files: 0,
      unhandled_files: 0,
      unparsed_files: 0,
    }).analyzed,
    "未返回覆盖",
  );
  assert.equal(invocationCoverageText("RUNNING").analyzed, "等待执行器报告");
  assert.equal(
    invocationCoverageText("PARTIAL", {
      unit: "files",
      seen: 1,
      analyzed: null,
      skipped: null,
      failed: null,
    }).analyzed,
    "未知 / 1 文件",
  );
});
