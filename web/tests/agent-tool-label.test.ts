import test from "node:test";
import assert from "node:assert/strict";
import { toolDisplayName } from "../src/agent-tool-label.ts";

const projectTools = [
  "list_project_operations",
  "project_api",
  "inspect_project",
  "list_source_files",
  "read_source_file",
  "graph_summary",
  "list_modules",
  "list_symbols",
  "get_symbol",
  "get_callers",
  "get_callees",
  "find_call_paths",
  "get_code_slice",
  "list_unresolved_calls",
  "repo_map",
  "list_entry_points",
  "list_sinks",
  "get_asg_node",
  "open_knowledge_view",
  "query_investigation_knowledge",
  "propose_path",
  "propose_claim",
  "open_question",
  "attach_evidence",
];

test("project tools have stable user-facing labels and unknown names stay traceable", () => {
  for (const name of projectTools) {
    assert.doesNotMatch(toolDisplayName(name), /_/);
  }
  assert.equal(toolDisplayName("repo_map"), "查看仓库概览");
  assert.equal(toolDisplayName("list_entry_points"), "列出程序入口");
  assert.equal(toolDisplayName("list_sinks"), "列出敏感操作");
  assert.equal(
    toolDisplayName("query_investigation_knowledge"),
    "查询调查知识",
  );
  assert.equal(toolDisplayName("future_tool"), "future_tool");
  assert.equal(toolDisplayName(), "工具调用");
});
