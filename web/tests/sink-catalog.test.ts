import test from "node:test";
import assert from "node:assert/strict";

import {
  sinkCatalogQuery,
  sinkEvidence,
  type AttackNodeWithDetail,
} from "../src/sink-catalog.ts";

test("attack surface opens the high-risk catalogue and keeps fallback exploration explicit", () => {
  const highRisk = sinkCatalogQuery("project one", "view/two", "high_risk", "sql_execution", "page/cursor");
  const url = new URL(highRisk, "https://example.invalid");
  assert.equal(url.pathname, "/v1/projects/project%20one/knowledge/views/view%2Ftwo/sinks");
  assert.equal(url.searchParams.get("partition"), "high_risk");
  assert.equal(url.searchParams.get("category"), "sql_execution");
  assert.equal(url.searchParams.get("cursor"), "page/cursor");
  assert.equal(url.searchParams.get("limit"), "50");

  const fallback = sinkCatalogQuery("p", "v", "unclassified", "", "");
  assert.equal(
    new URL(fallback, "https://example.invalid").searchParams.get("partition"),
    "unclassified",
  );
});

test("catalogue evidence is displayed without presenting rule presence as exploitability", () => {
  const node: AttackNodeWithDetail = {
    node_id: "sink-1",
    kind: "SensitiveOperation",
    label: "Runtime.exec",
    subject: "sink:process_execution",
    evidence_status: "inferred",
    detail: {
      catalog_id: "java.process.runtime-exec",
      catalog_version: "1.0.0",
      catalog_digest: "abcdef0123456789",
      dangerous_arguments: "[0]",
      has_flow: "false",
    },
  };
  const evidence = sinkEvidence(node);
  assert.equal(evidence.rule, "java.process.runtime-exec");
  assert.equal(evidence.version, "1.0.0");
  assert.match(evidence.digest, /^abcdef012345/);
  assert.equal(evidence.arguments, "[0]");
  assert.equal(evidence.hasFlow, false);
  assert.match(evidence.note, /不等于可利用/);
});
