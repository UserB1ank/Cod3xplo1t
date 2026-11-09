import test from "node:test";
import assert from "node:assert/strict";
import { pathGraph } from "../src/path-graph.ts";

test("path graph renders recorded direction, intermediate nodes and evidence without bridging missing hops", () => {
  const graph = pathGraph({entry_node_id:"entry", entry_subject:"handler", target_node_id:"sink", target_subject:"exec", steps:[
    {from:"entry",to:"service",subject:"service",file:"service.go",line:12,layer:"scg",kind:"calls",evidence:"call-1"},
    {from:"service",to:"sink",subject:"exec",file:"sink.go",line:0,layer:"asg",kind:"taint_flow",evidence:"flow-2"},
    {from:"",to:"unknown",kind:"unresolved",layer:"scg"},
  ]});
  assert.equal(graph.nodes.length, 4);
  assert.deepEqual(graph.edges.map(e=>[e.from,e.to]), [["entry","service"],["service","sink"]]);
  assert.equal(graph.edges[1].evidence, "flow-2");
  assert.equal(graph.nodes.find(n=>n.node_id==="service")?.line, 12);
  assert.equal(graph.nodes.find(n=>n.node_id==="sink")?.line, undefined);
  assert.equal(graph.omitted, 1);
  assert.equal(pathGraph({entry_subject:"display only",target_subject:"display only",steps:[]}).edges.length,0);
});

test("path graph keeps inferred SCG calls separate from ASG endpoint refs", () => {
  const graph = pathGraph({
    entry_node_id: "asgn-entry",
    entry_subject: "http_route:GET /run",
    target_node_id: "asgn-sink",
    target_subject: "sink:process_execution",
    scg_refs: ["sym-handler", "sym-run", "cs-call"],
    asg_refs: ["asgn-entry", "asgn-sink"],
    steps: [{
      from: "sym-handler",
      to: "sym-run",
      layer: "scg",
      kind: "CALLS",
      evidence: "cs-call",
      resolution: "resolved",
    }],
  });
  assert.deepEqual(graph.nodes.map((node) => node.node_id).sort(), [
    "asgn-entry",
    "asgn-sink",
    "sym-handler",
    "sym-run",
  ]);
  assert.equal(graph.edges.length, 1);
  assert.equal(graph.edges[0].layer, "scg");
  assert.equal(graph.edges[0].evidence, "cs-call");
  assert.equal(graph.edges[0].evidence_status, "resolved");
  assert.equal(graph.nodes.some((node) => node.node_id === "cs-call"), false);
});
