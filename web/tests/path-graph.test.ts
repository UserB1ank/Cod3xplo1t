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
