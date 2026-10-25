import test from "node:test";
import assert from "node:assert/strict";
import { layoutEntryGraph } from "../src/entry-graph.ts";

test("local graph preserves real edge direction, cycles and disconnected observations", () => {
  const graph = layoutEntryGraph(
    "entry",
    [
      { node_id: "sink" },
      { node_id: "entry" },
      { node_id: "service" },
      { node_id: "isolated" },
    ],
    [
      { from: "entry", to: "service" },
      { from: "service", to: "sink" },
      { from: "sink", to: "service" },
      { from: "sink", to: "missing" },
    ],
  );
  assert.equal(graph.nodes.length, 4);
  const byID = new Map(graph.nodes.map((n) => [n.id, n]));
  assert.ok(byID.get("entry")!.x < byID.get("service")!.x);
  assert.ok(byID.get("service")!.x < byID.get("sink")!.x);
  assert.equal(graph.edges.length, 3);
  assert.equal(graph.omittedEdges, 1);
  assert.equal(new Set(graph.nodes.map((n) => `${n.x},${n.y}`)).size, 4);
  assert.deepEqual(
    layoutEntryGraph(
      "entry",
      [
        ...[
          { node_id: "sink" },
          { node_id: "entry" },
          { node_id: "service" },
          { node_id: "isolated" },
        ],
      ].reverse(),
      [
        { from: "entry", to: "service" },
        { from: "service", to: "sink" },
        { from: "sink", to: "service" },
        { from: "sink", to: "missing" },
      ],
    ),
    graph,
  );
});

test("call graph adaptation preserves source symbols and reports unresolved calls", async () => {
  const { callGraphNeighborhood } = await import("../src/entry-graph.ts");
  const entry = {
    symbol_id: "handler",
    name: "handler",
    qualified_name: "service.handler",
    kind: "function",
    file: "api.go",
    start_line: 12,
    end_line: 15,
  };
  const callee = {
    ...entry,
    symbol_id: "export",
    name: "export",
    qualified_name: "service.export",
    file: "export.go",
    start_line: 4,
  };
  const result = callGraphNeighborhood({
    root: entry,
    nodes: [{ symbol: callee }],
    edges: [
      {
        edge_id: "call-1",
        from: "handler",
        to: "export",
        kind: "CALLS",
        resolution: "resolved",
        confidence: "high",
      },
    ],
    unresolved_call_sites: [{ id: "external" }],
    limitations: ["external calls unresolved"],
    meta: { truncated: false },
  });
  assert.equal(result.root.node_id, "handler");
  assert.equal(result.nodes.length, 2);
  assert.deepEqual(result.nodes[1].scg_refs, ["export"]);
  assert.equal(result.nodes[1].file, "export.go");
  assert.equal(result.edges[0].evidence_status, "resolved");
  assert.equal(result.unresolved_edges, 1);
  assert.deepEqual(result.limitations, ["external calls unresolved"]);
});
