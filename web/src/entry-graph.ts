// Lay out only observed nodes and relations. Missing endpoints never become facts.
export function layoutEntryGraph(
  root: string,
  nodes: { node_id: string }[],
  edges: { from: string; to: string }[],
) {
  const ids = [...new Set(nodes.map((node) => node.node_id))].sort();
  const known = new Set(ids);
  const visible = edges.filter(
    (edge) => known.has(edge.from) && known.has(edge.to),
  );
  const levels = new Map<string, number>();
  if (known.has(root)) levels.set(root, 0);
  const queue = known.has(root) ? [root] : [];
  for (let i = 0; i < queue.length; i++) {
    for (const edge of visible
      .filter((e) => e.from === queue[i])
      .sort((a, b) => a.to.localeCompare(b.to))) {
      if (!levels.has(edge.to)) {
        levels.set(edge.to, levels.get(edge.from)! + 1);
        queue.push(edge.to);
      }
    }
  }
  const last = Math.max(0, ...levels.values());
  for (const id of ids) if (!levels.has(id)) levels.set(id, last + 1);
  const columns = new Map<number, string[]>();
  for (const id of ids) {
    const level = levels.get(id)!;
    columns.set(level, [...(columns.get(level) || []), id]);
  }
  const height = Math.max(
    260,
    ...[...columns.values()].map((items) => items.length * 100 + 80),
  );
  return {
    nodes: ids.map((id) => {
      const column = columns.get(levels.get(id)!)!;
      return {
        id,
        x: 40 + levels.get(id)! * 270,
        y: (height - column.length * 100) / 2 + column.indexOf(id) * 100,
      };
    }),
    edges: visible,
    omittedEdges: edges.length - visible.length,
    width: Math.max(700, columns.size * 270 + 40),
    height,
  };
}

export interface CallNeighborhood {
  root: {
    symbol_id: string;
    name: string;
    qualified_name: string;
    kind: string;
    file: string;
    start_line: number;
  };
  nodes: { symbol: CallNeighborhood["root"] }[];
  edges: {
    edge_id: string;
    from: string;
    to: string;
    kind: string;
    resolution: string;
    confidence?: string;
  }[];
  unresolved_call_sites?: unknown[];
  limitations: string[];
  meta: { truncated: boolean };
}
export function callGraphNeighborhood(graph: CallNeighborhood) {
  const node = (symbol: CallNeighborhood["root"]) => ({
    node_id: symbol.symbol_id,
    label: symbol.name,
    subject: symbol.qualified_name,
    kind: "Function",
    file: symbol.file,
    line: symbol.start_line,
    scg_refs: [symbol.symbol_id],
  });
  return {
    root: node(graph.root),
    nodes: [
      ...new Map(
        [graph.root, ...graph.nodes.map((item) => item.symbol)].map(
          (symbol) => [symbol.symbol_id, node(symbol)],
        ),
      ).values(),
    ],
    edges: graph.edges.map((edge) => ({
      ...edge,
      evidence_status: edge.resolution,
    })),
    unresolved_edges: graph.unresolved_call_sites?.length || 0,
    limitations: graph.limitations,
    meta: graph.meta,
  };
}
