export interface PathStep {
  from: string;
  to: string;
  layer: string;
  kind: string;
  subject?: string;
  file?: string;
  line?: number;
  evidence?: string;
  confidence?: string;
  resolution?: string;
}
export interface GraphPath {
  entry_node_id?: string;
  entry_subject: string;
  target_node_id?: string;
  target_subject: string;
  steps?: PathStep[];
}
export interface PathGraphNode {
  node_id: string;
  label: string;
  subject: string;
  kind: string;
  file?: string;
  line?: number;
}
export function pathGraph(path: GraphPath) {
  const nodes = new Map<string, PathGraphNode>();
  const add = (id?: string, subject?: string, kind = "Function", file?: string, line?: number) => {
    if (!id) return;
    const old = nodes.get(id);
    nodes.set(id, {
      node_id: id,
      label: subject ? subject.split(" · ")[0].split(/[/.]/).filter(Boolean).slice(-2).join(".") : old?.label || id,
      subject: subject || old?.subject || id,
      kind: old?.kind || kind,
      file: file || old?.file,
      line: line && line > 0 ? line : old?.line,
    });
  };
  add(path.entry_node_id, path.entry_subject, "EntryPoint");
  add(path.target_node_id, path.target_subject, "SensitiveOperation");
  const edges = [];
  let omitted = 0;
  for (const [index, step] of (path.steps || []).entries()) {
    add(step.from);
    add(step.to, step.subject, "Function", step.file, step.line);
    if (!step.from || !step.to) { omitted++; continue; }
    edges.push({
      ...step,
      edge_id: `path-step-${index}`,
      evidence_status: step.resolution || step.confidence || "recorded",
    });
  }
  return {nodes: [...nodes.values()], edges, omitted};
}
