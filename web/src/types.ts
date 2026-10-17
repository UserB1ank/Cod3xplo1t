export type View = 'overview' | 'projects' | 'graph' | 'surface' | 'paths' | 'runs' | 'findings' | 'reports';
export type PathFilter = 'all' | 'queued' | 'active' | 'attention';
export type FindingStatus = 'candidate' | 'confirmed' | 'refuted' | 'inconclusive' | 'blocked';

export interface Project { id: string; name: string; source: string; identity: string; created_at: string; updated_at: string; version: number }
export interface Snapshot { snapshot_id: string; project_id: string; commit: string; vcs: string; created_at: string; manifest_present: boolean }
export interface Step { layer: string; from: string; to: string; kind: string; subject?: string; file?: string; line?: number; evidence?: string; confidence?: string }
export interface AuditPath {
  path_id: string; audit_id: string; snapshot_id: string; entry_subject: string; target_subject: string; target_kind: string;
  path_kind: string; path_status: string; status: string; steps: Step[]; objectives: string[]; controls: string[];
  limitations: string[]; open_questions: string[]; scg_refs: string[]; score: { priority: number; support: number; risk: number; utility: number };
  budget: { max_depth: number; max_branches: number; max_tool_calls: number }; attempts: number; version: number;
}
export interface Audit {
  audit_id: string; snapshot_id: string; status: string; path_count: number; created_at: string;
  counts_by_status: Record<string, number>; limits: { max_active_leases: number; exploration_fraction: number };
  coverage: { entry_points_examined: number; chains_resolved: number; chains_unresolved: number; truncated: boolean; truncation_reasons?: string[] };
}
export interface Finding {
  finding_id: string; hypothesis_id: string; path_id: string; audit_id: string; snapshot_id: string; title: string;
  severity: string; status: FindingStatus; supporting_evidence: string[]; contradicting_evidence: string[];
  inconclusive_evidence: string[]; limitations: string[]; reproduce_steps: string; created_at: string;
}
export interface Evidence { evidence_id: string; kind: string; tool: string; file?: string; line?: number; content: string; redacted: boolean; content_hash: string }
export interface FindingDetail { finding: Finding; evidence: { supporting: Evidence[]; contradicting: Evidence[]; inconclusive: Evidence[] }; verifications: Array<{ run_id: string; status: string; outcome: string }> }
export interface Run {
  run_id: string; path_id: string; audit_id: string; snapshot_id: string; runtime: string; status: string;
  started_at: string; heartbeat_at: string; tool_calls: number; input_tokens: number; output_tokens: number;
  elapsed_ms: number; stop_reason?: string; task?: { security_goal: string }; error?: string;
}
export interface AuditEvent { event_id: string; path_id?: string; run_id?: string; seq: number; type: string; actor?: string; reason?: string; summary?: string; created_at: string }
export interface GraphSummary {
  files: number; symbols: number; modules: number; edges: number; call_sites: number;
  resolution: { resolved: number; resolved_best_effort: number; dynamic: number; external: number; ambiguous: number; unsupported: number };
  limitations: string[];
}
export interface Scheduler {
  running: boolean; configured: boolean; config: { max_concurrent: number; interval_seconds: number };
  metrics: { ticks: number; active_leases: number; queue_depth: number; succeeded_total: number; failed_total: number; retried_total: number; last_tick_at: string };
}
export interface Workspace {
  projects: Project[]; snapshots: Snapshot[]; audits: Audit[]; project?: Project; snapshot?: Snapshot; audit?: Audit;
  paths: AuditPath[]; pathTotal: number; findings: Finding[]; findingTotal: number; runs: Run[]; runTotal: number;
  events: AuditEvent[]; graph?: GraphSummary; scheduler?: Scheduler; warnings: string[];
}
export interface Connection { base: string; token: string }
export interface AuditDraft { maxPaths: number; concurrency: number; toolCalls: number }
