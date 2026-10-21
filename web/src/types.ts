export type View = 'overview' | 'projects' | 'graph' | 'surface' | 'paths' | 'runs' | 'findings' | 'reports';
export type PathFilter = 'all' | 'queued' | 'active' | 'attention';
export type FindingStatus = 'candidate' | 'confirmed' | 'refuted' | 'inconclusive' | 'blocked';

export interface Project { id: string; name: string; description?: string; source: string; identity: string; created_at: string; updated_at: string; version: number }
export type ProjectInputState = 'importing' | 'ready' | 'failed' | 'legacy';
export interface ProjectInput { project_id: string; state: ProjectInputState; source_id?: string; source_kind?: string; source_name?: string; snapshot_id?: string; files: number; bytes: number; failure_code?: string; failure_message?: string; version: number; created_at: string; updated_at: string }
export interface ProjectDirectoryEntry { project: Project; audit_input?: ProjectInput }
export interface Snapshot { snapshot_id: string; project_id: string; commit: string; vcs: string; created_at: string; manifest_present: boolean; source_id?: string; source_version?: number }
export interface Step { layer: string; from: string; to: string; kind: string; subject?: string; file?: string; line?: number; evidence?: string; confidence?: string }
export interface PathSelection {
  schema_version: string; selection: 'selected' | 'filtered'; reason: string; filter_code?: string;
  score_version: number; weights_digest: string; source_path_id: string; source_artifact_id?: string;
  producer_plugin?: string; producer_version?: string; invocation_id?: string;
}
export interface EnhancementPath {
  path_id: string; entry_subject: string; target_subject: string; entry_node_id: string; target_node_id: string;
  path_status: string; priority: number; risk: number; support: number; utility: number;
  score_version: number; selection: PathSelection; limitations?: string[];
}
export interface EnhancementSummary {
  schema_version: string; producer_plugin?: string; producer_version?: string; invocation_id?: string;
  config_digest?: string; input_artifact_ids?: string[]; score_version: number; weights_digest: string;
  selected: EnhancementPath[]; filtered: EnhancementPath[]; limitations: string[];
}
export interface AuditPath {
  path_id: string; audit_id: string; snapshot_id: string; entry_subject: string; target_subject: string; target_kind: string;
  path_kind: string; path_status: string; status: string; steps: Step[]; objectives: string[]; controls: string[];
  limitations: string[]; open_questions: string[]; scg_refs: string[]; score: { priority: number; support: number; risk: number; utility: number; score_version?: number; weights?: Record<string, number> };
  features?: { reasons?: Record<string, string>; [key: string]: unknown };
  selection?: PathSelection;
  budget: { max_depth: number; max_branches: number; max_tool_calls: number }; attempts: number; version: number;
}
export interface Audit {
  audit_id: string; snapshot_id: string; status: string; path_count: number; created_at: string;
  counts_by_status: Record<string, number>; limits: { max_active_leases: number; exploration_fraction: number };
  coverage: { entry_points_examined: number; chains_resolved: number; chains_unresolved: number; truncated: boolean; truncation_reasons?: string[] };
  enhancement?: EnhancementSummary;
}
export interface Finding {
  finding_id: string; hypothesis_id: string; path_id: string; audit_id: string; snapshot_id: string; title: string;
  severity?: string; status: FindingStatus; confidence?: string; supporting_evidence: string[]; contradicting_evidence: string[];
  inconclusive_evidence: string[]; limitations: string[]; reproduce_steps?: string; created_at: string; updated_at?: string;
  version?: number;
}
export interface Evidence { evidence_id: string; kind: string; tool: string; file?: string; line?: number; content: string; redacted: boolean; content_hash: string }
export interface FindingDetail { finding: Finding; evidence: { supporting: Evidence[]; contradicting: Evidence[]; inconclusive: Evidence[] }; verifications?: Array<{ run_id: string; status: string; outcome: string }> }
export interface RunMetrics {
  rounds: number; model_requests?: number; repairs?: number; exchanges: number;
  novelty?: number[]; invalid_calls: number; truncations: number;
  // Empty means an older record: the counters are unknown, not zero.
  source?: '' | 'reported' | 'legacy_estimate';
}
export interface RuntimeInfo {
  name: string; version: string; ready: boolean; reason?: string;
  capabilities?: { name: string; version: string; tool_calls: boolean; turn_control?: boolean; token_usage: boolean };
  model?: string; config_version?: string; worker_version?: string; protocol_version?: string;
}
export interface RuntimePin {
  runtime: string; runtime_version?: string; protocol_version?: string; worker_version?: string;
  prompt_version?: string; model?: string; config_version?: string; tool_schema_digest?: string;
}
export interface Run {
  run_id: string; path_id: string; audit_id: string; snapshot_id: string; runtime: string; status: string;
  pin?: RuntimePin;
  started_at: string; heartbeat_at: string; tool_calls: number; input_tokens: number; output_tokens: number;
  elapsed_ms: number; stop_reason?: string; task?: { security_goal: string }; error?: string;
  tool_schema_digest?: string;
  metrics?: RunMetrics;
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

export interface AuditBudget {
  audit_id: string;
  limit_tokens: number;
  reserved_tokens: number;
  used_tokens: number;
  version: number;
  updated_at?: string;
}

export interface BudgetGrant {
  grant_id: string;
  tokens: number;
  decision: string;
  reason: string;
  requested_by: string;
  created_at: string;
}

export interface ActivityEntry {
  task_id: string;
  task_name: string;
  run_id?: string;
  path_id?: string;
  runtime?: string;
  status?: string;
  stage: 'analyzing' | 'verifying' | 'workflow' | 'paused' | string;
  started_at?: string;
  updated_at?: string;
  elapsed_ms: number;
  queued: number;
}

export interface ProjectActivity {
  project_id: string;
  active: ActivityEntry[];
  counts: { running: number; paused: number; queued: number; tasks: number };
}
