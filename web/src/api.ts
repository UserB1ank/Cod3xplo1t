import type { AnalysisRun, Audit, PathSubtask, AuditBudget, AuditDraft, AuditEvent, AuditPath, BudgetGrant, Connection, Finding, FindingDetail, GraphSummary, Project, ProjectDirectoryEntry, ProjectInput, Run, Scheduler, Snapshot, Workspace } from './types.ts';

export class ApiError extends Error {
  status: number;
  code: string;
  diagnostics?: {path: string; code: string; message: string}[];
  constructor(status: number, code: string, message: string, diagnostics?: {path: string; code: string; message: string}[]) { super(message); this.name = 'ApiError'; this.status = status; this.code = code; this.diagnostics = diagnostics; }
}

export function normalizeBase(input: string) {
  const value = input.trim().replace(/\/+$/, '');
  if (value === '/api') return value;
  let url: URL;
  try { url = new URL(value); } catch { throw new Error('API 地址应为 /api 或完整的 HTTP(S) 地址。'); }
  if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password || url.search || url.hash) throw new Error('API 地址不能包含凭据、查询参数或片段。');
  if (!url.pathname || url.pathname === '/') url.pathname = '/api';
  if (!url.pathname.endsWith('/api')) throw new Error('API 地址应以 /api 结尾。');
  return url.toString().replace(/\/+$/, '');
}

function forbiddenMessage(code?: string) {
  switch (code) {
    case 'network_disabled':
      return '远程 Git 访问未启用。请使用本地文件夹，或以 CODEXPLOIT_ALLOW_NETWORK=true 重新启动服务后重试。';
    case 'origin_forbidden':
      return '请求来源无效。请使用部署时打印的同一地址访问，并检查反向代理是否保留 Host。';
    case 'git_access_denied':
      return 'Git 仓库访问被拒绝，请检查仓库权限或凭据引用。';
    default:
      return '当前凭据没有执行该操作的权限。';
  }
}

function cleanPath(path: AuditPath): AuditPath {
  return { ...path, steps: path.steps || [], controls: path.controls || [], limitations: path.limitations || [], objectives: path.objectives || [], open_questions: path.open_questions || [], scg_refs: path.scg_refs || [] };
}
function cleanFinding(finding: Finding): Finding {
  return { ...finding, supporting_evidence: finding.supporting_evidence || [], contradicting_evidence: finding.contradicting_evidence || [], inconclusive_evidence: finding.inconclusive_evidence || [], limitations: finding.limitations || [], reproduce_steps: finding.reproduce_steps || '' };
}

export class ApiClient {
  private connection: Connection;
  private fetcher: typeof fetch;
  constructor(connection: Connection, fetcher: typeof fetch = fetch) { this.connection = { ...connection, base: normalizeBase(connection.base) }; this.fetcher = fetcher.bind(globalThis); }

  async response(path: string, options: RequestInit = {}, acceptedStatuses: readonly number[] = []) {
    if (!path.startsWith('/') || path.includes('..') || path.startsWith('//')) throw new Error('无效的 API 路径。');
    const headers = new Headers(options.headers);
    headers.set('Accept', 'application/json');
    if (this.connection.token) headers.set('Authorization', `Bearer ${this.connection.token}`);
    if (typeof options.body === 'string' && !headers.has('Content-Type')) headers.set('Content-Type', 'application/json');
    const response = await this.fetcher(this.connection.base + path, { ...options, headers, credentials: 'same-origin', redirect: 'error', cache: 'no-store' });
    if (!response.ok && !acceptedStatuses.includes(response.status)) {
      const body = await response.json().catch(() => ({})) as { error?: string; code?: string; diagnostics?: {path: string; code: string; message: string}[] };
      const message = response.status === 401 ? (body.code === 'invalid_credentials' ? '账号或密码不正确。' : '登录已过期或访问凭据无效，请重新登录。') : response.status === 403 ? forbiddenMessage(body.code) : response.status === 412 ? '数据已被其他操作更新，请刷新后重试。' : body.error || `请求失败（${response.status}）`;
      throw new ApiError(response.status, body.code || 'request_failed', message, body.diagnostics);
    }
    return response;
  }
  async get<T>(path: string, signal?: AbortSignal): Promise<T> { return (await this.response(path, { signal })).json() as Promise<T>; }
  async post<T>(path: string, body: unknown, signal?: AbortSignal, headers?: HeadersInit): Promise<T> {
    return (await this.response(path, { method: 'POST', body: JSON.stringify(body), signal, headers: { 'Idempotency-Key': crypto.randomUUID(), ...headers } })).json() as Promise<T>;
  }
  projects(signal?: AbortSignal) { return this.get<{ projects: Project[] }>('/projects', signal); }
  projectDirectory(signal?: AbortSignal) { return this.get<{ api_version: string; projects: ProjectDirectoryEntry[] }>('/v1/projects', signal); }
  projectInput(projectID: string, signal?: AbortSignal) { return this.get<{ api_version: string; input: ProjectInput }>(`/v1/projects/${encodeURIComponent(projectID)}/audit-input`, signal); }
  async updateProject(projectID: string, body: { name?: string; description?: string }) {
    const current = await this.response(`/projects/${encodeURIComponent(projectID)}`);
    const etag = current.headers.get('ETag');
    if (!etag) throw new Error('项目缺少版本标识，请刷新后重试。');
    await current.arrayBuffer();
    return (await this.response(`/projects/${encodeURIComponent(projectID)}`, {
      method: 'PATCH', body: JSON.stringify(body), headers: { 'If-Match': etag },
    })).json() as Promise<Project>;
  }
  async deleteProject(projectID: string) {
    return this.response(`/v1/projects/${encodeURIComponent(projectID)}`, { method: 'DELETE' });
  }

  async workspace(projectChoice?: string, snapshotChoice?: string, signal?: AbortSignal): Promise<Workspace> {
    const { projects: rawProjects } = await this.projects(signal);
    const projects = rawProjects || [];
    const project = projects.find(p => p.id === projectChoice) || projects[0];
    const empty: Workspace = { projects, project, snapshots: [], audits: [], paths: [], pathTotal: 0, findings: [], findingTotal: 0, runs: [], runTotal: 0, events: [], warnings: [] };
    if (!project) return empty;
    const snapshotPage = await this.get<{ snapshots: Snapshot[] }>(`/snapshots?project_id=${encodeURIComponent(project.id)}`, signal);
    const snapshots = (snapshotPage.snapshots || []).sort((a, b) => b.created_at.localeCompare(a.created_at));
    const snapshot = snapshots.find(s => s.snapshot_id === snapshotChoice) || snapshots[0];
    if (!snapshot) return { ...empty, snapshots };
    const warnings: string[] = [];
    const optional = async <T,>(name: string, request: Promise<T>, fallback: T): Promise<T> => {
      try { return await request; } catch (error) {
        if (signal?.aborted || error instanceof ApiError && [401, 403].includes(error.status)) throw error;
        warnings.push(`${name}：${error instanceof Error ? error.message : '数据不可用'}`);
        return fallback;
      }
    };
    const sid = encodeURIComponent(snapshot.snapshot_id);
    const [auditPage, graph, scheduler] = await Promise.all([
      optional('审计列表', this.get<{ audits: Audit[] }>(`/audits?snapshot_id=${sid}&limit=100`, signal), { audits: [] }),
      optional<GraphSummary | undefined>('源码图谱', this.get<GraphSummary>(`/snapshots/${sid}/graph`, signal), undefined),
      optional<Scheduler | undefined>('调度器', this.get<Scheduler>('/scheduler', signal), undefined),
    ]);
    const audits = (auditPage.audits || []).sort((a, b) => b.created_at.localeCompare(a.created_at));
    const audit = audits[0];
    if (!audit) return { ...empty, snapshots, snapshot, audits, graph, scheduler, warnings };
    const aid = encodeURIComponent(audit.audit_id);
    const [pathPage, findingPage, runPage, events] = await Promise.all([
      optional('审计路径', this.get<{ paths: AuditPath[]; total: number }>(`/audits/${aid}/paths?limit=100&sort=priority`, signal), { paths: [], total: 0 }),
      optional('发现', this.get<{ findings: Finding[]; total: number }>(`/findings?audit_id=${aid}&limit=100`, signal), { findings: [], total: 0 }),
      optional('Agent 运行', this.get<{ runs: Run[]; total: number }>(`/runs?audit_id=${aid}&limit=100`, signal), { runs: [], total: 0 }),
      optional('审计事件', this.get<{ events: AuditEvent[] }>(`/audits/${aid}/events?limit=100`, signal), { events: [] }),
    ]);
    return { projects, project, snapshots, snapshot, audits, audit, paths: (pathPage.paths || []).map(cleanPath), pathTotal: pathPage.total, findings: (findingPage.findings || []).map(cleanFinding), findingTotal: findingPage.total, runs: runPage.runs || [], runTotal: runPage.total, events: (events.events || []).sort((a, b) => b.seq - a.seq), graph, scheduler, warnings };
  }
  selectPaths(projectID: string, pathIDs: string[]) { return this.post<{ selections: PathSubtask[]; reused: boolean }>(`/v1/projects/${encodeURIComponent(projectID)}/path-selections`, { api_version: 'codexploit/v1', path_ids: pathIDs }); }
  pathSelections(projectID: string, pathID?: string, signal?: AbortSignal) { return this.get<{ selections: PathSubtask[] }>(`/v1/projects/${encodeURIComponent(projectID)}/path-selections${pathID ? `?path_id=${encodeURIComponent(pathID)}` : ''}`, signal); }
  analysisRuns(projectID: string, signal?: AbortSignal) { return this.get<{ analysis_runs: AnalysisRun[] }>(`/v1/projects/${encodeURIComponent(projectID)}/analysis-runs?limit=20`, signal); }
  startAnalysis(projectID: string, body: { agent_assisted: boolean; runtime?: string; idempotency_key?: string }) { return this.post<{ analysis_run: AnalysisRun; reused: boolean }>(`/v1/projects/${encodeURIComponent(projectID)}/analysis-runs`, { api_version: 'codexploit/v1', ...body }); }
  analysisRun(projectID: string, analysisRunID: string, signal?: AbortSignal) { return this.get<{ analysis_run: AnalysisRun }>(`/v1/projects/${encodeURIComponent(projectID)}/analysis-runs/${encodeURIComponent(analysisRunID)}`, signal); }
  cancelAnalysisRun(projectID: string, analysisRunID: string) { return this.post<{ analysis_run: AnalysisRun }>(`/v1/projects/${encodeURIComponent(projectID)}/analysis-runs/${encodeURIComponent(analysisRunID)}/cancel`, {}); }
  path(id: string, signal?: AbortSignal) { return this.get<{ path: AuditPath; events: AuditEvent[] }>(`/paths/${encodeURIComponent(id)}`, signal); }
  finding(id: string, signal?: AbortSignal) { return this.get<FindingDetail>(`/findings/${encodeURIComponent(id)}`, signal); }
  taskBudget(projectID: string, taskID: string, signal?: AbortSignal) { return this.get<{ budget: AuditBudget; grants: BudgetGrant[] }>(`/v1/projects/${encodeURIComponent(projectID)}/tasks/${encodeURIComponent(taskID)}/budget`, signal); }
  grantBudget(projectID: string, taskID: string, body: { tokens: number; reason: string; decision: string; expected_version: number }) { return this.post<{ budget: AuditBudget; grant: BudgetGrant }>(`/v1/projects/${encodeURIComponent(projectID)}/tasks/${encodeURIComponent(taskID)}/budget/grants`, body); }
  runEvents(id: string, signal?: AbortSignal) { return this.get<{ events: AuditEvent[] }>(`/runs/${encodeURIComponent(id)}/events?limit=100`, signal); }
  resumeRun(projectID: string, runID: string) { return this.post<{ api_version: string; run: Run }>(`/v1/projects/${encodeURIComponent(projectID)}/runs/${encodeURIComponent(runID)}/resume`, {}); }
  async slice(path: AuditPath, signal?: AbortSignal) {
    const target = [...path.steps].reverse().find(s => s.file);
    if (!target?.file) return [];
    const response = await this.post<{ sections: { start_line: number; lines: string[] }[] }>(`/snapshots/${encodeURIComponent(path.snapshot_id)}/graph/slice`, { file: target.file, start_line: Math.max(1, (target.line || 1) - 5), end_line: (target.line || 1) + 8, max_lines: 24, max_sections: 1 }, signal);
    return (response.sections || []).flatMap(s => (s.lines || []).map((content, i) => ({ line: s.start_line + i, content, highlight: s.start_line + i === target.line })));
  }
  async changePath(id: string, verb: 'pause' | 'resume') {
    const current = await this.response(`/paths/${encodeURIComponent(id)}`);
    const etag = current.headers.get('ETag');
    if (!etag) throw new Error('路径缺少版本标识，请刷新后重试。');
    await current.arrayBuffer();
    return this.post(`/paths/${encodeURIComponent(id)}/${verb}`, { reason: '由 WebUI 操作者请求' }, undefined, { 'If-Match': etag });
  }
  createAudit(snapshotId: string, draft: AuditDraft) {
    return this.post('/audits', { snapshot_id: snapshotId, limits: { max_paths: draft.maxPaths, max_active_leases: draft.concurrency }, budget: { max_tool_calls: draft.toolCalls } });
  }
  async report(auditId: string, format: string, includeCandidates: boolean) {
    return (await this.response(`/audits/${encodeURIComponent(auditId)}/report?format=${format}&include_candidates=${includeCandidates}`)).text();
  }
}
