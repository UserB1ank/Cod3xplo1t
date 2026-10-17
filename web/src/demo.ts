import type { AuditPath, FindingDetail, FindingStatus, Workspace } from './types.ts';
import { pathCounts } from './domain.ts';

const snapshotId = 'snap-c482a691f09b4ef98f06d239a71c830e';
const auditId = 'audit-3794be182de1489ca60b71f3a4e8c92d';
const now = '2026-10-16T07:24:18Z';
export const examples = [
  { entry: 'GET /v1/files/:name', handler: 'DownloadFile', sink: 'os.ReadFile', kind: 'path_traversal', label: '文件路径边界', file: 'internal/handlers/files.go', line: 48 },
  { entry: 'GET /v1/users/search', handler: 'SearchUsers', sink: 'db.QueryContext', kind: 'sql_injection', label: '数据库查询', file: 'internal/handlers/users.go', line: 92 },
  { entry: 'POST /v1/webhooks', handler: 'CreateWebhook', sink: 'http.Client.Do', kind: 'ssrf', label: '外部请求目标', file: 'internal/services/webhook.go', line: 116 },
  { entry: 'POST /v1/reports/export', handler: 'ExportReport', sink: 'exec.Command', kind: 'command_injection', label: '进程执行边界', file: 'internal/services/export.go', line: 64 },
  { entry: 'GET /v1/assets/:id', handler: 'ReadAsset', sink: 'os.Open', kind: 'path_traversal', label: '资源访问边界', file: 'internal/handlers/assets.go', line: 37 },
  { entry: 'POST /v1/sessions', handler: 'CreateSession', sink: 'session.Save', kind: 'authorization', label: '会话权限边界', file: 'internal/handlers/sessions.go', line: 78 },
  { entry: 'GET /v1/orders/:id', handler: 'GetOrder', sink: 'orders.FindByID', kind: 'authorization', label: '对象级授权', file: 'internal/handlers/orders.go', line: 103 },
  { entry: 'POST /v1/templates', handler: 'RenderTemplate', sink: 'template.Execute', kind: 'template_injection', label: '模板渲染边界', file: 'internal/services/templates.go', line: 52 },
];
export function demoWorkspace(projectId = 'proj-atlas'): Workspace {
  const projects = [
    { id: 'proj-atlas', name: 'atlas-api', source: 'https://example.invalid/platform/atlas-api', identity: 'example.invalid/platform/atlas-api', created_at: now, updated_at: now, version: 1 },
    { id: 'proj-billing', name: 'billing-gateway', source: 'https://example.invalid/platform/billing-gateway', identity: 'example.invalid/platform/billing-gateway', created_at: now, updated_at: now, version: 1 },
    { id: 'proj-worker', name: 'event-worker', source: 'https://example.invalid/platform/event-worker', identity: 'example.invalid/platform/event-worker', created_at: now, updated_at: now, version: 1 },
  ];
  const project = projects.find(p => p.id === projectId) || projects[0];
  const snapshot = { snapshot_id: snapshotId.replace('c482', project.id === 'proj-atlas' ? 'c482' : project.id === 'proj-billing' ? 'd591' : 'e625'), project_id: project.id, commit: '7f3a9b2c048d3e1ab8c62eea4d91f6ba3c58a901', vcs: 'git', created_at: '2026-10-16T06:58:00Z', manifest_present: true };
  const statuses = ['ANALYZING', 'QUEUED', 'QUEUED', 'VERIFYING', 'ANALYZING', 'BLOCKED', 'CONCLUDED', 'CONCLUDED', 'QUEUED', 'QUEUED', 'CONCLUDED', 'PAUSED', 'QUEUED', 'QUEUED', 'FAILED', 'QUEUED', 'CONCLUDED', 'CONCLUDED', 'QUEUED', 'QUEUED', 'CONCLUDED', 'QUEUED', 'CONCLUDED', 'QUEUED'];
  const paths: AuditPath[] = statuses.map((status, i) => {
    const e = examples[i % examples.length];
    return {
      path_id: `path-${String(i + 1).padStart(4, '0')}-82c4ea91`, audit_id: auditId, snapshot_id: snapshot.snapshot_id,
      entry_subject: e.entry, target_subject: e.sink, target_kind: e.kind, path_kind: e.kind, status,
      path_status: i % 5 === 2 ? 'candidate' : i % 7 === 5 ? 'unresolved' : 'statically_supported',
      steps: [
        { layer: 'asg', from: 'entry', to: 'handler', kind: 'HANDLES', subject: e.handler, file: e.file, line: e.line - 7, evidence: 'observed' },
        { layer: 'scg', from: 'handler', to: 'service', kind: 'CALLS', subject: `service.${e.handler}`, file: e.file, line: e.line - 3, evidence: 'observed' },
        { layer: 'scg', from: 'service', to: 'sink', kind: 'CALLS', subject: e.sink, file: e.file, line: e.line, evidence: 'observed' },
      ],
      objectives: [e.label], controls: i % 3 === 0 ? ['authentication middleware'] : [],
      limitations: ['调用图可达性不证明输入数据传播。', '控制存在性不代表其有效性已被验证。'],
      open_questions: ['用户可控输入是否能够到达敏感参数？', '权限校验是否覆盖全部分支？'], scg_refs: [`sym-${i}-handler`, `sym-${i}-sink`],
      score: { priority: Math.round((0.96 - i * 0.026) * 100) / 100, support: i % 5 === 2 ? 0.48 : 0.82, risk: 0.86 - i * 0.015, utility: 0.77 },
      budget: { max_depth: 2, max_branches: 4, max_tool_calls: 30 }, attempts: status === 'FAILED' ? 3 : status === 'QUEUED' ? 0 : 1, version: 1,
    };
  });
  const findingStates: FindingStatus[] = ['confirmed', 'candidate', 'confirmed', 'inconclusive', 'blocked', 'refuted', 'candidate', 'confirmed'];
  const titles = ['文件下载参数越过目录约束', '搜索查询存在输入拼接', 'Webhook 目标未限制内部地址', '导出命令参数的传播尚未确定', '资源访问验证缺少测试环境', '订单对象权限检查已阻断路径', '模板参数的信任边界待确认', '下载接口缺少对象级校验'];
  const findings = findingStates.map((status, i) => ({
    finding_id: `finding-000${i + 1}-a97cd21f`, hypothesis_id: `hyp-${i + 1}-e87b1f`, path_id: paths[[6, 1, 7, 10, 16, 17, 20, 22][i]].path_id,
    audit_id: auditId, snapshot_id: snapshot.snapshot_id, title: titles[i], severity: ['high', 'medium', 'high', 'medium', 'low', 'medium', 'medium', 'high'][i], status,
    supporting_evidence: status === 'confirmed' ? [`evidence-${i}-source`, `evidence-${i}-runtime`] : [`evidence-${i}-source`],
    contradicting_evidence: status === 'refuted' ? [`evidence-${i}-control`] : [], inconclusive_evidence: status === 'inconclusive' ? [`evidence-${i}-partial`] : [],
    limitations: ['本工作区为虚构演示样例；结论不指向任何真实仓库。'],
    reproduce_steps: status === 'confirmed' ? '在隔离演示样例中提交边界输入，观察到预期约束以外的行为；运行日志与源代码位置已关联。' : '', created_at: now,
  }));
  const runs = ['RUNNING', 'RUNNING', 'SUCCEEDED', 'SUCCEEDED', 'TIMED_OUT', 'PAUSED'].map((status, i) => ({
    run_id: `run-00${i + 1}-c82ed5f3`, path_id: paths[[0, 4, 6, 7, 14, 11][i]].path_id, audit_id: auditId, snapshot_id: snapshot.snapshot_id,
    runtime: i % 2 ? 'cli' : 'scripted', status, started_at: `2026-10-16T07:${String(13 + i).padStart(2, '0')}:08Z`, heartbeat_at: now,
    tool_calls: [18, 9, 26, 21, 30, 12][i], input_tokens: [8400, 6200, 9100, 7500, 8800, 3100][i], output_tokens: [1200, 840, 1900, 1400, 760, 420][i], elapsed_ms: [128000, 84000, 195000, 174000, 600000, 92000][i],
    task: { security_goal: examples[i % examples.length].label }, stop_reason: status === 'TIMED_OUT' ? 'deadline_exceeded' : undefined,
  }));
  return {
    projects, project, snapshots: [snapshot], snapshot, paths, pathTotal: paths.length, findings, findingTotal: findings.length, runs, runTotal: runs.length,
    audits: [{ audit_id: auditId, snapshot_id: snapshot.snapshot_id, status: 'READY', path_count: paths.length, created_at: now, counts_by_status: pathCounts(paths), limits: { max_active_leases: 4, exploration_fraction: 0.2 }, coverage: { entry_points_examined: 48, chains_resolved: 21, chains_unresolved: 3, truncated: false } }],
    audit: { audit_id: auditId, snapshot_id: snapshot.snapshot_id, status: 'READY', path_count: paths.length, created_at: now, counts_by_status: pathCounts(paths), limits: { max_active_leases: 4, exploration_fraction: 0.2 }, coverage: { entry_points_examined: 48, chains_resolved: 21, chains_unresolved: 3, truncated: false } },
    graph: { files: 186, symbols: 1248, modules: 12, edges: 3042, call_sites: 840, resolution: { resolved: 704, resolved_best_effort: 32, dynamic: 52, external: 43, ambiguous: 9, unsupported: 0 }, limitations: ['仅分析 Go，未执行目标代码。', 'FLOWS_TO 数据流边尚未生成。'] },
    scheduler: { running: true, configured: true, config: { max_concurrent: 4, interval_seconds: 30 }, metrics: { ticks: 42, active_leases: 3, queue_depth: 12, succeeded_total: 8, failed_total: 1, retried_total: 2, last_tick_at: now } },
    events: [
      { event_id: 'event-105', path_id: paths[6].path_id, seq: 105, type: 'verification_finished', actor: 'verification', reason: '复现证据已关联到 finding', created_at: '2026-10-16T07:24:18Z' },
      { event_id: 'event-104', path_id: paths[0].path_id, seq: 104, type: 'tool_result', actor: 'agent', reason: '读取最小代码切片 · 48 行', created_at: '2026-10-16T07:24:06Z' },
      { event_id: 'event-103', path_id: paths[4].path_id, seq: 103, type: 'path_claimed', actor: 'scheduler', reason: '领取下一条到期路径', created_at: '2026-10-16T07:23:48Z' },
      { event_id: 'event-102', path_id: paths[0].path_id, seq: 102, type: 'expansion_decided', actor: 'policy', reason: '批准局部扩展 · +1 hop', created_at: '2026-10-16T07:23:21Z' },
    ], warnings: [],
  };
}

export function demoCode(path: AuditPath) {
  const line = path.steps.at(-1)?.line || 48;
  const functionName = path.steps[0]?.subject || 'HandleRequest';
  const lines = path.path_kind === 'sql_injection'
    ? [`func ${functionName}(ctx *Context) error {`, '    query := ctx.Query("search")', '    statement := buildSearch(query)', '    rows, err := db.QueryContext(ctx, statement)', '    if err != nil { return err }', '    defer rows.Close()', '    return respond(ctx, rows)', '}']
    : [`func ${functionName}(ctx *Context) error {`, '    name := ctx.Param("name")', '    candidate := filepath.Join(baseDir, name)', '    content, err := os.ReadFile(candidate)', '    if err != nil { return err }', '    return ctx.Blob(content)', '}'];
  return lines.map((content, i) => ({ line: line - 3 + i, content, highlight: i === 3 }));
}

export function demoFindingDetail(finding: Workspace['findings'][number]): FindingDetail {
  const evidence = (id: string, kind: string, content: string) => ({ evidence_id: id, kind, tool: 'demo-fixture@1', file: 'internal/handlers/files.go', line: 48, content, redacted: false, content_hash: 'sha256:demo-content-reference' });
  return {
    finding,
    evidence: {
      supporting: finding.supporting_evidence.map((id, i) => evidence(id, i ? 'runtime_log' : 'source', i ? '隔离演示样例：观察到约束以外的行为，复现步骤已记录。' : '代码位置：外部输入参与敏感调用参数的构造。单凭可达性不能确认漏洞。')),
      contradicting: finding.contradicting_evidence.map(id => evidence(id, 'static_query', '对象所属关系检查在到达敏感操作前拒绝了不匹配的主体。')),
      inconclusive: finding.inconclusive_evidence.map(id => evidence(id, 'runtime_log', '环境未覆盖全部分支，未取得足以确认或排除的证据。')),
    }, verifications: finding.status === 'candidate' ? [] : [{ run_id: 'verify-demo-a241', status: finding.status === 'blocked' ? 'BLOCKED' : 'SUCCEEDED', outcome: finding.status.toUpperCase() }],
  };
}
