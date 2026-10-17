import type { AuditPath, Finding, FindingStatus, PathFilter, Workspace } from './types.ts';

export const ACTIVE = new Set(['ANALYZING', 'LOCAL_EXPLORING', 'VERIFYING']);
export const ATTENTION = new Set(['BLOCKED', 'FAILED', 'INTERRUPTED']);
export const pathStatus: Record<string, string> = {
  DISCOVERED: '已发现', QUEUED: '待处理', ANALYZING: '分析中', LOCAL_EXPLORING: '局部探索',
  HYPOTHESIS_FORMED: '已形成假设', VERIFYING: '验证中', CONCLUDED: '已完成', BLOCKED: '受阻',
  PAUSED: '已暂停', FAILED: '执行失败', CANCELLED: '已取消', INTERRUPTED: '已中断',
};
export const findingStatus: Record<FindingStatus, string> = { confirmed: '已确认', candidate: '候选', refuted: '已排除', inconclusive: '证据不足', blocked: '验证受阻' };
export const findingMeaning: Record<FindingStatus, string> = {
  confirmed: '已通过验证复现，并保留复现步骤和支持证据。',
  candidate: '尚未验证的假设，需要补充证据后才能确认。',
  refuted: '存在与假设矛盾的证据，已保留排除依据。',
  inconclusive: '验证已执行，但现有证据不足以得出结论。',
  blocked: '验证未能执行。环境或审批等前提仍未满足。',
};
export const eventNames: Record<string, string> = {
  path_claimed: '路径已被领取', path_status_changed: '路径状态更新', path_heartbeat: '收到 worker 心跳',
  hypothesis_recorded: '记录结构化假设', run_started: 'Agent 开始分析', run_finished: 'Agent 运行结束',
  tool_result: '查询结果已记录', expansion_decided: '局部扩展策略已决策', verification_finished: '验证完成', audit_created: '审计已创建',
};
export const countFormat = new Intl.NumberFormat('zh-CN');
export function compact(n: number) { return n >= 1000 ? `${(n / 1000).toFixed(1)}k` : String(n); }
export function shortId(id = '', n = 8) { return id.length > n + 6 ? `${id.split('-')[0]}-${id.slice(-n)}` : id || '—'; }
export function clock(value?: string) {
  if (!value || Number.isNaN(Date.parse(value))) return '—';
  return new Intl.DateTimeFormat('zh-CN', { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }).format(new Date(value));
}
export function dateLabel(value?: string) {
  if (!value || Number.isNaN(Date.parse(value))) return '—';
  return new Intl.DateTimeFormat('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false, timeZone: 'Asia/Shanghai' }).format(new Date(value));
}
export function filterPaths(paths: AuditPath[], query: string, filter: PathFilter) {
  const q = query.trim().toLocaleLowerCase();
  return paths.filter(p => {
    if (filter === 'queued' && p.status !== 'QUEUED') return false;
    if (filter === 'active' && !ACTIVE.has(p.status)) return false;
    if (filter === 'attention' && !ATTENTION.has(p.status)) return false;
    return !q || [p.path_id, p.entry_subject, p.target_subject, p.path_kind, ...p.steps.map(s => s.file || '')].join(' ').toLocaleLowerCase().includes(q);
  });
}
export function pathCounts(paths: AuditPath[]) {
  return paths.reduce<Record<string, number>>((counts, p) => { counts[p.status] = (counts[p.status] || 0) + 1; return counts; }, {});
}
export function findingCounts(findings: Finding[]) {
  return findings.reduce<Record<FindingStatus, number>>((counts, f) => { counts[f.status]++; return counts; }, { confirmed: 0, candidate: 0, refuted: 0, inconclusive: 0, blocked: 0 });
}
export function statistics(workspace: Workspace) {
  const counts = workspace.audit?.counts_by_status || pathCounts(workspace.paths);
  const findings = findingCounts(workspace.findings);
  const resolution = workspace.graph?.resolution;
  const resolved = resolution ? (resolution.resolved || 0) + (resolution.resolved_best_effort || 0) : 0;
  const sites = workspace.graph?.call_sites || 0;
  return {
    queued: counts.QUEUED || 0, active: [...ACTIVE].reduce((n, s) => n + (counts[s] || 0), 0),
    confirmed: findings.confirmed, running: workspace.runs.filter(r => r.status === 'RUNNING').length,
    coverage: sites > 0 ? Math.min(100, Math.round(resolved / sites * 1000) / 10) : undefined,
    tokens: workspace.runs.reduce((n, r) => n + r.input_tokens + r.output_tokens, 0),
    partial: workspace.paths.length < workspace.pathTotal || workspace.findings.length < workspace.findingTotal || workspace.runs.length < workspace.runTotal,
  };
}
export function priorityBins(paths: AuditPath[]) {
  const bins = Array<number>(10).fill(0);
  paths.forEach(p => bins[Math.min(9, Math.max(0, Math.floor(p.score.priority * 10)))]++);
  return bins;
}
export function reportText(workspace: Workspace, format: 'md' | 'json' | 'sarif', includeCandidates: boolean) {
  const findings = workspace.findings.filter(f => includeCandidates || f.status !== 'candidate');
  if (format === 'json') return JSON.stringify({ schema_version: 1, audit_id: workspace.audit?.audit_id, demo: true, findings }, null, 2);
  if (format === 'sarif') return JSON.stringify({ version: '2.1.0', runs: [{ tool: { driver: { name: 'Codexploit demo' } }, results: findings.map(f => ({ ruleId: f.finding_id, level: f.status === 'confirmed' ? 'warning' : f.status === 'refuted' ? 'none' : 'note', message: { text: `[${findingStatus[f.status]}] ${f.title} — ${findingMeaning[f.status]}` } })) }] }, null, 2);
  return ['# Codexploit 审计报告（演示数据）', '', `审计：${workspace.audit?.audit_id || '—'}`, '', '候选未获验证，验证受阻与证据不足均不等于排除。', '', ...findings.flatMap(f => [`## ${f.title}`, '', `状态：${findingStatus[f.status]}`, '', findingMeaning[f.status], '', f.reproduce_steps || '暂无复现步骤。', ''])].join('\n');
}
