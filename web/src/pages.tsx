import { useMemo, useState } from 'react';
import { Activity, ArrowDownToLine, ArrowRight, ArrowUpRight, Box, Check, ChevronDown, CircleDot, Code2, Database, FileCode2, FileJson, FileText, Filter, GitBranch, Layers, ListFilter, Loader2, Play, Search, Shield, SlidersHorizontal, Timer, TriangleAlert, Workflow } from 'lucide-react';
import type { AuditPath, Finding, FindingStatus, PathFilter, Project, Run, View, Workspace } from './types';
import { Badge, EmptyState, Hint, Panel, PathGraph, PathTable } from './components';
import { ACTIVE, clock, compact, countFormat, dateLabel, eventNames, filterPaths, findingCounts, findingMeaning, findingStatus, priorityBins, shortId, statistics } from './domain';

export interface PageProps {
  data: Workspace; demo: boolean;
  onPath: (path: AuditPath) => void; onFinding: (finding: Finding) => void; onRun: (run: Run) => void;
  onNavigate: (view: View) => void; onProject: (project: Project) => void; onNewAudit: () => void;
}

export function Overview(props: PageProps) {
  const { data, onNavigate, onPath } = props;
  const stats = statistics(data);
  const bins = priorityBins(data.paths);
  const maxBin = Math.max(1, ...bins);
  const needsAttention = data.paths.filter(p => ['BLOCKED', 'FAILED', 'INTERRUPTED'].includes(p.status));
  const maxConcurrent = data.audit?.limits.max_active_leases || 4;
  return <>
    <div className="metric-strip">
      <Metric label="待处理路径" value={stats.queued.toString().padStart(2, '0')} note={<><span className="accent">{data.paths.filter(p => p.score.priority >= 0.85).length} 条</span>高优先级路径</>} icon={Workflow} />
      <Metric label="已确认发现" value={stats.confirmed.toString().padStart(2, '0')} note={<>来自 {data.findings.length} 条已载入发现</>} icon={Shield} alert={stats.confirmed > 0} />
      <Metric label="调用解析覆盖" value={stats.coverage === undefined ? '—' : `${stats.coverage}%`} note={data.graph ? <>{countFormat.format(data.graph.symbols)} 个符号 · {countFormat.format(data.graph.files)} 个文件</> : '当前快照尚无源码图谱'} icon={Code2} />
      <Metric label="运行中 Agent" value={String(stats.running).padStart(2, '0')} suffix={`/ ${maxConcurrent}`} note={<>{compact(stats.tokens)} tokens · 已载入运行</>} icon={Activity} />
    </div>
    {stats.partial && <Hint>统计基于当前载入项；待处理数来自审计汇总。路径、发现或运行仍有未载入页面。</Hint>}
    <div className="overview-top-grid">
      <Panel title="从入口到敏感操作" eyebrow="ATTACK PATH EXPLORER" action={<button className="text-button" onClick={() => onNavigate('surface')}>攻击面视图<ArrowUpRight size={14} /></button>} className="graph-panel">
        <PathGraph path={data.paths[0]} onOpen={() => data.paths[0] && onPath(data.paths[0])} />
      </Panel>
      <Panel title="审计状态" eyebrow="CURRENT AUDIT" className="audit-summary">
        <div className="audit-summary-top"><span className="mono">{shortId(data.audit?.audit_id, 6)}</span><Badge status={data.audit?.status || '未创建'} /></div>
        <div className="audit-progress-label"><span>路径处理进度</span><strong>{data.paths.filter(p => ['CONCLUDED', 'HYPOTHESIS_FORMED'].includes(p.status)).length}<small> / {data.pathTotal}</small></strong></div>
        <div className="progress-segments">{Array.from({ length: 24 }, (_, i) => <i key={i} className={i < data.paths.filter(p => ['CONCLUDED', 'HYPOTHESIS_FORMED'].includes(p.status)).length / Math.max(1, data.pathTotal) * 24 ? 'filled' : ''} />)}</div>
        <div className="audit-mini-stats"><div><span>活跃路径</span><strong>{stats.active}<small> / {maxConcurrent}</small></strong></div><div><span>待关注</span><strong>{needsAttention.length.toString().padStart(2, '0')}</strong></div></div>
        <div className="distribution-heading"><span>优先级分布</span><span>低 → 高</span></div><div className="histogram">{bins.map((count, i) => <div key={i} title={`${(i / 10).toFixed(1)}–${((i + 1) / 10).toFixed(1)}：${count} 条`}><i className={i >= 8 ? 'hot' : ''} style={{ height: `${Math.max(5, count / maxBin * 100)}%` }} /></div>)}</div>
        <div className="audit-summary-footer"><span className={`connection-dot ${data.scheduler?.running ? 'connected' : ''}`} />{data.scheduler?.running ? '调度器运行中' : data.scheduler ? '调度器未运行' : '调度器未配置'}<span>{data.scheduler?.config.interval_seconds || '—'}s / tick</span></div>
      </Panel>
    </div>
    <div className="overview-bottom-grid">
      <Panel title="路径优先队列" action={<button className="text-button" onClick={() => onNavigate('paths')}>全部 {data.pathTotal} 条<ArrowRight size={14} /></button>}>
        <PathTable paths={data.paths.slice(0, 6)} onSelect={onPath} compact />
        <div className="table-note"><ListFilter size={13} />按调度优先级排序<span>优先级不等于漏洞严重度</span></div>
      </Panel>
      <Panel title="最近活动" action={<span className="live-label"><span />事件记录</span>} className="activity-panel">
        {data.events.length ? <div className="activity-feed">{data.events.slice(0, 4).map((event, i) => <button key={event.event_id} className="activity-event" onClick={() => { const p = data.paths.find(p => p.path_id === event.path_id); if (p) onPath(p); else onNavigate('runs'); }}><span className={`activity-marker ${i === 0 ? 'latest' : ''}`}><span /></span><div><strong>{eventNames[event.type] || event.type}</strong><p>{event.reason || event.summary || shortId(event.path_id)}</p><span className="mono">{clock(event.created_at)}<span className="muted-dot">·</span>{event.actor || 'system'}</span></div></button>)}</div> : <EmptyState title="尚无审计活动">创建审计后，事件会在此出现。</EmptyState>}
        <button className="activity-footer" onClick={() => onNavigate('runs')}>打开运行监控<ArrowRight size={14} /></button>
      </Panel>
    </div>
    <Hint>路径显示调用图可达性，不证明数据传播。控制存在不代表有效；已确认发现必须关联验证证据。</Hint>
  </>;
}

function Metric({ label, value, suffix, note, icon: Icon, alert }: { label: string; value: string; suffix?: string; note: React.ReactNode; icon: typeof Activity; alert?: boolean }) {
  return <div className={`metric ${alert ? 'alert-metric' : ''}`}><div className="metric-label">{label}<Icon size={16} strokeWidth={1.5} /></div><div className="metric-number">{value}{suffix && <span>{suffix}</span>}</div><div className="metric-note">{note}</div></div>;
}

export function ProjectsPage({ data, onProject, onNewAudit, demo }: PageProps) {
  const [query, setQuery] = useState('');
  const projects = data.projects.filter(p => `${p.name} ${p.identity}`.toLowerCase().includes(query.toLowerCase()));
  return <>
    <div className="section-toolbar"><div className="search-input"><Search size={15} /><input aria-label="搜索项目" placeholder="搜索仓库或项目名称…" value={query} onChange={e => setQuery(e.target.value)} /></div><span className="muted">{projects.length} 个项目</span></div>
    <div className="project-grid">{projects.map((project, i) => <button className={`project-card ${project.id === data.project?.id ? 'current' : ''}`} key={project.id} onClick={() => onProject(project)}><div className="project-card-top"><span className={`project-monogram project-${i}`}>{project.name.slice(0, 1).toUpperCase()}</span><span>{project.id === data.project?.id ? '当前项目' : '打开项目'}<ArrowUpRight size={15} /></span></div><h2>{project.name}</h2><p className="mono">{project.identity}</p><div className="project-card-footer"><span><span className="language-dot" />{demo ? 'Go' : '仓库'}</span><span>{dateLabel(project.updated_at)}</span></div></button>)}</div>
    <Panel title="当前项目快照" action={<span className="subtle-label">不可变分析基线</span>}>
      {data.snapshots.length ? <div className="table-scroll"><table className="standard-table"><thead><tr><th>快照</th><th>Commit</th><th>仓库类型</th><th>Manifest</th><th>创建时间</th></tr></thead><tbody>{data.snapshots.map(snapshot => <tr key={snapshot.snapshot_id}><td className="mono">{shortId(snapshot.snapshot_id)}</td><td className="mono"><GitBranch size={13} className="inline-icon" />{snapshot.commit.slice(0, 10)}</td><td>{snapshot.vcs}</td><td>{snapshot.manifest_present ? <span className="inline-label"><Check size={13} />已登记</span> : '未生成'}</td><td>{dateLabel(snapshot.created_at)}</td></tr>)}</tbody></table></div> : <EmptyState title="当前项目没有已登记快照">使用快照链创建并登记一个分析基线后，即可开始审计。</EmptyState>}
    </Panel>
    <div className="next-action"><div><Layers size={22} /><span><strong>从一个固定版本开始</strong><small>审计、图谱与证据始终关联同一快照。</small></span></div><button className="button secondary" onClick={onNewAudit} disabled={!data.snapshot}>为当前快照创建审计<ArrowRight size={14} /></button></div>
  </>;
}

export function GraphPage({ data, onPath, surface = false }: PageProps & { surface?: boolean }) {
  const [pathId, setPathId] = useState('');
  const active = data.paths.find(p => p.path_id === pathId) || data.paths[0];
  const files = [...new Set(data.paths.flatMap(p => p.steps.map(s => s.file).filter((file): file is string => !!file)))];
  return <>
    <div className="graph-summary-strip"><span><FileCode2 size={16} /><strong>{countFormat.format(data.graph?.files || 0)}</strong>文件</span><span><Box size={16} /><strong>{countFormat.format(data.graph?.symbols || 0)}</strong>符号</span><span><GitBranch size={16} /><strong>{countFormat.format(data.graph?.edges || 0)}</strong>关系</span><span className="graph-summary-end">{surface ? 'ASG · 攻击面路径' : 'SCG · 调用路径'}</span></div>
    <div className="graph-page-grid"><Panel title="文件索引" action={<span className="mono">{files.length}</span>} className="file-index"><span className="index-note">来自已载入路径</span>{files.map(file => <button key={file} className={active?.steps.some(s => s.file === file) ? 'active' : ''} onClick={() => setPathId(data.paths.find(p => p.steps.some(s => s.file === file))?.path_id || '')}><FileCode2 size={15} /><span><small>{file.split('/').slice(0, -1).join('/')}/</small>{file.split('/').at(-1)}</span><ChevronDown size={12} /></button>)}</Panel>
      <Panel title={surface ? '攻击面路径视图' : '函数调用路径'} action={<select className="compact-select" aria-label="选择图谱中的路径" value={active?.path_id || ''} onChange={e => setPathId(e.target.value)}>{data.paths.map(p => <option key={p.path_id} value={p.path_id}>{shortId(p.path_id, 6)} · {p.entry_subject}</option>)}</select>}>
        <PathGraph path={active} expanded mode={surface ? 'surface' : 'graph'} onOpen={() => active && onPath(active)} />
        {active && <div className="graph-detail-grid"><div><span className="eyebrow">ENTRY POINT</span><strong>{active.entry_subject}</strong><small>快照 {shortId(active.snapshot_id)}</small></div><div><span className="eyebrow">EVIDENCE CLASS</span><strong>{active.path_status === 'statically_supported' ? '静态调用链支持' : active.path_status === 'candidate' ? '候选可达路径' : '解析不完整'}</strong><small>调用关系不等于污点传播</small></div><div><span className="eyebrow">SECURITY CONTROL</span><strong>{active.controls.length ? `${active.controls.length} 个已观察控制` : '未观察到控制'}</strong><small>有效性尚未评估</small></div></div>}
      </Panel>
    </div>
    <Hint>{surface ? '当前视图关联入口、已观察控制与敏感操作，不对控制顺序或有效性作额外推断。' : '视图取自已保存审计路径。未解析调用和切片截断会保留为限制，不作为已建立的数据流。'}</Hint>
  </>;
}

export function PathsPage({ data, onPath, onMore, loadingMore }: PageProps & { onMore: () => void; loadingMore: boolean }) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<PathFilter>('all');
  const [page, setPage] = useState(0);
  const filtered = useMemo(() => filterPaths(data.paths, query, filter), [data.paths, query, filter]);
  const tabs: { id: PathFilter; label: string; count: number }[] = [
    { id: 'all', label: '全部路径', count: data.paths.length }, { id: 'queued', label: '待处理', count: filterPaths(data.paths, '', 'queued').length },
    { id: 'active', label: '运行中', count: filterPaths(data.paths, '', 'active').length }, { id: 'attention', label: '需关注', count: filterPaths(data.paths, '', 'attention').length },
  ];
  const currentPage = Math.min(page, Math.max(0, Math.ceil(filtered.length / 12) - 1));
  return <Panel className="paths-workbench"><div className="workbench-toolbar"><div className="filter-tabs">{tabs.map(tab => <button key={tab.id} className={filter === tab.id ? 'active' : ''} onClick={() => { setFilter(tab.id); setPage(0); }}>{tab.label}<span>{tab.count}</span></button>)}</div><div className="search-input"><Search size={14} /><input aria-label="搜索审计路径" value={query} onChange={e => { setQuery(e.target.value); setPage(0); }} placeholder="搜索入口、文件或敏感操作…" /></div></div>
    <div className="table-context"><span><Filter size={13} />快照 {shortId(data.snapshot?.snapshot_id)}</span><span><SlidersHorizontal size={13} />按优先级降序</span></div>
    <PathTable paths={filtered.slice(currentPage * 12, currentPage * 12 + 12)} onSelect={onPath} />
    <div className="pagination"><span>{filtered.length ? `${currentPage * 12 + 1}–${Math.min(filtered.length, currentPage * 12 + 12)}` : '0'} / {filtered.length} 条匹配路径</span><div><button className="button small secondary" disabled={currentPage === 0} onClick={() => setPage(p => p - 1)}>上一页</button><span className="mono">{currentPage + 1} / {Math.max(1, Math.ceil(filtered.length / 12))}</span><button className="button small secondary" disabled={(currentPage + 1) * 12 >= filtered.length} onClick={() => setPage(p => p + 1)}>下一页</button></div></div>
    {data.paths.length < data.pathTotal && <div className="load-more"><span>已载入 {data.paths.length} / {data.pathTotal} 条。搜索与筛选仅应用于已载入项。</span><button className="text-button" onClick={onMore} disabled={loadingMore || data.paths.length >= 1000}>{loadingMore ? <Loader2 size={13} className="spin" /> : <ArrowDownToLine size={13} />}{data.paths.length >= 1000 ? '已达到页面载入预算' : '再载入 100 条'}</button></div>}
  </Panel>;
}

export function RunsPage({ data, onRun, onNavigate }: PageProps) {
  const [activeOnly, setActiveOnly] = useState(false);
  const runs = data.runs.filter(r => !activeOnly || r.status === 'RUNNING');
  const scheduler = data.scheduler;
  return <>
    <div className="scheduler-banner"><span className={`scheduler-symbol ${scheduler?.running ? 'running' : ''}`}><Activity size={23} /></span><div><h2>{scheduler?.running ? '调度器运行中' : scheduler?.configured ? '调度器已配置 · 当前未运行' : '尚未配置调度器'}</h2><p>{scheduler ? `${scheduler.config.interval_seconds}s 调度间隔 · 最大并发 ${scheduler.config.max_concurrent} · ${scheduler.metrics.ticks} 次已完成调度` : '配置常驻调度器后可查看派发与回收指标。'}</p></div><div className="scheduler-numbers"><span><strong>{scheduler?.metrics.queue_depth ?? '—'}</strong>等待队列</span><span><strong>{scheduler?.metrics.retried_total ?? '—'}</strong>已退避重试</span><span><strong>{scheduler?.metrics.active_leases ?? '—'}</strong>活跃租约</span></div></div>
    <Panel title="Agent 运行" action={<button className={`toggle-button ${activeOnly ? 'selected' : ''}`} onClick={() => setActiveOnly(v => !v)} aria-pressed={activeOnly}><span className="toggle-track"><i /></span>仅运行中</button>}>
      {runs.length ? <div className="run-grid">{runs.map(run => {
        const path = data.paths.find(p => p.path_id === run.path_id);
        return <button className={`run-card ${run.status === 'RUNNING' ? 'running' : ''}`} key={run.run_id} onClick={() => onRun(run)}><div className="run-card-top"><span className="run-icon"><Code2 size={19} /></span><span className="mono">{shortId(run.run_id)}</span><Badge status={run.status} /></div><h3>{path?.entry_subject || shortId(run.path_id)}</h3><p>{run.task?.security_goal || path?.objectives.join(' · ') || '路径语义分析'}</p><div className="run-tool-progress"><span>工具调用 <strong>{run.tool_calls} / {path?.budget.max_tool_calls || '—'}</strong></span><i><b style={{ width: `${Math.min(100, run.tool_calls / (path?.budget.max_tool_calls || Math.max(1, run.tool_calls)) * 100)}%` }} /></i></div><div className="run-card-footer"><span><Timer size={13} />{Math.round(run.elapsed_ms / 1000)}s</span><span>{compact(run.input_tokens + run.output_tokens)} tokens</span><ArrowUpRight size={15} /></div></button>;
      })}</div> : <EmptyState title={activeOnly ? '当前没有运行中的 Agent' : '还没有 Agent 运行'}>运行记录会保留预算、工具交换和结构化输出，不展示内部推理过程。</EmptyState>}
      <div className="table-note">已载入 {data.runs.length} / {data.runTotal} 条运行记录<button className="text-button" onClick={() => onNavigate('paths')}>查看待处理路径<ArrowRight size={13} /></button></div>
    </Panel>
  </>;
}

export function FindingsPage({ data, onFinding }: PageProps) {
  const [status, setStatus] = useState<'all' | FindingStatus>('all');
  const [query, setQuery] = useState('');
  const counts = findingCounts(data.findings);
  const findings = data.findings.filter(f => (status === 'all' || f.status === status) && `${f.title} ${f.finding_id}`.toLowerCase().includes(query.toLowerCase()));
  return <>
    <div className="finding-summary">{(['confirmed', 'candidate', 'inconclusive', 'blocked', 'refuted'] as FindingStatus[]).map(key => <button key={key} className={`${status === key ? 'selected' : ''} ${key}`} onClick={() => setStatus(status === key ? 'all' : key)}><span className="finding-summary-count">{String(counts[key]).padStart(2, '0')}</span><span>{findingStatus[key]}</span><ArrowUpRight size={15} /></button>)}</div>
    <Panel title="发现与证据" action={<div className="search-input narrow"><Search size={14} /><input aria-label="搜索发现" placeholder="搜索发现…" value={query} onChange={e => setQuery(e.target.value)} /></div>}>
      <div className="finding-filter-line"><button className={`text-button ${status === 'all' ? 'accent' : ''}`} onClick={() => setStatus('all')}>全部发现 <span className="mono">{data.findings.length}</span></button>{status !== 'all' && <span>{findingMeaning[status]}</span>}<span className="push-right">已载入 {data.findings.length} / {data.findingTotal}</span></div>
      {findings.length ? <div className="finding-list">{findings.map(finding => <button className="finding-row" key={finding.finding_id} onClick={() => onFinding(finding)}><span className={`finding-icon ${finding.status}`}><Shield size={19} strokeWidth={1.5} /></span><span className="finding-main"><strong>{finding.title}</strong><span className="mono">{shortId(finding.finding_id)}<span className="muted-dot">·</span>{shortId(finding.path_id)}</span></span><span className="evidence-count"><Layers size={13} />{finding.supporting_evidence.length + finding.contradicting_evidence.length + finding.inconclusive_evidence.length} 条证据</span><Badge status={finding.status} /><ArrowUpRight size={15} /></button>)}</div> : <EmptyState title="没有匹配的发现">调整状态或搜索条件。</EmptyState>}
    </Panel>
    <Hint>“验证受阻”与“证据不足”均不能作为排除依据。点击发现可分别查看支持、矛盾及不确定证据。</Hint>
  </>;
}

export function ReportsPage({ data, demo, onExport }: PageProps & { onExport: (format: 'md' | 'json' | 'sarif', includeCandidates: boolean) => Promise<void> }) {
  const [format, setFormat] = useState<'md' | 'json' | 'sarif'>('md');
  const [include, setInclude] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const counts = findingCounts(data.findings);
  const formats = [{ id: 'md' as const, title: 'Markdown', detail: '适合人工评审与文档归档', icon: FileText, ext: '.md' }, { id: 'json' as const, title: 'JSON', detail: '结构化 findings 与关联证据', icon: FileJson, ext: '.json' }, { id: 'sarif' as const, title: 'SARIF', detail: '对接代码扫描与开发工具', icon: Code2, ext: '.sarif' }];
  async function download() { setBusy(true); setError(''); try { await onExport(format, include); } catch (error) { setError(error instanceof Error ? error.message : '导出失败'); } finally { setBusy(false); } }
  return <div className="report-layout"><Panel title="生成可复核的审计报告" eyebrow="EVIDENCE, NOT ASSUMPTIONS" className="report-config"><p className="report-intro">带着证据交付结论。保留快照、路径、验证结果，以及尚未解决的问题。</p><div className="format-options">{formats.map(item => <button key={item.id} className={format === item.id ? 'selected' : ''} onClick={() => setFormat(item.id)}><item.icon size={21} strokeWidth={1.5} /><span><strong>{item.title}</strong><small>{item.detail}</small></span><span className="mono">{item.ext}</span><span className="radio-indicator">{format === item.id && <Check size={12} />}</span></button>)}</div><label className="check-option"><input type="checkbox" checked={include} onChange={e => setInclude(e.target.checked)} /><span><strong>包含尚未验证的候选</strong><small>候选会保留独立状态，不会标记为已确认漏洞。</small></span></label>{error && <div className="error-banner" role="alert">{error}</div>}<button className="button primary full-width" onClick={download} disabled={busy || !data.audit}>{busy ? <Loader2 size={16} className="spin" /> : <ArrowDownToLine size={16} />}{busy ? '正在生成…' : '生成并下载报告'}</button><span className="report-footnote">{demo ? '当前导出将明确标注为演示数据。' : '从所选审计的服务端 findings 与证据生成。'} 支持 Markdown / JSON / SARIF。</span></Panel>
    <Panel title="交付摘要" className="report-preview"><div className="report-sheet"><span className="report-sheet-brand"><Shield size={17} />CODEXPLOIT<span>REPORT / 01</span></span><div className="report-sheet-rule" /><span className="eyebrow">SECURITY AUDIT</span><h2>{data.project?.name || '尚未选择项目'}</h2><p className="mono">{shortId(data.snapshot?.snapshot_id)} / {data.snapshot?.commit.slice(0, 7) || '—'}</p><div className="report-sheet-count"><strong>{counts.confirmed.toString().padStart(2, '0')}</strong><span>已确认发现<small>当前已载入项</small></span></div><dl><div><dt>候选</dt><dd>{include ? counts.candidate : '不包含'}</dd></div><div><dt>证据不足 / 受阻</dt><dd>{counts.inconclusive + counts.blocked}</dd></div><div><dt>已排除</dt><dd>{counts.refuted}</dd></div><div><dt>输出格式</dt><dd className="mono">{format.toUpperCase()}</dd></div></dl><div className="report-sheet-caveat"><TriangleAlert size={14} />未复现不等于不存在漏洞。</div><span className="report-sheet-bottom">{demo ? 'DEMONSTRATION DATA' : 'SNAPSHOT-BOUND EVIDENCE'}</span></div></Panel>
  </div>;
}
