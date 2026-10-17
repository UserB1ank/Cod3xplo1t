import { useEffect, useState } from 'react';
import { ArrowRight, Check, Clock3, Code2, Copy, FileCode2, Layers, Loader2, Pause, Play, RefreshCw, Shield, Terminal, TriangleAlert } from 'lucide-react';
import type { AuditEvent, AuditPath, Finding, FindingDetail, Run, Workspace } from './types';
import { ApiClient } from './api';
import { Badge, CodeBlock, EmptyState, Hint, Modal } from './components';
import { demoCode, demoFindingDetail } from './demo';
import { ACTIVE, clock, compact, eventNames, findingMeaning, shortId } from './domain';

export type Selection = { kind: 'path'; item: AuditPath } | { kind: 'finding'; item: Finding } | { kind: 'run'; item: Run };

export default function Inspector({ selection, data, demo, client, onClose, onPathAction, onPathById }: { selection?: Selection; data: Workspace; demo: boolean; client?: ApiClient; onClose: () => void; onPathAction: (path: AuditPath, verb: 'pause' | 'resume') => Promise<void>; onPathById: (id: string) => void }) {
  const [tab, setTab] = useState('overview');
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [lines, setLines] = useState<{ line: number; content: string; highlight: boolean }[]>([]);
  const [finding, setFinding] = useState<FindingDetail>();
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [working, setWorking] = useState(false);
  const [reload, setReload] = useState(0);
  const [copied, setCopied] = useState(false);
  const id = selection ? selection.kind === 'path' ? selection.item.path_id : selection.kind === 'finding' ? selection.item.finding_id : selection.item.run_id : '';
  useEffect(() => { setTab('overview'); setCopied(false); }, [id]);
  useEffect(() => {
    setError(''); setEvents([]); setLines([]); setFinding(undefined);
    if (!selection) return;
    if (demo) {
      if (selection.kind === 'path') { setLines(demoCode(selection.item)); setEvents(data.events.filter(e => e.path_id === selection.item.path_id)); }
      if (selection.kind === 'finding') setFinding(demoFindingDetail(selection.item));
      if (selection.kind === 'run') setEvents(data.events.filter(e => e.path_id === selection.item.path_id));
      return;
    }
    if (!client) return;
    const controller = new AbortController();
    setBusy(true);
    async function read() {
      if (!selection || !client) return;
      try {
        if (selection.kind === 'path') {
          const results = await Promise.allSettled([client.path(selection.item.path_id, controller.signal), client.slice(selection.item, controller.signal)]);
          if (controller.signal.aborted) return;
          if (results[0].status === 'fulfilled') setEvents(results[0].value.events || []);
          if (results[1].status === 'fulfilled') setLines(results[1].value);
          const failed = results.find(r => r.status === 'rejected');
          if (failed?.status === 'rejected') throw failed.reason;
        } else if (selection.kind === 'finding') {
          const detail = await client.finding(selection.item.finding_id, controller.signal);
          if (!controller.signal.aborted) setFinding(detail);
        } else {
          const result = await client.runEvents(selection.item.run_id, controller.signal);
          if (!controller.signal.aborted) setEvents(result.events || []);
        }
      } catch (error) { if (!controller.signal.aborted) setError(error instanceof Error ? error.message : '读取详情失败'); }
      finally { if (!controller.signal.aborted) setBusy(false); }
    }
    void read();
    return () => controller.abort();
  }, [id, selection?.kind, demo, client, reload]);

  if (!selection) return null;
  const item = selection.kind === 'path' ? data.paths.find(p => p.path_id === selection.item.path_id) || selection.item : selection.kind === 'finding' ? data.findings.find(f => f.finding_id === selection.item.finding_id) || selection.item : data.runs.find(r => r.run_id === selection.item.run_id) || selection.item;
  const title = selection.kind === 'path' ? (item as AuditPath).entry_subject : selection.kind === 'finding' ? (item as Finding).title : shortId((item as Run).run_id);
  async function copy() { try { await navigator.clipboard.writeText(id); setCopied(true); } catch { setError('当前浏览器未允许复制，请手动选择标识。'); } }
  async function changePath(path: AuditPath, verb: 'pause' | 'resume') { setWorking(true); setError(''); try { await onPathAction(path, verb); } catch (error) { setError(error instanceof Error ? error.message : '操作失败'); } finally { setWorking(false); } }
  const path = selection.kind === 'path' ? item as AuditPath : undefined;
  const run = selection.kind === 'run' ? item as Run : undefined;
  const findingItem = selection.kind === 'finding' ? item as Finding : undefined;
  return <Modal open onClose={onClose} title={title} eyebrow={`${demo ? 'DEMO / ' : ''}${selection.kind === 'path' ? 'PATH INSPECTOR' : selection.kind === 'finding' ? 'FINDING & EVIDENCE' : 'AGENT RUN'}`} variant="drawer">
    <div className="inspector-meta"><span className="mono">{shortId(id, 14)}</span><button className="icon-button" onClick={copy} aria-label="复制标识">{copied ? <Check size={13} /> : <Copy size={13} />}</button><span className="push-right"><Badge status={item.status} /></span></div>
    <div className="inspector-tabs">{(path ? [{ id: 'overview', label: '路径详情' }, { id: 'code', label: '代码切片' }, { id: 'events', label: '事件记录' }] : findingItem ? [{ id: 'overview', label: '发现详情' }, { id: 'evidence', label: '关联证据' }] : [{ id: 'overview', label: '运行详情' }, { id: 'events', label: '工具与事件' }]).map(t => <button key={t.id} className={tab === t.id ? 'active' : ''} onClick={() => setTab(t.id)}>{t.label}</button>)}<button className="icon-button push-right" onClick={() => setReload(n => n + 1)} aria-label="重新读取详情"><RefreshCw size={13} className={busy ? 'spin' : ''} /></button></div>
    {error && <div className="error-banner" role="alert">{error}</div>}
    {busy && <div className="loading-line"><Loader2 size={14} className="spin" />正在读取关联记录…</div>}
    {path && tab === 'overview' && <>
      <div className="inspector-section"><div className="inspector-score"><div><span className="eyebrow">SCHEDULING PRIORITY</span><strong>{path.score.priority.toFixed(2)}</strong><small>启发式调度分值，不代表漏洞严重度</small></div><div className="score-breakdown"><span>静态支持<strong>{path.score.support.toFixed(2)}</strong></span><span>效用评分<strong>{path.score.utility.toFixed(2)}</strong></span><span>尝试次数<strong>{path.attempts}</strong></span></div></div></div>
      <div className="inspector-section"><h3><GitPathIcon />调用路径</h3><ol className="step-list"><li><span className="step-number">01</span><div><strong>{path.entry_subject}</strong><small>入口观察</small></div></li>{path.steps.map((step, i) => <li key={`${step.from}-${step.to}-${i}`}><span className="step-number">{String(i + 2).padStart(2, '0')}</span><div><strong>{step.subject || step.to}</strong><small className="mono">{step.file || step.layer}{step.line ? `:${step.line}` : ''}</small></div><span className="step-kind">{step.kind}</span></li>)}</ol></div>
      <div className="inspector-section"><h3><Shield size={15} />证据边界</h3><dl className="detail-list"><div><dt>路径证据</dt><dd>{path.path_status === 'statically_supported' ? '静态调用链支持' : path.path_status === 'candidate' ? '候选可达' : '解析不完整'}</dd></div><div><dt>已观察控制</dt><dd>{path.controls.length ? path.controls.join(' / ') : '未观察到'}</dd></div><div><dt>最大探索深度</dt><dd>{path.budget.max_depth} hops</dd></div><div><dt>工具调用预算</dt><dd>{path.budget.max_tool_calls}</dd></div><div><dt>快照</dt><dd className="mono">{shortId(path.snapshot_id)}</dd></div></dl>{path.limitations.map((limitation, i) => <Hint key={i}>{limitation}</Hint>)}</div>
      <div className="inspector-section"><h3><TriangleAlert size={15} />待解答问题</h3><ul className="question-list">{path.open_questions.length ? path.open_questions.map((question, i) => <li key={i}>{question}</li>) : <li>当前记录未列出额外问题。</li>}</ul></div>
      <div className="inspector-actions">{ACTIVE.has(path.status) ? <button className="button secondary" onClick={() => void changePath(path, 'pause')} disabled={working}>{working ? <Loader2 size={14} className="spin" /> : <Pause size={14} />}暂停路径</button> : ['PAUSED', 'BLOCKED', 'FAILED', 'INTERRUPTED'].includes(path.status) ? <button className="button secondary" onClick={() => void changePath(path, 'resume')} disabled={working}>{working ? <Loader2 size={14} className="spin" /> : <Play size={14} />}重新排队</button> : <span className="muted">{path.status === 'QUEUED' ? '路径正在等待调度器领取。' : '该状态不提供暂停或恢复操作。'}</span>}<button className="text-button" onClick={() => setTab('code')}>查看代码<FileCode2 size={14} /></button></div>
    </>}
    {path && tab === 'code' && <div className="inspector-section"><Hint>{demo ? '以下是固定演示样例源码，未读取当前仓库。' : '代码来自当前不可变快照中的有界切片。'}</Hint>{lines.length ? <CodeBlock lines={lines} file={path.steps.find(s => s.file)?.file || '代码切片'} /> : !busy && <EmptyState title="没有可展示的切片">该路径尚无文件位置，或源码树当前不可用。</EmptyState>}</div>}
    {findingItem && tab === 'overview' && <><div className="inspector-section"><div className={`finding-verdict ${findingItem.status}`}><Shield size={25} /><span><strong>{findingMeaning[findingItem.status]}</strong><small>结论与路径执行状态独立保存。</small></span></div><dl className="detail-list"><div><dt>严重度提示</dt><dd>{findingItem.severity ? (({ high: '高', medium: '中', low: '低', critical: '严重' } as Record<string, string>)[findingItem.severity] || findingItem.severity) : '未提供'}</dd></div><div><dt>支持证据</dt><dd>{findingItem.supporting_evidence.length} 条</dd></div><div><dt>矛盾证据</dt><dd>{findingItem.contradicting_evidence.length} 条</dd></div><div><dt>不确定证据</dt><dd>{findingItem.inconclusive_evidence.length} 条</dd></div></dl><button className="button secondary full-width" onClick={() => onPathById(findingItem.path_id)}>查看关联路径<ArrowRight size={14} /></button></div><div className="inspector-section"><h3>复现与限制</h3><p className="body-copy">{findingItem.reproduce_steps || '尚无复现步骤。只有具备复现证据与步骤的发现才能确认。'}</p>{findingItem.limitations?.map((limitation, i) => <Hint key={i}>{limitation}</Hint>)}</div></>}
    {findingItem && tab === 'evidence' && <div className="inspector-section">{finding ? (['supporting', 'contradicting', 'inconclusive'] as const).map(group => <section className="evidence-group" key={group}><h3><Layers size={15} />{{ supporting: '支持证据', contradicting: '矛盾证据', inconclusive: '不确定证据' }[group]}<span className="mono">{finding.evidence[group]?.length || 0}</span></h3>{finding.evidence[group]?.length ? finding.evidence[group].map(evidence => <article className="evidence-object" key={evidence.evidence_id}><header><Badge status={evidence.kind} label={evidence.kind} /><span>{evidence.redacted ? '已脱敏' : '已存储内容'}</span></header><p>{evidence.content}</p><footer className="mono">{evidence.tool}<span>{evidence.file}{evidence.line ? `:${evidence.line}` : ''}</span></footer></article>) : <p className="muted empty-evidence">该分组没有已记录证据。</p>}</section>) : !busy && <EmptyState title="证据详情不可用">请重新读取，或检查验证层是否已启用。</EmptyState>}</div>}
    {run && tab === 'overview' && <><div className="inspector-section"><h3><Code2 size={15} />运行预算与消耗</h3><div className="run-detail-metrics"><div><strong>{run.tool_calls}</strong><span>工具调用</span></div><div><strong>{compact(run.input_tokens + run.output_tokens)}</strong><span>已报告 tokens</span></div><div><strong>{Math.round(run.elapsed_ms / 1000)}s</strong><span>已用时间</span></div></div><dl className="detail-list"><div><dt>适配器</dt><dd className="mono">{run.runtime}</dd></div><div><dt>开始时间</dt><dd>{clock(run.started_at)}</dd></div><div><dt>最近心跳</dt><dd>{clock(run.heartbeat_at)}</dd></div><div><dt>停止原因</dt><dd>{run.stop_reason || '—'}</dd></div><div><dt>安全目标</dt><dd>{run.task?.security_goal || '未提供'}</dd></div></dl><button className="button secondary full-width" onClick={() => onPathById(run.path_id)}>打开关联审计路径<ArrowRight size={14} /></button></div><Hint>这里只展示任务、工具交换、预算及结构化结果，不展示或存储 Agent 内部推理过程。</Hint></>}
    {(path || run) && tab === 'events' && <div className="inspector-section"><h3><Terminal size={15} />已保存事件<span className="mono">{events.length}</span></h3>{events.length ? <div className="event-log">{[...events].sort((a, b) => a.seq - b.seq).map(event => <article key={event.event_id}><span className="mono">{clock(event.created_at)}</span><div><strong>{eventNames[event.type] || event.type}</strong><p>{event.reason || event.summary || '该事件没有摘要。'}</p></div><span className="mono">#{event.seq}</span></article>)}</div> : !busy && <EmptyState title="没有已载入事件">重新读取可获取当前保存的交换记录。</EmptyState>}</div>}
  </Modal>;
}

function GitPathIcon() { return <ArrowRight size={15} />; }
