import { useEffect, useId, useRef, useState, type ReactNode } from 'react';
import { ArrowRight, Box, ChevronRight, CircleDashed, Code2, Database, FileCode2, Focus, Info, Minus, Plus, Shield, X } from 'lucide-react';
import type { AuditPath, FindingStatus } from './types';
import { ACTIVE, ATTENTION, findingStatus, pathStatus, shortId } from './domain';

export function Badge({ status, label }: { status: string; label?: string }) {
  const tone = status === 'confirmed' ? 'danger' : status === 'candidate' || status === 'inconclusive' || status === 'blocked' || ATTENTION.has(status) ? 'warning' : ACTIVE.has(status) || status === 'RUNNING' ? 'active' : 'neutral';
  return <span className={`badge ${tone}`}><span className="status-dot" />{label || findingStatus[status as FindingStatus] || pathStatus[status] || ({ RUNNING: '运行中', SUCCEEDED: '已完成', TIMED_OUT: '已超时', CREATED: '待启动', READY: '就绪' } as Record<string, string>)[status] || status}</span>;
}

export function Panel({ title, eyebrow, action, children, className = '' }: { title?: ReactNode; eyebrow?: string; action?: ReactNode; children: ReactNode; className?: string }) {
  return <section className={`panel ${className}`}>
    {(title || action) && <div className="panel-heading"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2>{title}</h2></div>{action}</div>}
    {children}
  </section>;
}

export function EmptyState({ title, children, action }: { title: string; children?: ReactNode; action?: ReactNode }) {
  return <div className="empty-state"><CircleDashed size={30} strokeWidth={1.3} /><h3>{title}</h3>{children && <p>{children}</p>}{action}</div>;
}

export function Hint({ children, className = '' }: { children: ReactNode; className?: string }) {
  return <div className={`hint ${className}`}><Info size={14} /><span>{children}</span></div>;
}

export function Modal({ open, onClose, title, eyebrow, children, wide = false, variant = 'default' }: { open: boolean; onClose: () => void; title: string; eyebrow?: string; children: ReactNode; wide?: boolean; variant?: 'default' | 'drawer' }) {
  const ref = useRef<HTMLDialogElement>(null);
  const id = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (open && dialog && !dialog.open) dialog.showModal();
    if (!open && dialog?.open) dialog.close();
  }, [open]);
  return <dialog ref={ref} className={`modal ${wide ? 'wide' : ''} ${variant === 'drawer' ? 'detail-modal' : ''}`} aria-labelledby={id} onCancel={onClose} onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
    <div className="modal-inner"><div className="modal-heading"><div>{eyebrow && <span className="eyebrow">{eyebrow}</span>}<h2 id={id}>{title}</h2></div><button className="icon-button" onClick={onClose} aria-label="关闭对话框"><X size={18} /></button></div>{children}</div>
  </dialog>;
}

export function PathTable({ paths, onSelect, compact = false, selected }: { paths: AuditPath[]; onSelect: (path: AuditPath) => void; compact?: boolean; selected?: string }) {
  return paths.length === 0 ? <EmptyState title="没有匹配的路径">调整筛选条件，或先为当前快照创建审计。</EmptyState> : <div className="table-scroll"><table className={`path-table ${compact ? 'compact' : ''}`}>
    <thead><tr><th className="row-number">#</th><th>入口 / 敏感操作</th>{!compact && <th>证据等级</th>}<th title="启发式调度分值，不代表漏洞严重性">优先级</th><th>状态</th><th aria-label="详情" /></tr></thead>
    <tbody>{paths.map((path, i) => {
      const method = path.entry_subject.match(/^(GET|POST|PUT|PATCH|DELETE)\s/)?.[1];
      return <tr key={path.path_id} className={selected === path.path_id ? 'selected' : ''} onClick={() => onSelect(path)}>
        <td className="row-number">{String(i + 1).padStart(2, '0')}</td>
        <td><button className="path-link" onClick={e => { e.stopPropagation(); onSelect(path); }}><span className="entry-line">{method && <span className={`method ${method === 'GET' ? '' : 'write'}`}>{method}</span>}<span>{method ? path.entry_subject.slice(method.length + 1) : path.entry_subject || shortId(path.path_id)}</span></span><span className="sink-line"><ArrowRight size={12} />{path.target_subject || path.target_kind}<span className="muted-dot">·</span>{path.path_kind.replaceAll('_', ' ')}</span></button></td>
        {!compact && <td><span className={`evidence-class ${path.path_status === 'unresolved' ? 'uncertain' : ''}`}>{path.path_status === 'statically_supported' ? '静态支持' : path.path_status === 'candidate' ? '候选可达' : '待解析'}</span></td>}
        <td><span className={`priority ${path.score.priority >= 85 ? 'high' : ''}`}><span>{path.score.priority.toFixed(1)}</span><i><b style={{ width: `${Math.max(0, Math.min(100, path.score.priority))}%` }} /></i></span></td>
        <td><Badge status={path.status} /></td><td><ChevronRight size={15} className="row-arrow" /></td>
      </tr>;
    })}</tbody>
  </table></div>;
}

export function PathGraph({ path, expanded = false, mode = 'surface', onOpen }: { path?: AuditPath; expanded?: boolean; mode?: 'surface' | 'graph'; onOpen?: () => void }) {
  const [focus, setFocus] = useState(0);
  const [zoom, setZoom] = useState(1);
  useEffect(() => { setFocus(0); setZoom(1); }, [path?.path_id]);
  if (!path) return <EmptyState title="当前快照还没有可展示的路径">构建源码图谱与攻击面后，生成审计路径以查看调用关系。</EmptyState>;
  const nodes = [
    { type: 'ENTRY POINT', label: path.entry_subject || '未知入口', detail: path.steps[0]?.file || '入口证据', icon: Box },
    { type: 'HANDLER', label: path.steps[0]?.subject || '未解析 handler', detail: `L${path.steps[0]?.line || '—'} · ${path.steps[0]?.kind || '待解析'}`, icon: Code2 },
    { type: mode === 'surface' ? 'BUSINESS LOGIC' : 'CALL SITE', label: path.steps[1]?.subject || '未解析调用', detail: path.steps[1]?.file || '调用证据', icon: Shield },
    { type: 'SENSITIVE OPERATION', label: path.target_subject || '未知敏感操作', detail: path.steps.at(-1)?.file || path.target_kind, icon: path.target_kind.includes('sql') ? Database : FileCode2 },
  ];
  return <div className={`path-graph ${expanded ? 'expanded' : ''}`}>
    <div className="graph-toolbar"><span className="mono"><span className="mini-cross">+</span> {shortId(path.path_id, 8)}</span><div><button className="icon-button" aria-label="缩小图谱" onClick={() => setZoom(z => Math.max(0.85, z - 0.1))}><Minus size={14} /></button><span className="zoom-label">{Math.round(zoom * 100)}%</span><button className="icon-button" aria-label="放大图谱" onClick={() => setZoom(z => Math.min(1.4, z + 0.1))}><Plus size={14} /></button><button className="icon-button" aria-label="重置图谱缩放" onClick={() => setZoom(1)}><Focus size={14} /></button></div></div>
    <div className="graph-scroll"><div className="graph-stage" style={{ minWidth: `${640 * zoom}px` }}>
      <div className="boundary-label"><span />不可信输入<span className="boundary-rule" />应用信任边界<span /></div>
      <div className="graph-nodes">{nodes.map((node, i) => <div className="graph-node-slot" key={node.type}>
        <span className="graph-step">0{i + 1} / <span>{node.type}</span></span>
        <button className={`graph-node ${focus === i ? 'focused' : ''} ${i === 3 ? 'sink-node' : ''}`} onClick={() => setFocus(i)} aria-pressed={focus === i}>
          <node.icon size={19} strokeWidth={1.5} /><strong>{node.label}</strong><span title={node.detail}>{node.detail}</span>
        </button>
        {i < 3 && <span className={`graph-connector ${path.path_status === 'unresolved' ? 'unresolved' : ''}`}><ArrowRight size={18} strokeWidth={1.3} /></span>}
      </div>)}</div>
      <div className="graph-path-caption"><span className="dashed-mark" />调用可达路径 · {path.steps.length} 个已保存步骤<span className="graph-caption-end">{path.scg_refs.length} SCG REFS</span></div>
      {mode === 'surface' && <div className="control-observation"><Shield size={12} />{path.controls.length ? `已观察到 ${path.controls.length} 个控制` : '未观察到安全控制'}<span>顺序与有效性未评估</span></div>}
    </div></div>
    <div className="graph-footer"><span><span className="legend-dot" />{nodes[focus].type}<span className="muted-dot">·</span>{nodes[focus].label}</span>{onOpen && <button className="text-button" onClick={onOpen}>查看路径<ArrowRight size={13} /></button>}</div>
  </div>;
}

export function CodeBlock({ lines, file }: { lines: { line: number; content: string; highlight: boolean }[]; file: string }) {
  return <div className="code-block"><div className="code-header"><FileCode2 size={14} /><span>{file}</span><span className="language-label">GO</span></div><pre>{lines.map(line => <div className={line.highlight ? 'code-line highlighted' : 'code-line'} key={line.line}><span className="line-number">{line.line}</span><code>{line.content.split(/("[^"\n]*"|\b(?:func|return|if|defer|var|const|nil|package)\b)/g).map((part, i) => <span key={i} className={part.startsWith('"') ? 'code-string' : /^(func|return|if|defer|var|const|nil|package)$/.test(part) ? 'code-keyword' : ''}>{part}</span>)}</code></div>)}</pre></div>;
}
