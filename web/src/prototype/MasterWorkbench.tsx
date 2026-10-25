import { useEffect, useRef, useState } from 'react';
import { ArrowRight, Bot, ChevronRight, CircleHelp, GitBranch, Layers, Network, Pause, Play, Send, Shield, Square, Users, X } from 'lucide-react';
import { initialSupervisor, makeTask, type Message, type ReviewPath, type Status, type SupervisedProject, type SupervisorState, type WorkTask } from './supervisor-model';
import './master-workbench.css';

type Props = {
  project: SupervisedProject & { name: string; phase: number };
  paths: ReviewPath[];
  update: (fn: (p: Props['project']) => Props['project']) => void;
  onPaths: () => void;
  onGraph: () => void;
  onFindings: () => void;
  initialTaskID?: number;
};
const names: Record<Status, string> = { queued: '待审查', running: '运行中', paused: '已暂停', stopped: '已停止', done: '已完成' };
const pathLabel = (id: number) => `PATH-${String(id + 1).padStart(3, '0')}`;
const roleNames = { human: '你', master: '主 Agent', tool: '工具执行' };
export default function MasterWorkbench({ project, paths, update, onPaths, onGraph, onFindings, initialTaskID }: Props) {
  const [view, setView] = useState<'master' | 'exploration' | number>('master');
  const [inspectedID, setInspectedID] = useState<number | undefined>(initialTaskID);
  const [draft, setDraft] = useState('');
  const [contextTask, setContextTask] = useState<number | null>(null);
  const feed = useRef<HTMLDivElement>(null);
  const following = useRef(true);
  const [filter, setFilter] = useState('all');
  const s = project.supervisor || initialSupervisor();
  const tasks = project.tasks;
  const inspected = tasks.find(t => t.id === inspectedID) || tasks[0];
  const active = typeof view === 'number' ? tasks.find(t => t.id === view) : undefined;
  const [showPolicy, setShowPolicy] = useState(false);
  const ready = project.phase === 4;
  useEffect(() => { following.current = true; }, [view]);
  useEffect(() => { if (feed.current && following.current) feed.current.scrollTop = feed.current.scrollHeight; }, [s.messages.length, active?.events.length, view]);
  const running = tasks.filter(t => t.status === 'running').length;
  const newPaths = paths.filter(p => p.origin === 'agent');
  function change(fn: (s: SupervisorState, tasks: WorkTask[]) => { supervisor: SupervisorState; tasks: WorkTask[] }) {
    update(p => ({ ...p, ...fn(p.supervisor || initialSupervisor(), p.tasks) }));
  }
  function record(text: string, title: string, extra: Partial<SupervisorState> = {}) {
    change((s, tasks) => ({ tasks, supervisor: { ...s, ...extra, messages: [...s.messages, { role: 'master', title, text }] } }));
  }
  function explore(text: string) {
    if (!ready || s.mode !== 'active' || s.exploration?.status === 'running') return;
    record(`审查方向：${text}。将查询入口与未覆盖模块，核对源码引用，最多新增 ${s.maxPaths} 条候选路径。${s.autoReview ? '新路径自动创建审查任务。' : '新增后等待人工选择审查。'}`, '开始探索图谱', { exploration: { status: 'running', step: 0, direction: text } });
    setView('master');
  }
  function schedule() {
    const candidates = paths.map((path, id) => ({ path, id })).filter(({id}) => !tasks.some(t => t.id === id)).slice(0, 3);
    change((s, tasks) => ({ tasks: tasks.length ? tasks : candidates.map(({path,id}) => makeTask(id, path, '主 Agent 选择优先路径')), supervisor: { ...s, scheduling: true, messages: [...s.messages, { role: 'master', title: '启动审查队列', text: `按优先顺序分配待审查任务，同时最多运行 ${s.concurrency} 个审查 Agent。人工暂停的任务不会自动恢复。` }] } }));
  }
  function globalControl(mode: SupervisorState['mode']) {
    change((s, tasks) => ({
      tasks: tasks.map(t => {
        if (mode === 'paused' && t.status === 'running') return { ...t, pausedByMaster: true, status: 'paused', events: [...t.events, '人工暂停全部：主 Agent 已暂停该子任务。'] };
        if (mode === 'active' && t.pausedByMaster && t.status === 'paused') return { ...t, pausedByMaster: false, status: 'running', events: [...t.events, '恢复全局执行：继续未完成的审查。'] };
        if (mode === 'stopped' && ['queued','running','paused'].includes(t.status)) return { ...t, status: 'stopped', pausedByMaster: false, events: [...t.events, '人工停止全部：本次子任务执行结束，历史记录保留。'], directions: t.directions.map(d => ({ ...d, state: d.state === '待接收' ? '未应用' : d.state })) };
        return t;
      }),
      supervisor: { ...s, mode, scheduling: mode === 'stopped' ? false : s.scheduling, exploration: s.exploration ? { ...s.exploration, status: mode === 'paused' && s.exploration.status === 'running' ? 'paused' : mode === 'active' && s.exploration.status === 'paused' ? 'running' : mode === 'stopped' && ['paused','running'].includes(s.exploration.status) ? 'stopped' : s.exploration.status } : null,
        messages: [...s.messages, { role: 'master', title: mode === 'paused' ? '全部执行已暂停' : mode === 'stopped' ? '本轮指挥已停止' : '全局执行已恢复', text: mode === 'paused' ? '图谱探索与运行中的子任务已暂停，不再调度新任务。你仍可补充方向。' : mode === 'stopped' ? '图谱探索和未完成子任务全部终止。日志、路径与证据保留；不会自动恢复。' : '恢复被全局暂停的任务。单独人工暂停的子任务保持暂停。' }] },
    }));
  }
  function childControl(id: number, status: Status) {
    change((s, tasks) => ({ tasks: tasks.map(t => t.id !== id ? t : { ...t, status, pausedByMaster: false, events: [...t.events, status === 'running' ? '人工启动或继续该子任务。' : status === 'paused' ? '人工单独暂停该子任务。' : '人工停止该子任务，保留已有证据。'], directions: status === 'stopped' ? t.directions.map(d => ({ ...d, state: d.state === '待接收' ? '未应用' : d.state })) : t.directions }), supervisor: { ...s, messages: [...s.messages, { role: 'master', title: '子任务控制', text: `${pathLabel(id)} 已${status === 'running' ? '启动' : status === 'paused' ? '暂停' : '停止'}，其余任务保持当前状态。` }] } }));
  }
  function submit() {
    const text = draft.trim();
    if (!text || s.mode === 'stopped') return;
    if (active) {
      change((s, tasks) => ({ tasks: tasks.map(t => t.id === active.id ? { ...t, directions: [...t.directions, { text, state: '待接收' }] } : t), supervisor: { ...s, messages: [...s.messages, { role: 'human', title: `直接对话 ${pathLabel(active.id)}`, text }] } }));
    } else {
      // Free conversation has no frontend intent router. A real model will choose
      // its own response and tool calls; the local prototype only records input.
      change((s, tasks) => ({ tasks, supervisor: { ...s, messages: [
        ...s.messages,
        { role: 'human', title: contextTask === null ? '对话' : `附带上下文：${pathLabel(contextTask)}`, text },
        { role: 'tool', title: '模型待接入 · 原型', text: '对话已记录。此原型没有连接模型，不会根据自由文本执行操作；正式版本由主 Agent 自主选择回应或调用 MCP 工具。' },
      ] } }));
    }
    setDraft('');
    setContextTask(null);
  }
  function playExample() {
    if (!ready || s.mode !== 'active' || s.exploration?.status === 'running') return;
    const direction = '重点检查跨租户访问，先检查上游授权并保留反证。';
    change((s, tasks) => ({ tasks, supervisor: { ...s, auditDirection: direction, messages: [
      ...s.messages,
      { role: 'human', title: '预设演示对话', text: '检查图谱是否遗漏了入口，补充值得审查的路径，并让子 Agent 先核实上游授权。' },
      { role: 'master', title: '预设模型响应 · 非真实推理', text: '我会先查询图谱和关联源码，再根据证据补充候选路径，分配审查任务并传递授权检查要求。下面播放一段固定的工具编排示例，与自由输入的内容无关。' },
    ] } }));
    explore(direction);
    schedule();
    setView('master');
  }
  const displayedMessages: Message[] = view === 'exploration' ? [
    { role: 'master', title: '探索任务', text: s.exploration?.direction || '尚未启动图谱探索。' },
    ...s.messages.filter(m => m.title?.includes('模拟') || m.title?.includes('候选路径') || m.title?.includes('探索完成')),
  ] : active ? active.events.map(text => ({ role: 'tool', title: pathLabel(active.id), text })) : s.messages;
  return <div className="m-workspace">
    <div className="j-heading m-heading"><div><span className="j-eyebrow">AGENT COMMAND CENTER</span><h1>Agent 工作台</h1><p>向主 Agent 表达审计意图，观察它探索、调度与修正审查。</p></div><div className="m-global"><span className={`j-badge ${s.mode === 'active' ? 'green' : ''}`}>{s.mode === 'active' ? (s.exploration?.status === 'running' ? '正在探索图谱' : s.scheduling ? '正在协调审查' : '主 Agent 就绪') : s.mode === 'paused' ? '全局已暂停' : '本轮已停止'}</span><button className="j-btn" onClick={() => setShowPolicy(!showPolicy)}><Layers size={14}/>执行策略</button>{s.mode === 'active' ? <button className="j-btn" onClick={() => globalControl('paused')}><Pause size={13}/>暂停全部</button> : <button className="j-btn primary" onClick={() => globalControl('active')}><Play size={13}/>{s.mode === 'stopped' ? '开始新一轮指挥' : '继续全部'}</button>}<button className="j-btn danger" disabled={s.mode === 'stopped'} onClick={() => globalControl('stopped')}><Square size={12}/>停止全部</button></div></div>
    {showPolicy && <div className="m-policy j-panel"><div><strong>自动执行范围</strong><p>设置应用于后续探索和调度。当前仅模拟执行。</p></div><label><input type="checkbox" checked={s.autoReview} onChange={e => record(e.target.checked ? '后续新发现路径将自动创建审查任务。' : '后续新路径等待人工选择审查。', '执行策略已更新', { autoReview: e.target.checked })}/>自动审查新发现路径</label><label>同时审查上限<select value={s.concurrency} onChange={e => record('后续调度使用新的并发上限，已运行任务不强制中断。','并发策略已更新',{concurrency:Number(e.target.value)})}><option value={1}>1 个 Agent</option><option value={2}>2 个 Agent</option><option value={3}>3 个 Agent</option></select></label><label>每轮新增路径上限<select value={s.maxPaths} onChange={e => record('后续探索使用新的路径数量上限。','探索范围已更新',{maxPaths:Number(e.target.value)})}><option value={1}>1 条</option><option value={2}>2 条</option></select></label><button aria-label="关闭执行策略" onClick={() => setShowPolicy(false)}><X size={17}/></button></div>}
    {!ready && <div className="j-coverage"><CircleHelp size={17}/><p>请先在项目总览完成图谱化分析，再启动图谱探索与路径审查。</p></div>}
    <div className="m-summary"><span><Users size={15}/>{running} 个审查 Agent 运行中</span><span><GitBranch size={15}/>{paths.length} 条路径 <em>+{newPaths.length} Agent 发现</em></span><span>{tasks.filter(t => t.status === 'done').length} / {tasks.length} 个子任务完成</span><button onClick={onPaths}>查看路径清单 <ArrowRight size={13}/></button></div>
    <div className="m-layout j-panel"><aside className="m-task-sidebar"><div className="m-sidebar-title"><h2>指挥与任务</h2><span>{tasks.length + (s.exploration ? 1 : 0)}</span></div><button className={`m-master-tab ${view === 'master' ? 'selected' : ''}`} onClick={() => setView('master')}><span className="m-avatar"><Bot size={20}/></span><span><strong>主 Agent</strong><small>项目指挥 · 统一调度</small></span><ChevronRight size={14}/></button><div className="m-list-heading">探索任务</div><button className={`m-task-tab ${view === 'exploration' ? 'selected' : ''}`} onClick={() => setView('exploration')}><span className="m-task-icon"><Network size={16}/></span><span><strong>图谱与路径探索</strong><small>{s.exploration ? names[s.exploration.status] : '尚未开始'}{s.exploration?.status === 'done' ? ` · ${newPaths.length} 条新增路径` : ''}</small></span></button><div className="m-list-heading"><span>路径审查子任务</span><button onClick={onPaths}>选择路径 +</button></div><select className="m-filter" aria-label="筛选子任务" value={filter} onChange={e => setFilter(e.target.value)}><option value="all">全部状态</option>{Object.entries(names).map(([key,text]) => <option key={key} value={key}>{text}</option>)}</select>{tasks.filter(t => filter === 'all' || t.status === filter).map(t => <button key={t.id} className={`m-task-tab ${view === t.id ? 'selected' : ''}`} onClick={() => { setView(t.id); setInspectedID(t.id); }}><span className={`m-state-dot ${t.status}`}/><span><small>{pathLabel(t.id)}</small><strong>{t.name}</strong><small>{names[t.status]}{paths[t.id]?.origin === 'agent' ? ' · Agent 发现' : ''}</small></span></button>)}{!tasks.length && <p className="m-task-empty">让主 Agent 调度优先路径，或从路径清单选择。</p>}<div className="m-sidebar-foot"><Shield size={15}/><span>你始终可以直接介入子任务</span></div></aside>
      <section className="m-main"><div className="m-conversation-header"><span className="m-avatar">{active ? <Shield size={21}/> : view === 'exploration' ? <Network size={21}/> : <Bot size={21}/>}</span><div><h2>{active ? active.name : view === 'exploration' ? '图谱与路径探索' : '主 Agent'}</h2><p>{active ? `${pathLabel(active.id)} · 路径审查子 Agent` : view === 'exploration' ? '发现遗漏入口与新的候选路径' : '负责项目审计规划、路径探索与子任务协调'}</p></div>{view !== 'master' && <button onClick={() => setView('master')}>返回主 Agent <ArrowRight size={13}/></button>}</div>
      {active && <div className="m-child-controls"><span className="j-badge">{names[active.status]}</span><div>{['queued','paused'].includes(active.status) && <button className="j-btn primary" disabled={s.mode !== 'active' || running >= s.concurrency} onClick={() => childControl(active.id,'running')}><Play size={12}/>{active.status === 'paused' ? '继续' : '启动'}</button>}{active.status === 'running' && <button className="j-btn" onClick={() => childControl(active.id,'paused')}><Pause size={12}/>暂停</button>}{!['stopped','done'].includes(active.status) && <button className="j-btn danger" onClick={() => childControl(active.id,'stopped')}><Square size={12}/>停止子任务</button>}</div></div>}
      <div className="m-messages" ref={feed} onScroll={() => { const e = feed.current; if (e) following.current = e.scrollHeight - e.scrollTop - e.clientHeight < 70; }} aria-live="polite">{displayedMessages.map((m,i) => <article key={i} className={`m-message ${m.role}`}><span className="m-message-avatar">{m.role === 'human' ? '你' : m.role === 'tool' ? <Network size={14}/> : <Bot size={16}/>}</span><div><div className="m-message-meta"><strong>{roleNames[m.role]}</strong><span>{m.title || (m.role === 'human' ? '人工指令' : '审计协调')}</span></div><p>{m.text}</p></div></article>)}
      {view === 'master' && <div className="m-demo-tools"><div><Network size={17}/><span><strong>模型与工具编排预览</strong><small>自由对话尚未接入模型。可播放固定示例，查看工具调用如何改变项目。</small></span></div><button className="j-btn" disabled={!ready || s.mode !== 'active' || s.exploration?.status === 'running' || s.scheduling} onClick={playExample}><Play size={13}/>播放工具调用示例</button></div>}
      {s.exploration?.status === 'running' && !active && <div className="m-exploring"><span/>正在探索图谱 · 步骤 {s.exploration.step + 1} / 3</div>}
      {s.mode !== 'active' && <div className="m-paused-note">{s.mode === 'paused' ? '全局已暂停，允许补充方向，继续后再应用。' : '本轮已停止。开始新一轮指挥后可探索新路径；已停止子任务不会自动重启。'}</div>}
      </div>
      <form className="m-composer" onSubmit={e => { e.preventDefault(); submit(); }}>
        <div className="m-composer-label"><label htmlFor="m-message">{active ? '与子 Agent 对话' : '与主 Agent 对话'}</label><span className="m-model-status">{active ? '子任务上下文已附带' : '模型待接入'}</span></div>
        {!active && contextTask !== null && <div className="m-context-chip"><span>附带上下文：{pathLabel(contextTask)}</span><button type="button" aria-label="移除任务上下文" onClick={() => setContextTask(null)}><X size={12}/></button></div>}
        <textarea id="m-message" value={draft} onChange={e => setDraft(e.target.value)} disabled={s.mode === 'stopped' || !!active && ['done','stopped'].includes(active.status)} placeholder={active ? '直接补充背景、追问证据或调整审查要求…' : '描述你想了解的问题、审计目标或希望调整的方向…'}/>
        <div><small>{active ? '对话随子任务传递，在下一执行边界回执。' : '直接对话，无需选择类型；正式版本由模型自主选择工具。'}</small><button type="submit" className="j-btn primary" disabled={!draft.trim() || s.mode === 'stopped' || !!active && ['done','stopped'].includes(active.status)}><Send size={13}/>发送</button></div>
      </form></section>
      <aside className="m-context"><div className="m-context-heading"><h3>项目上下文</h3><Shield size={15}/></div><div className="m-context-section"><small>当前审计范围</small><strong>{project.name}</strong><p>已导入源码 · {ready ? '图谱化分析已完成' : '图谱化分析未完成'}</p><button onClick={onGraph}>查看代码图谱 <ArrowRight size={12}/></button></div><div className="m-context-section"><h3>本轮审计方向</h3><p>{s.auditDirection || '尚未设置。可向主 Agent 补充关注范围与业务背景。'}</p></div><div className="m-context-section"><h3>执行边界</h3><dl><dt>并发审查</dt><dd>{running} / {s.concurrency}</dd><dt>单轮新增路径</dt><dd>最多 {s.maxPaths} 条</dd><dt>新路径审查</dt><dd>{s.autoReview ? '自动调度' : '人工选择'}</dd></dl><button onClick={() => setShowPolicy(true)}>调整执行策略 <ChevronRight size={12}/></button></div><div className="m-context-section"><h3>Agent 工具能力</h3><p>由后端 MCP 提供，模型按对话与上下文选择调用。</p><details><summary>查看可用工具示例</summary><code>graph.query · 查询图谱</code><code>code.read · 阅读源码</code><code>paths.propose · 提交路径</code><code>tasks.dispatch · 调度任务</code><code>tasks.message · 发送子任务消息</code><code>tasks.control · 控制任务</code><code>findings.read · 查看证据</code></details></div><div className="m-context-section"><h3>选中子任务</h3>{tasks.length ? <><select aria-label="选择要调整的子任务" value={inspected?.id ?? ''} onChange={e => setInspectedID(Number(e.target.value))}>{tasks.map(t => <option key={t.id} value={t.id}>{pathLabel(t.id)} · {t.name}</option>)}</select><strong>{inspected?.name}</strong><small>{inspected && names[inspected.status]}</small>{inspected && <><code>{paths[inspected.id].entry}</code><button onClick={() => setView(inspected.id)}>进入子任务 <ArrowRight size={12}/></button><button disabled={['done','stopped'].includes(inspected.status)} onClick={() => { setView('master'); setContextTask(inspected.id); setDraft(`关于「${inspected.name}」：`); }}>引用到主 Agent 对话</button></>}</> : <p>尚无子任务，先调度优先路径或选择路径。</p>}</div><div className="m-context-section"><h3>人工与主 Agent 指令</h3>{(active || inspected)?.directions.length ? (active || inspected)!.directions.map((d,i) => <div className="m-instruction" key={i}><span className={`j-badge ${d.state === '已应用' ? 'green' : ''}`}>{d.state}</span><p>{d.text}</p></div>) : <p>指令接收与应用情况在这里追踪。</p>}</div>{newPaths.length > 0 && <div className="m-context-section m-new-paths"><h3>Agent 新发现 {newPaths.length} 条路径</h3>{newPaths.map(p => <p key={p.entry}>{p.name}</p>)}<button onClick={onPaths}>查看依据并选择审查 <ArrowRight size={12}/></button></div>}<button className="m-results-link" onClick={onFindings}>查看发现与证据 <ArrowRight size={13}/></button><p className="m-footnote">所有路径与执行均为原型示例。主 Agent 的推测不会自动成为代码事实或已确认漏洞。</p></aside>
    </div>
  </div>;
}
