export type Status = 'queued' | 'running' | 'paused' | 'stopped' | 'done';
export type WorkTask = {
  id: number;
  name: string;
  status: Status;
  step: number;
  events: string[];
  directions: { text: string; state: '待接收' | '已应用' | '未应用' }[];
  pausedByMaster?: boolean;
};
export type ReviewPath = {
  name: string; entry: string; sink: string; reason: string; rank: string;
  file: string; line: number; origin?: 'agent';
};
export type Message = { role: 'human' | 'master' | 'tool'; text: string; title?: string };
export type SupervisorState = {
  mode: 'active' | 'paused' | 'stopped';
  messages: Message[];
  exploration: { status: Status; step: number; direction: string } | null;
  autoReview: boolean;
  scheduling: boolean;
  concurrency: number;
  maxPaths: number;
  auditDirection: string;
};
export type SupervisedProject = {
  tasks: WorkTask[];
  extraPaths?: ReviewPath[];
  supervisor?: SupervisorState;
};
export const initialSupervisor = (): SupervisorState => ({
  mode: 'active', exploration: null, autoReview: false, scheduling: false,
  concurrency: 2, maxPaths: 2, auditDirection: '',
  messages: [{ role: 'master', title: '主 Agent 已就绪', text: '直接告诉我你的审计目标或问题。正式版本中，我会根据对话和项目上下文，自主查询图谱、阅读源码、协调子 Agent 或回答问题。当前原型未连接模型，可播放固定工具调用示例。' }],
});
export const discoveredExamples: ReviewPath[] = [
  { name: '订单批量下载的租户边界', entry: 'POST /api/orders/batch-download', sink: 'repository.ExportBatch', reason: 'Agent 探索发现另一入口复用导出服务，需独立核实租户约束。', rank: '优先', file: 'internal/orders/batch.go', line: 58, origin: 'agent' },
  { name: '异步导出回调的授权传递', entry: 'Queue / export.completed', sink: 'storage.ReadObject', reason: 'Agent 从共享模块向上追踪到消息入口，授权上下文传递尚未证明。', rank: '探索', file: 'internal/workers/export.go', line: 92, origin: 'agent' },
];
export function makeTask(id: number, path: ReviewPath, source = '人工选择路径'): WorkTask {
  return { id, name: path.name, status: 'queued', step: 0, directions: [], events: [`${source}，已创建独立审查任务，等待调度。`] };
}
export function advanceSupervisor<P extends SupervisedProject>(project: P, basePathCount: number): P {
  if (!project.supervisor || project.supervisor.mode !== 'active') return project;
  let s = project.supervisor;
  let tasks = project.tasks;
  let extraPaths = project.extraPaths || [];
  if (s.exploration?.status === 'running') {
    const step = s.exploration.step + 1;
    if (step === 1) {
      s = { ...s, exploration: { ...s.exploration, step }, messages: [...s.messages, { role: 'tool', title: 'graph.query · 模拟', text: '已查看程序入口和未覆盖模块，正在反向检索复用敏感操作的调用方。' }] };
    } else if (step === 2) {
      s = { ...s, exploration: { ...s.exploration, step }, messages: [...s.messages, { role: 'tool', title: 'code.read · 模拟', text: '已读取批量导出与异步处理的示例源码。正在检查路径引用并去重，未证明的授权关系保留为未知。' }] };
    } else {
      const additions = discoveredExamples.filter(path => !extraPaths.some(old => old.entry === path.entry)).slice(0, s.maxPaths);
      const start = basePathCount + extraPaths.length;
      extraPaths = [...extraPaths, ...additions];
      if (s.autoReview) tasks = [...tasks, ...additions.map((path, i) => makeTask(start + i, path, '主 Agent 自动分配新发现路径'))];
      s = { ...s, exploration: { ...s.exploration, step, status: 'done' }, scheduling: s.scheduling || s.autoReview,
        messages: [...s.messages, { role: 'master', title: additions.length ? `新增 ${additions.length} 条候选路径` : '探索完成 · 未新增重复路径', text: additions.length ? `${additions.map(path => path.name).join('；')}。来源和依据已写入项目路径清单。${s.autoReview ? '已按授权创建审查子任务，并按并发上限调度。' : '等待你选择是否加入审查。'}` : '当前示例探索范围已覆盖，已有路径未重复添加。' }] };
    }
  }
  if (s.scheduling) {
    let slots = s.concurrency - tasks.filter(t => t.status === 'running').length;
    const started: WorkTask[] = [];
    tasks = tasks.map(t => {
      if (t.status !== 'queued' || slots <= 0) return t;
      slots--;
      started.push(t);
      return { ...t, status: 'running', directions: s.auditDirection && !t.directions.some(d => d.text === `项目审计方向：${s.auditDirection}`) ? [...t.directions, { text: `项目审计方向：${s.auditDirection}`, state: '待接收' as const }] : t.directions, events: [...t.events, '主 Agent 调度：开始审查，保留反证检查与范围限制。'] };
    });
    if (started.length) s = { ...s, messages: [...s.messages, { role: 'master', title: '调度审查子 Agent', text: started.map(t => `PATH-${String(t.id + 1).padStart(3, '0')} · ${t.name}`).join('；') }] };
    if (!tasks.some(t => t.status === 'queued' || t.status === 'running')) s = { ...s, scheduling: false, messages: [...s.messages, { role: 'master', title: '审查队列已结束', text: '当前队列已处理完毕。候选与证据可在发现页查看，暂停或停止的任务保留原状态。' }] };
  }
  return { ...project, tasks, extraPaths, supervisor: s };
}
