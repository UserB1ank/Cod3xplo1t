import { useEffect, useRef, useState, type FormEvent } from 'react';
import type { ApiClient } from './api';
import { EmptyState, Failure, Hint, Panel } from './components';
import { knowledgeBase, readInvestigation, type KnowledgePage, type KnowledgeRecord } from './investigation';
import './investigation.css';

const relationLabel = { supports: '支持', contradicts: '反驳', context: '上下文' };
const kindLabel = { claim: '◇ 猜想', observation: '◇ 重复观察', question: '？待解问题', evidence: '▤ 证据' };
const message = (error: unknown) => error instanceof Error ? error.message : '调查知识暂时不可用';

export function InvestigationKnowledge({ api, projectID, snapshotID, canWrite }: { api: ApiClient; projectID: string; snapshotID: string; canWrite: boolean }) {
  const [page, setPage] = useState<KnowledgePage>();
  const [detail, setDetail] = useState<KnowledgePage>();
  const [selection, setSelection] = useState('');
  const [cursor, setCursor] = useState(0);
  const [pin, setPin] = useState(0);
  const [reload, setReload] = useState(0);
  const [error, setError] = useState('');
  const [busy, setBusy] = useState(false);
  const [loading, setLoading] = useState(true);
  const request = useRef<{ body: string; key: string }>();
  const [statement, setStatement] = useState('');
  const [category, setCategory] = useState('vulnerability');
  const [conditions, setConditions] = useState('');
  const [file, setFile] = useState('');
  const [start, setStart] = useState(1);
  const [end, setEnd] = useState(1);
  const [note, setNote] = useState('');
  const [noteKind, setNoteKind] = useState('question');
  const [referenceKind, setReferenceKind] = useState('source');
  const [referenceID, setReferenceID] = useState('');
  const [relation, setRelation] = useState('context');
  const base = knowledgeBase(projectID);

  useEffect(() => {
    const controller = new AbortController();
    setLoading(true);
    setError('');
    setDetail(undefined);
    readInvestigation(api, projectID, snapshotID, '', pin, cursor, controller.signal).then(value => {
      if (controller.signal.aborted) return;
      setPage(value);
      setPin(value.revision);
    }).catch(e => { if (!controller.signal.aborted) { setPage(undefined); setError(message(e)); } })
      .finally(() => { if (!controller.signal.aborted) setLoading(false); });
    return () => controller.abort();
  }, [api, projectID, snapshotID, pin, cursor, reload]);

  useEffect(() => {
    if (!selection || !page || loading) return;
    const controller = new AbortController();
    readInvestigation(api, projectID, snapshotID, selection, page.revision, 0, controller.signal).then(value => {
      if (!controller.signal.aborted) setDetail(value);
    }).catch(e => { if (!controller.signal.aborted) setError(message(e)); });
    return () => controller.abort();
  }, [api, projectID, snapshotID, selection, page, loading]);

  function refresh() { setPin(0); setCursor(0); setReload(n => n + 1); }
  async function write(path: string, body: Record<string, unknown>) {
    const encoded = JSON.stringify({ path, body });
    if (request.current?.body !== encoded) request.current = { body: encoded, key: crypto.randomUUID() };
    const result = await api.post<{ record: KnowledgeRecord }>(path, { ...body, request_key: request.current.key });
    request.current = undefined;
    return result.record;
  }
  async function create(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const record = await write(base, { snapshot_id: snapshotID, category, statement, conditions, target: { file, start_line: start, end_line: end } });
      setSelection(record.claim_id); setStatement(''); refresh();
    } catch (e) { setError(message(e)); } finally { setBusy(false); }
  }
  async function append(event: FormEvent) {
    event.preventDefault(); setBusy(true); setError('');
    try {
      const body: Record<string, unknown> = { snapshot_id: snapshotID, statement: note };
      if (noteKind === 'evidence') {
        body.relation = relation;
        body.reference = referenceKind === 'source' ? { kind: 'source', target: { file, start_line: start, end_line: end } } : { kind: referenceKind, id: referenceID };
      }
      await write(`${base}/${encodeURIComponent(selection)}/${noteKind === 'question' ? 'questions' : 'evidence'}`, body);
      setNote(''); refresh();
    } catch (e) { setError(message(e)); } finally { setBusy(false); }
  }
  async function moreDetail() {
    if (!detail) return;
    setBusy(true); setError('');
    try {
      const next = await readInvestigation(api, projectID, snapshotID, selection, detail.revision, detail.next_cursor);
      setDetail({ ...next, records: [...detail.records, ...next.records] });
    } catch (e) { setError(message(e)); } finally { setBusy(false); }
  }
  const sourceFields = <div className="knowledge-toolbar">
    <label>源码相对路径 <input required value={file} maxLength={1024} placeholder="src/handler.go" onChange={e => setFile(e.target.value)} /></label>
    <label>起始行 <input required type="number" min={1} value={start} onChange={e => setStart(Number(e.target.value))} /></label>
    <label>结束行 <input required type="number" min={start} max={start + 199} value={end} onChange={e => setEnd(Number(e.target.value))} /></label>
  </div>;

  return <Panel title="调查知识" className="investigation-knowledge" action={<button className="button" onClick={refresh} disabled={busy || loading}>刷新知识</button>}><div className="investigation-body">
    <Hint>猜想、待解问题和证据在这里积累。支持与反驳均保留；漏洞确认仍以验证裁定为准。</Hint>
    {error && <Failure message={error} />}
    {loading ? <p role="status">正在读取调查知识…</p> : page && <>
      <p className="muted">知识账本 {page.revision}{page.head_revision > page.revision ? ` · 有更新（${page.head_revision}），刷新后查看` : ''}</p>
      {page.records.length === 0 ? <EmptyState title="尚无猜想">可以由项目助手调查后登记，也可手动提出具体猜想。</EmptyState> : <div className="table-scroll"><table className="standard-table">
        <thead><tr><th>类型</th><th>判断与条件</th><th>位置</th><th>来源</th></tr></thead>
        <tbody>{page.records.map(row => <tr key={row.record_id}>
          <td>◇ 猜想</td><td><button className="text-button" disabled={busy} aria-pressed={selection === row.claim_id} onClick={() => { setSelection(row.claim_id); if (selection !== row.claim_id) setDetail(undefined); if (row.target) { setFile(row.target.file); setStart(row.target.start_line); setEnd(row.target.end_line); } }}>{row.statement}</button>{row.conditions && <p className="muted">{row.conditions}</p>}</td>
          <td>{row.target?.file}:{row.target?.start_line}–{row.target?.end_line}</td><td>{row.actor}<br /><small>{row.run_id || '人工提交'}</small></td>
        </tr>)}</tbody>
      </table></div>}
      <div className="knowledge-toolbar">
        <button className="button" disabled={cursor === 0 || busy} onClick={() => { setSelection(''); setCursor(0); }}>首页</button>
        <button className="button" disabled={!page.has_more || busy} onClick={() => { setSelection(''); setCursor(page.next_cursor); }}>下一页</button>
      </div>
    </>}
    {selection && detail && <section aria-label="猜想详情">
      <h3>判断、问题与证据</h3>
      {detail.records.map(row => <article key={row.record_id} className="investigation-record">
        <div><strong>{kindLabel[row.kind]}{row.relation ? ` · ${relationLabel[row.relation]}` : ''}</strong>
          <p>{row.statement}</p>{row.conditions && <p>适用条件：{row.conditions}</p>}
          {row.reference && <div><p>{row.reference.kind === 'source' ? `${row.reference.target?.file}:${row.reference.target?.start_line}–${row.reference.target?.end_line}` : `${row.reference.kind} · ${row.reference.id}`}</p>
            {row.reference.content && <pre style={{ whiteSpace: 'pre-wrap', overflowWrap: 'anywhere' }}>{row.reference.content}</pre>}
            {row.reference.sha256 && <p className="mono">SHA-256 {row.reference.sha256}</p>}
            {row.reference.redacted && <p>内容已脱敏：{row.reference.redaction_notes}</p>}
          </div>}
          <small>{row.actor} · {row.created_at} · 账本 {row.revision}{row.run_id ? ` · ${row.run_id}` : ''}</small>
        </div>
      </article>)}
      {detail.has_more && <button className="button" disabled={busy} onClick={moreDetail}>继续读取问题与证据</button>}
      {canWrite && <form onSubmit={append}>
        <label>追加内容 <select value={noteKind} onChange={e => setNoteKind(e.target.value)}><option value="question">待解问题</option><option value="evidence">证据引用</option></select></label>
        <label>问题或证据关联理由 <textarea required maxLength={4000} value={note} onChange={e => setNote(e.target.value)} /></label>
        {noteKind === 'evidence' && <>
          <label>关系 <select value={relation} onChange={e => setRelation(e.target.value)}><option value="context">上下文</option><option value="supports">支持</option><option value="contradicts">反驳</option></select></label>
          <label>证据来源 <select value={referenceKind} onChange={e => setReferenceKind(e.target.value)}><option value="source">源码片段</option><option value="evidence">已有证据</option><option value="artifact">已有产物</option></select></label>
          {referenceKind === 'source' ? sourceFields : <label>记录 ID <input required value={referenceID} onChange={e => setReferenceID(e.target.value)} /></label>}
        </>}
        <button className="button primary" disabled={busy}>保存{noteKind === 'question' ? '问题' : '证据'}</button>
      </form>}
    </section>}
    {canWrite && <details><summary>提出猜想</summary><form onSubmit={create}>
      <label>类型 <select value={category} onChange={e => setCategory(e.target.value)}><option value="vulnerability">潜在漏洞</option><option value="control">安全控制</option><option value="business_rule">业务规则</option></select></label>
      <label>具体判断 <textarea required maxLength={4000} value={statement} onChange={e => setStatement(e.target.value)} /></label>
      <label>适用条件 <textarea maxLength={2000} value={conditions} onChange={e => setConditions(e.target.value)} /></label>
      {sourceFields}<button className="button primary" disabled={busy}>保存猜想</button>
    </form></details>}
  </div></Panel>;
}
