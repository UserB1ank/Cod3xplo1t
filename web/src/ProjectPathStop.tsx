import { useEffect, useState } from "react";
import { Loader2, Square } from "lucide-react";
import type { ApiClient } from "./api";
import { Hint, Modal } from "./components";
import {
  pathStopMessage,
  projectPathStopStatus,
  stopProjectPaths,
  type PathStopResult,
} from "./project-path-controls";

export function ProjectPathStop({ api, projectID, disabled, onChanged }: {
  api: ApiClient;
  projectID: string;
  disabled?: boolean;
  onChanged: () => void;
}) {
  const [open, setOpen] = useState(false);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<PathStopResult>();
  const [error, setError] = useState("");
  useEffect(() => {
    if (!open || !result || result.state !== "STOPPING") return;
    const controller = new AbortController();
    const timer = window.setInterval(() => {
      projectPathStopStatus(api, projectID, controller.signal).then(value => {
        if (controller.signal.aborted) return;
        setResult(value);
        setError("");
        if (value.state === "STOPPED") onChanged();
      }).catch(value => {
        if (!controller.signal.aborted) setError(`无法确认停止状态：${value instanceof Error ? value.message : "请求失败"}。可以重新查询或重试。`);
      });
    }, 2000);
    return () => {
      controller.abort();
      window.clearInterval(timer);
    };
  }, [api, projectID, open, result?.state, onChanged]);
  async function stop() {
    setBusy(true);
    setError("");
    try {
      setResult(await stopProjectPaths(api, projectID));
      onChanged();
    } catch (value) {
      setError(`停止结果尚未确认：${value instanceof Error ? value.message : "请求失败"}。已处理的操作会保留，可以重试。`);
    } finally {
      setBusy(false);
    }
  }
  return <>
    <button
      className="button secondary"
      disabled={disabled || busy}
      onClick={() => { setOpen(true); setResult(undefined); setError(""); }}
    >
      <Square size={14} />停止所有路径
    </button>
    <Modal open={open} title="停止当前项目的所有路径" onClose={() => setOpen(false)}>
      <p>关闭现有任务的路径调度，取消关联工作流和未结束的路径。已完成的路径、证据和报告会保留。</p>
      <Hint>取消后的路径不会自动恢复。活动运行需要等待执行器结束；源码导入、独立插件调用和主 Agent 对话由各自面板控制。</Hint>
      {result && <div role="status" className={result.state === "STOPPED" ? "success-message" : "message"}>{pathStopMessage(result)}</div>}
      {!!result?.errors.length && <ul>{result.errors.map((item, i) => <li key={`${item.id}-${i}`}>{item.id}：{item.message}</li>)}</ul>}
      {error && <div role="alert" className="error-message">{error}</div>}
      <div className="form-footer">
        <button className="button secondary" disabled={busy} onClick={() => setOpen(false)}>关闭</button>
        <button
          className="button danger"
          disabled={disabled || busy || result?.state === "STOPPED"}
          onClick={() => void stop()}
        >
          {busy ? <Loader2 className="spin" size={14} /> : <Square size={14} />}
          {busy ? "正在停止…" : result ? "重试停止" : "停止所有路径"}
        </button>
      </div>
    </Modal>
  </>;
}
