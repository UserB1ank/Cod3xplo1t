import type { ReviewBatchView } from "./types.ts";

export function reviewBatchStateLabel(state: ReviewBatchView["batch"]["state"]) {
  return {
    RUNNING: "运行中",
    PAUSED: "已暂停",
    CANCELLING: "正在停止",
    CANCELLED: "已取消",
    COMPLETED: "已完成",
    FAILED: "失败",
  }[state] || state;
}

export function reviewBatchProgressLine(progress: ReviewBatchView["progress"]) {
  return `进行中 ${progress.active} · 等待 ${progress.queued} · 受阻 ${progress.blocked} · 暂停 ${progress.paused} · 失败 ${progress.failed} · 取消 ${progress.cancelled}`;
}
