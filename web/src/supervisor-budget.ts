import type { AuditBudget, SupervisorCheckpoint, SupervisorRun } from "./types.ts";

export function supervisorBudgetAvailable(budget: AuditBudget) {
  return Math.max(0, budget.limit_tokens - budget.used_tokens - budget.reserved_tokens);
}

export function supervisorBudgetSummary(budget: AuditBudget) {
  return `已用 ${budget.used_tokens} · 预留 ${budget.reserved_tokens} · 剩余 ${supervisorBudgetAvailable(budget)} · 上限 ${budget.limit_tokens}`;
}

export function supervisorBudgetRecovery(run?: SupervisorRun) {
  if (!run) return "";
  if (run.stop_reason === "global_budget") {
    return "审计级 token 预算已耗尽；审批追加预算后可从当前检查点继续新的 Run Segment。";
  }
  if (run.status === "PAUSED" || run.status === "PARTIAL") {
    return "当前 Segment 已保留检查点，可继续；累计 token 预算不会重置。";
  }
  return "";
}

export function supervisorCheckpointSummary(checkpoint: SupervisorCheckpoint) {
  const budget = checkpoint.budget;
  return [
    `${checkpoint.completed.length} 项已完成`,
    `${checkpoint.pending.length} 项待办`,
    budget?.remaining_tokens === undefined ? "" : `剩余 ${budget.remaining_tokens} tokens`,
    budget?.remaining_rounds === undefined ? "" : `剩余 ${budget.remaining_rounds} 轮`,
    checkpoint.last_error?.code ? `最后错误 ${checkpoint.last_error.code}` : "",
  ].filter(Boolean).join(" · ");
}
