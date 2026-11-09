import test from "node:test";
import assert from "node:assert/strict";
import { supervisorBudgetAvailable, supervisorBudgetRecovery, supervisorBudgetSummary, supervisorCheckpointSummary } from "../src/supervisor-budget.ts";

test("supervisor budget keeps used, reserved and available explicit", () => {
  const budget = { audit_id: "audit-1", limit_tokens: 60000, used_tokens: 12000, reserved_tokens: 8000, version: 3 };
  assert.equal(supervisorBudgetAvailable(budget), 40000);
  assert.equal(supervisorBudgetSummary(budget), "已用 12000 · 预留 8000 · 剩余 40000 · 上限 60000");
  assert.match(supervisorBudgetRecovery({ status: "PAUSED", stop_reason: "global_budget" } as never), /审批追加预算/);
});

test("structured checkpoint exposes completed, pending and remaining budget", () => {
  assert.equal(supervisorCheckpointSummary({
    schema_version: 2,
    user_message_id: "sm-1",
    stop_reason: "global_budget",
    model_turns: 72,
    tool_calls: 120,
    input_tokens: 1000,
    output_tokens: 200,
    completed: ["claim:claim-1", "tool_ok:repo_map:call-1"],
    pending: ["complete_user_request:sm-1"],
    claim_ids: ["claim-1"],
    evidence_ids: ["evidence-1"],
    last_error: { code: "BUDGET", message: "exhausted" },
    budget: { remaining_tokens: 0, remaining_rounds: 18 },
    next_action: "approve",
    created_at: "2026-01-01T00:00:00Z",
  }), "2 项已完成 · 1 项待办 · 剩余 0 tokens · 剩余 18 轮 · 最后错误 BUDGET");
});
