import test from "node:test";
import assert from "node:assert/strict";
import { supervisorBudgetAvailable, supervisorBudgetRecovery, supervisorBudgetSummary } from "../src/supervisor-budget.ts";

test("supervisor budget keeps used, reserved and available explicit", () => {
  const budget = { audit_id: "audit-1", limit_tokens: 60000, used_tokens: 12000, reserved_tokens: 8000, version: 3 };
  assert.equal(supervisorBudgetAvailable(budget), 40000);
  assert.equal(supervisorBudgetSummary(budget), "已用 12000 · 预留 8000 · 剩余 40000 · 上限 60000");
  assert.match(supervisorBudgetRecovery({ status: "PAUSED", stop_reason: "global_budget" } as never), /审批追加预算/);
});
