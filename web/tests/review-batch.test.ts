import test from "node:test";
import assert from "node:assert/strict";
import { reviewBatchProgressLine, reviewBatchStateLabel } from "../src/review-batch.ts";

test("review batch progress keeps blocked, paused and failed states distinct", () => {
  assert.equal(reviewBatchProgressLine({
    total: 4,
    queued: 1,
    active: 1,
    reviewed: 0,
    failed: 1,
    cancelled: 0,
    blocked: 1,
    paused: 0,
  }), "进行中 1 · 等待 1 · 受阻 1 · 暂停 0 · 失败 1 · 取消 0");
  assert.equal(reviewBatchStateLabel("PAUSED"), "已暂停");
  assert.equal(reviewBatchStateLabel("FAILED"), "失败");
});
