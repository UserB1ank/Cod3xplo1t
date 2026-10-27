import test from "node:test";
import assert from "node:assert/strict";
import { AgentMessageSendState } from "../src/agent-send-state.ts";

test("failed retries reuse the pending key without allowing concurrent sends", () => {
  const state = new AgentMessageSendState();
  let sequence = 0;
  const createID = () => `message-${++sequence}`;

  assert.equal(state.begin("same request", createID), "message-1");
  assert.equal(state.begin("same request", createID), undefined);

  state.complete(false);
  assert.equal(state.begin("same request", createID), "message-1");

  state.complete(false);
  assert.equal(state.begin("changed request", createID), "message-2");

  state.complete(true);
  assert.equal(state.begin("changed request", createID), "message-3");
});
