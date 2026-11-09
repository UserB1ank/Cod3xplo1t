import test from "node:test";
import assert from "node:assert/strict";
import {
  continuableRun,
  projectAgentConversation,
  terminalRunFallback,
} from "../src/agent-conversation.ts";
import type { SupervisorSession } from "../src/types.ts";

function sessionWith(
  messages: SupervisorSession["messages"],
  status = "FAILED",
): SupervisorSession {
  return {
    session_id: "session-one",
    project_id: "project-one",
    snapshot_id: "snapshot-one",
    title: "Agent conversation",
    state: status,
    messages,
    runs: [
      {
        run_id: "run-one",
        session_id: "session-one",
        project_id: "project-one",
        status,
        runtime: "llm",
        model: "fixture",
        config_version: "1",
        prompt_version: "1",
        tool_digest: "fixture",
        input_tokens: 1,
        output_tokens: 1,
        created_at: "2026-01-01T00:00:00Z",
        updated_at: "2026-01-01T00:00:01Z",
        version: 1,
      },
    ],
    events: [],
    created_at: "2026-01-01T00:00:00Z",
    updated_at: "2026-01-01T00:00:01Z",
    version: 1,
  };
}

test("tool-only assistant turns become historical tool activity", () => {
  const session = sessionWith([
    {
      message_id: "message-one",
      session_id: "session-one",
      project_id: "project-one",
      role: "assistant",
      content: "",
      calls: [
        {
          call_id: "call-one",
          name: "repo_map",
          arguments: "{}",
        },
      ],
      run_id: "run-one",
      status: "complete",
      seq: 1,
      created_at: "2026-01-01T00:00:01Z",
    },
  ]);

  const conversation = projectAgentConversation(session);

  assert.equal(conversation.length, 1);
  assert.equal(conversation[0].kind, "tool-activity");
  assert.equal(conversation[0].calls.length, 1);
  assert.doesNotMatch(JSON.stringify(conversation), /正在读取/);
});

test("legacy terminal runs without text receive a visible fallback", () => {
  const session = sessionWith(
    [
      {
        message_id: "message-one",
        session_id: "session-one",
        project_id: "project-one",
        role: "assistant",
        content: "",
        calls: [{ call_id: "call-one", name: "repo_map", arguments: "{}" }],
        run_id: "run-one",
        status: "complete",
        seq: 1,
        created_at: "2026-01-01T00:00:01Z",
      },
    ],
    "PAUSED",
  );

  const fallback = terminalRunFallback(session);
  assert.equal(fallback?.run.status, "PAUSED");
  assert.match(fallback?.message || "", /已暂停/);
  assert.match(fallback?.message || "", /未完成/);
});

test("backend terminal messages suppress the legacy fallback", () => {
  const session = sessionWith(
    [
      {
        message_id: "terminal",
        session_id: "session-one",
        project_id: "project-one",
        role: "assistant",
        content: "本次运行已暂停。",
        message_kind: "paused",
        run_id: "run-one",
        status: "complete",
        seq: 1,
        created_at: "2026-01-01T00:00:01Z",
      },
    ],
    "PAUSED",
  );

  assert.equal(terminalRunFallback(session), undefined);
});

test("only the latest paused run with its user message can continue", () => {
  const session = sessionWith([], "PAUSED");
  session.runs[0].user_message_id = "message-user";
  assert.equal(continuableRun(session)?.run_id, "run-one");

  session.runs[0].status = "SUCCEEDED";
  assert.equal(continuableRun(session), undefined);

  session.runs[0].status = "PAUSED";
  session.runs[0].user_message_id = "";
  assert.equal(continuableRun(session), undefined);

  session.runs[0].user_message_id = "message-user";
  session.runs.push({
    ...session.runs[0],
    run_id: "run-active",
    status: "RUNNING",
    root_run_id: "run-one",
  });
  assert.equal(continuableRun(session), undefined);
});

test("tool results remain distinct from chat messages", () => {
  const session = sessionWith([
    {
      message_id: "tool-result-one",
      session_id: "session-one",
      project_id: "project-one",
      role: "tool",
      content: '{"ok":true,"result":"mapped"}',
      tool_call_id: "call-one",
      run_id: "run-one",
      status: "complete",
      seq: 1,
      created_at: "2026-01-01T00:00:02Z",
    },
  ]);

  const conversation = projectAgentConversation(session);

  assert.equal(conversation.length, 1);
  assert.equal(conversation[0].kind, "tool-result");
});

test("a run groups repeated tool-only assistant turns into one activity", () => {
  const session = sessionWith([
    {
      message_id: "assistant-one",
      session_id: "session-one",
      project_id: "project-one",
      role: "assistant",
      content: "",
      calls: [{ call_id: "call-one", name: "repo_map", arguments: "{}" }],
      run_id: "run-one",
      status: "complete",
      seq: 1,
      created_at: "2026-01-01T00:00:01Z",
    },
    {
      message_id: "tool-one",
      session_id: "session-one",
      project_id: "project-one",
      role: "tool",
      content: '{"ok":true,"result":"mapped"}',
      tool_call_id: "call-one",
      run_id: "run-one",
      status: "complete",
      seq: 2,
      created_at: "2026-01-01T00:00:02Z",
    },
    {
      message_id: "assistant-two",
      session_id: "session-one",
      project_id: "project-one",
      role: "assistant",
      content: "",
      calls: [
        {
          call_id: "call-two",
          name: "list_entry_points",
          arguments: "{}",
        },
      ],
      run_id: "run-one",
      status: "complete",
      seq: 3,
      created_at: "2026-01-01T00:00:03Z",
    },
    {
      message_id: "tool-two",
      session_id: "session-one",
      project_id: "project-one",
      role: "tool",
      content: '{"ok":true,"result":"entries"}',
      tool_call_id: "call-two",
      run_id: "run-one",
      status: "complete",
      seq: 4,
      created_at: "2026-01-01T00:00:04Z",
    },
  ]);

  const conversation = projectAgentConversation(session);
  const activities = conversation.filter(
    (entry) => entry.kind === "tool-activity",
  );

  assert.equal(activities.length, 1);
  assert.equal(activities[0].calls.length, 2);
  assert.equal(activities[0].results.length, 2);
  assert.deepEqual(conversation.map((entry) => entry.kind), ["tool-activity"]);
});

test("an empty assistant answer stays an empty result instead of loading copy", () => {
  const session = sessionWith([
    {
      message_id: "empty-answer",
      session_id: "session-one",
      project_id: "project-one",
      role: "assistant",
      content: "   ",
      run_id: "run-one",
      status: "complete",
      seq: 1,
      created_at: "2026-01-01T00:00:01Z",
    },
  ]);

  const conversation = projectAgentConversation(session);

  assert.equal(conversation.length, 1);
  assert.equal(conversation[0].kind, "empty-message");
  assert.doesNotMatch(JSON.stringify(conversation), /正在读取/);
});

test("tool calls alongside assistant prose keep both the message and grouped results", () => {
  const session = sessionWith([
    {
      message_id: "assistant-prose",
      session_id: "session-one",
      project_id: "project-one",
      role: "assistant",
      content: "I will attach the evidence.",
      calls: [
        {
          call_id: "call-attach",
          name: "attach_evidence",
          arguments: "{}",
        },
      ],
      run_id: "run-one",
      status: "complete",
      seq: 1,
      created_at: "2026-01-01T00:00:01Z",
    },
    {
      message_id: "tool-attach",
      session_id: "session-one",
      project_id: "project-one",
      role: "tool",
      content: '{"ok":false,"error":"missing claim"}',
      tool_call_id: "call-attach",
      run_id: "run-one",
      status: "complete",
      seq: 2,
      created_at: "2026-01-01T00:00:02Z",
    },
  ]);

  const conversation = projectAgentConversation(session);
  const activity = conversation.find((entry) => entry.kind === "tool-activity");

  assert.deepEqual(
    conversation.map((entry) => entry.kind),
    ["message", "tool-activity"],
  );
  assert.equal(activity?.calls.length, 1);
  assert.equal(activity?.results.length, 1);
});
