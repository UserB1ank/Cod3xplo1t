import test from "node:test";
import assert from "node:assert/strict";
import { composerAction, insertComposerNewline } from "../src/assistant-composer.ts";

test("Enter sends, Ctrl+Enter replaces the selection with a newline", () => {
  assert.equal(composerAction({key: "Enter", ctrlKey: false}), "send");
  assert.equal(composerAction({key: "Enter", ctrlKey: true}), "newline");
  assert.deepEqual(insertComposerNewline("ab选中文字cd", 2, 6), {value: "ab\ncd", cursor: 3});
  assert.deepEqual(insertComposerNewline("中文", 2, 2), {value: "中文\n", cursor: 3});
});

test("input method confirmation and held Enter never submit a conversation", () => {
  assert.equal(composerAction({key: "Enter", ctrlKey: false, isComposing: true}), "ignore");
  assert.equal(composerAction({key: "Enter", ctrlKey: false, keyCode: 229}), "ignore");
  assert.equal(composerAction({key: "Enter", ctrlKey: false, repeat: true}), "ignore");
  assert.equal(composerAction({key: "a", ctrlKey: false}), "ignore");
});
