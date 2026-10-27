import test from "node:test";
import assert from "node:assert/strict";
import { isFollowingLatest } from "../src/agent-scroll.ts";

test("conversation follows the latest only while within the bottom threshold", () => {
  assert.equal(
    isFollowingLatest({ scrollHeight: 300, scrollTop: 0, clientHeight: 400 }),
    true,
  );
  assert.equal(
    isFollowingLatest({ scrollHeight: 1000, scrollTop: 520, clientHeight: 400 }),
    true,
  );
  assert.equal(
    isFollowingLatest({ scrollHeight: 1000, scrollTop: 519, clientHeight: 400 }),
    false,
  );
});
