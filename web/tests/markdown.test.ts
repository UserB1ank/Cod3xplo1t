import test from "node:test";
import assert from "node:assert/strict";
import { parseInline, parseMarkdown } from "../src/markdown-parser.ts";

test("tables, headings and emphasis become structured blocks", () => {
  const blocks = parseMarkdown(
    "## 结论\n\n| 项 | 状态 |\n| --- | --- |\n| 路径 | **未审查** |\n",
  );
  assert.deepEqual(
    blocks.map((block) => block.type),
    ["heading", "table"],
  );
  const table = blocks[1];
  assert.equal(table.type, "table");
  if (table.type !== "table") return;
  assert.equal(table.header.length, 2);
  assert.equal(table.rows.length, 1);
  assert.equal(table.rows[0][1][0].type, "strong");
});

test("inline code, links and emphasis are parsed without HTML", () => {
  const nodes = parseInline('看 `a.go` 与 [证据](https://example.invalid/x)，<script>alert(1)</script>');
  assert.ok(nodes.some((node) => node.type === "code" && node.text === "a.go"));
  const link = nodes.find((node) => node.type === "link");
  assert.equal(link?.type, "link");
  if (link?.type === "link") assert.equal(link.href, "https://example.invalid/x");
  const text = nodes.filter((node) => node.type === "text").map((node) => node.text).join("");
  assert.match(text, /<script>alert\(1\)<\/script>/);
});

test("identifiers with underscores are not mistaken for emphasis", () => {
  const nodes = parseInline("snapshot_id and call_site_id stay literal");
  assert.equal(nodes.some((node) => node.type === "em"), false);
});

test("unsafe links stay literal instead of becoming anchors", () => {
  const nodes = parseInline("[点我](javascript:alert(1))");
  assert.equal(nodes.some((node) => node.type === "link"), false);
  assert.match(nodes.map((node) => ("text" in node ? node.text : "")).join(""), /点我/);
});

test("fenced code keeps its body out of other Markdown rules", () => {
  const blocks = parseMarkdown("```go\nfunc main() {}\n| not | a table |\n```\n");
  assert.equal(blocks.length, 1);
  assert.equal(blocks[0].type, "code");
  if (blocks[0].type === "code") {
    assert.equal(blocks[0].language, "go");
    assert.match(blocks[0].text, /func main/);
    assert.match(blocks[0].text, /\| not \|/);
  }
});

test("lists and paragraphs preserve their text", () => {
  const blocks = parseMarkdown("- 第一项\n- 第二项\n\n普通段落\n第二行");
  assert.equal(blocks[0].type, "list");
  if (blocks[0].type === "list") assert.equal(blocks[0].items.length, 2);
  assert.equal(blocks[1].type, "paragraph");
});
