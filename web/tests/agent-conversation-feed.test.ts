import test from "node:test";
import assert from "node:assert/strict";
import { createElement } from "react";
import { renderToStaticMarkup } from "react-dom/server";
import { createServer } from "vite";
import path from "node:path";
import { fileURLToPath } from "node:url";

const webRoot = path.dirname(path.dirname(fileURLToPath(import.meta.url)));

test("conversation feed exposes a named, incremental live log", async (t) => {
  const vite = await createServer({
    root: webRoot,
    configFile: false,
    appType: "custom",
    logLevel: "silent",
    server: { middlewareMode: true },
  });
  t.after(async () => {
    await vite.close();
  });

  const { AgentConversationFeed } = await vite.ssrLoadModule(
    "/src/AgentConversationFeed.tsx",
  );
  const html = renderToStaticMarkup(
    createElement(
      AgentConversationFeed,
      {
        label: "主 Agent 对话",
        busy: true,
        className: "supervisor-messages",
      },
      createElement("p", null, "历史消息"),
    ),
  );

  assert.match(html, /role="log"/);
  assert.match(html, /aria-label="主 Agent 对话"/);
  assert.match(html, /aria-live="polite"/);
  assert.match(html, /aria-relevant="additions"/);
  assert.match(html, /aria-busy="true"/);
});
