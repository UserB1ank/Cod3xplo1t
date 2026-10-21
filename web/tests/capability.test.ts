import test from "node:test";
import assert from "node:assert/strict";
import {
  adapterDetail,
  adapterStatus,
  capabilityStatus,
  executionModelLabel,
  type CapabilityAdapter,
  type CapabilityView,
} from "../src/capability.ts";

function adapter(overrides: Partial<CapabilityAdapter> = {}): CapabilityAdapter {
  return {
    id: "adapter-one",
    name: "Adapter",
    kind: "plugin_runtime",
    declared: true,
    installed: false,
    measured: false,
    capabilities: [],
    ...overrides,
  };
}

test("declared, installed and measured are separate states", () => {
  assert.equal(adapterStatus(adapter()).label, "仅声明 · 未安装");
  assert.equal(adapterStatus(adapter({ installed: true })).label, "已安装 · 未实测");
  assert.equal(adapterStatus(adapter({ installed: true, measured: true })).label, "已实测可执行");
  assert.equal(adapterStatus(adapter({ declared: false })).label, "不可用");
});

test("adapter detail names the runtime and protocol without inventing a backend", () => {
  assert.equal(
    adapterDetail(
      adapter({
        kind: "agent_runtime",
        version: "1.3.0",
        protocol_version: "agent-worker/v1",
      }),
    ),
    "agent runtime · v1.3.0 · agent-worker/v1",
  );
  assert.equal(adapterDetail(adapter({ kind: "environment_backend" })), "environment backend");
});

test("a capability is only available when an adapter was measured", () => {
  const view = {
    key: "environment",
    label: "环境供应",
    available: false,
    execution_model: "environment_backend",
    plugins: [],
    adapters: [adapter({ kind: "environment_backend" })],
    contracts: [],
  } as CapabilityView;
  assert.equal(capabilityStatus(view).label, "不可用");
  assert.equal(capabilityStatus({ ...view, available: true }).label, "可用");
  assert.equal(executionModelLabel("verification_executor"), "验证执行器");
  assert.equal(executionModelLabel("plugin_execute"), "固定版本插件 Execute");
});
