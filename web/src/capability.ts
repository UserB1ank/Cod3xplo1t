export type ExecutionModel =
  | "plugin_execute"
  | "agent_runtime"
  | "environment_backend"
  | "verification_executor"
  | "native_service";

export interface CapabilityContract {
  kind: string;
  capability: string;
  schemas: string[];
}

export interface CapabilityAdapter {
  id: string;
  name: string;
  kind:
    | "plugin_runtime"
    | "agent_runtime"
    | "environment_backend"
    | "verification_executor"
    | "native_service";
  version?: string;
  protocol_version?: string;
  declared: boolean;
  installed: boolean;
  measured: boolean;
  capabilities: string[];
  reason?: string;
}

export interface CapabilityView {
  key: string;
  label: string;
  available: boolean;
  reason?: string;
  execution_model: ExecutionModel;
  plugins: {
    id: string;
    version: string;
    name: string;
    runtime: string;
    source: string;
    installed: boolean;
    executable: boolean;
    adapter_kind: "plugin_runtime";
    protocol_version?: string;
    package_version: string;
    declared: boolean;
    measured: boolean;
    reason?: string;
  }[];
  adapters: CapabilityAdapter[];
  contracts: CapabilityContract[];
}

export interface DomainProtocol {
  schema: string;
  capability: string;
  transport: Exclude<ExecutionModel, "native_service">;
  direction: "input" | "output" | "bidirectional";
  file: string;
  description: string;
}

export function executionModelLabel(model: ExecutionModel) {
  switch (model) {
    case "plugin_execute":
      return "固定版本插件 Execute";
    case "agent_runtime":
      return "Agent Runtime";
    case "environment_backend":
      return "环境供应后端";
    case "verification_executor":
      return "验证执行器";
    default:
      return "宿主原生服务";
  }
}

export function adapterStatus(adapter: CapabilityAdapter) {
  if (adapter.measured) return { label: "已实测可执行", tone: "ready" as const };
  if (adapter.installed) return { label: "已安装 · 未实测", tone: "importing" as const };
  if (adapter.declared) return { label: "仅声明 · 未安装", tone: "failed" as const };
  return { label: "不可用", tone: "failed" as const };
}

export function capabilityStatus(view: CapabilityView) {
  return view.available
    ? { label: "可用", tone: "ready" as const }
    : { label: "不可用", tone: "failed" as const };
}

export function adapterDetail(adapter: CapabilityAdapter) {
  const parts = [adapter.kind.replaceAll("_", " ")];
  if (adapter.version) parts.push(`v${adapter.version}`);
  if (adapter.protocol_version) parts.push(adapter.protocol_version);
  return parts.join(" · ");
}
