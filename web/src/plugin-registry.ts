export interface StagePort {
  name: string;
  kind: string;
  schema_id: string;
  cardinality: string;
  required: boolean;
}
export interface StageOperation {
  id: string;
  stage: string;
  capability: string;
  profile: string;
  inputs: StagePort[];
  outputs: StagePort[];
  config_schema: object;
}
export interface PluginRelease {
  plugin_id: string;
  plugin_version: string;
  os: string;
  arch: string;
  package_digest: string;
  manifest_digest: string;
}
export interface PluginInstallation {
  id: string;
  release: PluginRelease;
  worker_id: string;
  installed: boolean;
  enabled: boolean;
  integrity: string;
  probe: string;
  reason?: string;
  checked_at?: string;
  version: number;
}
export interface RegistryRecord {
  manifest: {
    api_version: string;
    id: string;
    version: string;
    name: string;
    description?: string;
    languages?: string[];
    kind?: string;
    permissions?: { network: string; source_write: boolean };
    runtime: { kind: string; protocol?: string };
    operations?: StageOperation[];
    tools?: { id: string; version: string; entrypoint: string }[];
    consumes?: string[];
    produces?: string[];
  };
  stages: string[];
  package_digest: string;
  manifest_digest: string;
  executable: boolean;
  installed: boolean;
  reason?: string;
  installation?: PluginInstallation;
}

interface TypedArtifact {
  id: string;
  kind: string;
  schema_id: string;
  scope: { project_id: string; source_id: string; snapshot_id: string };
}

export function stageInputs<T extends TypedArtifact>(
  operation: { inputs: StagePort[] },
  artifacts: T[],
  selected: Record<string, string | string[]>,
) {
  const inputs: T[] = [];
  const input_ports: string[] = [];
  for (const port of operation.inputs) {
    const eligible = artifacts.filter(
      (ref) => ref.kind === port.kind && ref.schema_id === port.schema_id,
    );
    const value = selected[port.name];
    const ids = Array.isArray(value) ? value : value ? [value] : [];
    const matches = ids.length
      ? eligible.filter((ref) => ids.includes(ref.id))
      : eligible;
    if (!port.required && matches.length === 0 && ids.length === 0) continue;
    if (
      (port.required && matches.length === 0) ||
      (port.cardinality === "one" && matches.length !== 1) ||
      (ids.length > 0 && matches.length !== ids.length)
    ) {
      throw new Error(`请为 ${port.name} 选择符合类型和 Schema 的固定产物。`);
    }
    for (const match of matches) {
      inputs.push(match);
      input_ports.push(port.name);
    }
  }
  const scopes = new Set(inputs.map((ref) => JSON.stringify(ref.scope)));
  if (scopes.size > 1) throw new Error("输入产物必须属于同一固定源码快照。");
  return { inputs, input_ports };
}

export interface RegistryStage {
  stage: string;
  capability: string;
  label: string;
  transport: string;
  inputs: StagePort[];
  outputs: StagePort[];
}
export interface PluginGroup {
  id: string;
  current: RegistryRecord;
  versions: RegistryRecord[];
}
export function registryState(row: RegistryRecord) {
  if (!row.installed)
    return { key: "uninstalled", label: "待安装", tone: "neutral" };
  if (row.installation?.integrity === "failed")
    return { key: "integrity", label: "校验失败", tone: "danger" };
  if (row.installation && !row.installation.enabled)
    return { key: "disabled", label: "已禁用", tone: "neutral" };
  if (row.installation?.probe === "failed")
    return { key: "probe", label: "实测失败", tone: "warning" };
  if (row.executable)
    return { key: "ready", label: "可执行", tone: "positive" };
  return { key: "unavailable", label: "暂不可执行", tone: "warning" };
}
export function pluginGroups(records: RegistryRecord[]): PluginGroup[] {
  const groups = new Map<string, RegistryRecord[]>();
  for (const row of records)
    groups.set(row.manifest.id, [...(groups.get(row.manifest.id) || []), row]);
  const compare = (a: RegistryRecord, b: RegistryRecord) =>
    b.manifest.version.localeCompare(a.manifest.version, "en", {
      numeric: true,
    });
  return [...groups]
    .map(([id, rows]) => {
      const versions = rows.sort(compare);
      return {
        id,
        versions,
        current:
          versions.find((row) => row.executable) ||
          versions.find((row) => row.installed) ||
          versions[0],
      };
    })
    .sort((a, b) =>
      a.current.manifest.name.localeCompare(b.current.manifest.name, "zh-CN"),
    );
}
export function filterPlugins(
  groups: PluginGroup[],
  filter: { query: string; stage: string; state: string },
) {
  const query = filter.query.trim().toLocaleLowerCase();
  return groups.flatMap((group) => {
    const eligible = group.versions.filter(
      (row) =>
        (!filter.stage || row.stages?.includes(filter.stage)) &&
        (!filter.state || registryState(row).key === filter.state) &&
        (!query ||
          `${group.id} ${row.manifest.name} ${row.manifest.description || ""}`
            .toLocaleLowerCase()
            .includes(query)),
    );
    if (!eligible.length) return [];
    return [
      {
        ...group,
        current: eligible.includes(group.current) ? group.current : eligible[0],
      },
    ];
  });
}

export function stageManifestTemplate(stage: RegistryStage) {
  const process = stage.transport === "plugin_execute";
  const protocols: Record<string, string> = {
    native_service: "source-provider",
    agent_runtime: "agent-runtime",
    environment_backend: "environment-provider",
    verification_executor: "verification-executor",
  };
  return {
    api_version: "codexploit/plugin/v2",
    id: `example.${stage.stage.replaceAll(".", "-")}`,
    version: "0.1.0",
    name: `${stage.label}插件`,
    description: "开发模板，请填写实际工具能力和局限。",
    languages: ["any"],
    runtime: {
      kind: process ? "process" : stage.transport,
      protocol: process
        ? "codexploit/file-job/v1"
        : `codexploit/${protocols[stage.transport]}/v1`,
      ...(process ? { entrypoint: "bin/adapter" } : {}),
    },
    permissions: {
      network: "none",
      source_write: false,
      target_execution: false,
    },
    operations: [
      {
        id: "execute",
        stage: stage.stage,
        capability: stage.capability,
        profile: "standard",
        inputs: stage.inputs,
        outputs: stage.outputs,
        config_schema: {
          type: "object",
          properties: {},
          additionalProperties: false,
        },
      },
    ],
  };
}

export function invocationCoverageText(
  status: string,
  stage?: {
    unit: string;
    seen: number | null;
    analyzed: number | null;
    skipped: number | null;
    failed: number | null;
  },
  legacy?: {
    input_files: number;
    parsed_files: number;
    partial_files: number;
    unhandled_files: number;
    unparsed_files: number;
  },
) {
  if (["CREATED", "RUNNING"].includes(status))
    return { analyzed: "等待执行器报告", omitted: "待报告" };
  if (stage) {
    const units: Record<string, string> = {
      files: "文件",
      symbols: "符号",
      paths: "路径",
      findings: "发现",
    };
    return {
      analyzed: `${stage.analyzed ?? "未知"} / ${stage.seen ?? "未知"} ${units[stage.unit] || stage.unit}`,
      omitted: `${stage.skipped ?? "未知"} / ${stage.failed ?? "未知"}`,
    };
  }
  if (
    !legacy ||
    (!legacy.input_files && !["SUCCEEDED", "PARTIAL"].includes(status))
  )
    return { analyzed: "未返回覆盖", omitted: "未报告" };
  return {
    analyzed: `${legacy.parsed_files} 完整 · ${legacy.partial_files} 部分`,
    omitted: `${legacy.unhandled_files} / ${legacy.unparsed_files}`,
  };
}
