const toolLabels: Record<string, string> = {
  list_project_operations: "查看项目可用操作",
  project_api: "执行项目操作",
  inspect_project: "查看项目记录",
  list_source_files: "列出源码文件",
  read_source_file: "读取源码窗口",
  graph_summary: "读取图谱摘要",
  list_modules: "列出模块",
  list_symbols: "检索符号",
  get_symbol: "读取符号",
  get_callers: "查询调用方",
  get_callees: "查询被调用方",
  find_call_paths: "查找调用路径",
  get_code_slice: "读取源码片段",
  list_unresolved_calls: "查看未解析调用",
  repo_map: "查看仓库概览",
  list_entry_points: "列出程序入口",
  list_sinks: "列出敏感操作",
  get_asg_node: "读取攻击面节点",
  open_knowledge_view: "打开固定知识视图",
  query_investigation_knowledge: "查询调查知识",
  propose_path: "提交候选路径",
  propose_claim: "提交调查猜想",
  open_question: "提出待解问题",
  attach_evidence: "附加调查证据",
};

export function toolDisplayName(name?: string) {
  return (name && toolLabels[name]) || name || "工具调用";
}
