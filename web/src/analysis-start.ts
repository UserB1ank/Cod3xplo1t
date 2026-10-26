import { ApiClient, ApiError } from './api.ts';
import { formatBytes } from './project-management.ts';

export async function startProjectAnalysis(api: ApiClient, projectID: string, agentAssisted: boolean, confirm: (message: string) => boolean) {
 try {
  return await api.startAnalysis(projectID, {agent_assisted: agentAssisted});
 } catch (error) {
  if (!(error instanceof ApiError) || error.code !== 'source_size_confirmation_required' || !Number.isSafeInteger(error.sourceBytes) || error.sourceBytes! <= 500 * 1024 * 1024) throw error;
  if (!confirm(`源码文件总大小为 ${formatBytes(error.sourceBytes!)}（${error.sourceBytes!.toLocaleString()} 字节），超过默认预算 500 MiB。是否继续图谱化？`)) return;
  return api.startAnalysis(projectID, {agent_assisted: agentAssisted, confirm_source_bytes: error.sourceBytes});
 }
}
