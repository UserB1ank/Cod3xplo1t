import type { ApiClient } from './api.ts';

export interface KnowledgeTarget { file: string; start_line: number; end_line: number }
export interface KnowledgeRecord {
  record_id: string;
  claim_id: string;
  scope: { project_id: string; snapshot_id: string };
  kind: 'claim' | 'observation' | 'question' | 'evidence';
  status: 'conjecture' | 'open' | 'recorded';
  category?: string;
  statement: string;
  conditions?: string;
  target?: KnowledgeTarget;
  reference?: { kind: string; id?: string; target?: KnowledgeTarget; content?: string; sha256?: string; redacted?: boolean; redaction_notes?: string };
  relation?: 'supports' | 'contradicts' | 'context';
  actor: string;
  session_id?: string;
  run_id?: string;
  created_at: string;
  revision: number;
}
export interface KnowledgePage {
  records: KnowledgeRecord[];
  revision: number;
  head_revision: number;
  next_cursor: number;
  has_more: boolean;
}
export const knowledgeBase = (project: string) => `/v1/projects/${encodeURIComponent(project)}/knowledge/claims`;
export function readInvestigation(api: ApiClient, project: string, input: string, claim = '', revision = 0, cursor = 0, signal?: AbortSignal): Promise<KnowledgePage> {
  const query = new URLSearchParams({ snapshot_id: input, revision: String(revision), cursor: String(cursor), limit: '25' });
  return api.get<KnowledgePage>(`${knowledgeBase(project)}${claim ? '/' + encodeURIComponent(claim) : ''}?${query}`, signal);
}
