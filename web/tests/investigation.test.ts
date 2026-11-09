import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiClient } from '../src/api.ts';
import { readInvestigation } from '../src/investigation.ts';

test('investigation continuation preserves project, input, ledger revision and cursor', async () => {
  let requested = '';
  const api = new ApiClient({ base: '/api', token: '' }, (async (url: string) => {
    requested = String(url);
    return new Response(JSON.stringify({ records: [], revision: 7, head_revision: 9, next_cursor: 4, has_more: false }), { status: 200 });
  }) as typeof fetch);
  const page = await readInvestigation(api, 'project-a', 'input-a', 'claim-a', 7, 4);
  const url = new URL(requested, 'https://example.invalid');
  assert.equal(url.pathname, '/api/v1/projects/project-a/knowledge/claims/claim-a');
  assert.equal(url.searchParams.get('snapshot_id'), 'input-a');
  assert.equal(url.searchParams.get('revision'), '7');
  assert.equal(url.searchParams.get('cursor'), '4');
  assert.equal(page.head_revision, 9);
});

test('investigation storage failure stays an error', async () => {
  const api = new ApiClient({ base: '/api', token: '' }, (async () => new Response(JSON.stringify({ code: 'claim_unavailable', error: 'Knowledge unavailable' }), { status: 503 })) as typeof fetch);
  await assert.rejects(readInvestigation(api, 'project-a', 'input-a'), /Knowledge unavailable/);
});
