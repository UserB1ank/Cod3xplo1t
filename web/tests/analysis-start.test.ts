import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiClient } from '../src/api.ts';
import { startProjectAnalysis } from '../src/analysis-start.ts';

test('oversized project waits for confirmation, then sends the actual byte count', async () => {
 const bodies: any[] = [];
 const bytes = 501 * 1024 * 1024;
 const api = new ApiClient({base:'/api',token:''}, async (_url,init) => {
  bodies.push(JSON.parse(String(init?.body)));
  return bodies.length === 1 ? new Response(JSON.stringify({code:'source_size_confirmation_required',error:'too large',source_bytes:bytes}),{status:409}) : new Response(JSON.stringify({analysis_run:{analysis_run_id:'analysis-one'},reused:false}),{status:201});
 });
 let questions = 0;
 const result = await startProjectAnalysis(api,'project',false,message => { questions++; assert.match(message,/501 MiB/); assert.match(message,/500 MiB/); return true; });
 assert.equal(questions,1);
 assert.equal(bodies[1].confirm_source_bytes,bytes);
 assert.equal(result?.analysis_run.analysis_run_id,'analysis-one');
});

test('cancelling the size question does not send a second request',async () => {
 let requests = 0;
 const api = new ApiClient({base:'/api',token:''},async () => { requests++; return new Response(JSON.stringify({code:'source_size_confirmation_required',source_bytes:501*1024*1024}),{status:409}); });
 assert.equal(await startProjectAnalysis(api,'project',true,() => false),undefined);
 assert.equal(requests,1);
});
