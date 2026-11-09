import test from 'node:test';
import assert from 'node:assert/strict';
import { ApiClient } from '../src/api.ts';
import { finishSourceSetupAndStartAnalysis, startProjectAnalysis } from '../src/analysis-start.ts';

test('oversized project waits for confirmation, then sends the actual byte count', async () => {
 const bodies: any[] = [];
 const bytes = 501 * 1024 * 1024;
 const api = new ApiClient({base:'/api',token:''}, async (_url,init) => {
  bodies.push(JSON.parse(String(init?.body)));
  return bodies.length === 1 ? new Response(JSON.stringify({code:'source_size_confirmation_required',error:'too large',source_bytes:bytes}),{status:409}) : new Response(JSON.stringify({analysis_run:{analysis_run_id:'analysis-one'},reused:false}),{status:201});
 });
 let questions = 0;
 const result = await startProjectAnalysis(api,'project','CSHARPSRC',false,message => { questions++; assert.match(message,/501 MiB/); assert.match(message,/500 MiB/); return true; });
 assert.equal(questions,1);
 assert.equal(bodies[0].frontend,'CSHARPSRC');
 assert.equal(bodies[1].frontend,'CSHARPSRC');
 assert.equal(bodies[1].confirm_source_bytes,bytes);
 assert.equal(result?.analysis_run.analysis_run_id,'analysis-one');
});

test('cancelling the size question does not send a second request',async () => {
 let requests = 0;
 const api = new ApiClient({base:'/api',token:''},async () => { requests++; return new Response(JSON.stringify({code:'source_size_confirmation_required',source_bytes:501*1024*1024}),{status:409}); });
 assert.equal(await startProjectAnalysis(api,'project','AUTO',true,() => false),undefined);
 assert.equal(requests,1);
});

test('new project source setup starts deterministic graph analysis automatically',async () => {
 const order: string[] = [];
 let analysisBody: any;
 const api = new ApiClient({base:'/api',token:''},async (url,init) => {
  order.push(String(url).endsWith('/analysis-runs') ? 'analysis' : 'other');
  analysisBody = JSON.parse(String(init?.body));
  return new Response(JSON.stringify({analysis_run:{analysis_run_id:'analysis-auto'},reused:false}),{status:201});
 });
 const result = await finishSourceSetupAndStartAnalysis(api,'project','GOLANG',async () => { order.push('source'); },() => true);
 assert.deepEqual(order,['source','analysis']);
 assert.equal(analysisBody.frontend,'GOLANG');
 assert.equal(analysisBody.agent_assisted,false);
 assert.equal(result?.analysis_run.analysis_run_id,'analysis-auto');
});
