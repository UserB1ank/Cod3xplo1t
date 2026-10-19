import assert from "node:assert/strict";
import { createServer } from "node:http";
import { spawn } from "node:child_process";
import { createInterface } from "node:readline";
import { test } from "node:test";
import { once } from "node:events";

const WORKER = new URL("../dist/main.js", import.meta.url).pathname;

function sse(chunks) {
	return chunks.map((chunk) => `data: ${JSON.stringify(chunk)}\n\n`).join("") + "data: [DONE]\n\n";
}

function textChunk(text, finish = null, usage = undefined) {
	const chunk = {
		id: "chatcmpl-test",
		object: "chat.completion.chunk",
		created: 0,
		model: "test-model",
		choices: [{ index: 0, delta: finish ? {} : { role: "assistant", content: text }, finish_reason: finish }],
	};
	if (usage) {
		chunk.usage = usage;
	}
	return chunk;
}

function toolChunk() {
	return {
		id: "chatcmpl-test",
		object: "chat.completion.chunk",
		created: 0,
		model: "test-model",
		choices: [
			{
				index: 0,
				delta: {
					role: "assistant",
					tool_calls: [
						{
							index: 0,
							id: "call-1",
							type: "function",
							function: { name: "get_code_slice", arguments: '{"symbol_id":"S1"}' },
						},
					],
				},
				finish_reason: null,
			},
		],
	};
}

/** startProvider records requests and answers with a tool call, then an answer. */
async function startProvider() {
	const requests = [];
	const server = createServer(async (request, response) => {
		let body = "";
		request.on("data", (chunk) => (body += chunk));
		await once(request, "end");
		const parsed = JSON.parse(body);
		requests.push(parsed);
		response.writeHead(200, { "content-type": "text/event-stream" });
		const messages = parsed.messages ?? [];
		const sawToolResult = messages.some((message) => message.role === "tool");
		if (!sawToolResult) {
			response.end(sse([toolChunk(), textChunk("", "tool_calls")]));
			return;
		}
		const answer = JSON.stringify({ schema_version: 2, security_goal: "goal", hypothesis: { statement: "x", status: "inconclusive", confidence: "low" }, obligations: [], supporting_evidence: [], contradicting_evidence: [], next_action: "stop", finding_candidate: false });
		response.end(
			sse([
				textChunk(answer),
				textChunk("", "stop", { prompt_tokens: 100, completion_tokens: 20, total_tokens: 120 }),
			]),
		);
	});
	server.listen(0, "127.0.0.1");
	await once(server, "listening");
	const address = server.address();
	return { server, requests, baseUrl: `http://127.0.0.1:${address.port}/v1` };
}

/** host drives the worker protocol and returns the frames it observed. */
async function runHost(baseUrl) {
	const worker = spawn(process.execPath, [WORKER], { stdio: ["pipe", "pipe", "pipe"] });
	const frames = [];
	const toolResults = [];
	const lines = createInterface({ input: worker.stdout, crlfDelay: Infinity });
	let seq = 0;
	const send = (frame) => {
		frame.seq = ++seq;
		worker.stdin.write(`${JSON.stringify(frame)}\n`);
	};
	let settled;
	const done = new Promise((resolve) => (settled = resolve));
	lines.on("line", (line) => {
		const frame = JSON.parse(line);
		frames.push(frame);
		switch (frame.type) {
			case "hello":
				send({
					type: "init",
					run_id: "run-1",
					generation: 1,
					private: {
						protocol: "chat-completions",
						base_url: baseUrl,
						model: "test-model",
						api_key: "synthetic",
						timeout_seconds: 20,
						max_output_tokens: 1024,
					},
				});
				send({
					type: "start",
					run_id: "run-1",
					generation: 1,
					task: "TASK\nGOAL\ngoal\n\nOBLIGATIONS\n- source_is_attacker_controlled — x\n",
					instructions: "You audit code.",
					tools: [
						{
							name: "get_code_slice",
							description: "read a slice",
							version: "1",
							input_schema: {
								type: "object",
								properties: { symbol_id: { type: "string" } },
								additionalProperties: false,
							},
						},
					],
					limits: {},
				});
				break;
			case "request_permit":
				send({ type: "permit_reply", reply_to: frame.request_id, decision: "continue" });
				break;
			case "tool_request":
				toolResults.push(frame.args);
				send({
					type: "tool_result",
					reply_to: frame.request_id,
					call_id: frame.call_id,
					tool: frame.tool,
					ok: true,
					result: JSON.stringify({ ok: true, result: "slice", budget: { calls_left: 9 } }),
				});
				break;
			case "answer_proposed":
				send({ type: "answer_reply", reply_to: frame.request_id, decision: "accepted" });
				break;
			case "settled":
				settled(frame);
				break;
		}
	});
	let timer;
	const status = await Promise.race([
		done,
		new Promise((_, reject) => (timer = setTimeout(() => reject(new Error("worker did not settle")), 15000))),
	]);
	clearTimeout(timer);
	worker.kill();
	return { frames, toolResults, status };
}

test("the Pi worker requests a tool and proposes the host-accepted answer", async () => {
	const provider = await startProvider();
	try {
		const { frames, toolResults, status } = await runHost(provider.baseUrl);
		assert.equal(status.status, "completed");
		assert.deepEqual(toolResults, [{ symbol_id: "S1" }]);
		assert.ok(frames.some((frame) => frame.type === "usage" && frame.input_tokens === 100));
		const second = provider.requests[1];
		const toolMessage = second.messages.find((message) => message.role === "tool");
		assert.ok(toolMessage, "the worker did not send the host tool result back to the provider");
		assert.match(JSON.stringify(toolMessage), /calls_left/);
	} finally {
		provider.server.close();
	}
});
