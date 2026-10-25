import { Agent, type AgentTool } from "@earendil-works/pi-agent-core";
import { createModels, createProvider, type Model } from "@earendil-works/pi-ai";
import { openAICompletionsApi } from "@earendil-works/pi-ai/api/openai-completions.lazy";
import { openAIResponsesApi } from "@earendil-works/pi-ai/api/openai-responses.lazy";
import type { TSchema } from "typebox";

import { HostLink, errorText, type Frame } from "./protocol.js";

const PROTOCOL_VERSION = 1;
const PI_VERSION = "1.3.0";
const MAX_REPAIR_TURNS = 4;

interface ModelConfig {
	protocol: string;
	base_url: string;
	model: string;
	api_key: string;
	timeout_seconds: number;
	max_output_tokens: number;
}

interface ToolDescriptor {
	name: string;
	description: string;
	input_schema: Record<string, unknown>;
	version: string;
}

interface StartFrame extends Frame {
	task: string;
	instructions: string;
	tools: ToolDescriptor[];
	run_id: string;
	generation: number;
}

const link = new HostLink();
let config: ModelConfig | undefined;
let currentRequest = "";
let agent: Agent | undefined;
let cancelled = false;

link.onFrame((frame) => {
	switch (frame.type) {
		case "init":
			config = frame.private as ModelConfig;
			break;
		case "start":
			void runAgent(frame as StartFrame);
			break;
		case "cancel":
			cancelled = true;
			void agent?.abort();
			break;
	}
});

link.send({
	type: "hello",
	v: PROTOCOL_VERSION,
	worker: "pi",
	pi_version: PI_VERSION,
	node: process.version,
});

/** Build the provider from the private config. No env, no model catalog, no login. */
function buildModel(cfg: ModelConfig): Model<"openai-completions" | "openai-responses"> {
	const api = cfg.protocol === "responses" ? "openai-responses" : "openai-completions";
	return {
		id: cfg.model,
		name: cfg.model,
		api,
		provider: "codexploit",
		baseUrl: cfg.base_url,
		reasoning: false,
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 128000,
		maxTokens: cfg.max_output_tokens > 0 ? cfg.max_output_tokens : 4096,
	} as Model<"openai-completions" | "openai-responses">;
}

function estimateTokens(context: unknown): number {
	const messages = (context as { messages?: unknown[] }).messages ?? [];
	const size = JSON.stringify(messages).length;
	return Math.max(1, Math.ceil(size / 2));
}

// The host owns execution order and budget. The worker only collects the calls the
// model made in one assistant turn and submits them together; the debounce lets
// the agent core start every execute callback of that turn before we flush.
interface PendingCall {
	callID: string;
	tool: string;
	args: unknown;
	resolve: (reply: { ok?: boolean; result?: unknown; error?: string }) => void;
}

let pendingCalls: PendingCall[] = [];
let batchTimer: NodeJS.Timeout | null = null;

function flushToolBatch(): void {
	const calls = pendingCalls;
	pendingCalls = [];
	if (batchTimer) {
		clearTimeout(batchTimer);
		batchTimer = null;
	}
	if (calls.length === 0) {
		return;
	}
	void link
		.request("tool_batch", {
			round_id: currentRequest,
			calls: calls.map((call) => ({ call_id: call.callID, tool: call.tool, args: call.args })),
		})
		.then((reply) => {
			const results = Array.isArray(reply.results)
				? (reply.results as Array<{ call_id?: string; ok?: boolean; result?: unknown; error?: string }>)
				: [];
			const byID = new Map(results.map((result) => [String(result.call_id ?? ""), result]));
			for (const call of calls) {
				const result = byID.get(call.callID);
				if (!result) {
					call.resolve({ ok: false, result: "", error: "the host did not answer this call" });
					continue;
				}
				call.resolve(result);
			}
		})
		.catch((error: unknown) => {
			for (const call of calls) {
				call.resolve({ ok: false, result: "", error: errorText(error) });
			}
		});
}

function enqueueToolCall(callID: string, tool: string, args: unknown): Promise<{ ok?: boolean; result?: unknown; error?: string }> {
	return new Promise((resolve) => {
		pendingCalls.push({ callID, tool, args, resolve });
		if (batchTimer) {
			clearTimeout(batchTimer);
		}
		batchTimer = setTimeout(flushToolBatch, 10);
	});
}

function makeTools(descriptors: ToolDescriptor[]): AgentTool[] {
	return descriptors.map((descriptor) => ({
		name: descriptor.name,
		label: descriptor.name,
		description: descriptor.description,
		parameters: descriptor.input_schema as unknown as TSchema,
		execute: async (callID: string, params: unknown) => {
			const reply = await enqueueToolCall(callID, descriptor.name, params);
			const text = typeof reply.result === "string" ? reply.result : JSON.stringify(reply);
			return {
				content: [{ type: "text" as const, text }],
				details: {},
				isError: reply.ok === false,
			};
		},
	}));
}

function lastAssistantText(messages: readonly unknown[]): string {
	for (let index = messages.length - 1; index >= 0; index--) {
		const message = messages[index] as { role?: string; content?: unknown };
		if (message.role !== "assistant") {
			continue;
		}
		const blocks = Array.isArray(message.content) ? message.content : [];
		const text = blocks
			.filter((block): block is { type: string; text: string } => {
				const value = block as { type?: string; text?: string };
				return value.type === "text" && typeof value.text === "string";
			})
			.map((block) => block.text)
			.join("\n")
			.trim();
		if (text !== "") {
			return text;
		}
	}
	return "";
}

/** The answer must be one JSON object; a fenced block is stripped before parsing. */
function parseAnswer(text: string): unknown {
	const trimmed = text.trim();
	const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/);
	const body = fenced ? fenced[1].trim() : trimmed;
	try {
		return JSON.parse(body) as unknown;
	} catch {
		return {};
	}
}

async function runAgent(start: StartFrame): Promise<void> {
	link.setRun(start.run_id ?? "", typeof start.generation === "number" ? start.generation : 0);
	if (!config) {
		link.send({ type: "error", code: "no_init", message: "the worker received start before init" });
		process.exit(1);
	}
	const model = buildModel(config);
	const provider = createProvider({
		id: "codexploit",
		name: "Codexploit",
		baseUrl: config.base_url,
		auth: {
			apiKey: {
				name: "Codexploit",
				resolve: async () => ({ auth: { apiKey: config?.api_key ?? "" } }),
			},
		},
		models: [model],
		api: config.protocol === "responses" ? openAIResponsesApi() : openAICompletionsApi(),
	});
	const models = createModels();
	models.setProvider(provider);
	const selected = models.getModel("codexploit", config.model) as Model<"openai-completions" | "openai-responses"> | undefined;
	if (!selected) {
		link.send({ type: "error", code: "no_model", message: "the configured model is not available" });
		process.exit(1);
	}

	let streamRequests = 0;
	const streamFn = async (requestModel: typeof selected, context: unknown, options?: Record<string, unknown>) => {
		streamRequests++;
		const requestID = `req-${streamRequests}`;
		const permit = await link.request("request_permit", {
			request_id: requestID,
			round_id: `round-${streamRequests}`,
			model: requestModel.id,
			input_tokens_estimate: estimateTokens(context),
			max_output_tokens: config?.max_output_tokens ?? 0,
			estimate_basis: "2 bytes per token plus framing",
		});
		if (permit.decision !== "continue") {
			throw new Error(`provider request was not permitted: ${String(permit.reason ?? "stop")}`);
		}
		// HostLink assigns the protocol identity used by the host's reservation.
		// Usage must settle that identity, rather than our local round label.
		if (typeof permit.reply_to !== "string" || permit.reply_to === "") {
			throw new Error("provider permit is missing its request identity");
		}
		currentRequest = permit.reply_to;
		return models.streamSimple(requestModel, context as never, options as never);
	};

	agent = new Agent({
		initialState: { systemPrompt: start.instructions, model: selected },
		streamFn: streamFn as never,
		// Parallel only lets the core start every call of one assistant turn so the
		// worker can submit the batch; the host still reserves and executes it.
		toolExecution: "parallel",
	});
	agent.state.tools = makeTools(start.tools ?? []);
	agent.subscribe(async (event) => {
		if (event.type !== "message_end" || event.message.role !== "assistant") {
			return;
		}
		const usage = (event.message as { usage?: { input?: number; output?: number; cacheRead?: number; cacheWrite?: number } }).usage;
		if (!usage || currentRequest === "") {
			return;
		}
		link.send({
			type: "usage",
			request_id: currentRequest,
			input_tokens: (usage.input ?? 0) + (usage.cacheRead ?? 0) + (usage.cacheWrite ?? 0),
			output_tokens: usage.output ?? 0,
		});
	});

	try {
		await agent.prompt(start.task);
		let answer: unknown = {};
		let accepted = false;
		for (let turn = 0; turn < MAX_REPAIR_TURNS; turn++) {
			const text = lastAssistantText(agent.state.messages);
			if (text === "") {
				break;
			}
			answer = parseAnswer(text);
			const reply = await link.request("answer_proposed", { raw: answer });
			if (reply.decision === "accepted") {
				accepted = true;
				break;
			}
			if (reply.decision !== "repair") {
				break;
			}
			await agent.prompt(
				`Your previous output was rejected: ${String(reply.reason ?? "invalid answer")}. ` +
					"Return only the JSON object required by the task.",
			);
		}
		if (cancelled) {
			link.send({ type: "settled", status: "cancelled", reason: "the run was cancelled" });
			process.exit(0);
		}
		if (!accepted) {
			link.send({ type: "settled", status: "failed", reason: "no answer was accepted" });
			process.exit(1);
		}
		link.send({ type: "settled", status: "completed" });
		process.stdout.write("", () => process.exit(0));
	} catch (error) {
		if (cancelled) {
			link.send({ type: "settled", status: "cancelled", reason: "the run was cancelled" });
			process.exit(0);
		}
		link.send({ type: "error", code: "run_failed", message: errorText(error) });
		process.exit(1);
	}
}
