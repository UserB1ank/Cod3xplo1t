import { createInterface } from "node:readline";

/**
 * One frame of the worker protocol. Frames are JSON objects on their own line;
 * stdout carries nothing else.
 */
export interface Frame {
	type: string;
	v?: number;
	run_id?: string;
	generation?: number;
	seq?: number;
	request_id?: string;
	reply_to?: string;
	[key: string]: unknown;
}

/** The link owns framing, sequence numbers and request/reply pairing. */
export class HostLink {
	private sequence = 0;
	private nextID = 0;
	private readonly pending = new Map<string, (frame: Frame) => void>();
	private readonly handlers: Array<(frame: Frame) => void> = [];
	private runID = "";
	private generation = 0;
	private readonly replies = new Set([
		"permit_reply",
		"tool_result",
		"answer_reply",
		"repair_reply",
	]);

	constructor() {
		const lines = createInterface({ input: process.stdin, crlfDelay: Infinity });
		lines.on("line", (line) => this.receive(line));
	}

	onFrame(handler: (frame: Frame) => void): void {
		this.handlers.push(handler);
	}

	/** setRun binds the run identity every public frame must carry. */
	setRun(runID: string, generation: number): void {
		this.runID = runID;
		this.generation = generation;
	}

	/** send writes one public frame. Section 6 of the design forbids anything else. */
	send(frame: Frame): void {
		frame.seq = ++this.sequence;
		if (frame.run_id === undefined && this.runID !== "") {
			frame.run_id = this.runID;
			frame.generation = this.generation;
		}
		process.stdout.write(`${JSON.stringify(frame)}\n`);
	}

	/** request sends a request frame and resolves when its reply arrives. */
	request(type: string, payload: Record<string, unknown>): Promise<Frame> {
		const requestID = `${type}-${++this.nextID}`;
		return new Promise<Frame>((resolve) => {
			this.pending.set(requestID, resolve);
			this.send({ ...payload, type, request_id: requestID });
		});
	}

	private receive(line: string): void {
		const trimmed = line.trim();
		if (trimmed === "") {
			return;
		}
		let frame: Frame;
		try {
			frame = JSON.parse(trimmed) as Frame;
		} catch {
			this.fail("protocol_error", "a frame was not valid JSON");
			return;
		}
		const replyTo = typeof frame.reply_to === "string" ? frame.reply_to : "";
		if (replyTo !== "" && this.replies.has(frame.type)) {
			const resolve = this.pending.get(replyTo);
			if (resolve) {
				this.pending.delete(replyTo);
				resolve(frame);
			}
			return;
		}
		for (const handler of this.handlers) {
			handler(frame);
		}
	}

	private fail(code: string, message: string): void {
		this.send({ type: "error", code, message });
	}
}

/** Bounded single-line summary of an unknown error. */
export function errorText(error: unknown): string {
	if (error instanceof Error) {
		return error.message.slice(0, 500);
	}
	return String(error).slice(0, 500);
}
