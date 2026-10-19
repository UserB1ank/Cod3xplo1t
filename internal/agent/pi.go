package agent

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"sync"
	"time"
)

// PiRuntime runs one fixed worker process per run and speaks the worker protocol
// over JSONL on stdin/stdout. The worker is trusted code from the deployment, not
// a sandbox; the boundary that matters is that it owns no authority: every
// provider request needs a host permit, every tool call is executed by the host,
// and every answer is validated by the host.
//
// Unlike CLIRuntime, stdin stays open: replies travel back as frames. The worker
// protocol is a new contract, so the CLI adapter is untouched.

// Worker protocol limits. The defaults are the documented ones; each is capped so
// an operator cannot remove the bound by configuration.
const (
	DefaultPiHelloTimeout = 5 * time.Second
	DefaultPiFrameBytes   = int64(1) << 20
	DefaultPiOutputBytes  = int64(16) << 20
	DefaultPiStderrBytes  = 64 << 10
	DefaultPiCancelGrace  = 2 * time.Second
	PiProtocolVersion     = 1
)

// Pi configuration errors.
var (
	ErrPiStart       = errors.New("agent: pi worker failed to start")
	ErrPiProtocol    = errors.New("agent: pi worker broke the protocol")
	ErrPiOutput      = errors.New("agent: pi worker exceeded the output limit")
	ErrPiTimeout     = errors.New("agent: pi worker handshake timed out")
	ErrPiUnavailable = errors.New("agent: pi worker is not available")
)

// PiConfig is one deployment's worker. The command is fixed argv; nothing about
// it comes from a request.
type PiConfig struct {
	Name       string
	Command    []string
	WorkingDir string
	Timeout    time.Duration
	// Init is the private frame: model credentials and endpoint. It is written to
	// the worker and never logged, recorded or placed in an event.
	Init json.RawMessage
	// InitSource builds the private frame per run, so a frozen or rotated model
	// configuration is read at start, not at wiring time. It wins over Init.
	InitSource func() (json.RawMessage, error)
	// WorkerFile is the entrypoint the deployment claims to have installed. When
	// set, readiness requires it to exist; the command itself may carry flags.
	WorkerFile string
	// PinSource reports the model and config version used for the private init.
	PinSource func() (RuntimePin, error)
	// Tools are the native descriptors the worker may advertise; the host still
	// authorises every call against the run policy.
	Tools []ToolDescriptor
	Env   []string

	HelloTimeout   time.Duration
	MaxFrameBytes  int64
	MaxOutputBytes int64
	MaxStderrBytes int
	CancelGrace    time.Duration
}

// PiRuntime is the worker adapter.
type PiRuntime struct {
	cfg     PiConfig
	version string
}

// NewPiRuntime validates the configuration. A missing command or init is an
// operator error, refused at wiring time.
func NewPiRuntime(cfg PiConfig) (*PiRuntime, error) {
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, fmt.Errorf("%w: name is required", ErrPiUnavailable)
	}
	if len(cfg.Command) == 0 || strings.TrimSpace(cfg.Command[0]) == "" {
		return nil, fmt.Errorf("%w: command is required", ErrPiUnavailable)
	}
	if cfg.InitSource == nil && len(bytes.TrimSpace(cfg.Init)) == 0 {
		return nil, fmt.Errorf("%w: the private init frame is required", ErrPiUnavailable)
	}
	if cfg.HelloTimeout <= 0 {
		cfg.HelloTimeout = DefaultPiHelloTimeout
	}
	if cfg.MaxFrameBytes <= 0 || cfg.MaxFrameBytes > DefaultPiFrameBytes {
		cfg.MaxFrameBytes = DefaultPiFrameBytes
	}
	if cfg.MaxOutputBytes <= 0 || cfg.MaxOutputBytes > DefaultPiOutputBytes {
		cfg.MaxOutputBytes = DefaultPiOutputBytes
	}
	if cfg.MaxStderrBytes <= 0 || cfg.MaxStderrBytes > DefaultPiStderrBytes {
		cfg.MaxStderrBytes = DefaultPiStderrBytes
	}
	if cfg.CancelGrace <= 0 || cfg.CancelGrace > DefaultPiCancelGrace {
		cfg.CancelGrace = DefaultPiCancelGrace
	}
	return &PiRuntime{cfg: cfg, version: "1"}, nil
}

// SetTools fixes the native descriptors the worker may advertise. It is called at
// wiring time, after the registry and the allowlist are known.
func (r *PiRuntime) SetTools(tools []ToolDescriptor) {
	r.cfg.Tools = append([]ToolDescriptor(nil), tools...)
}

// Ready reports whether the deployment can actually run a worker: the node
// binary, the worker entrypoint and the model settings must all be usable.
func (r *PiRuntime) Ready() error {
	if _, err := exec.LookPath(r.cfg.Command[0]); err != nil {
		return fmt.Errorf("%w: %v", ErrPiUnavailable, err)
	}
	if r.cfg.WorkerFile != "" {
		if info, err := os.Stat(r.cfg.WorkerFile); err != nil || info.IsDir() {
			return fmt.Errorf("%w: worker entrypoint %s is not a file", ErrPiUnavailable, r.cfg.WorkerFile)
		}
	}
	if r.cfg.InitSource != nil {
		if _, err := r.cfg.InitSource(); err != nil {
			return fmt.Errorf("%w: %v", ErrPiUnavailable, err)
		}
	}
	return nil
}

// Capabilities declares turn control, because the worker cannot start a provider
// request without a permit.
func (r *PiRuntime) Capabilities() RuntimeCapabilities {
	return RuntimeCapabilities{
		Name: r.cfg.Name, Version: r.version, ToolCalls: true, TurnControl: true,
		TokenUsage: true, Streaming: true,
		Notes: []string{
			"fixed worker process per run, JSONL worker protocol v1",
			"no built-in filesystem, shell or network: tools are host-executed",
		},
	}
}

// piFrame is one worker protocol frame. Private init is a separate type so it
// cannot be logged by accident through this struct.
type piFrame struct {
	Type       string `json:"type"`
	V          int    `json:"v,omitempty"`
	RunID      string `json:"run_id,omitempty"`
	Generation int64  `json:"generation,omitempty"`
	Seq        int64  `json:"seq,omitempty"`
	RequestID  string `json:"request_id,omitempty"`
	ReplyTo    string `json:"reply_to,omitempty"`
	Worker     string `json:"worker,omitempty"`
	PiVersion  string `json:"pi_version,omitempty"`
	Node       string `json:"node,omitempty"`
	Status     string `json:"status,omitempty"`
	Code       string `json:"code,omitempty"`
	Message    string `json:"message,omitempty"`

	RoundID             string `json:"round_id,omitempty"`
	Model               string `json:"model,omitempty"`
	InputTokensEstimate int    `json:"input_tokens_estimate,omitempty"`
	MaxOutputTokens     int    `json:"max_output_tokens,omitempty"`
	EstimateBasis       string `json:"estimate_basis,omitempty"`
	ReservedTokens      int    `json:"reserved_tokens,omitempty"`

	CallID string          `json:"call_id,omitempty"`
	Tool   string          `json:"tool,omitempty"`
	Args   json.RawMessage `json:"args,omitempty"`
	OK     *bool           `json:"ok,omitempty"`
	Result string          `json:"result,omitempty"`
	Error  string          `json:"error,omitempty"`

	Raw      json.RawMessage `json:"raw,omitempty"`
	Decision string          `json:"decision,omitempty"`
	Reason   string          `json:"reason,omitempty"`

	InputTokens  int `json:"input_tokens,omitempty"`
	OutputTokens int `json:"output_tokens,omitempty"`

	Task         string           `json:"task,omitempty"`
	Instructions string           `json:"instructions,omitempty"`
	Tools        []ToolDescriptor `json:"tools,omitempty"`
	Limits       map[string]any   `json:"limits,omitempty"`
}

type piInitFrame struct {
	Type       string          `json:"type"`
	RunID      string          `json:"run_id"`
	Generation int64           `json:"generation"`
	Private    json.RawMessage `json:"private"`
}

// piWriter serialises frames from the adapter goroutine; writes happen one at a
// time, but cancellation can race a reply.
type piWriter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func (w *piWriter) send(frame any) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.enc.Encode(frame)
}

// Start launches the worker. The task's rendered projection and native tool
// descriptors come from the orchestrator context, not from the adapter.
func (r *PiRuntime) Start(ctx context.Context, task Task) (*Handle, error) {
	if err := ValidateTask(task); err != nil {
		return nil, err
	}
	rendered, ok := RenderedTaskFrom(ctx)
	if !ok {
		return nil, fmt.Errorf("%w: no rendered task was bound to the run", ErrPiProtocol)
	}
	init := r.cfg.Init
	if r.cfg.InitSource != nil {
		source, err := r.cfg.InitSource()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrPiUnavailable, err)
		}
		init = source
	}
	if len(bytes.TrimSpace(init)) == 0 {
		return nil, fmt.Errorf("%w: the private init frame is empty", ErrPiUnavailable)
	}
	runID := taskRunID(ctx, task)
	generation := RunGeneration(ctx)
	ctx, cancel := context.WithCancel(ctx)
	events, done := make(chan RuntimeEvent), make(chan RuntimeResult, 1)
	go func() {
		defer cancel()
		defer close(events)
		defer close(done)
		result := r.run(ctx, task, runID, generation, rendered, init, events)
		if result.Err != nil {
			result.ExitCode = -1
		}
		done <- result
	}()
	return &Handle{Events: events, Done: done, Cancel: cancel}, nil
}

func taskRunID(ctx context.Context, task Task) string {
	if id := RunIDFrom(ctx); id != "" {
		return id
	}
	return RunID(task.PathID, "pi", 1)
}

// run is the worker session: handshake, then a frame loop that translates worker
// requests into host events and waits for the host's decisions.
func (r *PiRuntime) run(ctx context.Context, task Task, runID string, generation int64, rendered string, init json.RawMessage, events chan<- RuntimeEvent) RuntimeResult {
	home, err := os.MkdirTemp("", "codexploit-pi-home-")
	if err != nil {
		return RuntimeResult{Err: fmt.Errorf("%w: private home: %v", ErrPiStart, err)}
	}
	defer os.RemoveAll(home)

	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	cmd := exec.CommandContext(runCtx, r.cfg.Command[0], r.cfg.Command[1:]...)
	cmd.Dir = r.cfg.WorkingDir
	if cmd.Dir == "" {
		cmd.Dir = home
	}
	env := append([]string{}, r.cfg.Env...)
	env = append(env, "HOME="+home, "TMPDIR="+home, "XDG_CONFIG_HOME="+home, "XDG_CACHE_HOME="+home)
	cmd.Env = minimalEnv(env)
	cmd.WaitDelay = cliWaitDelay
	cmd.Cancel = func() error {
		killProcessGroup(cmd)
		return nil
	}
	configureProcessGroup(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return RuntimeResult{Err: fmt.Errorf("%w: stdin: %v", ErrPiStart, err)}
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		return RuntimeResult{Err: fmt.Errorf("%w: stdout: %v", ErrPiStart, err)}
	}
	stderr := &tailBuffer{limit: r.cfg.MaxStderrBytes}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		return RuntimeResult{Err: fmt.Errorf("%w: %v", ErrPiStart, err)}
	}
	writer := &piWriter{enc: json.NewEncoder(stdin)}
	defer func() {
		_ = stdin.Close()
		killProcessGroup(cmd)
		_ = cmd.Wait()
	}()

	lines := make(chan []byte, 16)
	readErr := make(chan error, 1)
	go readStdoutLines(stdout, lines, readErr, r.cfg.MaxOutputBytes)

	// The worker speaks first. Nothing is sent before hello, so a process that
	// dies immediately is a start failure, not a half-written session.
	if result, ok := r.awaitHello(runCtx, lines, readErr, cmd, runID); !ok {
		return result
	}
	if err := writer.send(piInitFrame{Type: "init", RunID: runID, Generation: generation, Private: init}); err != nil {
		return RuntimeResult{Err: fmt.Errorf("%w: init frame: %v", ErrPiProtocol, err)}
	}
	start := piFrame{
		Type: "start", V: PiProtocolVersion, RunID: runID, Generation: generation,
		Task: rendered, Instructions: modelInstructions, Tools: r.piTools(task.Exploration.AllowedTools),
		Limits: map[string]any{
			"max_tool_calls":  task.Exploration.MaxToolCalls,
			"token_budget":    task.Budget.TokenBudget,
			"timeout_seconds": task.Exploration.TimeoutSeconds,
		},
	}
	if err := writer.send(start); err != nil {
		return RuntimeResult{Err: fmt.Errorf("%w: start frame: %v", ErrPiProtocol, err)}
	}

	var (
		sequence int64
		settled  bool
		result   RuntimeResult
		accepted bool
	)
	for {
		select {
		case <-runCtx.Done():
			_ = writer.send(piFrame{Type: "cancel", RunID: runID, Generation: generation, Reason: "run cancelled"})
			drainWithGrace(cmd, lines, r.cfg.CancelGrace)
			if accepted {
				return result
			}
			return RuntimeResult{Err: runCtx.Err()}
		case line, ok := <-lines:
			if !ok {
				if settled {
					return result
				}
				// A stream that ends before settled is a failed run: the worker may
				// not leave an answer half-accepted.
				if err := <-readErr; err != nil && !errors.Is(err, io.EOF) {
					return RuntimeResult{Err: fmt.Errorf("%w: %v", ErrPiOutput, err)}
				}
				return RuntimeResult{Err: fmt.Errorf("%w: the stream ended before settled: %s", ErrPiProtocol, strings.TrimSpace(stderr.String()))}
			}
			if int64(len(line)) > r.cfg.MaxFrameBytes {
				return RuntimeResult{Err: fmt.Errorf("%w: frame exceeds %d bytes", ErrPiProtocol, r.cfg.MaxFrameBytes)}
			}
			var frame piFrame
			if err := json.Unmarshal(line, &frame); err != nil {
				return RuntimeResult{Err: fmt.Errorf("%w: %v", ErrPiProtocol, err)}
			}
			if frame.RunID != "" && frame.RunID != runID {
				return RuntimeResult{Err: fmt.Errorf("%w: frame names run %q", ErrPiProtocol, frame.RunID)}
			}
			if frame.Generation != 0 && frame.Generation != generation {
				return RuntimeResult{Err: fmt.Errorf("%w: stale generation %d", ErrPiProtocol, frame.Generation)}
			}
			if frame.Type == "hello" {
				return RuntimeResult{Err: fmt.Errorf("%w: duplicate hello", ErrPiProtocol)}
			}
			if frame.Seq != 0 {
				if frame.Seq <= sequence {
					return RuntimeResult{Err: fmt.Errorf("%w: sequence %d did not advance past %d", ErrPiProtocol, frame.Seq, sequence)}
				}
				sequence = frame.Seq
			}

			switch frame.Type {
			case "request_permit":
				decision, ok := r.permit(runCtx, events, frame)
				if !ok {
					return RuntimeResult{Err: runCtx.Err()}
				}
				if err := writer.send(piFrame{Type: "permit_reply", RunID: runID, Generation: generation,
					ReplyTo: frame.RequestID, Decision: decision.Decision, Reason: decision.Reason, ReservedTokens: decision.ReservedTokens}); err != nil {
					return RuntimeResult{Err: fmt.Errorf("%w: %v", ErrPiProtocol, err)}
				}
			case "tool_request":
				reply, ok := r.tool(runCtx, events, frame)
				if !ok {
					return RuntimeResult{Err: runCtx.Err()}
				}
				if err := writer.send(piFrame{Type: "tool_result", RunID: runID, Generation: generation,
					ReplyTo: frame.RequestID, CallID: frame.CallID, Tool: frame.Tool,
					OK: &reply.OK, Result: reply.Result, Error: reply.Error}); err != nil {
					return RuntimeResult{Err: fmt.Errorf("%w: %v", ErrPiProtocol, err)}
				}
			case "answer_proposed":
				decision, ok := r.answer(runCtx, events, frame)
				if !ok {
					return RuntimeResult{Err: runCtx.Err()}
				}
				if decision.Decision == DecisionAccepted {
					accepted = true
				}
				if err := writer.send(piFrame{Type: "answer_reply", RunID: runID, Generation: generation,
					ReplyTo: frame.RequestID, Decision: decision.Decision, Reason: decision.Reason}); err != nil {
					return RuntimeResult{Err: fmt.Errorf("%w: %v", ErrPiProtocol, err)}
				}
			case "usage":
				sendEvent(runCtx, events, RuntimeEvent{Type: runtimeEventNote, Summary: "provider usage reported",
					RequestID: frame.RequestID, InputTokens: frame.InputTokens, OutputTokens: frame.OutputTokens})
			case "settled":
				settled = true
				if frame.Status != "" && frame.Status != "completed" {
					result.Err = fmt.Errorf("%w: worker settled as %s: %s", ErrPiProtocol, frame.Status, frame.Reason)
				}
			case "error":
				return RuntimeResult{Err: fmt.Errorf("%w: %s: %s", ErrPiProtocol, frame.Code, frame.Message)}
			default:
				return RuntimeResult{Err: fmt.Errorf("%w: unknown frame %q", ErrPiProtocol, frame.Type)}
			}
		}
	}
}

// awaitHello waits for the worker's hello inside the handshake window. It drains
// lines so a chatty worker cannot deadlock the pipe.
func (r *PiRuntime) awaitHello(ctx context.Context, lines <-chan []byte, readErr <-chan error, cmd *exec.Cmd, runID string) (RuntimeResult, bool) {
	timer := time.NewTimer(r.cfg.HelloTimeout)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return RuntimeResult{Err: ctx.Err()}, false
		case <-timer.C:
			killProcessGroup(cmd)
			return RuntimeResult{Err: fmt.Errorf("%w after %s", ErrPiTimeout, r.cfg.HelloTimeout)}, false
		case err := <-readErr:
			if err != nil && !errors.Is(err, io.EOF) {
				return RuntimeResult{Err: fmt.Errorf("%w: %v", ErrPiOutput, err)}, false
			}
			return RuntimeResult{Err: fmt.Errorf("%w: the worker closed stdout before hello", ErrPiProtocol)}, false
		case line, ok := <-lines:
			if !ok {
				return RuntimeResult{Err: fmt.Errorf("%w: the worker closed stdout before hello", ErrPiProtocol)}, false
			}
			if int64(len(line)) > r.cfg.MaxFrameBytes {
				return RuntimeResult{Err: fmt.Errorf("%w: hello exceeds %d bytes", ErrPiProtocol, r.cfg.MaxFrameBytes)}, false
			}
			var frame piFrame
			if err := json.Unmarshal(line, &frame); err != nil {
				return RuntimeResult{Err: fmt.Errorf("%w: hello is not JSON: %v", ErrPiProtocol, err)}, false
			}
			if frame.Type != "hello" {
				return RuntimeResult{Err: fmt.Errorf("%w: first frame is %q, want hello", ErrPiProtocol, frame.Type)}, false
			}
			if frame.V != 0 && frame.V != PiProtocolVersion {
				return RuntimeResult{Err: fmt.Errorf("%w: worker protocol %d, want %d", ErrPiProtocol, frame.V, PiProtocolVersion)}, false
			}
			if frame.RunID != "" && frame.RunID != runID {
				return RuntimeResult{Err: fmt.Errorf("%w: hello names run %q", ErrPiProtocol, frame.RunID)}, false
			}
			return RuntimeResult{}, true
		}
	}
}

func (r *PiRuntime) piTools(allowed []string) []ToolDescriptor {
	byName := map[string]ToolDescriptor{}
	for _, descriptor := range r.cfg.Tools {
		byName[descriptor.Name] = descriptor
	}
	out := make([]ToolDescriptor, 0, len(allowed))
	for _, name := range allowed {
		if descriptor, ok := byName[name]; ok {
			out = append(out, descriptor)
		}
	}
	return out
}

func (r *PiRuntime) permit(ctx context.Context, events chan<- RuntimeEvent, frame piFrame) (PermitDecision, bool) {
	reply := make(chan PermitDecision, 1)
	request := &PermitRequest{
		RequestID: frame.RequestID, RoundID: frame.RoundID, Generation: frame.Generation,
		Model: frame.Model, InputTokensEstimate: frame.InputTokensEstimate,
		MaxOutputTokens: frame.MaxOutputTokens, EstimateBasis: frame.EstimateBasis,
	}
	if !sendEvent(ctx, events, RuntimeEvent{Type: EventModelPermitRequested, RequestID: frame.RequestID, Permit: request, PermitReply: reply, Summary: "worker requests one provider request"}) {
		return PermitDecision{}, false
	}
	select {
	case decision := <-reply:
		return decision, true
	case <-ctx.Done():
		return PermitDecision{}, false
	}
}

func (r *PiRuntime) tool(ctx context.Context, events chan<- RuntimeEvent, frame piFrame) (ToolResult, bool) {
	reply := make(chan ToolResult, 1)
	request := &ToolRequest{CallID: frame.CallID, Tool: frame.Tool, Args: frame.Args}
	if !sendEvent(ctx, events, RuntimeEvent{Type: EventToolRequested, RequestID: frame.RequestID, Tool: request, ToolReply: reply, Summary: "worker requests one tool call"}) {
		return ToolResult{}, false
	}
	select {
	case result := <-reply:
		return result, true
	case <-ctx.Done():
		return ToolResult{}, false
	}
}

func (r *PiRuntime) answer(ctx context.Context, events chan<- RuntimeEvent, frame piFrame) (AnswerDecision, bool) {
	reply := make(chan AnswerDecision, 1)
	proposal := &AnswerProposal{RequestID: frame.RequestID, Raw: frame.Raw}
	if !sendEvent(ctx, events, RuntimeEvent{Type: EventAnswerProposed, RequestID: frame.RequestID, Proposal: proposal, ProposalReply: reply, Summary: "worker proposes a structured answer"}) {
		return AnswerDecision{}, false
	}
	select {
	case decision := <-reply:
		return decision, true
	case <-ctx.Done():
		return AnswerDecision{}, false
	}
}

// drainWithGrace gives the worker a bounded moment to exit after cancel before the
// process group is killed. The defer in run always kills, so this is the polite
// half of the rule.
func drainWithGrace(cmd *exec.Cmd, lines <-chan []byte, grace time.Duration) {
	deadline := time.After(grace)
	for {
		select {
		case _, ok := <-lines:
			if !ok {
				return
			}
		case <-deadline:
			killProcessGroup(cmd)
			return
		}
	}
}

// Pin reports the model and settings version the worker would receive. The
// worker and protocol versions are fixed by this adapter.
func (r *PiRuntime) Pin() (RuntimePin, error) {
	pin := RuntimePin{
		Runtime: "pi", RuntimeVersion: r.version, ProtocolVersion: "1",
		WorkerVersion: "1.3.0", PromptVersion: PromptVersion,
	}
	if r.cfg.PinSource == nil {
		return pin, nil
	}
	extra, err := r.cfg.PinSource()
	if err != nil {
		return pin, err
	}
	pin.Model, pin.ConfigVersion = extra.Model, extra.ConfigVersion
	return pin, nil
}
