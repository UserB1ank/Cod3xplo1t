package agent

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// CLIRuntime adapts a real agent CLI — Claude Code, DSH, OpenCode, or anything
// else that speaks the protocol — to the Runtime interface. It is how the design's
// "first version is a CLI adapter" is realised without binding the product to one
// vendor: the contract is the process boundary, not an SDK.
//
// The adapter owns one process and nothing else. It never receives the lease, the
// budget controller or the tool registry, so a CLI cannot widen its own limits by
// asking nicely; every request it emits is decided by the orchestrator.
//
// Deployment contract (design §11): Go can bound a subprocess' environment,
// deadline, output and process group, but it cannot fully network-sandbox it.
// Adapters must therefore be run in a restricted container or VM, with no egress
// by default, and with the task's MinimalCodeSlice materialised read-only. The
// adapter itself never writes source files.

// DefaultCLIMaxOutputBytes bounds the stdout an adapter will read when
// CLIConfig.MaxOutputBytes is unset. A CLI that streams a transcript would
// otherwise be able to fill memory before the answer is validated.
const DefaultCLIMaxOutputBytes int64 = 4 << 20

const (
	// cliWaitDelay bounds how long a finished or cancelled process may keep its
	// pipes open. Without it, a CLI that spawned a grandchild which inherited
	// stdout would leave the adapter waiting for an EOF that never comes.
	cliWaitDelay = 5 * time.Second
	// cliStderrLimit keeps only the tail of stderr: enough to explain an exit,
	// small enough that a chatty child cannot exhaust memory.
	cliStderrLimit = 4 << 10
	// cliEventBuffer is the event channel capacity. It absorbs a burst of decoded
	// events while the orchestrator is busy elsewhere without hiding back-pressure.
	cliEventBuffer = 16
	// cliMaxSummaryChars caps an event summary at the protocol's statement bound.
	// A summary is a short explicit statement; truncating it is what keeps "no
	// hidden reasoning" a limit rather than a request.
	cliMaxSummaryChars = MaxStatementChars
	// cliReadBuffer is the stdout line buffer size.
	cliReadBuffer = 64 << 10
)

// Errors a CLI run can end with. Each one names a different operator action:
// a config mistake, a missing binary, a failing CLI, a runaway CLI, a deadline and
// a CLI that does not follow the protocol are not the same problem.
var (
	ErrCLIConfig      = errors.New("agent: invalid cli runtime config")
	ErrCLIStart       = errors.New("agent: cli runtime failed to start")
	ErrCLIExit        = errors.New("agent: cli runtime exited with an error")
	ErrCLIOutputLimit = errors.New("agent: cli runtime exceeded the stdout limit")
	ErrCLITimeout     = errors.New("agent: cli runtime timed out")
	ErrCLIProtocol    = errors.New("agent: cli runtime broke the event protocol")
)

// errOutputLimit is raised by the bounded stdout reader and translated into
// ErrCLIOutputLimit once the process has been stopped.
var errOutputLimit = errors.New("agent: cli stdout limit reached")

// CLIFeature is a tri-state capability declaration.
//
// It exists because Go's zero value for bool cannot say "unset": an operator who
// configures nothing must get each capability's documented default, not false.
type CLIFeature uint8

const (
	// FeatureDefault uses the capability's documented default.
	FeatureDefault CLIFeature = iota
	// FeatureEnabled asserts the CLI speaks this part of the protocol.
	FeatureEnabled
	// FeatureDisabled asserts it does not, so the orchestrator does not build a
	// task the CLI cannot honour.
	FeatureDisabled
)

// Enabled resolves the tri-state against the capability's documented default.
func (f CLIFeature) Enabled(fallback bool) bool {
	switch f {
	case FeatureEnabled:
		return true
	case FeatureDisabled:
		return false
	default:
		return fallback
	}
}

// CLIConfig configures one CLI adapter.
type CLIConfig struct {
	// Name and Version identify the adapter in the run record.
	Name    string
	Version string
	// Command is the argv of the CLI. It is executed directly, never through a
	// shell: a task is structured input, not a command line.
	Command []string
	// Env is the complete allowlist of extra environment entries, in "KEY=VALUE"
	// form. Nothing else is inherited except PATH, HOME and TMPDIR (plus
	// SystemRoot on Windows), so a parent's proxy credentials are not leaked into
	// an agent process; an operator who wants egress through a proxy must name the
	// proxy variable here explicitly. Configured entries win over inherited ones.
	Env []string
	// WorkingDir, when set, is the process' working directory. The orchestrator is
	// expected to have materialised the task's MinimalCodeSlice there read-only.
	// The adapter never writes source files.
	WorkingDir string
	// Timeout bounds the run in addition to ctx. Zero means ctx alone bounds it,
	// which is the usual case: the orchestrator owns the deadline.
	Timeout time.Duration
	// MaxOutputBytes bounds stdout. Zero or negative uses
	// DefaultCLIMaxOutputBytes; exceeding it stops the run with ErrCLIOutputLimit.
	MaxOutputBytes int64
	// HeartbeatInterval emits run_heartbeat events while the run is in progress, so
	// the orchestrator can tell a quiet CLI from a dead one. Zero disables them.
	HeartbeatInterval time.Duration
	// ToolCalls declares whether the CLI emits tool_requested events. It defaults
	// to true: the protocol defines them and an adapter is expected to honour it.
	// An adapter that cannot speak them gets a task without a tool budget.
	ToolCalls CLIFeature
	// Expansions declares whether the CLI emits expansion_requested events. It
	// defaults to true for the same reason.
	Expansions CLIFeature
	// TokenUsage declares whether the CLI reports input_tokens/output_tokens. It
	// defaults to false: a CLI that never reports usage must not make the
	// orchestrator believe the token budget is enforced.
	TokenUsage CLIFeature
}

// CLIRuntime is the subprocess adapter for one CLI.
type CLIRuntime struct {
	cfg CLIConfig
}

// Compile-time proof that the adapter honours the contract.
var _ Runtime = (*CLIRuntime)(nil)

// NewCLIRuntime validates the configuration. A missing command is refused here
// rather than at Start, because it is an operator error and belongs at wiring time.
func NewCLIRuntime(cfg CLIConfig) (*CLIRuntime, error) {
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, fmt.Errorf("%w: name is required: an unattributed run cannot be audited", ErrCLIConfig)
	}
	if len(cfg.Command) == 0 || strings.TrimSpace(cfg.Command[0]) == "" {
		return nil, fmt.Errorf("%w: command is required", ErrCLIConfig)
	}
	return &CLIRuntime{cfg: cfg}, nil
}

// Config returns the configuration the adapter was built with.
func (r *CLIRuntime) Config() CLIConfig { return r.cfg }

// Capabilities reports what the adapter was configured to provide. Streaming is
// inherent to reading events as the process runs; Resume is false because a CLI
// session is not a process checkpoint, which is why the orchestrator persists
// evidence and rebuilds context instead of trusting a session (design §10).
func (r *CLIRuntime) Capabilities() RuntimeCapabilities {
	return RuntimeCapabilities{
		Name:       r.cfg.Name,
		Version:    r.cfg.Version,
		ToolCalls:  r.cfg.ToolCalls.Enabled(true),
		Expansions: r.cfg.Expansions.Enabled(true),
		Streaming:  true,
		TokenUsage: r.cfg.TokenUsage.Enabled(false),
		Resume:     false,
		Notes: []string{
			"subprocess adapters cannot be fully network-sandboxed by Go alone: run them in a restricted container or VM with no egress by default (design section 11)",
			"the adapter never writes source files; when WorkingDir is set the orchestrator must have materialised the task's MinimalCodeSlice there read-only",
			"only the configured Env is passed, plus PATH, HOME and TMPDIR: proxy variables are not inherited unless the operator names them",
			"cannot resume: a CLI session is not a process checkpoint",
			"unknown event types are recorded as notes; malformed stdout stops the run",
		},
	}
}

// Start validates the task and launches the CLI. stdout is parsed as
// newline-delimited JSON events; stderr is captured and attached to the run error.
func (r *CLIRuntime) Start(ctx context.Context, task Task) (*Handle, error) {
	if err := ValidateTask(task); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	runCtx, cancel := context.WithCancel(ctx)
	events := make(chan RuntimeEvent, cliEventBuffer)
	done := make(chan RuntimeResult, 1)
	var once sync.Once
	handle := &Handle{
		Events: events,
		Done:   done,
		Cancel: func() { once.Do(cancel) },
	}
	go r.run(runCtx, task, events, done)
	return handle, nil
}

// run owns one process for its whole life: start, stream, stop, reap, classify.
// It is deliberately linear. Cancellation is a context plus a process-group kill,
// not a race between goroutines, so a child that spawns grandchildren cannot
// outlive the run.
func (r *CLIRuntime) run(parent context.Context, task Task, events chan<- RuntimeEvent, done chan<- RuntimeResult) {
	result := RuntimeResult{ExitCode: -1}
	defer close(done)
	defer func() { done <- result }()
	defer close(events)

	runCtx, stop := context.WithCancel(parent)
	defer stop()
	// Our own timeout is tracked separately from the parent's context so the run
	// error can say which deadline expired; the parent's error is reported as is.
	var timedOut atomic.Bool
	if r.cfg.Timeout > 0 {
		timer := time.AfterFunc(r.cfg.Timeout, func() {
			timedOut.Store(true)
			stop()
		})
		defer timer.Stop()
	}
	if err := runCtx.Err(); err != nil {
		result.Err = err
		return
	}

	outputLimit := r.cfg.MaxOutputBytes
	if outputLimit <= 0 {
		outputLimit = DefaultCLIMaxOutputBytes
	}

	cmd := exec.CommandContext(runCtx, r.cfg.Command[0], r.cfg.Command[1:]...)
	cmd.Dir = r.cfg.WorkingDir
	cmd.Env = minimalEnv(r.cfg.Env)
	// WaitDelay together with Cancel is what makes a runaway or cancelled CLI
	// bounded: the context stops the process group, and WaitDelay stops the
	// adapter from waiting forever on a pipe a surviving grandchild still holds.
	cmd.WaitDelay = cliWaitDelay
	cmd.Cancel = func() error {
		killProcessGroup(cmd)
		return nil
	}
	configureProcessGroup(cmd)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		result.Err = fmt.Errorf("%w: stdin: %v", ErrCLIStart, err)
		return
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		_ = stdin.Close()
		result.Err = fmt.Errorf("%w: stdout: %v", ErrCLIStart, err)
		return
	}
	stderr := &tailBuffer{limit: cliStderrLimit}
	cmd.Stderr = stderr

	if err := cmd.Start(); err != nil {
		_ = stdin.Close()
		result.Err = fmt.Errorf("%w: %v", ErrCLIStart, err)
		return
	}

	lines := make(chan []byte, cliEventBuffer)
	readErr := make(chan error, 1)
	waitCh := make(chan error, 1)
	go readStdoutLines(stdout, lines, readErr, outputLimit)
	go func() { waitCh <- cmd.Wait() }()
	go writeTaskJSON(stdin, task)

	var (
		linesClosed bool
		processDone bool
		processErr  error
		failure     error
		answer      *Answer
		cancelled   bool
	)
	parentDone := parent.Done()
	started := time.Now()

	var tick <-chan time.Time
	if r.cfg.HeartbeatInterval > 0 {
		ticker := time.NewTicker(r.cfg.HeartbeatInterval)
		defer ticker.Stop()
		tick = ticker.C
	}

	// The loop ends only when the process is reaped and stdout has been fully
	// drained, so no event is ever dropped by an early exit.
	for !(processDone && linesClosed) {
		select {
		case line, ok := <-lines:
			if !ok {
				linesClosed = true
				lines = nil
				if readErrVal := <-readErr; readErrVal != nil && failure == nil {
					switch {
					case errors.Is(readErrVal, errOutputLimit):
						failure = fmt.Errorf("%w: the process wrote more than %d bytes to stdout", ErrCLIOutputLimit, outputLimit)
						stop()
					case runCtx.Err() == nil:
						// A read error while the run is live means stdout was not
						// the event stream the protocol promised.
						failure = fmt.Errorf("%w: %v", ErrCLIProtocol, readErrVal)
						stop()
					}
				}
				continue
			}
			if failure != nil {
				// Still drain: the reader must never block on a full buffer while
				// the process is being stopped.
				continue
			}
			decoded, err := r.handleLine(runCtx, events, task, line)
			if err != nil {
				failure = err
				stop()
				continue
			}
			if decoded != nil {
				answer = decoded
			}
		case err := <-waitCh:
			processDone = true
			processErr = err
			waitCh = nil
		case <-parentDone:
			// Nil the channel so a cancelled parent does not spin the loop.
			cancelled = true
			stop()
			parentDone = nil
		case <-tick:
			sendEvent(runCtx, events, RuntimeEvent{
				Type:    EventRunHeartbeat,
				Summary: "cli runtime is alive",
				Detail:  map[string]string{"elapsed_ms": fmt.Sprint(time.Since(started).Milliseconds())},
			})
		}
	}

	if processErr != nil {
		result.ExitCode = exitCodeOf(processErr)
	} else {
		result.ExitCode = 0
	}
	switch {
	case failure != nil:
		result.Err = failure
	case timedOut.Load():
		// Both sentinels are wrapped so callers can test either one.
		result.Err = fmt.Errorf("%w: %w", ErrCLITimeout, context.DeadlineExceeded)
	case cancelled || parent.Err() != nil:
		result.Err = parent.Err()
		if result.Err == nil {
			result.Err = context.Canceled
		}
	case processErr != nil:
		result.Err = fmt.Errorf("%w: %v", ErrCLIExit, processErr)
	}
	if result.Err != nil {
		result.Err = attachStderr(result.Err, stderr)
		return
	}
	// A clean exit without an answer is not an adapter failure: the orchestrator
	// records INVALID_OUTPUT from a missing answer, and it never trusts this field
	// without validating it again anyway.
	result.Answer = answer
}

// cliEvent is the newline-delimited JSON shape a CLI writes to stdout. Unknown
// envelope fields are ignored so the protocol can grow without breaking older
// adapters; the answer itself is still decoded strictly by DecodeAnswer.
type cliEvent struct {
	Type         string            `json:"type"`
	Summary      string            `json:"summary"`
	Detail       map[string]string `json:"detail"`
	Tool         *ToolRequest      `json:"tool"`
	Expansion    *ExpansionAsk     `json:"expansion"`
	Answer       json.RawMessage   `json:"answer"`
	InputTokens  int               `json:"input_tokens"`
	OutputTokens int               `json:"output_tokens"`
}

// handleLine turns one stdout line into at most one runtime event. Malformed JSON
// is a protocol failure: only an unknown *type* is forgiven, because a CLI cannot
// be expected to know every future event and must not be able to smuggle a
// transcript in as one.
func (r *CLIRuntime) handleLine(ctx context.Context, events chan<- RuntimeEvent, task Task, line []byte) (*Answer, error) {
	trimmed := bytes.TrimSpace(line)
	if len(trimmed) == 0 {
		return nil, nil
	}
	var wire cliEvent
	if err := json.Unmarshal(trimmed, &wire); err != nil {
		return nil, fmt.Errorf("%w: stdout is not a JSON event: %v", ErrCLIProtocol, err)
	}
	event, answer, err := r.eventFromWire(wire, task)
	if err != nil {
		sendEvent(ctx, events, RuntimeEvent{
			Type:    EventOutputRejected,
			Summary: "cli output rejected by the protocol",
			Detail:  map[string]string{"error": err.Error()},
		})
		return nil, err
	}
	if !sendEvent(ctx, events, event) {
		return nil, ctx.Err()
	}
	return answer, nil
}

// eventFromWire maps one decoded envelope onto a RuntimeEvent. An absent type is
// inferred from the payload; an unknown type becomes a note that keeps the
// original name in its detail. The answer is the only field decoded strictly, and
// it goes through DecodeAnswer so the adapter cannot be more permissive than the
// protocol.
func (r *CLIRuntime) eventFromWire(wire cliEvent, task Task) (RuntimeEvent, *Answer, error) {
	reported := strings.TrimSpace(wire.Type)
	resolved := reported
	if resolved == "" {
		switch {
		case len(bytes.TrimSpace(wire.Answer)) > 0:
			resolved = EventOutputReceived
		case wire.Tool != nil:
			resolved = EventToolRequested
		case wire.Expansion != nil:
			resolved = EventExpansionAsked
		default:
			resolved = runtimeEventNote
		}
	}

	event := RuntimeEvent{
		Type:         resolved,
		Summary:      truncateSummary(wire.Summary),
		Detail:       wire.Detail,
		Tool:         wire.Tool,
		Expansion:    wire.Expansion,
		InputTokens:  wire.InputTokens,
		OutputTokens: wire.OutputTokens,
	}
	if !knownRuntimeEvent(resolved) {
		// An unknown type is recorded as a note and nothing else: its payload is
		// not a request the orchestrator may act on, so it is dropped rather than
		// passed along with an unfamiliar label.
		return RuntimeEvent{
			Type:    runtimeEventNote,
			Summary: event.Summary,
			Detail:  mergeDetail(wire.Detail, "reported_type", reported),
		}, nil, nil
	}

	if resolved != EventOutputReceived {
		return event, nil, nil
	}
	if len(bytes.TrimSpace(wire.Answer)) == 0 {
		// An output event without an answer carries nothing to validate.
		return event, nil, nil
	}
	answer, err := DecodeAnswer(wire.Answer, task)
	if err != nil {
		return RuntimeEvent{}, nil, err
	}
	event.Answer = answer
	return event, answer, nil
}

// knownRuntimeEvents is the protocol vocabulary. Anything outside it is a note.
var knownRuntimeEvents = map[string]bool{
	EventRunCreated:       true,
	EventRunStarted:       true,
	EventTaskDelivered:    true,
	EventToolRequested:    true,
	EventToolAllowed:      true,
	EventToolResult:       true,
	EventToolDenied:       true,
	EventExpansionAsked:   true,
	EventExpansionDecided: true,
	EventOutputReceived:   true,
	EventOutputRejected:   true,
	EventHypothesis:       true,
	EventRunHeartbeat:     true,
	EventRunFinished:      true,
	EventRunError:         true,
	runtimeEventNote:      true,
}

func knownRuntimeEvent(eventType string) bool { return knownRuntimeEvents[eventType] }

// readStdoutLines splits stdout into lines and reports the terminal read error.
// It sends the error before closing lines, so a receiver that sees the channel
// closed can read the reason without racing the goroutine.
func readStdoutLines(stdout io.Reader, lines chan<- []byte, readErr chan<- error, limit int64) {
	var terminal error
	defer func() {
		readErr <- terminal
		close(lines)
	}()
	reader := bufio.NewReaderSize(&limitedReader{reader: stdout, remaining: limit}, cliReadBuffer)
	for {
		line, err := reader.ReadBytes('\n')
		// A line is an event only when it is complete. A final line without a
		// newline is complete (EOF ends it); a line cut short by a read error is
		// not, and parsing it would report a malformed event instead of the
		// truncation that caused it.
		if len(line) > 0 && (err == nil || errors.Is(err, io.EOF)) {
			lines <- line
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				terminal = err
			}
			return
		}
	}
}

// limitedReader fails closed once MaxOutputBytes has been read. When the stream
// ends exactly at the limit it probes one byte so a task that fills the budget to
// the byte is not mistaken for one that overran it.
type limitedReader struct {
	reader    io.Reader
	remaining int64
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.remaining <= 0 {
		var probe [1]byte
		n, err := l.reader.Read(probe[:])
		if n > 0 {
			return 0, errOutputLimit
		}
		return 0, err
	}
	if int64(len(p)) > l.remaining {
		p = p[:l.remaining]
	}
	n, err := l.reader.Read(p)
	l.remaining -= int64(n)
	return n, err
}

// writeTaskJSON delivers the task as one JSON document and closes stdin. The
// write error is deliberately ignored: a CLI that refuses the task reports it
// through its exit status, and EPIPE here means the same thing.
func writeTaskJSON(stdin io.WriteCloser, task Task) {
	defer stdin.Close()
	raw, err := json.Marshal(task)
	if err != nil {
		return
	}
	raw = append(raw, '\n')
	_, _ = stdin.Write(raw)
}

// minimalEnv builds the child's environment: the configured entries plus the few
// variables a process needs to function. Proxy variables are conspicuously not
// inherited — the default is no network egress, and egress must be configured.
func minimalEnv(configured []string) []string {
	inherited := []string{"PATH", "HOME", "TMPDIR"}
	if runtime.GOOS == "windows" {
		// The Windows loader resolves DLLs through SystemRoot; without it a child
		// can fail before it runs any code. It carries no policy.
		inherited = append(inherited, "SystemRoot")
	}
	env := make(map[string]string, len(inherited)+len(configured))
	for _, key := range inherited {
		if value, ok := os.LookupEnv(key); ok && value != "" {
			env[key] = value
		}
	}
	for _, entry := range configured {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(key) == "" {
			continue
		}
		env[key] = value
	}
	keys := make([]string, 0, len(env))
	for key := range env {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+env[key])
	}
	return out
}

// tailBuffer keeps the last limit bytes written to it. stderr is copied by
// os/exec's own goroutine, which may still be writing after Wait returns when
// WaitDelay expires, so the ring is mutex-guarded.
type tailBuffer struct {
	mu    sync.Mutex
	buf   []byte
	limit int
}

func (b *tailBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	if b.limit <= 0 {
		return n, nil
	}
	if len(p) >= b.limit {
		b.buf = append(b.buf[:0], p[len(p)-b.limit:]...)
		return n, nil
	}
	if over := len(b.buf) + len(p) - b.limit; over > 0 {
		b.buf = append(b.buf[:0], b.buf[over:]...)
	}
	b.buf = append(b.buf, p...)
	return n, nil
}

func (b *tailBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.buf))
}

// attachStderr explains an exit with the tail of what the CLI said. It is
// collapsed to one line so a run error stays readable in a log, and it stays
// bounded because the capture is bounded.
func attachStderr(err error, stderr *tailBuffer) error {
	if err == nil {
		return nil
	}
	text := stderr.String()
	if text == "" {
		return err
	}
	return fmt.Errorf("%w (stderr: %s)", err, strings.Join(strings.Fields(text), " "))
}

// exitCodeOf reports the process exit status, or -1 when the process was killed
// by a signal or never ran to completion.
func exitCodeOf(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}

// truncateSummary caps an event summary at the protocol's statement bound, on a
// rune boundary so the result stays valid UTF-8.
func truncateSummary(summary string) string {
	if len(summary) <= cliMaxSummaryChars {
		return summary
	}
	cut := cliMaxSummaryChars
	for cut > 0 && !utf8.RuneStart(summary[cut]) {
		cut--
	}
	return summary[:cut]
}

// mergeDetail copies a detail map with one key added: the wire map belongs to the
// decoded line, and the emitted event should own its own data.
func mergeDetail(detail map[string]string, key, value string) map[string]string {
	merged := make(map[string]string, len(detail)+1)
	for k, v := range detail {
		merged[k] = v
	}
	merged[key] = value
	return merged
}
