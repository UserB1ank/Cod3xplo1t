package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The CLI adapter is tested by re-executing this test binary as the CLI. That
// costs no compilation step and works the same on linux, macos and windows, which
// matters because the process lifecycle — groups, pipes, deadlines — is exactly
// what differs per platform.
const (
	cliHelperEnv = "AGENT_CLI_HELPER"
	cliMarkerEnv = "AGENT_CLI_MARKER"

	modeAnswer        = "answer"
	modeTool          = "tool"
	modeGarbage       = "garbage"
	modeBadAnswer     = "bad-answer"
	modeUnknownType   = "unknown-type"
	modeFail          = "fail"
	modeFlood         = "flood"
	modeHang          = "hang"
	modeHangWithChild = "hang-with-child"
	modeMarker        = "marker"
	modeEnvReport     = "env-report"
	modeCwdReport     = "cwd-report"
	modeSlowAnswer    = "slow-answer"
	modeNoAnswer      = "no-answer"
)

// TestAgentCLIHelperProcess is not a test of its own: it is the body of the CLI the
// adapter tests spawn. A normal run leaves it a no-op. Everything it writes to
// stdout is protocol output, so it always ends in os.Exit: the test framework's
// own "PASS" line would otherwise be parsed as an event.
func TestAgentCLIHelperProcess(t *testing.T) {
	mode := os.Getenv(cliHelperEnv)
	if mode == "" {
		return
	}
	if mode == modeMarker {
		// The grandchild is not a CLI: it has no stdin to read. It exists only to
		// prove whether the process group reached it.
		time.Sleep(time.Second)
		_ = os.WriteFile(os.Getenv(cliMarkerEnv), []byte("survived"), 0o600)
		os.Exit(0)
	}
	var task Task
	if err := json.NewDecoder(os.Stdin).Decode(&task); err != nil {
		fmt.Fprintln(os.Stderr, "helper: cannot decode task:", err)
		os.Exit(2)
	}

	switch mode {
	case modeAnswer:
		cliHelperEmit(map[string]any{
			"type": runtimeEventNote, "summary": "task received", "detail": cliHelperTaskDetail(task),
		})
		cliHelperEmitAnswer(adapterTestAnswer(task))
	case modeTool:
		cliHelperEmit(map[string]any{
			"type": EventToolRequested, "summary": "want a graph query",
			"tool": map[string]any{"call_id": "call-1", "tool": "graph.query", "args": map[string]string{"symbol": "sym-1"}},
		})
		cliHelperEmit(map[string]any{
			"type": EventExpansionAsked, "summary": "want more room",
			"expansion": map[string]any{
				"target_node_id": "node-2", "purpose": "confirm the sink",
				"expected_gain": "one more hop", "estimated_cost": "1 hop",
			},
		})
		cliHelperEmitAnswer(adapterTestAnswer(task))
	case modeGarbage:
		fmt.Fprintln(os.Stdout, "this line is not JSON")
	case modeBadAnswer:
		cliHelperEmit(map[string]any{
			"type": EventOutputReceived,
			"answer": map[string]any{
				"schema_version": SchemaVersion,
				"security_goal":  task.SecurityGoal,
				"hypothesis": map[string]any{
					"statement":  "the input reaches the sink",
					"status":     HypothesisConfirmed,
					"confidence": "high",
				},
			},
		})
	case modeUnknownType:
		// The tool payload rides an unknown type on purpose: it must not become an
		// actionable request just because it was labelled differently.
		cliHelperEmit(map[string]any{
			"type": "sparkles", "summary": "not a protocol event",
			"detail": map[string]string{"origin": "helper"},
			"tool":   map[string]any{"call_id": "call-x", "tool": "shell.exec", "args": map[string]string{"cmd": "id"}},
		})
		cliHelperEmitAnswer(adapterTestAnswer(task))
	case modeFail:
		// The head is deliberately far from the end: only the last 4 KiB of stderr
		// may survive, and the test checks exactly that.
		fmt.Fprint(os.Stderr, "head-marker ")
		fmt.Fprint(os.Stderr, strings.Repeat("x", 8192))
		fmt.Fprintln(os.Stderr, " kaboom tail-marker")
		os.Exit(3)
	case modeFlood:
		// Valid protocol events, far more of them than the configured stdout
		// budget: the run must stop on the limit, not on a parse error.
		padding := strings.Repeat("x", 256)
		for i := 0; i < 512; i++ {
			cliHelperEmit(map[string]any{"type": runtimeEventNote, "summary": padding})
		}
	case modeHang:
		cliHelperEmit(map[string]any{"type": runtimeEventNote, "summary": "about to hang"})
		time.Sleep(60 * time.Second)
	case modeHangWithChild:
		child := exec.Command(os.Args[0], "-test.run=^TestAgentCLIHelperProcess$")
		// Later entries win in os/exec's environment dedup, so the grandchild gets
		// its own mode instead of inheriting this one.
		child.Env = append(os.Environ(),
			cliHelperEnv+"="+modeMarker,
			cliMarkerEnv+"="+os.Getenv(cliMarkerEnv))
		_ = child.Start()
		cliHelperEmit(map[string]any{"type": runtimeEventNote, "summary": "spawned a grandchild and hangs"})
		time.Sleep(60 * time.Second)
	case modeMarker:
		// Handled before the task is read: the grandchild has no stdin.
		os.Exit(0)
	case modeEnvReport:
		cliHelperEmit(map[string]any{
			"type": runtimeEventNote, "summary": "env report",
			"detail": map[string]string{
				"has_helper":      os.Getenv(cliHelperEnv),
				"has_configured":  os.Getenv("AGENT_CLI_EXTRA"),
				"has_parent_only": os.Getenv("AGENT_CLI_PARENT_ONLY"),
				"has_proxy":       os.Getenv("HTTP_PROXY"),
				"has_path":        os.Getenv("PATH"),
			},
		})
	case modeCwdReport:
		wd, err := os.Getwd()
		if err != nil {
			wd = "error: " + err.Error()
		}
		cliHelperEmit(map[string]any{
			"type": runtimeEventNote, "summary": "cwd report", "detail": map[string]string{"cwd": wd},
		})
	case modeSlowAnswer:
		cliHelperEmit(map[string]any{"type": runtimeEventNote, "summary": "thinking"})
		time.Sleep(300 * time.Millisecond)
		cliHelperEmitAnswer(adapterTestAnswer(task))
	case modeNoAnswer:
		// A clean exit with no structured output at all.
	default:
		fmt.Fprintln(os.Stderr, "helper: unknown mode", mode)
		os.Exit(2)
	}
	os.Exit(0)
}

func cliHelperEmit(payload map[string]any) {
	raw, err := json.Marshal(payload)
	if err != nil {
		fmt.Fprintln(os.Stderr, "helper: cannot marshal event:", err)
		os.Exit(2)
	}
	fmt.Fprintln(os.Stdout, string(raw))
}

func cliHelperEmitAnswer(answer Answer) {
	cliHelperEmit(map[string]any{"type": EventOutputReceived, "summary": "answer ready", "answer": answer})
}

// cliHelperTaskDetail echoes what the helper received on stdin, which is how the
// tests prove the task round-tripped as the protocol's struct and not as a blob.
func cliHelperTaskDetail(task Task) map[string]string {
	return map[string]string{
		"schema_version": strconv.Itoa(task.SchemaVersion),
		"path_id":        task.PathID,
		"security_goal":  task.SecurityGoal,
		"slice_count":    strconv.Itoa(len(task.MinimalCodeSlice)),
		"evidence_count": strconv.Itoa(len(task.EvidenceRefs)),
		"token_budget":   strconv.Itoa(task.Budget.TokenBudget),
		"allowed_tools":  strings.Join(task.Exploration.AllowedTools, ","),
	}
}

// cliTestRuntime builds a runtime that re-executes this test binary as the CLI.
func cliTestRuntime(t *testing.T, mode string, extraEnv ...string) *CLIRuntime {
	t.Helper()
	return cliTestRuntimeWith(t, CLIConfig{}, mode, extraEnv...)
}

func cliTestRuntimeWith(t *testing.T, cfg CLIConfig, mode string, extraEnv ...string) *CLIRuntime {
	t.Helper()
	if cfg.Name == "" {
		cfg.Name = "test-cli"
	}
	if cfg.Version == "" {
		cfg.Version = "0.0.1"
	}
	cfg.Command = []string{os.Args[0], "-test.run=^TestAgentCLIHelperProcess$"}
	cfg.Env = append([]string{cliHelperEnv + "=" + mode}, extraEnv...)
	if cfg.Timeout == 0 {
		cfg.Timeout = 10 * time.Second
	}
	if cfg.MaxOutputBytes == 0 {
		cfg.MaxOutputBytes = 1 << 20
	}
	adapter, err := NewCLIRuntime(cfg)
	if err != nil {
		t.Fatalf("NewCLIRuntime: %v", err)
	}
	return adapter
}

func TestCLIRuntimeCapabilities(t *testing.T) {
	adapter := cliTestRuntime(t, modeAnswer)
	caps := adapter.Capabilities()
	if caps.Name != "test-cli" || caps.Version != "0.0.1" {
		t.Fatalf("capabilities name/version = %q/%q", caps.Name, caps.Version)
	}
	if !caps.ToolCalls || !caps.Expansions || !caps.Streaming {
		t.Fatalf("documented defaults must be true: %+v", caps)
	}
	if caps.TokenUsage {
		t.Error("token usage must default to false when the CLI does not report it")
	}
	if caps.Resume {
		t.Error("a CLI session is not a process checkpoint")
	}
	if len(caps.Notes) == 0 {
		t.Error("capabilities must document the deployment contract")
	}

	on, err := NewCLIRuntime(CLIConfig{Name: "cli", Command: []string{"cli"}, TokenUsage: FeatureEnabled})
	if err != nil {
		t.Fatalf("NewCLIRuntime: %v", err)
	}
	if !on.Capabilities().TokenUsage {
		t.Error("an operator who asserts token usage must see it reported")
	}
	off, err := NewCLIRuntime(CLIConfig{Name: "cli", Command: []string{"cli"}, ToolCalls: FeatureDisabled})
	if err != nil {
		t.Fatalf("NewCLIRuntime: %v", err)
	}
	if off.Capabilities().ToolCalls {
		t.Error("an operator who disables tool calls must see them disabled")
	}
}

func TestNewCLIRuntimeValidatesConfig(t *testing.T) {
	cases := map[string]CLIConfig{
		"missing name":    {Command: []string{"cli"}},
		"missing command": {Name: "cli"},
		"empty argv0":     {Name: "cli", Command: []string{""}},
	}
	for label, cfg := range cases {
		if _, err := NewCLIRuntime(cfg); !errors.Is(err, ErrCLIConfig) {
			t.Errorf("%s: error = %v, want ErrCLIConfig", label, err)
		}
	}
}

func TestCLIRuntimeStartRejectsInvalidTask(t *testing.T) {
	adapter := cliTestRuntime(t, modeAnswer)
	if _, err := adapter.Start(context.Background(), Task{}); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("Start with an empty task = %v, want ErrInvalidTask", err)
	}
}

func TestCLIRuntimeAnswersAndRoundTripsTask(t *testing.T) {
	task := adapterTestTask()
	adapter := cliTestRuntime(t, modeAnswer)
	handle, err := adapter.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if result.Err != nil {
		t.Fatalf("run failed: %v", result.Err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}

	note := adapterEventOfType(events, runtimeEventNote)
	if note == nil {
		t.Fatalf("no note event; got %s", adapterEventTypes(events))
	}
	want := map[string]string{
		"schema_version": "1",
		"path_id":        task.PathID,
		"security_goal":  task.SecurityGoal,
		"slice_count":    "1",
		"evidence_count": "1",
		"token_budget":   strconv.Itoa(task.Budget.TokenBudget),
		"allowed_tools":  strings.Join(task.Exploration.AllowedTools, ","),
	}
	for key, value := range want {
		if note.Detail[key] != value {
			t.Errorf("task round-trip detail[%q] = %q, want %q", key, note.Detail[key], value)
		}
	}

	output := adapterEventOfType(events, EventOutputReceived)
	if output == nil || output.Answer == nil {
		t.Fatalf("output event missing an answer: %+v", output)
	}
	if result.Answer == nil || result.Answer.Hypothesis.Statement != output.Answer.Hypothesis.Statement {
		t.Fatalf("terminal answer = %+v", result.Answer)
	}
}

func TestCLIRuntimeRequestsToolsAndExpansions(t *testing.T) {
	task := adapterTestTask()
	adapter := cliTestRuntime(t, modeTool)
	handle, err := adapter.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if result.Err != nil {
		t.Fatalf("run failed: %v", result.Err)
	}

	requested := adapterEventOfType(events, EventToolRequested)
	if requested == nil || requested.Tool == nil || requested.Tool.Tool != "graph.query" {
		t.Fatalf("tool request missing: %+v", requested)
	}
	if err := ValidateToolRequest(*requested.Tool, task.Exploration, 0); err != nil {
		t.Fatalf("an allowlisted request must validate: %v", err)
	}
	expansion := adapterEventOfType(events, EventExpansionAsked)
	if expansion == nil || expansion.Expansion == nil || expansion.Expansion.TargetNodeID != "node-2" {
		t.Fatalf("expansion request missing: %+v", expansion)
	}
}

func TestCLIRuntimeRejectsMalformedStdout(t *testing.T) {
	adapter := cliTestRuntime(t, modeGarbage)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, ErrCLIProtocol) {
		t.Fatalf("result error = %v, want ErrCLIProtocol", result.Err)
	}
}

func TestCLIRuntimeRejectsConfirmedAnswer(t *testing.T) {
	adapter := cliTestRuntime(t, modeBadAnswer)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, ErrInvalidAnswer) {
		t.Fatalf("result error = %v, want ErrInvalidAnswer", result.Err)
	}
	if result.Answer != nil {
		t.Error("a rejected answer must not reach the result")
	}
	if adapterEventOfType(events, EventOutputRejected) == nil {
		t.Fatalf("no output_rejected event; got %s", adapterEventTypes(events))
	}
}

// TestCLIRuntimeFoldsUnknownTypeIntoNote is the forward-compatibility rule: a
// type this orchestrator does not know must not crash the run or be dropped.
func TestCLIRuntimeFoldsUnknownTypeIntoNote(t *testing.T) {
	adapter := cliTestRuntime(t, modeUnknownType)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if result.Err != nil {
		t.Fatalf("an unknown type must not fail the run: %v", result.Err)
	}
	var note *RuntimeEvent
	for i := range events {
		if events[i].Type == runtimeEventNote && events[i].Detail["reported_type"] == "sparkles" {
			note = &events[i]
		}
	}
	if note == nil {
		t.Fatalf("unknown type was not recorded as a note; got %s", adapterEventTypes(events))
	}
	if note.Detail["origin"] != "helper" {
		t.Errorf("note dropped the original detail: %+v", note.Detail)
	}
	if note.Tool != nil {
		t.Errorf("a tool payload on an unknown type must not survive as a request: %+v", note.Tool)
	}
	if adapterEventOfType(events, EventOutputReceived) == nil {
		t.Error("the answer after the unknown event was lost")
	}
}

func TestCLIRuntimeNonZeroExitCarriesStderrTail(t *testing.T) {
	adapter := cliTestRuntime(t, modeFail)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, ErrCLIExit) {
		t.Fatalf("result error = %v, want ErrCLIExit", result.Err)
	}
	if result.ExitCode != 3 {
		t.Fatalf("exit code = %d, want 3", result.ExitCode)
	}
	message := result.Err.Error()
	if !strings.Contains(message, "kaboom") || !strings.Contains(message, "tail-marker") {
		t.Errorf("error %q must carry the stderr tail", message)
	}
	if strings.Contains(message, "head-marker") {
		t.Errorf("error %q must keep only the last %d bytes of stderr", message, cliStderrLimit)
	}
}

func TestCLIRuntimeEnforcesOutputLimit(t *testing.T) {
	adapter := cliTestRuntimeWith(t, CLIConfig{MaxOutputBytes: 4096}, modeFlood)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, ErrCLIOutputLimit) {
		t.Fatalf("result error = %v, want ErrCLIOutputLimit", result.Err)
	}
}

func TestCLIRuntimeDeadlineKillsHangingProcess(t *testing.T) {
	adapter := cliTestRuntime(t, modeHang)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	handle, err := adapter.Start(ctx, adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	started := time.Now()
	// The run can only finish if the hanging process was actually killed: the
	// adapter waits for the process before it reports a result.
	_, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("result error = %v, want context.DeadlineExceeded", result.Err)
	}
	if elapsed := time.Since(started); elapsed > 10*time.Second {
		t.Fatalf("the run took %s after a 200ms deadline", elapsed)
	}
	if result.ExitCode != -1 {
		t.Fatalf("exit code = %d, want -1 for a killed process", result.ExitCode)
	}
}

func TestCLIRuntimeCancelStopsRun(t *testing.T) {
	adapter := cliTestRuntime(t, modeHang)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-handle.Events:
	case <-time.After(10 * time.Second):
		t.Fatal("no event arrived before cancellation")
	}
	handle.Cancel()
	handle.Cancel() // safe to call more than once

	_, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("result error = %v, want context.Canceled", result.Err)
	}
}

// TestCLIRuntimeProcessGroupKillReachesGrandchild covers the case that makes a
// process group necessary: the CLI exits but a process it spawned keeps running.
// Without a group kill the grandchild outlives the run and writes its marker.
func TestCLIRuntimeProcessGroupKillReachesGrandchild(t *testing.T) {
	if testing.Short() {
		t.Skip("process-group kill test waits for a grandchild timer")
	}
	marker := filepath.Join(t.TempDir(), "grandchild-marker")
	adapter := cliTestRuntime(t, modeHangWithChild, cliMarkerEnv+"="+marker)
	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()
	handle, err := adapter.Start(ctx, adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("result error = %v, want context.DeadlineExceeded", result.Err)
	}
	// The grandchild writes its marker one second after it started. Waiting past
	// that moment is what turns "no marker" into evidence that it was killed.
	time.Sleep(2 * time.Second)
	if _, err := os.Stat(marker); err == nil {
		t.Fatal("the grandchild survived the run: the process group was not killed")
	}
}

func TestCLIRuntimeEmitsHeartbeats(t *testing.T) {
	adapter := cliTestRuntimeWith(t, CLIConfig{HeartbeatInterval: 30 * time.Millisecond}, modeSlowAnswer)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if result.Err != nil {
		t.Fatalf("run failed: %v", result.Err)
	}
	if adapterCountEvents(events, EventRunHeartbeat) == 0 {
		t.Fatalf("no heartbeat events; got %s", adapterEventTypes(events))
	}
}

// TestCLIRuntimeMinimalEnvironment pins the egress default: the child sees the
// configured environment plus PATH/HOME/TMPDIR and nothing else. A parent proxy
// variable in particular must not leak in by accident.
func TestCLIRuntimeMinimalEnvironment(t *testing.T) {
	t.Setenv("AGENT_CLI_PARENT_ONLY", "parent-secret")
	t.Setenv("HTTP_PROXY", "http://proxy.invalid:3128")

	adapter := cliTestRuntime(t, modeEnvReport, "AGENT_CLI_EXTRA=visible")
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if result.Err != nil {
		t.Fatalf("run failed: %v", result.Err)
	}
	note := adapterEventOfType(events, runtimeEventNote)
	if note == nil {
		t.Fatalf("no env report; got %s", adapterEventTypes(events))
	}
	checks := map[string]string{
		"has_configured":  "visible",
		"has_parent_only": "",
		"has_proxy":       "",
	}
	for key, want := range checks {
		if got := note.Detail[key]; got != want {
			t.Errorf("detail[%q] = %q, want %q", key, got, want)
		}
	}
	if note.Detail["has_path"] == "" {
		t.Error("PATH must be passed so the CLI can run")
	}
	if note.Detail["has_helper"] == "" {
		t.Error("the configured environment must reach the child")
	}
}

func TestCLIRuntimeRunsInWorkingDirectory(t *testing.T) {
	dir := t.TempDir()
	adapter := cliTestRuntimeWith(t, CLIConfig{WorkingDir: dir}, modeCwdReport)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if result.Err != nil {
		t.Fatalf("run failed: %v", result.Err)
	}
	note := adapterEventOfType(events, runtimeEventNote)
	if note == nil {
		t.Fatalf("no cwd report; got %s", adapterEventTypes(events))
	}
	if !adapterSamePath(dir, note.Detail["cwd"]) {
		t.Fatalf("child working directory = %q, want %q", note.Detail["cwd"], dir)
	}
}

// TestCLIRuntimeCleanExitWithoutAnswer records the documented behaviour for a CLI
// that exits cleanly and produces nothing: the adapter does not invent a failure,
// and it does not invent an answer either.
func TestCLIRuntimeCleanExitWithoutAnswer(t *testing.T) {
	adapter := cliTestRuntime(t, modeNoAnswer)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 15*time.Second)
	if result.Err != nil {
		t.Fatalf("clean exit reported as an error: %v", result.Err)
	}
	if result.Answer != nil {
		t.Error("no answer was produced, so none may be reported")
	}
	if len(events) != 0 {
		t.Fatalf("unexpected events: %s", adapterEventTypes(events))
	}
}

func TestCLIRuntimeTimeoutStopsSilentProcess(t *testing.T) {
	adapter := cliTestRuntimeWith(t, CLIConfig{Timeout: 200 * time.Millisecond}, modeHang)
	handle, err := adapter.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, result := adapterCollectRun(t, handle, 15*time.Second)
	if !errors.Is(result.Err, ErrCLITimeout) {
		t.Fatalf("result error = %v, want ErrCLITimeout", result.Err)
	}
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Errorf("a timeout must also satisfy context.DeadlineExceeded: %v", result.Err)
	}
}

// adapterSamePath compares directories the way an operating system would: through
// symlinks on unix, and case-insensitively on windows.
func adapterSamePath(want, got string) bool {
	if resolved, err := filepath.EvalSymlinks(want); err == nil {
		want = resolved
	}
	if resolved, err := filepath.EvalSymlinks(got); err == nil {
		got = resolved
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(want, got)
	}
	return want == got
}
