package verify

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The executors are tested without a real toolchain wherever the behaviour is the
// executor's own: the scripted replay covers the contract and the refusal paths,
// and the subprocess executor is driven through its Execution seam so output
// bounding, timeouts and the network refusal are deterministic on linux, macos and
// windows alike. The one thing that must be a real process is argv handling, which
// is checked by re-executing the test binary as the command.

// --- fixtures ----------------------------------------------------------------

// executorPlan builds a plan that passes Prepare, for executor-level tests.
func executorPlan(t *testing.T, steps ...Step) Plan {
	t.Helper()
	plan := Plan{
		SchemaVersion: SchemaVersion,
		HypothesisID:  "hyp-exec-1",
		FindingID:     FindingID("hyp-exec-1"),
		PathID:        "path-exec-1",
		AuditID:       "audit-exec-1",
		SnapshotID:    "snap-exec-1",
		SecurityGoal:  "prevent unauthorized file read",
		Claim:         "the export endpoint reads a path from the request",
		Steps:         steps,
		Environment:   DefaultEnvironment(),
		Scope:         Scope{Repository: "repo-1", SnapshotID: "snap-exec-1", AuthorizedBy: "operator-1"},
		GeneratedAt:   "2024-01-01T00:00:00Z",
		Limitations:   []string{"dynamic proof requires a deployed target"},
	}
	if len(steps) == 0 {
		plan.Steps = []Step{commandStep("prove the read", "the request is rejected")}
	}
	prepared, err := Prepare(plan)
	if err != nil {
		t.Fatalf("fixture plan does not pass Prepare: %v", err)
	}
	return prepared.Plan
}

// commandStep is one runnable step with the statement of what it expects and what
// would disprove it.
func commandStep(expectation, contradiction string) Step {
	return Step{
		Kind:          StepStaticCheck,
		Command:       []string{"echo", "observation"},
		Expectation:   expectation,
		Contradiction: contradiction,
	}
}

func intPtr(value int) *int { return &value }

// --- ScriptedExecutor --------------------------------------------------------

func TestScriptedExecutorConfirmedBuildsEvidence(t *testing.T) {
	plan := executorPlan(t, commandStep("the read succeeds", "the read is rejected"))
	executor := NewScriptedExecutor([]StepOutcome{{
		Kind: EvidenceRuntimeLog, ExitCode: intPtr(0),
		Content: "step[0] echo observation\nexit_code=0\nread /etc/passwd succeeded",
	}})

	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !executor.Capabilities().SupportsCommands || !executor.Capabilities().ReportsExitCode {
		t.Fatalf("scripted executor must report commands and exit codes: %+v", executor.Capabilities())
	}
	if result.Outcome != OutcomeConfirmed {
		t.Fatalf("outcome = %s, want CONFIRMED (reason %q)", result.Outcome, result.Reason)
	}
	if strings.TrimSpace(result.Reproduction) == "" {
		t.Fatal("a confirming result must carry the steps that reproduced it")
	}
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("exit code = %v, want 0", result.ExitCode)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(result.Evidence))
	}
	evidence := result.Evidence[0]
	if evidence.Kind != EvidenceRuntimeLog {
		t.Fatalf("evidence kind = %s, want runtime_log", evidence.Kind)
	}
	if evidence.SnapshotID != plan.SnapshotID || evidence.HypothesisID != plan.HypothesisID {
		t.Fatalf("evidence is not tied to the plan: %+v", evidence)
	}
	if result.ContradictingEvidence() != nil && len(result.ContradictingEvidence()) != 0 {
		t.Fatalf("unexpected contradicting evidence: %+v", result.ContradictingEvidence())
	}
	// The executor reported a claim; only DeriveOutcome may turn it into a verdict.
	outcome, _ := DeriveOutcome(result, plan)
	if outcome != OutcomeConfirmed {
		t.Fatalf("DeriveOutcome = %s, want CONFIRMED", outcome)
	}
}

func TestScriptedExecutorMarksContradiction(t *testing.T) {
	plan := executorPlan(t, commandStep("the read succeeds", "permission denied"))
	executor := NewScriptedExecutor([]StepOutcome{{
		Content: "step[0] echo observation\nexit_code=0\npermission denied",
	}})

	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence count = %d, want 1", len(result.Evidence))
	}
	if !isContradicting(result.Evidence[0]) {
		t.Fatalf("evidence was not marked as contradicting: %+v", result.Evidence[0])
	}
	if got := len(result.ContradictingEvidence()); got != 1 {
		t.Fatalf("contradicting evidence = %d, want 1", got)
	}
	if result.Outcome == OutcomeConfirmed {
		t.Fatal("an executor must not claim CONFIRMED while it carries contradicting evidence")
	}
	// DeriveOutcome is the verifier's call: a refutation needs contradicting
	// evidence, which is exactly what this result has.
	result.Outcome = OutcomeRefuted
	outcome, reason := DeriveOutcome(result, plan)
	if outcome != OutcomeRefuted {
		t.Fatalf("DeriveOutcome = %s (%s), want REFUTED", outcome, reason)
	}
}

func TestScriptedExecutorUnsupportedStepIsBlocked(t *testing.T) {
	plan := executorPlan(t, commandStep("the read succeeds", "the read is rejected"))
	executor := NewScriptedExecutor(nil)
	executor.SetCapabilities(ExecutorCapabilities{
		Name: "static-only", Version: "1", SupportsStaticQueries: true, ReportsExitCode: false,
	})

	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked || result.StopReason != VerifyStopUnsupported {
		t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, VerifyStopUnsupported)
	}
	if !strings.Contains(result.Reason, "static-only") {
		t.Fatalf("reason %q does not name the executor that refused", result.Reason)
	}
	if outcome, _ := DeriveOutcome(result, plan); outcome != OutcomeBlocked {
		t.Fatalf("DeriveOutcome = %s, want BLOCKED", outcome)
	}
}

func TestScriptedExecutorMissingScriptEntryIsBlocked(t *testing.T) {
	plan := executorPlan(t,
		commandStep("the read succeeds", "the read is rejected"),
		commandStep("the write succeeds", "the write is denied"),
	)
	executor := NewScriptedExecutor([]StepOutcome{{Content: "only step 0"}})

	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked || result.StopReason != VerifyStopUnsupported {
		t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, VerifyStopUnsupported)
	}
	if len(result.Evidence) != 1 {
		t.Fatalf("evidence from the steps that did run = %d, want 1", len(result.Evidence))
	}
}

func TestScriptedExecutorMapScriptAndErrors(t *testing.T) {
	plan := executorPlan(t,
		commandStep("the read succeeds", "the read is rejected"),
		commandStep("the write succeeds", "the write is denied"),
	)
	executor := NewMapScriptedExecutor(map[int]StepOutcome{
		0: {Content: "step[0] ran"},
		1: {Err: "binary not found"},
	})

	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if !strings.Contains(result.Err, "binary not found") {
		t.Fatalf("err = %q, want the step error", result.Err)
	}
	if result.Outcome == OutcomeConfirmed {
		t.Fatal("a step that errored must not let the plan confirm")
	}
	if len(result.ContradictingEvidence()) != 0 {
		t.Fatal("an error is not a contradiction: it is 'we could not tell'")
	}
	if executor.Calls() != 1 {
		t.Fatalf("calls = %d, want 1", executor.Calls())
	}
}

func TestScriptedExecutorHonoursCancellation(t *testing.T) {
	plan := executorPlan(t, commandStep("the read succeeds", "the read is rejected"))
	executor := NewScriptedExecutor([]StepOutcome{{Content: "unused"}})
	executor.StepDelay = 50 * time.Millisecond

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	start := time.Now()
	result, err := executor.Execute(ctx, plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("a cancelled replay took %s", elapsed)
	}
	if result.Outcome != OutcomeBlocked || result.StopReason != VerifyStopCancelled {
		t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, VerifyStopCancelled)
	}
}

func TestScriptedExecutorHonoursEnvironmentTimeout(t *testing.T) {
	env := DefaultEnvironment()
	env.TimeoutSeconds = 1
	plan := executorPlan(t, commandStep("the read succeeds", "the read is rejected"))
	plan.Environment = env
	prepared, err := Prepare(plan)
	if err != nil {
		t.Fatalf("Prepare: %v", err)
	}
	executor := NewScriptedExecutor([]StepOutcome{{Content: "unused"}})
	executor.StepDelay = 5 * time.Second

	// A deadline shorter than the script's own delay is the caller's budget, and
	// the replay must honour it.
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := executor.Execute(ctx, prepared.Plan, prepared.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked {
		t.Fatalf("outcome = %s, want BLOCKED", result.Outcome)
	}
	if result.StopReason != VerifyStopTimeout && result.StopReason != VerifyStopCancelled {
		t.Fatalf("stop reason = %s, want timed_out or cancelled", result.StopReason)
	}
}

// --- UnsupportedExecutor -----------------------------------------------------

func TestUnsupportedExecutorReportsBlocked(t *testing.T) {
	executor := NewUnsupportedExecutor("noop", "0", "static queries need the graph adapter")
	plan := executorPlan(t)

	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked {
		t.Fatalf("outcome = %s, want BLOCKED", result.Outcome)
	}
	if result.StopReason != VerifyStopUnsupported {
		t.Fatalf("stop reason = %s, want %s", result.StopReason, VerifyStopUnsupported)
	}
	if !strings.Contains(result.Reason, "graph adapter") {
		t.Fatalf("reason %q does not explain the gap", result.Reason)
	}
	if len(result.Evidence) != 0 {
		t.Fatalf("the fallback ran nothing, so it must produce no evidence: %+v", result.Evidence)
	}
	outcome, _ := DeriveOutcome(result, plan)
	if outcome != OutcomeBlocked {
		t.Fatalf("DeriveOutcome = %s, want BLOCKED", outcome)
	}
}

func TestUnsupportedExecutorHonoursCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result, err := NewUnsupportedExecutor("noop", "0", "").Execute(ctx, Plan{}, Environment{})
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked || result.StopReason != VerifyStopCancelled {
		t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, VerifyStopCancelled)
	}
}

// --- CLIExecutor: configuration and refusal ----------------------------------

// recordingExecution is the Execution seam: it records the requests it received
// and returns a scripted outcome, so the executor's own logic is tested without a
// subprocess.
type recordingExecution struct {
	requests []ExecRequest
	outcomes []ExecOutcome
	calls    int
}

func (r *recordingExecution) Run(ctx context.Context, req ExecRequest) ExecOutcome {
	r.requests = append(r.requests, req)
	if r.calls >= len(r.outcomes) {
		r.calls++
		return ExecOutcome{ExitCode: 0}
	}
	outcome := r.outcomes[r.calls]
	r.calls++
	return outcome
}

func TestNewCLIExecutorValidatesConfig(t *testing.T) {
	dir := t.TempDir()
	if _, err := NewCLIExecutor(CLIConfig{Name: "", Command: []string{"tool"}, WorkingDir: dir}); !errors.Is(err, ErrExecutorConfig) {
		t.Fatalf("missing name: err = %v, want ErrExecutorConfig", err)
	}
	if _, err := NewCLIExecutor(CLIConfig{Name: "tool", WorkingDir: dir}); !errors.Is(err, ErrExecutorConfig) {
		t.Fatalf("missing command: err = %v, want ErrExecutorConfig", err)
	}
	if _, err := NewCLIExecutor(CLIConfig{Name: "tool", Command: []string{"tool"}}); !errors.Is(err, ErrExecutorConfig) {
		t.Fatalf("missing working dir: err = %v, want ErrExecutorConfig", err)
	}
	if _, err := NewCLIExecutor(CLIConfig{Name: "tool", Command: []string{"tool"}, WorkingDir: filepath.Join(dir, "missing")}); !errors.Is(err, ErrExecutorConfig) {
		t.Fatalf("nonexistent working dir: err = %v, want ErrExecutorConfig", err)
	}
	executor, err := NewCLIExecutor(CLIConfig{Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: dir})
	if err != nil {
		t.Fatalf("valid config refused: %v", err)
	}
	if !executor.Capabilities().SupportsCommands || executor.Capabilities().SupportsStaticQueries {
		t.Fatalf("capabilities = %+v, want commands without static queries", executor.Capabilities())
	}
	if !executor.Capabilities().ReportsExitCode {
		t.Fatal("the subprocess executor reports exit codes")
	}
}

func TestCLIExecutorRefusesNetworkWithoutDeclaration(t *testing.T) {
	plan := executorPlan(t)
	env := plan.Environment
	env.Network = NetworkTargetOnly
	env.AllowedHosts = []string{"target.internal"}

	runner := &recordingExecution{}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(), Runner: runner,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	result, err := executor.Execute(context.Background(), plan, env)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked || result.StopReason != VerifyStopScopeDenied {
		t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, VerifyStopScopeDenied)
	}
	if !strings.Contains(result.Reason, "network") {
		t.Fatalf("reason %q does not name the network refusal", result.Reason)
	}
	if len(runner.requests) != 0 {
		t.Fatalf("the executor started %d commands despite the refusal", len(runner.requests))
	}
	// The refusal is still recorded as evidence, so the run has something to show.
	if len(result.Evidence) == 0 || result.Evidence[0].Kind != EvidenceEnvironment {
		t.Fatalf("a refusal must carry environment evidence: %+v", result.Evidence)
	}
	if outcome, _ := DeriveOutcome(result, plan); outcome != OutcomeBlocked {
		t.Fatalf("DeriveOutcome = %s, want BLOCKED", outcome)
	}
}

func TestCLIExecutorRunsWhenNetworkIsDeclared(t *testing.T) {
	plan := executorPlan(t)
	env := plan.Environment
	env.Network = NetworkRestricted
	env.AllowedHosts = []string{"target.internal"}

	runner := &recordingExecution{}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(),
		Runner: runner, AllowNetwork: true,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	if _, err := executor.Execute(context.Background(), plan, env); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(runner.requests) != len(plan.Steps) {
		t.Fatalf("commands run = %d, want %d", len(runner.requests), len(plan.Steps))
	}
}

func TestCLIExecutorUsesArgvAndMinimalEnvironment(t *testing.T) {
	plan := executorPlan(t, commandStep("ran", "denied"))
	runner := &recordingExecution{}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"prefix", "--flag"},
		Env:        []string{"CODEXPLOIT_PROFILE=local", "HTTP_PROXY=http://proxy.invalid:3128"},
		WorkingDir: t.TempDir(), Runner: runner,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	if _, err := executor.Execute(context.Background(), plan, plan.Environment); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(runner.requests) != 1 {
		t.Fatalf("requests = %d, want 1", len(runner.requests))
	}
	request := runner.requests[0]
	want := []string{"prefix", "--flag", "echo", "observation"}
	if strings.Join(request.Argv, "\x00") != strings.Join(want, "\x00") {
		t.Fatalf("argv = %v, want %v (argv only, never a shell string)", request.Argv, want)
	}
	env := map[string]string{}
	for _, entry := range request.Env {
		key, value, _ := strings.Cut(entry, "=")
		env[key] = value
	}
	if env["CODEXPLOIT_PROFILE"] != "local" {
		t.Fatalf("configured env was not passed: %v", request.Env)
	}
	for key := range env {
		switch key {
		case "PATH", "HOME", "TMPDIR", "SystemRoot", "CODEXPLOIT_PROFILE", "HTTP_PROXY":
		default:
			t.Fatalf("unexpected inherited variable %q: the child environment must be an allowlist", key)
		}
	}
	if _, ok := env["PATH"]; !ok {
		t.Fatalf("PATH must be inherited or nothing can be executed: %v", request.Env)
	}
	if os.Getenv("SOME_PARENT_SECRET") != "" {
		t.Fatal("test environment is not clean")
	}
}

func TestCLIExecutorBoundsOutputAndMarksTruncation(t *testing.T) {
	plan := executorPlan(t, commandStep("ran", "denied"))
	runner := &recordingExecution{outcomes: []ExecOutcome{{
		ExitCode: 0, Stdout: "kept", Stderr: "problem",
		Truncated: true, Discarded: 1024,
	}}}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(),
		MaxOutputBytes: 8, Runner: runner,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("no evidence was produced")
	}
	content := result.Evidence[0].Content
	if !strings.Contains(content, "output_truncated=true") || !strings.Contains(content, "discarded_bytes=1024") {
		t.Fatalf("the truncation is not recorded: %q", content)
	}
	if len(content) > MaxEvidenceContent {
		t.Fatalf("evidence content is %d bytes, over the limit", len(content))
	}
}

func TestCLIExecutorStopsOnTimeoutAndCancellation(t *testing.T) {
	plan := executorPlan(t,
		commandStep("ran", "denied"),
		commandStep("ran again", "denied again"),
	)

	cases := []struct {
		name       string
		outcome    ExecOutcome
		wantStatus VerificationStatus
		wantStop   string
	}{
		{"timeout", ExecOutcome{ExitCode: -1, TimedOut: true, Err: context.DeadlineExceeded}, VerifyTimedOut, VerifyStopTimeout},
		{"cancelled", ExecOutcome{ExitCode: -1, Cancelled: true, Err: context.Canceled}, VerifyCancelled, VerifyStopCancelled},
		{"start failure", ExecOutcome{ExitCode: -1, Err: errors.New("executable file not found")}, VerifyBlocked, VerifyStopExecutorErr},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runner := &recordingExecution{outcomes: []ExecOutcome{tc.outcome, {ExitCode: 0}}}
			executor, err := NewCLIExecutor(CLIConfig{
				Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(), Runner: runner,
			})
			if err != nil {
				t.Fatalf("NewCLIExecutor: %v", err)
			}
			result, err := executor.Execute(context.Background(), plan, plan.Environment)
			if err != nil {
				t.Fatalf("Execute: %v", err)
			}
			if result.Outcome != OutcomeBlocked || result.StopReason != tc.wantStop {
				t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, tc.wantStop)
			}
			if runner.calls != 1 {
				t.Fatalf("commands run = %d, want 1: a failed step stops the plan", runner.calls)
			}
			if got := terminalStatus(result.Outcome, result, context.Background()); got != tc.wantStatus {
				t.Fatalf("terminal status = %s, want %s", got, tc.wantStatus)
			}
			if len(result.Evidence) == 0 {
				t.Fatal("the step that ran must still produce evidence")
			}
		})
	}
}

func TestCLIExecutorRefusesStaticOnlyStep(t *testing.T) {
	plan := executorPlan(t)
	plan.Steps = []Step{{
		Kind:          StepStaticCheck,
		StaticQuery:   map[string]string{"kind": "callers"},
		Expectation:   "a caller passes attacker data",
		Contradiction: "no caller passes attacker data",
	}}
	runner := &recordingExecution{}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(), Runner: runner,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked || result.StopReason != VerifyStopUnsupported {
		t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, VerifyStopUnsupported)
	}
	if len(runner.requests) != 0 {
		t.Fatal("a static-only step must not start a process")
	}
}

func TestCLIExecutorNonZeroExitPreventsConfirmation(t *testing.T) {
	plan := executorPlan(t, commandStep("ran", "denied"))
	runner := &recordingExecution{outcomes: []ExecOutcome{{ExitCode: 2, Stdout: "boom"}}}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(), Runner: runner,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome == OutcomeConfirmed {
		t.Fatal("a non-zero exit must not confirm a plan")
	}
	if result.ExitCode == nil || *result.ExitCode != 2 {
		t.Fatalf("exit code = %v, want 2", result.ExitCode)
	}
}

func TestCLIExecutorMarksContradictionFromTheRedactedObservation(t *testing.T) {
	plan := executorPlan(t, commandStep("the read succeeds", "permission denied"))
	runner := &recordingExecution{outcomes: []ExecOutcome{{
		ExitCode: 0,
		Stdout:   "password=hunter2secret\npermission denied\n",
	}}}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(), Runner: runner,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome == OutcomeConfirmed {
		t.Fatal("a contradicting observation must not confirm")
	}
	if len(result.ContradictingEvidence()) == 0 {
		t.Fatalf("the contradiction was not marked: %+v", result.Evidence)
	}
	if strings.Contains(result.Evidence[0].Content, "hunter2secret") {
		t.Fatalf("the observation was stored unredacted: %q", result.Evidence[0].Content)
	}
	result.Outcome = OutcomeRefuted
	if outcome, _ := DeriveOutcome(result, plan); outcome != OutcomeRefuted {
		t.Fatalf("DeriveOutcome = %s, want REFUTED", outcome)
	}
}

// --- CLIExecutor: a real process ---------------------------------------------

const (
	verifyExecHelperEnv = "CODEXPLOIT_VERIFY_EXEC_HELPER"
	verifyExecModeEnv   = "CODEXPLOIT_VERIFY_MODE"
	verifyExecModeArgv  = "argv"
	verifyExecModeEnvV  = "env"
	verifyExecModeHang  = "hang"
	verifyExecModeFlood = "flood"
)

// TestVerifyExecHelperProcess is the body of the command the subprocess executor
// runs. A normal test run leaves it a no-op.
func TestVerifyExecHelperProcess(t *testing.T) {
	mode := os.Getenv(verifyExecHelperEnv)
	if mode == "" {
		return
	}
	switch os.Getenv(verifyExecModeEnv) {
	case verifyExecModeEnvV:
		// Report the configured variable and whether a proxy variable leaked in.
		fmt.Fprintf(os.Stdout, "configured=%s\n", os.Getenv("CODEXPLOIT_VERIFY_MARKER"))
		fmt.Fprintf(os.Stdout, "proxy=%s\n", os.Getenv("HTTPS_PROXY"))
	case verifyExecModeHang:
		// Sleep far longer than the step budget; the executor must kill this process.
		time.Sleep(30 * time.Second)
		fmt.Fprintln(os.Stdout, "the executor failed to stop this process")
	case verifyExecModeFlood:
		// Write far more than any bounded capture should keep.
		chunk := strings.Repeat("flood-", 1<<10)
		for i := 0; i < 1<<6; i++ {
			if _, err := fmt.Fprint(os.Stdout, chunk); err != nil {
				break
			}
		}
	default:
		// Print argv verbatim, so the executor's "argv, never a shell string" rule is
		// observable from the outside.
		fmt.Fprintf(os.Stdout, "argv=%s\n", strings.Join(os.Args[1:], "|"))
	}
	os.Exit(0)
}

// helperExecutor builds a subprocess executor whose command re-executes this test
// binary in the given mode.
func helperExecutor(t *testing.T, mode string, mutate func(*CLIConfig)) *CLIExecutor {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	cfg := CLIConfig{
		Name: "verify-test", Version: "1",
		Command:    []string{executable, "-test.run", "TestVerifyExecHelperProcess"},
		Env:        []string{"CODEXPLOIT_VERIFY_EXEC_HELPER=1", verifyExecModeEnv + "=" + mode},
		WorkingDir: t.TempDir(),
	}
	if mutate != nil {
		mutate(&cfg)
	}
	executor, err := NewCLIExecutor(cfg)
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	return executor
}

// hangingStep is a step whose command is the test helper, with a one second budget.
func hangingStep() Step {
	return Step{
		Kind:             StepDynamicProof,
		Command:          []string{"-test.run", "TestVerifyExecHelperProcess"},
		Expectation:      "the proof completes",
		Contradiction:    "the control blocks the request",
		TimeoutSeconds:   1,
		RequiresApproval: true,
	}
}

func TestCLIExecutorKillsARealProcessOnTimeout(t *testing.T) {
	plan := executorPlan(t, hangingStep())
	executor := helperExecutor(t, verifyExecModeHang, nil)

	started := time.Now()
	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	elapsed := time.Since(started)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if result.Outcome != OutcomeBlocked || result.StopReason != VerifyStopTimeout {
		t.Fatalf("result = %s/%s, want BLOCKED/%s", result.Outcome, result.StopReason, VerifyStopTimeout)
	}
	if elapsed > 20*time.Second {
		t.Fatalf("the timeout took %s: the process was not killed", elapsed)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("the timed-out step produced no evidence")
	}
	if !strings.Contains(result.Evidence[0].Content, "timed_out=true") {
		t.Fatalf("the timeout is not recorded in the evidence: %q", result.Evidence[0].Content)
	}
	if result.ExitCode != nil {
		t.Fatalf("exit code = %v, want none: a killed step has no exit status", *result.ExitCode)
	}
	if got := terminalStatus(result.Outcome, result, context.Background()); got != VerifyTimedOut {
		t.Fatalf("run status = %s, want TIMED_OUT", got)
	}
}

func TestCLIExecutorBoundsRealProcessOutput(t *testing.T) {
	plan := executorPlan(t, Step{
		Kind:          StepStaticCheck,
		Command:       []string{"-test.run", "TestVerifyExecHelperProcess"},
		Expectation:   "the step reports its observation",
		Contradiction: "the step reports a denial",
	})
	const byteCap = 4096
	executor := helperExecutor(t, verifyExecModeFlood, func(cfg *CLIConfig) { cfg.MaxOutputBytes = byteCap })

	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("the step produced no evidence")
	}
	// The evidence wraps the captured output in a bounded observation, so the cap is
	// asserted through the truncation record and the total size rather than through an
	// exact byte count.
	content := result.Evidence[0].Content
	if !strings.Contains(content, "output_truncated=true") {
		t.Fatalf("the cap was not recorded: %q", content)
	}
	if markers := strings.Count(content, "flood-"); markers > (byteCap/len("flood-"))+64 {
		t.Fatalf("the capture kept %d output markers, more than the cap allows", markers)
	}
	if len(content) > byteCap+8192 {
		t.Fatalf("the observation is %d bytes, larger than the cap plus its framing", len(content))
	}
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("exit code = %v, want 0", result.ExitCode)
	}
}

func TestCLIExecutorRunsRealProcessWithArgvAndAllowlist(t *testing.T) {
	t.Setenv(verifyExecHelperEnv, "1")
	t.Setenv(verifyExecModeEnv, verifyExecModeEnvV)
	t.Setenv("CODEXPLOIT_VERIFY_MARKER_FILE", "unused")
	t.Setenv("HTTPS_PROXY", "http://proxy.invalid:3128")
	t.Setenv("CODEXPLOIT_PARENT_SECRET", "must-not-be-inherited")

	plan := executorPlan(t, commandStep("ran", "denied"))
	executable, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "verify-test", Version: "1",
		Command:    []string{executable, "-test.run", "TestVerifyExecHelperProcess"},
		Env:        []string{"CODEXPLOIT_VERIFY_EXEC_HELPER=1", verifyExecModeEnv + "=env", "CODEXPLOIT_VERIFY_MARKER=marker-value"},
		WorkingDir: t.TempDir(),
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	result, err := executor.Execute(context.Background(), plan, plan.Environment)
	if err != nil {
		t.Fatalf("Execute: %v", err)
	}
	if len(result.Evidence) == 0 {
		t.Fatal("no evidence was produced")
	}
	content := result.Evidence[0].Content
	if !strings.Contains(content, "configured=marker-value") {
		t.Fatalf("the configured environment was not passed: %q", content)
	}
	if strings.Contains(content, "proxy=http://proxy.invalid") {
		t.Fatalf("a proxy variable leaked into the verification: %q", content)
	}
	if !strings.Contains(content, "proxy=\n") {
		t.Fatalf("the helper did not report an empty proxy variable: %q", content)
	}
	if strings.Contains(content, "must-not-be-inherited") {
		t.Fatalf("an unrelated parent variable leaked into the verification: %q", content)
	}
	if result.ExitCode == nil || *result.ExitCode != 0 {
		t.Fatalf("exit code = %v, want 0; evidence: %q", result.ExitCode, content)
	}
}

func TestCLIExecutorNeverUsesAShell(t *testing.T) {
	plan := executorPlan(t, Step{
		Kind:          StepStaticCheck,
		Command:       []string{";", "echo", "pwned", ">"},
		Expectation:   "the shell is never reached",
		Contradiction: "the shell is reached",
	})
	runner := &recordingExecution{outcomes: []ExecOutcome{{ExitCode: 127, Stderr: "executable file not found"}}}
	executor, err := NewCLIExecutor(CLIConfig{
		Name: "tool", Version: "1", Command: []string{"tool"}, WorkingDir: t.TempDir(), Runner: runner,
	})
	if err != nil {
		t.Fatalf("NewCLIExecutor: %v", err)
	}
	if _, err := executor.Execute(context.Background(), plan, plan.Environment); err != nil {
		t.Fatalf("Execute: %v", err)
	}
	argv := runner.requests[0].Argv
	if len(argv) != 5 || argv[1] != ";" || argv[3] != "pwned" {
		t.Fatalf("argv was rewritten: %v; shell metacharacters must stay plain arguments", argv)
	}
	for _, arg := range argv {
		lower := strings.ToLower(arg)
		if lower == "sh" || lower == "-c" || strings.HasSuffix(lower, "cmd.exe") || strings.HasSuffix(lower, "powershell") {
			t.Fatalf("argv contains a shell: %v", argv)
		}
	}
}

func TestFirstLocation(t *testing.T) {
	cases := []struct {
		output string
		want   string
	}{
		{"internal/api/handler.go:42: tainted input", "internal/api/handler.go"},
		{"no location here", ""},
		{"\", \"file\": \"a/b.go:7\"", ""},
		{"C:\\work\\main.go:12", "C:\\work\\main.go"},
		{"cmd/main.go:7", "cmd/main.go"},
		{"", ""},
	}
	for _, tc := range cases {
		if got := firstLocation(tc.output); got != tc.want {
			t.Fatalf("firstLocation(%q) = %q, want %q", tc.output, got, tc.want)
		}
	}
}
