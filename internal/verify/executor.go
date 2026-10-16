package verify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// Executor adapts one way of running a verification plan — a scripted replay, a
// restricted subprocess, a static query engine — to the verifier.
//
// The interface is deliberately narrower than the orchestrator: an executor
// receives a plan and an environment and returns what it observed. It never
// receives the store, the scope or the approval record, so it cannot widen its own
// authority; and it never decides a finding status, because a verdict belongs to
// DeriveOutcome and to nothing else. What an executor reports is a claim, and the
// claim is checked before it is believed.
type ExecutorCapabilities struct {
	Name    string
	Version string
	// SupportsCommands reports whether the adapter can run a step's command.
	SupportsCommands bool
	// SupportsStaticQueries reports whether the adapter can answer a step's static
	// query against the graph. A command-only adapter must say false; an adapter
	// that cannot do something must refuse it rather than pretend.
	SupportsStaticQueries bool
	// ReportsExitCode reports whether a failed process is distinguishable from a
	// successful one in what the adapter returns.
	ReportsExitCode bool
	// Notes are interview-facing caveats about the adapter. They end up in the run
	// record, because an unknown limitation is an untrustworthy verdict.
	Notes []string
}

// ErrExecutorConfig marks a misconfigured executor. It is an operator error found
// at wiring time, not a verification failure.
var ErrExecutorConfig = errors.New("verify: invalid executor configuration")

// Executor runs the steps of a plan and reports what it observed.
//
// Execute must never return a verdict the evidence does not support, and must
// never bypass DeriveOutcome: the verifier calls it on whatever comes back.
// Execute returns an error only when it could not report at all (a cancelled or
// unreachable environment); a plan it cannot run is a Result with
// OutcomeBlocked and a stop reason, not an error, because "we could not run this"
// is a finding the operator needs to see.
type Executor interface {
	Capabilities() ExecutorCapabilities
	Execute(ctx context.Context, plan Plan, env Environment) (Result, error)
}

// StepOutcome is one step's scripted result. It is what a deterministic executor
// produces for a step: what the step printed, how the process ended, and whether
// the observation matched the step's contradiction.
//
// It is deliberately not a verdict: an executor that claimed CONFIRMED here would
// be deciding the finding, which is the verifier's job.
type StepOutcome struct {
	// Kind is the evidence kind the observation is recorded as. It defaults to
	// EvidenceRuntimeLog; EvidenceTest is what a step that ran a real test suite
	// should use, because DeriveOutcome only counts those two as reproduction
	// evidence.
	Kind EvidenceKind
	// Command is the command line the observation came from. Empty means the
	// executor fills in the plan step's own command.
	Command string
	// ExitCode is the process exit status, nil when the step did not run a process.
	ExitCode *int
	// Content is the observation, redacted and hashed by NewEvidence.
	Content string
	// File and Line are the source location the observation points at, when it has
	// one.
	File string
	Line int
	// Contradicts marks the observation as contradicting the step's hypothesis. The
	// reason becomes the contradiction marker on the evidence, which is the only
	// thing DeriveOutcome reads when it counts contradictions.
	Contradicts string
	// Err reports that the step could not produce an observation. It never makes the
	// step contradictory: an error is "we could not tell", not "we disproved it".
	Err string
}

// --- ScriptedExecutor --------------------------------------------------------

// ScriptedExecutor is the deterministic executor used by tests, dry runs and
// demos. It replays a fixed per-step script instead of starting a process, so the
// same plan always produces the same evidence in the same order.
//
// It is a faithful stand-in for a real adapter, not a shortcut around one: it
// builds evidence through NewEvidence, it honours cancellation and the
// environment's timeout, and it reports what its script says rather than what
// would be convenient.
type ScriptedExecutor struct {
	capabilities ExecutorCapabilities
	// script maps a step index to what that step produces. A step with no entry is
	// unsupported, which is reported as BLOCKED rather than being skipped.
	script map[int]StepOutcome
	// StepDelay pauses before each step so a test can land a cancellation or a
	// timeout inside Execute. Zero replays as fast as the caller reads.
	StepDelay time.Duration
	calls     atomic.Int64
}

// NewScriptedExecutor builds a replay adapter. The script is copied, so a caller
// cannot change a running script.
func NewScriptedExecutor(stepScript []StepOutcome) *ScriptedExecutor {
	script := make(map[int]StepOutcome, len(stepScript))
	for i, outcome := range stepScript {
		script[i] = outcome
	}
	return &ScriptedExecutor{
		capabilities: ExecutorCapabilities{
			Name:                  "scripted",
			Version:               "1",
			SupportsCommands:      true,
			SupportsStaticQueries: true,
			ReportsExitCode:       true,
			Notes: []string{
				"deterministic replay executor: it starts no process and proves nothing about a real target",
			},
		},
		script: script,
	}
}

// NewMapScriptedExecutor builds a replay adapter from a step-indexed script, which
// is how a test states "step 2 contradicts, step 3 errors" without padding the
// earlier steps.
func NewMapScriptedExecutor(stepScript map[int]StepOutcome) *ScriptedExecutor {
	executor := NewScriptedExecutor(nil)
	for index, outcome := range stepScript {
		executor.script[index] = outcome
	}
	return executor
}

// Compile-time proof that the adapter honours the contract.
var _ Executor = (*ScriptedExecutor)(nil)

// SetCapabilities replaces what the adapter reports it can do. A test uses it to
// build a command-only adapter out of a replay adapter, which is the situation
// UnsupportedExecutor exists for.
func (e *ScriptedExecutor) SetCapabilities(capabilities ExecutorCapabilities) {
	e.capabilities = capabilities
}

// Capabilities reports what the replay adapter can do.
func (e *ScriptedExecutor) Capabilities() ExecutorCapabilities { return e.capabilities }

// Calls returns how many times Execute ran. The verifier's replay behaviour is
// asserted on it: the same plan must never be executed twice.
func (e *ScriptedExecutor) Calls() int64 { return e.calls.Load() }

// Execute replays the script for each step of the plan.
func (e *ScriptedExecutor) Execute(ctx context.Context, plan Plan, env Environment) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.calls.Add(1)
	env = env.Normalize()
	caps := e.capabilities
	var (
		evidence     []Evidence
		reproduction []string
		lastExit     *int
		stepIndex    int
		contradicted bool
		errs         []string
	)
	for stepIndex = 0; stepIndex < len(plan.Steps); stepIndex++ {
		step := plan.Steps[stepIndex]
		if !executableBy(step, caps) {
			return e.stop(plan, evidence, stepIndex, OutcomeBlocked, VerifyStopUnsupported,
				fmt.Sprintf("the %s executor cannot run a %s step", caps.Name, step.Kind)), nil
		}
		if !e.wait(ctx, env) {
			return e.stop(plan, evidence, stepIndex, OutcomeBlocked, stopReasonForContext(ctx),
				"the verification was stopped before the step could run"), nil
		}
		outcome, ok := e.script[stepIndex]
		if !ok {
			return e.stop(plan, evidence, stepIndex, OutcomeBlocked, VerifyStopUnsupported,
				fmt.Sprintf("the script declares no outcome for step %d", stepIndex)), nil
		}
		built, err := e.build(ctx, plan, step, stepIndex, outcome)
		if err != nil {
			return Result{}, err
		}
		// A contradiction is decided against the stored observation, so what is
		// marked and what is recorded always agree. The script may state it explicitly
		// or let the step's own contradiction phrase match the observation.
		contradiction := strings.TrimSpace(outcome.Contradicts)
		if contradiction == "" && strings.TrimSpace(step.Contradiction) != "" &&
			observationMatches(step.Contradiction, built.Content) {
			contradiction = step.Contradiction
		}
		if contradiction != "" {
			built = MarkContradicting(built, contradiction)
			contradicted = true
		}
		evidence = append(evidence, built)
		switch {
		case outcome.Err != "":
			errs = append(errs, fmt.Sprintf("step %d: %s", stepIndex, outcome.Err))
		case contradiction != "":
			reproduction = append(reproduction, fmt.Sprintf("step %d: %s", stepIndex, step.CommandLine()))
		default:
			reproduction = append(reproduction, fmt.Sprintf("step %d: %s", stepIndex, step.CommandLine()))
			if outcome.ExitCode != nil {
				lastExit = outcome.ExitCode
			}
		}
	}
	ran := len(evidence)
	complete := ran == len(plan.Steps) && len(errs) == 0
	outcome := OutcomeInconclusive
	reason := "the scripted replay produced evidence but nothing that confirms or refutes the claim"
	switch {
	case contradicted && confirmingEvidence(evidence):
		// The plan gave mixed signals: a contradiction is the stronger signal, so the
		// replay refuses to refute and reports that it could not settle the claim.
		reason = "the scripted replay produced both confirming and contradicting evidence"
	case contradicted:
		outcome = OutcomeRefuted
		reason = "the scripted replay produced contradicting evidence"
	case complete && ran > 0:
		outcome = OutcomeConfirmed
		reason = "the scripted replay ran every step and nothing contradicted the claim"
	}
	if len(errs) > 0 {
		reason = "the scripted replay could not complete: " + strings.Join(errs, "; ")
	}
	return Result{
		Outcome:      outcome,
		Reason:       reason,
		Reproduction: strings.Join(reproduction, "\n"),
		Evidence:     evidence,
		ExitCode:     lastExit,
		StopReason:   VerifyStopCompleted,
		Err:          strings.Join(errs, "; "),
	}, nil
}

func (e *ScriptedExecutor) stop(plan Plan, evidence []Evidence, stepIndex int, outcome Outcome, reason, detail string) Result {
	_ = stepIndex
	return Result{
		Outcome:    outcome,
		Reason:     detail,
		Evidence:   evidence,
		StopReason: reason,
	}
}

// confirmingEvidence reports whether any observation claims support for the
// hypothesis. It is what lets the replay tell "the claim was refuted" from "this
// plan gave contradictory answers".
func confirmingEvidence(evidence []Evidence) bool {
	for _, object := range evidence {
		if isContradicting(object) {
			continue
		}
		if object.Kind == EvidenceRuntimeLog || object.Kind == EvidenceTest {
			return true
		}
	}
	return false
}

// wait pauses before a step and reports whether the replay may continue. The
// environment's timeout bounds the replay as a whole, exactly as it bounds a real
// process, so a script cannot ignore the budget it was given.
func (e *ScriptedExecutor) wait(ctx context.Context, env Environment) bool {
	delay := e.StepDelay
	if env.TimeoutSeconds > 0 && time.Duration(env.TimeoutSeconds)*time.Second < delay {
		delay = time.Duration(env.TimeoutSeconds) * time.Second
	}
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

func (e *ScriptedExecutor) build(ctx context.Context, plan Plan, step Step, index int, outcome StepOutcome) (Evidence, error) {
	kind := outcome.Kind
	if kind == "" {
		kind = EvidenceRuntimeLog
	}
	command := outcome.Command
	if strings.TrimSpace(command) == "" {
		command = step.CommandLine()
	}
	content := outcome.Content
	if strings.TrimSpace(content) == "" {
		content = fmt.Sprintf("step[%d] %s\nno output", index, command)
	}
	return NewEvidence(kind, content, EvidenceOptions{
		Tool:         e.capabilities.Name,
		ToolVersion:  e.capabilities.Version,
		SnapshotID:   plan.SnapshotID,
		HypothesisID: plan.HypothesisID,
		FindingID:    plan.FindingID,
		PathID:       plan.PathID,
		File:         outcome.File,
		Line:         outcome.Line,
		Now:          NowString(evidenceNow(ctx)),
	})
}

// --- UnsupportedExecutor -----------------------------------------------------

// UnsupportedExecutor is the honest fallback: it runs nothing and reports
// BLOCKED with VerifyStopUnsupported.
//
// It exists so a step kind nobody implemented is a recorded "we could not verify
// this" instead of a silent gap that a report later reads as "nothing found".
type UnsupportedExecutor struct {
	CapabilitiesInfo ExecutorCapabilities
	// Reason explains what is missing, and it is recorded on the run.
	Reason string
}

// Compile-time proof that the fallback honours the contract.
var _ Executor = (*UnsupportedExecutor)(nil)

// NewUnsupportedExecutor builds a fallback for one step vocabulary. The default
// reason names the step kinds the placeholder cannot run.
func NewUnsupportedExecutor(name, version, reason string) *UnsupportedExecutor {
	if strings.TrimSpace(reason) == "" {
		reason = "no executor is configured for this step kind"
	}
	return &UnsupportedExecutor{
		CapabilitiesInfo: ExecutorCapabilities{Name: name, Version: version, Notes: []string{reason}},
		Reason:           reason,
	}
}

// Capabilities reports that this adapter can do nothing.
func (u *UnsupportedExecutor) Capabilities() ExecutorCapabilities {
	return u.CapabilitiesInfo
}

// Execute always reports BLOCKED. It never errors: an unsupported step is a
// finding about the environment, not a crash.
func (u *UnsupportedExecutor) Execute(ctx context.Context, plan Plan, env Environment) (Result, error) {
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return Result{
				Outcome:    OutcomeBlocked,
				Reason:     "the verification was stopped before it started",
				StopReason: stopReasonForContext(ctx),
			}, nil
		}
	}
	reason := strings.TrimSpace(u.Reason)
	if reason == "" {
		reason = "no executor is configured for this step kind"
	}
	return Result{
		Outcome:    OutcomeBlocked,
		Reason:     reason,
		StopReason: VerifyStopUnsupported,
	}, nil
}

func stopReasonForContext(ctx context.Context) string {
	switch {
	case ctx == nil:
		return VerifyStopCancelled
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return VerifyStopTimeout
	case ctx.Err() != nil:
		return VerifyStopCancelled
	default:
		return VerifyStopCompleted
	}
}

// executableBy reports whether an adapter can attempt a step at all. A step with
// a command needs SupportsCommands; a step with a static query and no command
// needs SupportsStaticQueries.
func executableBy(step Step, caps ExecutorCapabilities) bool {
	if len(step.Command) > 0 {
		return caps.SupportsCommands
	}
	if len(step.StaticQuery) > 0 {
		return caps.SupportsStaticQueries
	}
	return false
}

// CommandLine renders a step's argv for the evidence record. It is a rendering for
// humans, never something that gets executed: an executor runs argv, not a string.
func (s Step) CommandLine() string {
	switch {
	case len(s.Command) > 0:
		return strings.Join(s.Command, " ")
	case len(s.StaticQuery) > 0:
		keys := make([]string, 0, len(s.StaticQuery))
		for key := range s.StaticQuery {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			parts = append(parts, key+"="+s.StaticQuery[key])
		}
		return "static_query(" + strings.Join(parts, " ") + ")"
	default:
		return "step with no command or query"
	}
}

// --- CLIExecutor -------------------------------------------------------------

// DefaultCLIMaxOutputBytes bounds how much of a step's output is kept when
// CLIConfig.MaxOutputBytes is unset. A verification command that decides to print
// its way through memory must not be able to exhaust the worker.
const DefaultCLIMaxOutputBytes int64 = 256 << 10

const (
	// cliWaitDelay bounds how long a finished or cancelled process may keep its
	// pipes open. Without it a command whose grandchild inherited stdout would leave
	// the executor waiting for an EOF that never comes.
	cliWaitDelay = 5 * time.Second
	// defaultVerbTimeout bounds one step when neither the environment nor the step
	// declares a timeout.
	defaultVerbTimeout = 60 * time.Second
)

// CLIConfig configures the subprocess executor.
//
// Deployment contract (design §11): Go can bound a subprocess' argv, environment,
// deadline, output and process group, but it cannot network-sandbox it. This
// executor is therefore only as isolated as the container or VM it runs in. It
// refuses a plan that wants network unless an operator has explicitly declared the
// configured command network-capable, and that declaration is a claim about the
// deployment, not a sandbox.
type CLIConfig struct {
	// Name and Version identify the adapter in the run record.
	Name    string
	Version string
	// Command is the argv prefix of a network-capable verification command. It is
	// required, even for plans that carry their own commands, because naming the
	// deployment's allowed entry point is the whole point of the configuration.
	Command []string
	// Env is the complete allowlist of extra environment entries, in "KEY=VALUE"
	// form. Nothing else is inherited except PATH, HOME and TMPDIR (plus SystemRoot
	// on Windows), so a parent's proxy credentials are not leaked into a
	// verification; an operator who needs egress through a proxy must name the
	// proxy variable here explicitly. Configured entries win over inherited ones.
	Env []string
	// WorkingDir is the scratch directory: the executor's view of the snapshot. The
	// orchestrator materialises it; the executor never writes source files. It must
	// exist.
	WorkingDir string
	// MaxOutputBytes bounds the retained stdout and stderr per step. Zero or
	// negative uses DefaultCLIMaxOutputBytes; the excess is discarded and recorded
	// as a truncation, never written to the evidence.
	MaxOutputBytes int64
	// WaitDelay bounds how long a finished or cancelled process may keep the pipes
	// open. Zero uses a small default.
	WaitDelay time.Duration
	// AllowNetwork declares that the configured command is deployed inside a
	// network-capable restricted container or VM. It does not create a sandbox; it
	// records that the operator has one.
	AllowNetwork bool
	// Runner overrides how a command is started. It exists for tests that need to
	// assert the executor's refusal and bounding logic without a real subprocess,
	// and it is never set by the CLI wiring.
	Runner Execution
}

// Execution is how the CLI executor starts one command. It is a seam, not an
// extension point: the production implementation is the process runner below, and
// a test replaces it to make refusal and bounding deterministic.
type Execution interface {
	Run(ctx context.Context, req ExecRequest) ExecOutcome
}

// ExecRequest is one bounded command.
type ExecRequest struct {
	Argv      []string
	Dir       string
	Env       []string
	MaxBytes  int64
	WaitDelay time.Duration
	// Timeout bounds the command in addition to ctx. Zero uses a small default; the
	// caller's context always wins over it.
	Timeout time.Duration
}

// ExecOutcome is what one bounded command produced.
type ExecOutcome struct {
	ExitCode  int
	Stdout    string
	Stderr    string
	Truncated bool
	Discarded int64
	TimedOut  bool
	Cancelled bool
	Err       error
}

// CLIExecutor runs a plan's command steps as bounded subprocesses.
type CLIExecutor struct {
	cfg CLIConfig
}

// Compile-time proof that the adapter honours the contract.
var _ Executor = (*CLIExecutor)(nil)

// NewCLIExecutor validates the configuration. A missing command, a missing
// identity or a missing scratch directory is refused here rather than at Execute,
// because all three are wiring errors, not verification results.
func NewCLIExecutor(cfg CLIConfig) (*CLIExecutor, error) {
	if strings.TrimSpace(cfg.Name) == "" {
		return nil, fmt.Errorf("%w: name is required: an unattributed run cannot be audited", ErrExecutorConfig)
	}
	if len(cfg.Command) == 0 || strings.TrimSpace(cfg.Command[0]) == "" {
		return nil, fmt.Errorf("%w: command is required", ErrExecutorConfig)
	}
	if strings.TrimSpace(cfg.WorkingDir) == "" {
		return nil, fmt.Errorf("%w: working_dir is required: a verification needs a declared scratch space", ErrExecutorConfig)
	}
	info, err := os.Stat(cfg.WorkingDir)
	if err != nil {
		return nil, fmt.Errorf("%w: working_dir: %v", ErrExecutorConfig, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%w: working_dir %q is not a directory", ErrExecutorConfig, cfg.WorkingDir)
	}
	return &CLIExecutor{cfg: cfg}, nil
}

// Capabilities reports what the subprocess executor can do and what it cannot
// promise.
func (e *CLIExecutor) Capabilities() ExecutorCapabilities {
	notes := []string{
		"Go cannot network-sandbox a subprocess: this executor is only as isolated as the container or VM it runs in (design section 11)",
		"only the configured Env is passed, plus PATH, HOME and TMPDIR: proxy variables are not inherited unless the operator names them",
		"argv only, never a shell string; each step runs in its own process group so cancellation reaches its descendants",
	}
	if e.cfg.AllowNetwork {
		notes = append(notes, "the deployment declares the configured command network-capable; egress is bounded by the container or VM, not by this executor")
	} else {
		notes = append(notes, "no network: a plan whose environment asks for egress is refused unless the deployment declares the command network-capable")
	}
	return ExecutorCapabilities{
		Name: e.cfg.Name, Version: e.cfg.Version,
		SupportsCommands: true, SupportsStaticQueries: false, ReportsExitCode: true,
		Notes: notes,
	}
}

// Config returns the configuration the executor was built with.
func (e *CLIExecutor) Config() CLIConfig { return e.cfg }

func (e *CLIExecutor) runner() Execution {
	if e.cfg.Runner != nil {
		return e.cfg.Runner
	}
	return processRunner{}
}

// Execute runs each command step in order. A step it cannot run stops the plan:
// continuing past an unsupported step would report a verdict about a plan that
// never fully ran.
func (e *CLIExecutor) Execute(ctx context.Context, plan Plan, env Environment) (Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	env = env.Normalize()
	caps := e.Capabilities()
	var (
		evidence     []Evidence
		reproduction []string
		lastExit     *int
		contradicted bool
		incomplete   bool
	)
	if env.Network != NetworkNone && !e.cfg.AllowNetwork {
		// Refuse before starting anything: a command that would reach the network is
		// blocked, not attempted and then regretted.
		blocked := e.blocked(fmt.Sprintf(
			"the plan asks for %s network access and this deployment did not declare a network-capable command; Go cannot sandbox the network, so the deployment contract is a restricted container or VM with no egress (design section 11)",
			env.Network))
		blocked.Evidence = append(blocked.Evidence, e.environmentEvidence(plan, env))
		return blocked, nil
	}

	for index, step := range plan.Steps {
		if len(step.Command) == 0 {
			result := e.stop(plan, evidence, OutcomeBlocked, VerifyStopUnsupported,
				fmt.Sprintf("step %d has no command and this executor only runs commands", index))
			result.Evidence = append(result.Evidence, e.environmentEvidence(plan, env))
			return result, nil
		}
		select {
		case <-ctx.Done():
			result := e.stop(plan, evidence, OutcomeBlocked, stopReasonForContext(ctx),
				"the verification was stopped before the next step could run")
			result.Evidence = append(result.Evidence, e.environmentEvidence(plan, env))
			return result, nil
		default:
		}
		argv := append(append([]string(nil), e.cfg.Command...), step.Command...)
		// The step's own budget bounds the process; the caller's context still wins
		// when it expires first.
		stepCtx, stop := context.WithTimeout(ctx, e.stepTimeout(env, step))
		outcome := e.runner().Run(stepCtx, ExecRequest{
			Argv:      argv,
			Dir:       e.cfg.WorkingDir,
			Env:       minimalVerifyEnv(e.cfg.Env),
			MaxBytes:  e.cfg.MaxOutputBytes,
			WaitDelay: e.cfg.WaitDelay,
			Timeout:   e.stepTimeout(env, step),
		})
		stop()
		command := strings.Join(argv, " ")
		evidenceObject, err := NewEvidence(e.evidenceKind(step), e.observation(index, step, outcome), EvidenceOptions{
			Tool:         caps.Name,
			ToolVersion:  caps.Version,
			SnapshotID:   plan.SnapshotID,
			HypothesisID: plan.HypothesisID,
			FindingID:    plan.FindingID,
			PathID:       plan.PathID,
			File:         firstLocation(outcome.Stdout),
			Now:          NowString(evidenceNow(ctx)),
		})
		if err != nil {
			return Result{}, err
		}
		// A contradiction is decided against the redacted observation, so what is
		// marked and what is stored always agree.
		if step.Contradiction != "" && observationMatches(step.Contradiction, evidenceObject.Content) {
			evidenceObject = MarkContradicting(evidenceObject, step.Contradiction)
			contradicted = true
		}
		evidence = append(evidence, evidenceObject)
		reproduction = append(reproduction, fmt.Sprintf("step %d: %s", index, command))

		exit := outcome.ExitCode
		if !outcome.TimedOut && !outcome.Cancelled && outcome.Err == nil {
			lastExit = &exit
		}
		switch {
		case outcome.Cancelled:
			result := e.stop(plan, evidence, OutcomeBlocked, VerifyStopCancelled,
				"the verification was cancelled")
			result.Evidence = append(result.Evidence, e.environmentEvidence(plan, env))
			result.Reproduction = strings.Join(reproduction, "\n")
			return result, nil
		case outcome.TimedOut:
			result := e.stop(plan, evidence, OutcomeBlocked, VerifyStopTimeout,
				fmt.Sprintf("step %d exceeded its %s budget", index, e.stepTimeout(env, step)))
			result.Evidence = append(result.Evidence, e.environmentEvidence(plan, env))
			result.Reproduction = strings.Join(reproduction, "\n")
			return result, nil
		case outcome.Err != nil:
			result := e.stop(plan, evidence, OutcomeBlocked, VerifyStopExecutorErr,
				fmt.Sprintf("step %d could not be started: %v", index, outcome.Err))
			result.Evidence = append(result.Evidence, e.environmentEvidence(plan, env))
			result.Reproduction = strings.Join(reproduction, "\n")
			return result, nil
		case outcome.ExitCode != 0:
			incomplete = true
		}
	}

	evidence = append(evidence, e.environmentEvidence(plan, env))
	ran := len(plan.Steps) - countCommandless(plan)
	complete := !incomplete && ran == len(plan.Steps)
	verdict := OutcomeInconclusive
	reason := "the command steps ran but nothing confirms or refutes the claim"
	switch {
	case contradicted:
		reason = "a step produced the observation its contradiction named"
	case complete && len(reproduction) > 0:
		verdict = OutcomeConfirmed
		reason = "every step ran and nothing contradicted the claim"
	}
	if incomplete {
		reason = "at least one step exited non-zero, so the plan did not run to completion"
	}
	return Result{
		Outcome:      verdict,
		Reason:       reason,
		Reproduction: strings.Join(reproduction, "\n"),
		Evidence:     evidence,
		ExitCode:     lastExit,
		StopReason:   VerifyStopCompleted,
	}, nil
}

func countCommandless(plan Plan) int {
	count := 0
	for _, step := range plan.Steps {
		if len(step.Command) == 0 {
			count++
		}
	}
	return count
}

func (e *CLIExecutor) blocked(reason string) Result {
	return Result{
		Outcome:    OutcomeBlocked,
		Reason:     reason,
		StopReason: VerifyStopScopeDenied,
	}
}

func (e *CLIExecutor) stop(plan Plan, evidence []Evidence, outcome Outcome, reason, detail string) Result {
	_ = plan
	return Result{Outcome: outcome, Reason: detail, Evidence: evidence, StopReason: reason}
}

// evidenceKind is what a command step's observation is recorded as.
//
// It is always a runtime log. DeriveOutcome counts both a runtime log and a test as
// reproduction evidence, so labelling a command "test" because a word in the plan
// looked like one would let a probe promote itself to a reproduction. A step that
// really runs a test suite should say so through the evidence kind an adapter
// chooses (see StepOutcome.Kind), not through a guess about its prose.
func (e *CLIExecutor) evidenceKind(step Step) EvidenceKind { return EvidenceRuntimeLog }

func (e *CLIExecutor) stepTimeout(env Environment, step Step) time.Duration {
	seconds := step.TimeoutSeconds
	if seconds <= 0 {
		seconds = env.TimeoutSeconds
	}
	if seconds <= 0 {
		return defaultVerbTimeout
	}
	return time.Duration(seconds) * time.Second
}

// observation renders what a step produced: the command, the exit status, the
// retained output, and the flags that say the record is not the whole truth.
func (e *CLIExecutor) observation(index int, step Step, outcome ExecOutcome) string {
	var b strings.Builder
	fmt.Fprintf(&b, "step[%d] kind=%s\n", index, step.Kind)
	fmt.Fprintf(&b, "command=%s\n", strings.Join(step.Command, " "))
	fmt.Fprintf(&b, "exit_code=%d\n", outcome.ExitCode)
	if outcome.Truncated {
		fmt.Fprintf(&b, "output_truncated=true discarded_bytes=%d\n", outcome.Discarded)
	}
	if outcome.TimedOut {
		b.WriteString("timed_out=true\n")
	}
	if outcome.Cancelled {
		b.WriteString("cancelled=true\n")
	}
	if outcome.Err != nil {
		fmt.Fprintf(&b, "error=%v\n", outcome.Err)
	}
	b.WriteString("--- stdout ---\n")
	b.WriteString(tailText(outcome.Stdout, 4096))
	b.WriteString("\n--- stderr ---\n")
	b.WriteString(tailText(outcome.Stderr, 2048))
	return b.String()
}

// environmentEvidence records the profile and the quotas the run was bounded by.
// Without it a result cannot be tied back to the environment that produced it.
func (e *CLIExecutor) environmentEvidence(plan Plan, env Environment) Evidence {
	var b strings.Builder
	fmt.Fprintf(&b, "profile=%s\n", env.Profile)
	fmt.Fprintf(&b, "environment_digest=%s\n", env.Digest())
	fmt.Fprintf(&b, "network=%s\n", env.Network)
	fmt.Fprintf(&b, "allowed_hosts=%s\n", strings.Join(env.AllowedHosts, ","))
	fmt.Fprintf(&b, "source_read_only=%t\n", env.SourceReadOnly)
	fmt.Fprintf(&b, "mount_host_socket=%t\n", env.MountHostSocket)
	fmt.Fprintf(&b, "cpu_millis=%d memory_mb=%d disk_mb=%d max_processes=%d max_writes=%d\n",
		env.CPUMillis, env.MemoryMB, env.DiskMB, env.MaxProcesses, env.MaxWrites)
	fmt.Fprintf(&b, "timeout_seconds=%d\n", env.TimeoutSeconds)
	fmt.Fprintf(&b, "executor=%s@%s\n", e.cfg.Name, e.cfg.Version)
	fmt.Fprintf(&b, "working_dir=%s\n", e.cfg.WorkingDir)
	// Quotas below are declared, not enforced by this process: Go bounds argv,
	// environment, deadline, output and process group, and the container or VM
	// bounds the rest.
	b.WriteString("note=CPU, memory, disk and process quotas are enforced by the deployment container; this executor only declares them\n")
	evidence, err := NewEvidence(EvidenceEnvironment, b.String(), EvidenceOptions{
		Tool:         e.cfg.Name,
		ToolVersion:  e.cfg.Version,
		SnapshotID:   plan.SnapshotID,
		HypothesisID: plan.HypothesisID,
		FindingID:    plan.FindingID,
		PathID:       plan.PathID,
		Now:          NowString(nowUTC()),
	})
	if err != nil {
		// The content is built from validated fields and cannot fail to hash; an
		// error here would mean an unknown evidence kind, which is a programming
		// error rather than a runtime condition.
		return Evidence{}
	}
	return evidence
}

// minimalVerifyEnv builds the child's environment: the configured allowlist plus
// PATH, HOME and TMPDIR, and nothing else. A parent's proxy variables are exactly
// the kind of ambient authority a verification must not inherit.
func minimalVerifyEnv(configured []string) []string {
	inherited := []string{"PATH", "HOME", "TMPDIR"}
	if runtime.GOOS == "windows" {
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

// processRunner is the production Execution: one exec.Command, one process group,
// one bounded deadline, one bounded capture.
type processRunner struct{}

func (processRunner) Run(parent context.Context, req ExecRequest) ExecOutcome {
	outcome := ExecOutcome{ExitCode: -1}
	if len(req.Argv) == 0 {
		outcome.Err = errors.New("verify: empty argv")
		return outcome
	}
	limit := req.MaxBytes
	if limit <= 0 {
		limit = DefaultCLIMaxOutputBytes
	}
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	timeout := req.Timeout
	if timeout <= 0 {
		timeout = defaultVerbTimeout
	}
	timer := time.AfterFunc(timeout, cancel)
	defer timer.Stop()

	cmd := exec.CommandContext(ctx, req.Argv[0], req.Argv[1:]...)
	cmd.Dir = req.Dir
	cmd.Env = req.Env
	waitDelay := req.WaitDelay
	if waitDelay <= 0 {
		waitDelay = cliWaitDelay
	}
	cmd.WaitDelay = waitDelay
	cmd.Cancel = func() error {
		killProcessGroup(cmd)
		return nil
	}
	configureProcessGroup(cmd)

	stdout := newCappedBuffer(limit)
	stderr := newCappedBuffer(limit)
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		outcome.Err = err
		return outcome
	}
	waitErr := cmd.Wait()
	outcome.Stdout = stdout.String()
	outcome.Stderr = stderr.String()
	outcome.Truncated = stdout.truncated || stderr.truncated
	outcome.Discarded = stdout.discarded + stderr.discarded
	switch {
	case parent.Err() != nil:
		// The caller's budget expired or the caller cancelled: that is the run's
		// failure mode, not the step's.
		if errors.Is(parent.Err(), context.DeadlineExceeded) {
			outcome.TimedOut = true
		} else {
			outcome.Cancelled = true
		}
		outcome.Err = parent.Err()
	case ctx.Err() != nil:
		outcome.TimedOut = true
		outcome.Err = ctx.Err()
	case waitErr != nil:
		outcome.Err = waitErr
	}
	outcome.ExitCode = exitCodeOf(waitErr)
	return outcome
}

// cappedBuffer keeps the first limit bytes written to it and counts the rest.
//
// It keeps the head, not the tail: a command's first output is where the
// observation usually is, and a verification must not let a chatty child push the
// interesting line out of the record. The discarded byte count is recorded, so the
// truncation is visible instead of silent.
type cappedBuffer struct {
	mu        sync.Mutex
	buf       bytes.Buffer
	limit     int64
	truncated bool
	discarded int64
}

func newCappedBuffer(limit int64) *cappedBuffer {
	if limit <= 0 {
		limit = DefaultCLIMaxOutputBytes
	}
	return &cappedBuffer{limit: limit}
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	remaining := b.limit - int64(b.buf.Len())
	if remaining <= 0 {
		b.truncated = true
		b.discarded += int64(len(p))
		return len(p), nil
	}
	if int64(len(p)) <= remaining {
		b.buf.Write(p)
		return len(p), nil
	}
	b.buf.Write(p[:remaining])
	b.truncated = true
	b.discarded += int64(len(p)) - remaining
	return len(p), nil
}

func (b *cappedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// tailText bounds a rendered excerpt and repairs a truncated UTF-8 sequence, so a
// stored evidence object is always valid text.
func tailText(content string, limit int) string {
	if limit <= 0 || len(content) <= limit {
		return content
	}
	cut := content[:limit]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return cut + "\n[truncated]"
}

// observationMatches reports whether an observation satisfies a step's
// expectation or contradiction. It is a case-insensitive substring test, which is
// the weakest rule that is still honest: an adapter with a richer matcher may
// replace it, but the default never invents a match.
func observationMatches(want, observation string) bool {
	want = strings.TrimSpace(want)
	if want == "" {
		return false
	}
	return strings.Contains(strings.ToLower(observation), strings.ToLower(want))
}

// firstLocation finds the first "file:line" token in an output, so evidence points
// at code when the tool reported a location. It never guesses: no match means no
// location.
func firstLocation(output string) string {
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		candidate := line
		if idx := strings.IndexAny(candidate, " \t"); idx > 0 {
			candidate = candidate[:idx]
		}
		candidate = strings.Trim(candidate, "\"'()[]{},")
		for index, segment := range strings.Split(candidate, ":") {
			if index == 0 || !isDigits(segment) {
				continue
			}
			file := strings.Join(strings.Split(candidate, ":")[:index], ":")
			if filepath.Ext(file) == "" {
				continue
			}
			return file
		}
	}
	return ""
}

func isDigits(s string) bool {
	if s == "" {
		return false
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

// exitCodeOf reports a process exit status, or -1 when the process was killed by a
// signal or never completed.
func exitCodeOf(waitErr error) int {
	if waitErr == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if errors.As(waitErr, &exitErr) {
		return exitErr.ExitCode()
	}
	return -1
}
