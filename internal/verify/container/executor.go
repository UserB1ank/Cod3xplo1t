package container

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// ExecutorConfig binds one container adapter to one fixed, approved v2 plan and
// the frozen source tree it verifies. The adapter receives no Store and no Scope:
// it can run the plan it was constructed with, and it reports observations rather
// than a verdict.
type ExecutorConfig struct {
	Plan     verify.ExecutionPlan
	Approval verify.PlanApproval
	Source   verify.EnvironmentSource
	// Leases is the durable environment ownership record. A nil store makes the
	// executor refuse to run rather than run without fencing.
	Leases verify.EnvironmentLeaseStore
	Owner  string
	// LeaseTTL bounds one lease interval; the heartbeat renews well inside it.
	LeaseTTL time.Duration
	// MaxOutputBytes bounds each command observation.
	MaxOutputBytes int64
	Now            func() time.Time
}

// Executor is the verification tool adapter: it uses the V04 environment handle to
// run readiness and controlled probes, records structured observations, and lets
// the host's DeriveOutcome decide what they mean.
type Executor struct {
	Provider verify.EnvironmentProvider
	Config   ExecutorConfig
}

// NewExecutor validates the wiring. A misconfigured adapter is an operator error,
// not a verification failure, so it fails before anything is provisioned.
func NewExecutor(provider verify.EnvironmentProvider, cfg ExecutorConfig) (*Executor, error) {
	if provider == nil {
		return nil, fmt.Errorf("%w: no environment provider", verify.ErrExecutorConfig)
	}
	if cfg.Leases == nil {
		return nil, fmt.Errorf("%w: an environment lease store is required", verify.ErrExecutorConfig)
	}
	if strings.TrimSpace(cfg.Source.Path) == "" {
		return nil, fmt.Errorf("%w: a read-only source directory is required", verify.ErrExecutorConfig)
	}
	if !cfg.Source.ReadOnly {
		return nil, fmt.Errorf("%w: the source must be mounted read-only", verify.ErrExecutorConfig)
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 30 * time.Second
	}
	if cfg.LeaseTTL < 5*time.Second {
		return nil, fmt.Errorf("%w: a lease shorter than 5s cannot be renewed reliably", verify.ErrExecutorConfig)
	}
	if cfg.MaxOutputBytes <= 0 {
		cfg.MaxOutputBytes = 256 << 10
	}
	return &Executor{Provider: provider, Config: cfg}, nil
}

func (e *Executor) Capabilities() verify.ExecutorCapabilities {
	return verify.ExecutorCapabilities{
		Name: "container", Version: "1.0.0", SupportsCommands: true,
		SupportsStaticQueries: false, ReportsExitCode: true,
		Notes: []string{
			"source is mounted read-only at /source; /scratch and /tmp are the only writable paths",
			"network is none; the provider refuses an allowlist it cannot enforce",
			"readiness supports command probes; an http or tcp probe is refused, not approximated from the host",
		},
	}
}

// Execute provisions one environment, runs the readiness and controlled probes,
// and reports structured evidence. It always destroys the environment before it
// returns, including on cancellation and lease loss.
func (e *Executor) Execute(ctx context.Context, plan verify.Plan, env verify.Environment) (verify.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	build := e.Config.Plan
	if build.Digest == "" {
		build.Digest = build.DigestOf()
	}
	if err := verify.ValidateExecutionPlan(build); err != nil {
		return blockedResult("the fixed execution plan is invalid: "+err.Error(), verify.VerifyStopEnvironment), nil
	}
	if e.Config.Approval.Decision != verify.PlanApproved {
		return blockedResult("the plan has no recorded approval", verify.VerifyStopNoApproval), nil
	}
	if err := verify.ValidateApproval(build, e.Config.Approval, e.now()); err != nil {
		return blockedResult("the approval does not authorize this plan: "+err.Error(), verify.VerifyStopNoApproval), nil
	}
	if len(e.Config.Source.Digest) == 0 {
		return blockedResult("the frozen source has no digest; refusing to mount an unidentified tree", verify.VerifyStopEnvironment), nil
	}
	if len(build.Environment.Services) != 1 {
		return blockedResult("this provider executes exactly one service", verify.VerifyStopUnsupported), nil
	}

	owner := strings.TrimSpace(e.Config.Owner)
	if owner == "" {
		owner = "host"
	}
	now := e.now()
	if result, ok := e.reclaimExpired(ctx, build, now); !ok {
		return result, nil
	}
	leaseTTL := e.leaseTTL(build)
	lease, err := e.Config.Leases.AcquireEnvironmentLease(ctx, verify.EnvironmentLease{
		ID: build.ID, PlanID: build.ID, ProjectID: build.ProjectID, SnapshotID: build.SnapshotID,
		Owner: owner, Provider: "docker", SourceDigest: e.Config.Source.Digest,
		ExpiresAt: now.Add(leaseTTL).Format(time.RFC3339),
	}, now)
	if err != nil {
		switch {
		case errors.Is(err, verify.ErrLeaseHeld):
			return blockedResult("another execution owns this environment", verify.VerifyStopLeaseHeld), nil
		case errors.Is(err, verify.ErrLeaseExpired):
			return blockedResult("the environment lease expired before this execution started", verify.VerifyStopStale), nil
		default:
			return recognizeLeaseError(err)
		}
	}

	// From here on the environment is owned; every exit path releases the lease and
	// destroys whatever was created, and cleanup is recorded independently.
	cleanup := verify.CleanupFailed
	var handle verify.EnvironmentHandle
	failure := ""
	defer func() {
		destroyCtx, cancel := context.WithTimeout(context.WithoutCancel(context.Background()), 30*time.Second)
		defer cancel()
		if strings.TrimSpace(handle.ID) != "" {
			if err := e.Provider.Destroy(destroyCtx, handle); err != nil {
				failure = err.Error()
				cleanup = verify.CleanupFailed
			} else {
				cleanup = verify.CleanupSucceeded
			}
		} else {
			cleanup = verify.CleanupSucceeded
		}
		_, _ = e.Config.Leases.ReleaseEnvironmentLease(destroyCtx, lease.ID, lease.Owner, lease.Epoch, cleanup, failure, e.now())
	}()

	handle, err = e.Provider.Provision(ctx, verify.EnvironmentRequest{Plan: build, Approval: e.Config.Approval, Source: e.Config.Source, Owner: owner})
	if err != nil {
		return blockedResult("the environment could not be provisioned: "+err.Error(), verify.VerifyStopEnvironment), nil
	}
	bindNow := e.now()
	lease, err = e.Config.Leases.BindEnvironmentLease(ctx, lease.ID, lease.Owner, lease.Epoch,
		handle.ID, handle.Receipt.Digest, handle.Receipt.ImageDigest, bindNow.Add(leaseTTL), bindNow)
	if err != nil {
		return blockedResult("the environment lease could not be bound: "+err.Error(), verify.VerifyStopStale), nil
	}

	envDeadline, err := time.Parse(time.RFC3339, handle.ExpiresAt)
	if err != nil {
		return blockedResult("the environment expiry is not a valid timestamp: "+err.Error(), verify.VerifyStopEnvironment), nil
	}
	runCtx, cancel := context.WithDeadline(ctx, envDeadline)
	defer cancel()
	lost := make(chan struct{})
	go e.heartbeat(runCtx, cancel, lease, leaseTTL, envDeadline, lost)

	result := e.observe(runCtx, build, plan, handle, lost)
	result.Evidence = append(result.Evidence, e.environmentEvidence(build, handle, e.now()))
	if logs, err := e.Provider.Logs(ctx, handle, 200); err == nil && strings.TrimSpace(logs) != "" {
		if evidence, buildErr := verify.NewEvidence(verify.EvidenceRuntimeLog, "service log:\n"+logs, verify.EvidenceOptions{
			Tool: "container", ToolVersion: "1.0.0", SnapshotID: build.SnapshotID,
			HypothesisID: build.HypothesisID, FindingID: build.FindingID, PathID: build.PathID,
			Now: verify.NowString(e.now()),
		}); buildErr == nil {
			result.Evidence = append(result.Evidence, evidence)
		}
	}
	return result, nil
}

// reclaimExpired terminates an environment whose lease already expired before a
// new attempt takes a new epoch. Rejecting the stale result while leaving its
// container running would leak the resource and let two attempts share a target.
func (e *Executor) reclaimExpired(ctx context.Context, build verify.ExecutionPlan, now time.Time) (verify.Result, bool) {
	lease, err := e.Config.Leases.GetEnvironmentLease(ctx, build.ID)
	if err != nil {
		if errors.Is(err, verify.ErrLeaseNotFound) {
			return verify.Result{}, true
		}
		return blockedResult("the existing environment lease could not be read: "+err.Error(), verify.VerifyStopStale), false
	}
	expires, parseErr := time.Parse(time.RFC3339, lease.ExpiresAt)
	if parseErr != nil || expires.After(now) {
		return verify.Result{}, true
	}
	if !leaseStateActive(lease.State) && lease.Cleanup != verify.CleanupPending && lease.Cleanup != verify.CleanupFailed {
		return verify.Result{}, true
	}
	cleanup := verify.CleanupSucceeded
	failure := ""
	if strings.TrimSpace(lease.EnvironmentID) != "" {
		destroyCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
		defer cancel()
		if err := e.Provider.Destroy(destroyCtx, verify.EnvironmentHandle{ID: lease.EnvironmentID}); err != nil {
			cleanup, failure = verify.CleanupFailed, err.Error()
		}
	}
	if _, err := e.Config.Leases.ReleaseEnvironmentLease(ctx, lease.ID, lease.Owner, lease.Epoch, cleanup, failure, now); err != nil && !errors.Is(err, verify.ErrLeaseLost) {
		return blockedResult("the expired environment could not be released: "+err.Error(), verify.VerifyStopStale), false
	}
	if cleanup == verify.CleanupFailed {
		return blockedResult("the expired environment could not be destroyed; refusing to start a second target: "+failure, verify.VerifyStopEnvironment), false
	}
	return verify.Result{}, true
}

func leaseStateActive(state verify.EnvironmentState) bool {
	return state == verify.EnvironmentProvisioning || state == verify.EnvironmentReady || state == verify.EnvironmentRunning
}

func (e *Executor) observe(ctx context.Context, build verify.ExecutionPlan, plan verify.Plan, handle verify.EnvironmentHandle, lost <-chan struct{}) verify.Result {
	service := build.Environment.Services[0]
	readinessCtx, cancel := context.WithTimeout(ctx, e.readinessTimeout(build))
	defer cancel()
	if result, ok := e.waitReady(readinessCtx, build, service, handle, lost); !ok {
		return result
	}

	var (
		evidence     []verify.Evidence
		reproduction []string
		observed     strings.Builder
		lastExit     *int
		incomplete   bool
		reason       string
	)
	for index, step := range build.Steps {
		if err := leaseLost(lost); err != nil {
			return blockedWithEvidence("the environment lease was lost before step "+strconv.Itoa(index)+"; the result was discarded", verify.VerifyStopStale, evidence)
		}
		if len(step.Command) == 0 {
			return blockedWithEvidence("step "+strconv.Itoa(index)+" has no command and this executor only runs commands", verify.VerifyStopUnsupported, evidence)
		}
		timeout := step.TimeoutSeconds
		if timeout <= 0 {
			timeout = build.Budget.MaxSeconds
		}
		command := verify.CommandRequest{
			Argv: append([]string(nil), step.Command...), Workdir: service.Workdir,
			TimeoutSeconds: timeout, MaxOutputBytes: e.Config.MaxOutputBytes,
		}
		outcome, err := e.Provider.Exec(ctx, handle, command)
		if err != nil {
			if errors.Is(err, verify.ErrEnvironmentExpired) {
				return blockedWithEvidence("the environment expiry ended the run", verify.VerifyStopStale, evidence)
			}
			return blockedWithEvidence("step "+strconv.Itoa(index)+" could not run: "+err.Error(), verify.VerifyStopExecutorErr, evidence)
		}
		if err := leaseLost(lost); err != nil {
			return blockedWithEvidence("the environment lease was lost during step "+strconv.Itoa(index)+"; the result was discarded", verify.VerifyStopStale, evidence)
		}
		content := observationContent(index, step, outcome)
		evidenceObject, buildErr := verify.NewEvidence(verify.EvidenceRuntimeLog, content, verify.EvidenceOptions{
			Tool: "container", ToolVersion: "1.0.0", SnapshotID: build.SnapshotID,
			HypothesisID: build.HypothesisID, FindingID: build.FindingID, PathID: build.PathID,
			Now: verify.NowString(e.now()),
		})
		if buildErr != nil {
			return blockedWithEvidence("the observation could not be recorded: "+buildErr.Error(), verify.VerifyStopExecutorErr, evidence)
		}
		if step.Contradiction != "" && strings.Contains(content, step.Contradiction) {
			evidenceObject = verify.MarkContradicting(evidenceObject, step.Contradiction)
			incomplete = true
			reason = "step " + strconv.Itoa(index) + " produced the contradiction it named"
		}
		evidence = append(evidence, evidenceObject)
		reproduction = append(reproduction, fmt.Sprintf("step %d: %s", index, strings.Join(step.Command, " ")))
		observed.WriteString(outcome.Stdout)
		observed.WriteString("\n")
		observed.WriteString(outcome.Stderr)
		observed.WriteString("\n")

		exit := outcome.ExitCode
		if !outcome.TimedOut && !outcome.Cancelled && outcome.Err == "" {
			lastExit = &exit
		}
		switch {
		case outcome.Cancelled:
			return blockedWithEvidence("the verification was cancelled during step "+strconv.Itoa(index), verify.VerifyStopCancelled, evidence)
		case outcome.TimedOut:
			return blockedWithEvidence(fmt.Sprintf("step %d exceeded its %ds budget", index, timeout), verify.VerifyStopTimeout, evidence)
		case outcome.Err != "":
			return blockedWithEvidence("step "+strconv.Itoa(index)+" could not be started: "+outcome.Err, verify.VerifyStopExecutorErr, evidence)
		case outcome.ExitCode != 0:
			incomplete = true
			if reason == "" {
				reason = fmt.Sprintf("step %d exited with status %d, so the plan did not run to completion", index, outcome.ExitCode)
			}
		}
	}

	// Assertions are the structured part of the observation. A required assertion
	// that did not match keeps the result inconclusive; it never silently passes.
	if len(build.Assertions) == 0 {
		incomplete = true
		if reason == "" {
			reason = "the plan has no structured assertions, so a text match cannot confirm the claim"
		}
	}
	contradicted := false
	for _, assertion := range build.Assertions {
		matched, contradicts, err := evaluateAssertion(assertion, observed.String(), lastExit)
		if err != nil {
			return blockedWithEvidence("assertion "+assertion.ID+" is not supported: "+err.Error(), verify.VerifyStopUnsupported, evidence)
		}
		content := assertionContent(assertion, matched, contradicts, observed.String())
		evidenceObject, buildErr := verify.NewEvidence(verify.EvidenceTest, content, verify.EvidenceOptions{
			Tool: "container", ToolVersion: "1.0.0", SnapshotID: build.SnapshotID,
			HypothesisID: build.HypothesisID, FindingID: build.FindingID, PathID: build.PathID,
			Now: verify.NowString(e.now()),
		})
		if buildErr != nil {
			return blockedWithEvidence("the assertion could not be recorded: "+buildErr.Error(), verify.VerifyStopExecutorErr, evidence)
		}
		if contradicts {
			evidenceObject = verify.MarkContradicting(evidenceObject, assertion.Contradiction)
			contradicted = true
			reason = "assertion " + assertion.ID + " produced the contradiction it named"
		}
		if assertion.Required && !matched {
			incomplete = true
			if reason == "" {
				reason = "required assertion " + assertion.ID + " did not match the observed output"
			}
		}
		evidence = append(evidence, evidenceObject)
	}

	outcome := verify.OutcomeInconclusive
	switch {
	case contradicted:
		outcome = verify.OutcomeRefuted
	case !incomplete && len(build.Assertions) > 0 && len(reproduction) > 0:
		outcome = verify.OutcomeConfirmed
		if reason == "" {
			reason = "every step ran, every required assertion matched, and nothing contradicted the claim"
		}
	}
	if reason == "" {
		reason = "the evidence is insufficient to conclude"
	}
	return verify.Result{
		Outcome: outcome, Reason: reason, Reproduction: strings.Join(reproduction, "\n"),
		Evidence: evidence, ExitCode: lastExit, StopReason: verify.VerifyStopCompleted,
	}
}

func (e *Executor) waitReady(ctx context.Context, build verify.ExecutionPlan, service verify.ServiceSpec, handle verify.EnvironmentHandle, lost <-chan struct{}) (verify.Result, bool) {
	state, err := e.Provider.Status(ctx, handle)
	if err != nil || (state != verify.EnvironmentRunning && state != verify.EnvironmentReady) {
		logs, _ := e.Provider.Logs(ctx, handle, 100)
		result := blockedResult("the environment is not running"+errorSuffix(err)+logSuffix(logs), verify.VerifyStopEnvironment)
		return result, false
	}
	if len(service.Readiness) == 0 {
		return verify.Result{}, true
	}
	for _, probe := range service.Readiness {
		if probe.Kind != "command" {
			return blockedResult("readiness probe kind "+probe.Kind+" is not enforceable by this provider; it refuses instead of approximating it from the host", verify.VerifyStopUnsupported), false
		}
		interval := time.Duration(probe.IntervalSeconds) * time.Second
		if interval <= 0 {
			interval = time.Second
		}
		for {
			if err := leaseLost(lost); err != nil {
				return blockedResult("the environment lease was lost during readiness", verify.VerifyStopStale), false
			}
			outcome, err := e.Provider.Exec(ctx, handle, verify.CommandRequest{
				Argv: append([]string(nil), probe.Command...), TimeoutSeconds: 10,
				MaxOutputBytes: 32 << 10,
			})
			if err == nil && !outcome.TimedOut && !outcome.Cancelled && outcome.Err == "" && outcome.ExitCode == 0 {
				break
			}
			select {
			case <-ctx.Done():
				logs, _ := e.Provider.Logs(context.WithoutCancel(ctx), handle, 100)
				return blockedResult("the service did not become ready before the readiness budget expired"+logSuffix(logs), verify.VerifyStopEnvironment), false
			case <-time.After(interval):
			}
		}
	}
	return verify.Result{}, true
}

func (e *Executor) heartbeat(ctx context.Context, cancel context.CancelFunc, lease verify.EnvironmentLease, ttl time.Duration, deadline time.Time, lost chan<- struct{}) {
	interval := ttl / 3
	if interval < time.Second {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			now := e.now()
			until := now.Add(ttl)
			if !deadline.IsZero() && deadline.Before(until) {
				until = deadline
			}
			if !until.After(now) {
				close(lost)
				cancel()
				return
			}
			if _, err := e.Config.Leases.RenewEnvironmentLease(ctx, lease.ID, lease.Owner, lease.Epoch, until, now); err != nil {
				// Fence the result and actively stop the old work. Letting the test
				// continue while only rejecting its result would keep consuming the
				// environment a newer owner now believes it controls.
				close(lost)
				cancel()
				return
			}
		}
	}
}

func (e *Executor) environmentEvidence(build verify.ExecutionPlan, handle verify.EnvironmentHandle, now time.Time) verify.Evidence {
	receipt := handle.Receipt
	content := fmt.Sprintf(
		"environment_id=%s\nprovider=%s\nprovider_version=%s\nimage=%s\nimage_digest=%s\nsource_digest=%s\nnetwork=%s\nsource_read_only=%t\napplied=%s\ncpu_millis=%d\nmemory_mb=%d\nmax_processes=%d\nscratch_mb=%d\nttl_seconds=%d\nuser=%s\nexpires_at=%s\n",
		handle.ID, receipt.Provider, receipt.ProviderVersion, build.Environment.Template,
		receipt.ImageDigest, receipt.SourceDigest, receipt.NetworkMode, receipt.SourceReadOnly,
		strings.Join(receipt.Applied, ","), receipt.CPUMillis, receipt.MemoryMB,
		receipt.MaxProcesses, receipt.ScratchMB, receipt.TTLSeconds, receipt.User, handle.ExpiresAt,
	)
	evidence, err := verify.NewEvidence(verify.EvidenceEnvironment, content, verify.EvidenceOptions{
		Tool: "container", ToolVersion: "1.0.0", SnapshotID: build.SnapshotID,
		HypothesisID: build.HypothesisID, FindingID: build.FindingID, PathID: build.PathID,
		Now: verify.NowString(now),
	})
	if err != nil {
		return verify.Evidence{}
	}
	return evidence
}

func (e *Executor) readinessTimeout(build verify.ExecutionPlan) time.Duration {
	for _, service := range build.Environment.Services {
		for _, probe := range service.Readiness {
			if probe.TimeoutSeconds > 0 {
				return time.Duration(probe.TimeoutSeconds) * time.Second
			}
		}
	}
	seconds := build.Budget.MaxSeconds
	if seconds <= 0 || seconds > 120 {
		seconds = 120
	}
	return time.Duration(seconds) * time.Second
}

func (e *Executor) leaseTTL(build verify.ExecutionPlan) time.Duration {
	ttl := e.Config.LeaseTTL
	envTTL := time.Duration(build.Environment.TTLSeconds) * time.Second
	if envTTL > 0 && envTTL < ttl {
		ttl = envTTL
	}
	if ttl < 5*time.Second {
		ttl = 5 * time.Second
	}
	return ttl
}

func (e *Executor) now() time.Time {
	if e.Config.Now != nil {
		return e.Config.Now().UTC()
	}
	return time.Now().UTC()
}

// DigestSource produces the content digest the environment receipt binds. It
// rejects symlinks and non-regular files instead of following them out of the
// frozen tree.
func DigestSource(path string) (string, error) {
	h := sha256.New()
	err := filepath.WalkDir(path, func(name string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("%w: %s is not a regular file", verify.ErrEnvironmentUnsupported, name)
		}
		relative, err := filepath.Rel(path, name)
		if err != nil {
			return err
		}
		fmt.Fprintf(h, "%d:%s:%d:", len(relative), filepath.ToSlash(relative), info.Size())
		file, err := os.Open(name)
		if err != nil {
			return err
		}
		n, err := io.Copy(h, file)
		file.Close()
		if err != nil {
			return err
		}
		if n != info.Size() {
			return fmt.Errorf("%w: %s changed while it was hashed", verify.ErrEnvironmentUnsupported, relative)
		}
		return nil
	})
	if err != nil {
		return "", err
	}
	return "source-" + hex.EncodeToString(h.Sum(nil)[:12]), nil
}

func leaseLost(lost <-chan struct{}) error {
	select {
	case <-lost:
		return verify.ErrLeaseLost
	default:
		return nil
	}
}

func blockedResult(reason, stop string) verify.Result {
	return verify.Result{Outcome: verify.OutcomeBlocked, Reason: reason, StopReason: stop}
}

func blockedWithEvidence(reason, stop string, evidence []verify.Evidence) verify.Result {
	return verify.Result{Outcome: verify.OutcomeBlocked, Reason: reason, StopReason: stop, Evidence: evidence}
}

func recognizeLeaseError(err error) (verify.Result, error) {
	switch {
	case errors.Is(err, verify.ErrLeaseHeld):
		return blockedResult("another execution owns this environment", verify.VerifyStopLeaseHeld), nil
	case errors.Is(err, verify.ErrLeaseExpired), errors.Is(err, verify.ErrLeaseLost):
		return blockedResult("the environment lease was lost", verify.VerifyStopStale), nil
	default:
		return verify.Result{}, err
	}
}

func observationContent(index int, step verify.Step, outcome verify.CommandResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "step[%d] kind=%s\n", index, step.Kind)
	fmt.Fprintf(&b, "command=%s\n", strings.Join(step.Command, " "))
	fmt.Fprintf(&b, "exit_code=%d\n", outcome.ExitCode)
	if outcome.TimedOut {
		b.WriteString("timed_out=true\n")
	}
	if outcome.Cancelled {
		b.WriteString("cancelled=true\n")
	}
	if outcome.Truncated {
		fmt.Fprintf(&b, "output_truncated=true discarded_bytes=%d\n", outcome.Discarded)
	}
	if outcome.Err != "" {
		fmt.Fprintf(&b, "error=%s\n", outcome.Err)
	}
	b.WriteString("--- stdout ---\n")
	b.WriteString(outcome.Stdout)
	b.WriteString("\n--- stderr ---\n")
	b.WriteString(outcome.Stderr)
	return b.String()
}

func assertionContent(assertion verify.PlanAssertion, matched, contradicts bool, observation string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "assertion=%s kind=%s required=%t\n", assertion.ID, assertion.Kind, assertion.Required)
	fmt.Fprintf(&b, "expectation=%s\n", assertion.Expectation)
	fmt.Fprintf(&b, "contradiction=%s\n", assertion.Contradiction)
	fmt.Fprintf(&b, "matched=%t contradicted=%t\n", matched, contradicts)
	b.WriteString("--- observation ---\n")
	b.WriteString(tail(observation, 4096))
	return b.String()
}

// evaluateAssertion is deterministic and deliberately narrow: an assertion kind
// this adapter does not understand is an unsupported plan, never a silent pass.
func evaluateAssertion(assertion verify.PlanAssertion, observation string, exit *int) (matched, contradicted bool, err error) {
	switch assertion.Kind {
	case "stdout_contains", "contains", "text_contains", "http":
		matched = strings.Contains(observation, assertion.Expectation)
		contradicted = assertion.Contradiction != "" && strings.Contains(observation, assertion.Contradiction)
		return matched, contradicted, nil
	case "stdout_not_contains":
		matched = !strings.Contains(observation, assertion.Expectation)
		contradicted = assertion.Contradiction != "" && strings.Contains(observation, assertion.Contradiction)
		return matched, contradicted, nil
	case "exit_code":
		want, parseErr := strconv.Atoi(strings.TrimSpace(assertion.Expectation))
		if parseErr != nil {
			return false, false, fmt.Errorf("exit_code expectation %q is not an integer", assertion.Expectation)
		}
		if exit == nil {
			return false, false, nil
		}
		return *exit == want, false, nil
	case "http_status":
		want := strings.TrimSpace(assertion.Expectation)
		matched = strings.Contains(observation, "status="+want) || strings.Contains(observation, "status: "+want)
		contradicted = assertion.Contradiction != "" && strings.Contains(observation, "status="+assertion.Contradiction)
		return matched, contradicted, nil
	default:
		return false, false, fmt.Errorf("unknown assertion kind %q", assertion.Kind)
	}
}

func tail(value string, limit int) string {
	if len(value) <= limit {
		return value
	}
	return value[len(value)-limit:]
}

func errorSuffix(err error) string {
	if err == nil {
		return ""
	}
	return ": " + err.Error()
}

func logSuffix(logs string) string {
	if strings.TrimSpace(logs) == "" {
		return ""
	}
	return "\n--- service log ---\n" + tail(logs, 4096)
}
