package container

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

type fakeProvider struct {
	provisions   int
	destroys     int
	status       verify.EnvironmentState
	statusErr    error
	provisionErr error
	destroyErr   error
	logs         string
	exec         func(verify.CommandRequest) (verify.CommandResult, error)
}

func (f *fakeProvider) Capabilities() []string {
	return []string{"container", "network_none", "read_only_source"}
}
func (f *fakeProvider) Validate(context.Context, verify.PlanEnvironment) error { return nil }
func (f *fakeProvider) Provision(_ context.Context, request verify.EnvironmentRequest) (verify.EnvironmentHandle, error) {
	if f.provisionErr != nil {
		return verify.EnvironmentHandle{}, f.provisionErr
	}
	f.provisions++
	return verify.EnvironmentHandle{
		ID: "env-test", Provider: "docker", State: verify.EnvironmentReady,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
		Receipt: verify.EnvironmentReceipt{
			Provider: "docker", ProviderVersion: "test", User: DefaultUser,
			NetworkMode: "none", SourceReadOnly: true, SourceDigest: request.Source.Digest,
			ImageDigest: "sha256:image", EnvironmentID: "env-test",
			CPUMillis: 100, MemoryMB: 128, MaxProcesses: 16, ScratchMB: 16, TTLSeconds: 60,
			Applied: []string{"non_root", "read_only_rootfs", "network_none", "read_only_source"},
			Digest:  "receipt-test",
		},
	}, nil
}
func (f *fakeProvider) Status(context.Context, verify.EnvironmentHandle) (verify.EnvironmentState, error) {
	if f.statusErr != nil {
		return verify.EnvironmentFailed, f.statusErr
	}
	if f.status == "" {
		return verify.EnvironmentRunning, nil
	}
	return f.status, nil
}
func (f *fakeProvider) Exec(_ context.Context, _ verify.EnvironmentHandle, request verify.CommandRequest) (verify.CommandResult, error) {
	return f.exec(request)
}
func (f *fakeProvider) Logs(context.Context, verify.EnvironmentHandle, int) (string, error) {
	return f.logs, nil
}
func (f *fakeProvider) Destroy(context.Context, verify.EnvironmentHandle) error {
	f.destroys++
	return f.destroyErr
}

func executorPlan(t *testing.T, assertions []verify.PlanAssertion) (verify.ExecutionPlan, verify.PlanApproval, verify.EnvironmentSource) {
	t.Helper()
	now := time.Now().UTC()
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "app.txt"), []byte("fixture"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest, err := DigestSource(source)
	if err != nil {
		t.Fatal(err)
	}
	plan := verify.ExecutionPlan{
		SchemaVersion: verify.ExecutionPlanSchemaVersion, ID: "plan-exec", ProjectID: "proj-1",
		HypothesisID: "hyp-1", FindingID: "finding-hyp-1", PathID: "path-1", AuditID: "audit-1", SnapshotID: "snap-1",
		SecurityGoal: "sql_injection", Claim: "the endpoint returns the secret",
		Verifier: verify.PlanVerifier{Adapter: "container", Version: "1.0.0", Capability: "verification"},
		Steps: []verify.Step{{
			Kind: verify.StepDynamicProof, Command: []string{"/probe"},
			Expectation: "SECRET_TOKEN", Contradiction: "denied",
			TimeoutSeconds: 20, RequiresApproval: true,
		}},
		Assertions: assertions,
		Environment: verify.PlanEnvironment{
			OS: "linux", Arch: "amd64",
			Provider: verify.PlanProvider{Name: "docker", Version: "1.0.0", Capabilities: []string{"container", "network_none"}},
			Template: "fixture:1", Network: verify.PlanNetwork{Mode: "none"}, SourceReadOnly: true,
			ScratchMB: 16, TTLSeconds: 60, Permissions: []string{"dynamic_exec"},
			Resources: verify.PlanResources{CPUMillis: 100, MemoryMB: 128, DiskMB: 64, MaxProcesses: 16, MaxWrites: 10},
			Services: []verify.ServiceSpec{{
				Name: "target", Role: "target", Template: "fixture:1", Command: []string{"/server"},
				Readiness: []verify.ReadinessProbe{{Kind: "command", Command: []string{"/probe", "health"}, TimeoutSeconds: 20, IntervalSeconds: 1}},
			}},
		},
		Scope:     verify.Scope{Repository: "repo-1", SnapshotID: "snap-1", RequiresHumanApproval: true},
		Budget:    verify.PlanBudget{MaxSeconds: 30, MaxSteps: 1, MaxCommands: 1},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
		CreatedAt: now.Format(time.RFC3339),
	}
	plan.Digest = plan.DigestOf()
	approval := verify.PlanApproval{
		PlanID: plan.ID, PlanDigest: plan.DigestOf(), Decision: verify.PlanApproved,
		Actor: "operator", ActorRole: "writer", Permissions: []string{"dynamic_exec"},
		Reason: "run the single-service verification", DecidedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	approval.Digest = approval.DigestOf()
	return plan, approval, verify.EnvironmentSource{SnapshotID: plan.SnapshotID, Digest: digest, ReadOnly: true, Path: source}
}

func executingProvider(results ...verify.CommandResult) *fakeProvider {
	queue := append([]verify.CommandResult(nil), results...)
	return &fakeProvider{exec: func(verify.CommandRequest) (verify.CommandResult, error) {
		if len(queue) == 0 {
			return verify.CommandResult{ExitCode: 0}, nil
		}
		result := queue[0]
		queue = queue[1:]
		return result, nil
	}}
}

func TestExecutorConfirmsOnlyWithStructuredAssertions(t *testing.T) {
	assertions := []verify.PlanAssertion{
		{ID: "a1", Kind: "http_status", Expectation: "200", Contradiction: "500", Required: true},
		{ID: "a2", Kind: "stdout_contains", Expectation: "SECRET_TOKEN", Contradiction: "denied", Required: true},
	}
	plan, approval, source := executorPlan(t, assertions)
	provider := executingProvider(
		verify.CommandResult{ExitCode: 0},                                      // readiness
		verify.CommandResult{ExitCode: 0, Stdout: "SECRET_TOKEN status=200\n"}, // probe
	)
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval, Source: source,
		Leases: verify.NewMemoryEnvironmentLeases(), Owner: "worker-a",
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	result, err := executor.Execute(context.Background(), verify.LegacyPlan(plan), verify.DefaultEnvironment())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Outcome != verify.OutcomeConfirmed {
		t.Fatalf("outcome = %s (%s), evidence = %+v", result.Outcome, result.Reason, result.Evidence)
	}
	if provider.provisions != 1 || provider.destroys != 1 {
		t.Fatalf("provisions=%d destroys=%d", provider.provisions, provider.destroys)
	}
	kinds := map[verify.EvidenceKind]bool{}
	for _, evidence := range result.Evidence {
		kinds[evidence.Kind] = true
		if evidence.ID == "" || evidence.ContentHash == "" {
			t.Fatalf("evidence not built: %+v", evidence)
		}
	}
	for _, want := range []verify.EvidenceKind{verify.EvidenceRuntimeLog, verify.EvidenceTest, verify.EvidenceEnvironment} {
		if !kinds[want] {
			t.Fatalf("missing %s evidence: %+v", want, kinds)
		}
	}
	// DeriveOutcome is still the only producer of a verdict.
	outcome, _ := verify.DeriveOutcome(result, verify.LegacyPlan(plan))
	if outcome != verify.OutcomeConfirmed {
		t.Fatalf("DeriveOutcome = %s", outcome)
	}
}

func TestExecutorRefutesWithContradictingEvidence(t *testing.T) {
	plan, approval, source := executorPlan(t, []verify.PlanAssertion{
		{ID: "a1", Kind: "stdout_contains", Expectation: "SECRET_TOKEN", Contradiction: "denied", Required: true},
	})
	provider := executingProvider(
		verify.CommandResult{ExitCode: 0},
		verify.CommandResult{ExitCode: 0, Stdout: "denied\n"},
	)
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval, Source: source,
		Leases: verify.NewMemoryEnvironmentLeases(), Owner: "worker-a",
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	result, err := executor.Execute(context.Background(), verify.LegacyPlan(plan), verify.DefaultEnvironment())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Outcome != verify.OutcomeRefuted {
		t.Fatalf("outcome = %s (%s)", result.Outcome, result.Reason)
	}
	if len(result.ContradictingEvidence()) == 0 {
		t.Fatal("refutation has no contradicting evidence")
	}
	if outcome, _ := verify.DeriveOutcome(result, verify.LegacyPlan(plan)); outcome != verify.OutcomeRefuted {
		t.Fatalf("DeriveOutcome = %s", outcome)
	}
}

func TestExecutorEnvironmentFailureIsBlockedNotRefuted(t *testing.T) {
	plan, approval, source := executorPlan(t, []verify.PlanAssertion{
		{ID: "a1", Kind: "stdout_contains", Expectation: "SECRET_TOKEN", Contradiction: "denied", Required: true},
	})
	provider := &fakeProvider{provisionErr: errors.New("docker run failed"), exec: func(verify.CommandRequest) (verify.CommandResult, error) {
		t.Fatal("exec must not run when provisioning failed")
		return verify.CommandResult{}, nil
	}}
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval, Source: source,
		Leases: verify.NewMemoryEnvironmentLeases(), Owner: "worker-a",
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	result, err := executor.Execute(context.Background(), verify.LegacyPlan(plan), verify.DefaultEnvironment())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Outcome != verify.OutcomeBlocked || result.StopReason != verify.VerifyStopEnvironment {
		t.Fatalf("result = %+v", result)
	}
	if outcome, _ := verify.DeriveOutcome(result, verify.LegacyPlan(plan)); outcome != verify.OutcomeBlocked {
		t.Fatalf("DeriveOutcome = %s", outcome)
	}
}

func TestExecutorRefusesLeaseHeldByAnotherExecution(t *testing.T) {
	plan, approval, source := executorPlan(t, []verify.PlanAssertion{{
		ID: "a1", Kind: "stdout_contains", Expectation: "SECRET_TOKEN", Contradiction: "denied", Required: true,
	}})
	leases := verify.NewMemoryEnvironmentLeases()
	now := time.Now().UTC()
	if _, err := leases.AcquireEnvironmentLease(context.Background(), verify.EnvironmentLease{
		ID: plan.ID, PlanID: plan.ID, ProjectID: plan.ProjectID, SnapshotID: plan.SnapshotID,
		Owner: "worker-other", ExpiresAt: now.Add(time.Minute).Format(time.RFC3339),
	}, now); err != nil {
		t.Fatalf("seed lease: %v", err)
	}
	provider := &fakeProvider{exec: func(verify.CommandRequest) (verify.CommandResult, error) {
		t.Fatal("exec must not run when the lease is held")
		return verify.CommandResult{}, nil
	}}
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval, Source: source, Leases: leases, Owner: "worker-a",
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	result, err := executor.Execute(context.Background(), verify.LegacyPlan(plan), verify.DefaultEnvironment())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Outcome != verify.OutcomeBlocked || result.StopReason != verify.VerifyStopLeaseHeld {
		t.Fatalf("result = %+v", result)
	}
	if provider.provisions != 0 {
		t.Fatal("provisioned despite a held lease")
	}
}

func TestExecutorRefusesUnenforceableReadinessProbe(t *testing.T) {
	plan, approval, source := executorPlan(t, []verify.PlanAssertion{})
	plan.Environment.Services[0].Readiness = []verify.ReadinessProbe{{Kind: "http", Path: "/health", Port: 8080, TimeoutSeconds: 5}}
	plan.Digest = plan.DigestOf()
	approval.PlanDigest = plan.Digest
	approval.Digest = approval.DigestOf()
	provider := executingProvider()
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval, Source: source,
		Leases: verify.NewMemoryEnvironmentLeases(), Owner: "worker-a",
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	result, err := executor.Execute(context.Background(), verify.LegacyPlan(plan), verify.DefaultEnvironment())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Outcome != verify.OutcomeBlocked || !strings.Contains(result.Reason, "not enforceable") {
		t.Fatalf("result = %+v", result)
	}
	if provider.destroys != 1 {
		t.Fatalf("environment was not destroyed: %d", provider.destroys)
	}
}

func TestDigestSourceIsStableAndContentSensitive(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("one"), 0o644); err != nil {
		t.Fatal(err)
	}
	first, err := DigestSource(dir)
	if err != nil {
		t.Fatalf("digest: %v", err)
	}
	second, err := DigestSource(dir)
	if err != nil || second != first {
		t.Fatalf("digest is not stable: %s %s %v", first, second, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "a.txt"), []byte("two"), 0o644); err != nil {
		t.Fatal(err)
	}
	third, err := DigestSource(dir)
	if err != nil || third == first {
		t.Fatalf("digest ignored content: %s %s %v", first, third, err)
	}
}

func TestExecutorReclaimsExpiredEnvironmentBeforeNewEpoch(t *testing.T) {
	plan, approval, source := executorPlan(t, []verify.PlanAssertion{
		{ID: "a1", Kind: "stdout_contains", Expectation: "SECRET_TOKEN", Contradiction: "PERMISSION_DENIED", Required: true},
	})
	leases := verify.NewMemoryEnvironmentLeases()
	now := time.Now().UTC()
	if _, err := leases.AcquireEnvironmentLease(context.Background(), verify.EnvironmentLease{
		ID: plan.ID, PlanID: plan.ID, ProjectID: plan.ProjectID, SnapshotID: plan.SnapshotID,
		Owner: "worker-old", EnvironmentID: "env-old",
		ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339),
	}, now); err != nil {
		t.Fatalf("seed expired lease: %v", err)
	}
	provider := executingProvider(
		verify.CommandResult{ExitCode: 0},
		verify.CommandResult{ExitCode: 0, Stdout: "SECRET_TOKEN\n"},
	)
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval, Source: source,
		Leases: leases, Owner: "worker-new",
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	result, err := executor.Execute(context.Background(), verify.LegacyPlan(plan), verify.DefaultEnvironment())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Outcome != verify.OutcomeConfirmed {
		t.Fatalf("outcome = %s (%s)", result.Outcome, result.Reason)
	}
	lease, err := leases.GetEnvironmentLease(context.Background(), plan.ID)
	if err != nil {
		t.Fatalf("lease: %v", err)
	}
	if lease.Epoch != 2 || lease.Owner != "worker-new" || lease.Cleanup != verify.CleanupSucceeded {
		t.Fatalf("lease = %+v", lease)
	}
	if provider.destroys != 2 {
		t.Fatalf("destroys = %d, want old + new environments", provider.destroys)
	}
}

func TestExecutorRefusesToStartWhenExpiredCleanupFails(t *testing.T) {
	plan, approval, source := executorPlan(t, []verify.PlanAssertion{})
	leases := verify.NewMemoryEnvironmentLeases()
	now := time.Now().UTC()
	if _, err := leases.AcquireEnvironmentLease(context.Background(), verify.EnvironmentLease{
		ID: plan.ID, PlanID: plan.ID, ProjectID: plan.ProjectID, SnapshotID: plan.SnapshotID,
		Owner: "worker-old", EnvironmentID: "env-old",
		ExpiresAt: now.Add(-time.Minute).Format(time.RFC3339),
	}, now); err != nil {
		t.Fatalf("seed expired lease: %v", err)
	}
	provider := &fakeProvider{destroyErr: errors.New("docker rm failed"), exec: func(verify.CommandRequest) (verify.CommandResult, error) {
		t.Fatal("exec must not run when the previous environment could not be destroyed")
		return verify.CommandResult{}, nil
	}}
	executor, err := NewExecutor(provider, ExecutorConfig{
		Plan: plan, Approval: approval, Source: source,
		Leases: leases, Owner: "worker-new",
	})
	if err != nil {
		t.Fatalf("new executor: %v", err)
	}
	result, err := executor.Execute(context.Background(), verify.LegacyPlan(plan), verify.DefaultEnvironment())
	if err != nil {
		t.Fatalf("execute: %v", err)
	}
	if result.Outcome != verify.OutcomeBlocked || !strings.Contains(result.Reason, "could not be destroyed") {
		t.Fatalf("result = %+v", result)
	}
	if provider.provisions != 0 {
		t.Fatal("started a second target while the old one was still alive")
	}
}
