package container

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func lifecycleRequest(t *testing.T) verify.EnvironmentRequest {
	t.Helper()
	now := time.Now().UTC()
	plan := verify.ExecutionPlan{
		SchemaVersion: verify.ExecutionPlanSchemaVersion, ID: "plan-container", ProjectID: "proj-1",
		HypothesisID: "hyp-1", PathID: "path-1", AuditID: "audit-1", SnapshotID: "snap-1",
		SecurityGoal: "sql_injection", Claim: "claim",
		Verifier:   verify.PlanVerifier{Adapter: "container", Version: "1.0.0", Capability: "verification"},
		Steps:      []verify.Step{{Kind: verify.StepDynamicProof, Expectation: "secret", Contradiction: "400", RequiresApproval: true}},
		Assertions: []verify.PlanAssertion{{ID: "a1", Kind: "http", Expectation: "secret", Contradiction: "400", Required: true}},
		Environment: verify.PlanEnvironment{
			OS: "linux", Arch: "amd64", Provider: verify.PlanProvider{Name: "docker", Version: "1.0.0", Capabilities: []string{"container"}},
			Template: "codexploit:local", Network: verify.PlanNetwork{Mode: "none"}, SourceReadOnly: true,
			ScratchMB: 16, TTLSeconds: 60, Permissions: []string{"dynamic_exec"},
			Resources: verify.PlanResources{CPUMillis: 100, MemoryMB: 128, DiskMB: 64, MaxProcesses: 16, MaxWrites: 10},
			Services:  []verify.ServiceSpec{{Name: "target", Role: "target", Template: "codexploit:local", Command: []string{"sleep", "60"}}},
		},
		Scope:     verify.Scope{Repository: "repo-1", SnapshotID: "snap-1", RequiresHumanApproval: true},
		Budget:    verify.PlanBudget{MaxSeconds: 30, MaxSteps: 1, MaxCommands: 1},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	plan.Digest = plan.DigestOf()
	approval := verify.PlanApproval{
		PlanID: plan.ID, PlanDigest: plan.DigestOf(), Decision: verify.PlanApproved,
		Actor: "test", ActorRole: "writer", Permissions: []string{"dynamic_exec"},
		Reason: "docker lifecycle test", DecidedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	approval.Digest = approval.DigestOf()
	return verify.EnvironmentRequest{
		Plan: plan, Approval: approval,
		Source: verify.EnvironmentSource{SnapshotID: plan.SnapshotID, ReadOnly: true},
	}
}

func TestDockerEnvironmentLifecycle(t *testing.T) {
	if os.Getenv("CODEXPLOIT_DOCKER_TESTS") != "1" {
		t.Skip("set CODEXPLOIT_DOCKER_TESTS=1 to run the real container lifecycle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	request := lifecycleRequest(t)
	source := t.TempDir()
	if err := os.WriteFile(filepath.Join(source, "app.txt"), []byte("fixture"), 0o444); err != nil {
		t.Fatal(err)
	}
	request.Source.Path = source
	digest, err := DigestSource(source)
	if err != nil {
		t.Fatal(err)
	}
	request.Source.Digest = digest
	provider := Provider{}
	handle, err := provider.Provision(ctx, request)
	if err != nil {
		t.Fatalf("provision: %v", err)
	}
	defer func() { _ = provider.Destroy(context.Background(), handle) }()
	if handle.Receipt.NetworkMode != "none" || !handle.Receipt.SourceReadOnly || handle.Receipt.Digest == "" {
		t.Fatalf("receipt = %+v", handle.Receipt)
	}
	state, err := provider.Status(ctx, handle)
	if err != nil || (state != verify.EnvironmentRunning && state != verify.EnvironmentProvisioning) {
		t.Fatalf("status = %s %v", state, err)
	}
	if err := provider.Destroy(ctx, handle); err != nil {
		t.Fatalf("destroy: %v", err)
	}
	if _, err := provider.Status(ctx, handle); err == nil {
		t.Fatal("destroyed environment still reported")
	}
}

func TestRunArgsEnforceEveryIsolationRule(t *testing.T) {
	spec := runSpec{
		Name: "env-test", SourcePath: "/tmp/source", SourceDigest: "src-1",
		RequestDigest: "req-1", PlanID: "plan-1", ProjectID: "proj-1",
		Policy: verify.ContainerPolicy{
			Image: "fixture:1", User: DefaultUser, ReadOnlyRootFS: true,
			Env: []string{"APP_MODE=test"}, SourceMount: "/source", SourceReadOnly: true,
			ScratchMB: 32, TTLSeconds: 60, CPUMillis: 250, MemoryMB: 256,
			PIDs: 32, NetworkMode: "none",
		},
		Command: []string{"/server"}, ExpiresAt: time.Unix(1700000000, 0).UTC(),
	}
	args := strings.Join(runArgs(spec), " ")
	for _, want := range []string{
		"--user " + DefaultUser, "--read-only", "--cap-drop ALL",
		"--security-opt no-new-privileges", "--network none",
		"--memory 256m", "--memory-swap 256m", "--cpus 0.25",
		"--pids-limit 32", "--tmpfs /tmp:rw,noexec,nosuid,nodev,size=32m",
		"--tmpfs /scratch:rw,nosuid,nodev,size=32m",
		"--mount type=bind,source=/tmp/source,target=/source,readonly",
		"--env APP_MODE=test", "--entrypoint /server fixture:1",
		"codexploit.plan=plan-1", "codexploit.source=src-1",
	} {
		if !strings.Contains(args, want) {
			t.Fatalf("run args missing %q: %s", want, args)
		}
	}
	for _, forbidden := range []string{"docker.sock", "/var/run", "--privileged", "--network host", "--network bridge"} {
		if strings.Contains(args, forbidden) {
			t.Fatalf("run args contain %q: %s", forbidden, args)
		}
	}
	if strings.Contains(args, "--entrypoint sleep") {
		t.Fatalf("a plan command must not be replaced by the default sleep: %s", args)
	}
}

func TestProviderRejectsNetworkAllowlistInsteadOfWideningIt(t *testing.T) {
	env := verify.PlanEnvironment{
		Template: "fixture:1", OS: "linux", Arch: "amd64",
		Network:        verify.PlanNetwork{Mode: "allowlist", AllowedHosts: []string{"api.example.test"}},
		SourceReadOnly: true, ScratchMB: 16, TTLSeconds: 60,
		Resources: verify.PlanResources{CPUMillis: 100, MemoryMB: 128, MaxProcesses: 16},
	}
	err := Provider{}.Validate(context.Background(), env)
	if err == nil || !strings.Contains(err.Error(), "allowlist") {
		t.Fatalf("allowlist validation = %v", err)
	}
}
