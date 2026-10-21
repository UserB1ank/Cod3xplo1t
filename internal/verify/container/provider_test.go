package container

import (
	"context"
	"os"
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
	return verify.EnvironmentRequest{Plan: plan, Approval: approval}
}

func TestDockerEnvironmentLifecycle(t *testing.T) {
	if os.Getenv("CODEXPLOIT_DOCKER_TESTS") != "1" {
		t.Skip("set CODEXPLOIT_DOCKER_TESTS=1 to run the real container lifecycle")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	provider := Provider{}
	handle, err := provider.Provision(ctx, lifecycleRequest(t))
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
