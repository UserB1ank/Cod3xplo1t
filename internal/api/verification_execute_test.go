package api

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// planProvider is a deterministic environment provider for the API contract test.
// It never contacts Docker; the real single-service path is exercised by
// internal/verify/container's Docker e2e test.
type planProvider struct {
	provisions int
	destroys   int
	exec       []verify.CommandResult
}

func (p *planProvider) Capabilities() []string {
	return []string{"container", "network_none", "read_only_source"}
}
func (p *planProvider) Validate(context.Context, verify.PlanEnvironment) error { return nil }
func (p *planProvider) Provision(_ context.Context, request verify.EnvironmentRequest) (verify.EnvironmentHandle, error) {
	p.provisions++
	return verify.EnvironmentHandle{
		ID: "env-api", Provider: "docker", State: verify.EnvironmentReady,
		ExpiresAt: time.Now().Add(time.Minute).Format(time.RFC3339),
		Receipt: verify.EnvironmentReceipt{
			Provider: "docker", ProviderVersion: "test", User: "10001:10001",
			NetworkMode: "none", SourceReadOnly: true, SourceDigest: request.Source.Digest,
			ImageDigest: "sha256:fixture", EnvironmentID: "env-api", Applied: []string{"non_root", "network_none"},
			Digest: "receipt-api", CPUMillis: 100, MemoryMB: 128, MaxProcesses: 16, ScratchMB: 16, TTLSeconds: 120,
		},
	}, nil
}
func (p *planProvider) Status(context.Context, verify.EnvironmentHandle) (verify.EnvironmentState, error) {
	return verify.EnvironmentRunning, nil
}
func (p *planProvider) Exec(context.Context, verify.EnvironmentHandle, verify.CommandRequest) (verify.CommandResult, error) {
	if len(p.exec) == 0 {
		return verify.CommandResult{ExitCode: 0}, nil
	}
	result := p.exec[0]
	p.exec = p.exec[1:]
	return result, nil
}
func (p *planProvider) Logs(context.Context, verify.EnvironmentHandle, int) (string, error) {
	return "", nil
}
func (p *planProvider) Destroy(context.Context, verify.EnvironmentHandle) error {
	p.destroys++
	return nil
}

func TestApprovedPlanExecutesInContainerAndDerivesVerdict(t *testing.T) {
	rt, err := app.Build(context.Background(), app.Config{
		Workspace: filepath.Join(t.TempDir(), "work"), DBPath: "memory",
		Agent: app.AgentConfig{
			Enabled: true, Runtime: app.AgentRuntimeScripted,
			ScriptedAnswerJSON: agentTestPlaceholderAnswer(t), MaxToolCalls: 30,
		},
		Verification: app.VerificationConfig{Enabled: true, Executor: app.VerifyExecutorContainer},
	})
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	if rt.ContainerVerification == nil || rt.Verifier == nil {
		t.Fatal("container verification was not wired")
	}
	provider := &planProvider{exec: []verify.CommandResult{
		{ExitCode: 0}, // readiness
		{ExitCode: 0, Stdout: "SECRET_TOKEN status=200\n"}, // controlled probe
	}}
	rt.ContainerVerification.Provider = provider
	env := serveTestEnv(t, rt, false)
	project := createProject(t, env.ts, newTestSource(t))
	snapshotResp := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if snapshotResp.status != http.StatusCreated {
		t.Fatalf("snapshot: %d %s", snapshotResp.status, snapshotResp.body)
	}
	var snapshot snapshotResponse
	snapshotResp.decode(t, &snapshot)

	now := time.Now().UTC()
	plan := verify.ExecutionPlan{
		SchemaVersion: verify.ExecutionPlanSchemaVersion, HypothesisID: "hyp-api", FindingID: "finding-hyp-api",
		PathID: "path-api", AuditID: "audit-api", SnapshotID: snapshot.Snapshot.SnapshotID,
		SecurityGoal: "data_exposure", Claim: "the endpoint returns the seeded secret",
		Verifier: verify.PlanVerifier{Adapter: "container", Version: "1.0.0", Capability: "verification"},
		Steps: []verify.Step{{
			Kind: verify.StepDynamicProof, Command: []string{"/probe"}, Expectation: "SECRET_TOKEN",
			Contradiction: "PERMISSION_DENIED", TimeoutSeconds: 10, RequiresApproval: true,
		}},
		Assertions: []verify.PlanAssertion{{
			ID: "a1", Kind: "stdout_contains", Expectation: "SECRET_TOKEN", Contradiction: "PERMISSION_DENIED", Required: true,
		}},
		Environment: verify.PlanEnvironment{
			OS: "linux", Arch: "amd64",
			Provider: verify.PlanProvider{Name: "docker", Version: "1.0.0", Capabilities: []string{"container", "network_none", "read_only_source"}},
			Template: "fixture:1", Network: verify.PlanNetwork{Mode: "none"}, SourceReadOnly: true,
			ScratchMB: 16, TTLSeconds: 120, Permissions: []string{"dynamic_exec"},
			Resources: verify.PlanResources{CPUMillis: 100, MemoryMB: 128, DiskMB: 64, MaxProcesses: 16, MaxWrites: 10},
			Services: []verify.ServiceSpec{{
				Name: "target", Role: "target", Template: "fixture:1", Command: []string{"/server"},
				Readiness: []verify.ReadinessProbe{{Kind: "command", Command: []string{"/probe", "health"}, TimeoutSeconds: 5}},
			}},
		},
		Scope:     verify.Scope{Repository: "repo-api", SnapshotID: snapshot.Snapshot.SnapshotID, RequiresHumanApproval: true},
		Budget:    verify.PlanBudget{MaxSeconds: 30, MaxSteps: 1, MaxCommands: 1},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.Project.ID+"/verification-plans", plan, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create plan: %d %s", created.status, created.body)
	}
	var createdBody struct {
		Plan verify.PlanRecord `json:"plan"`
	}
	created.decode(t, &createdBody)
	approval := map[string]any{
		"decision": "approved", "reason": "approved for the container test",
		"expires_at": now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	decided := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.Project.ID+"/verification-plans/"+createdBody.Plan.Plan.ID+"/decision",
		approval, map[string]string{"If-Match": created.header.Get("ETag")})
	if decided.status != http.StatusOK {
		t.Fatalf("decide: %d %s", decided.status, decided.body)
	}

	executed := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.Project.ID+"/verification-plans/"+createdBody.Plan.Plan.ID+"/execute", nil, nil)
	if executed.status != http.StatusOK {
		t.Fatalf("execute: %d %s", executed.status, executed.body)
	}
	var body struct {
		Run         verify.Run              `json:"run"`
		Attempt     int                     `json:"attempt"`
		Environment *verify.EnvironmentLease `json:"environment"`
	}
	executed.decode(t, &body)
	if body.Run.Outcome != verify.OutcomeConfirmed || body.Attempt != 1 {
		t.Fatalf("run outcome=%s attempt=%d body=%s", body.Run.Outcome, body.Attempt, executed.body)
	}
	if len(body.Run.EvidenceIDs) == 0 {
		t.Fatal("verdict cites no evidence")
	}
	if body.Environment == nil || body.Environment.Cleanup != verify.CleanupSucceeded {
		t.Fatalf("environment = %+v", body.Environment)
	}
	if provider.provisions != 1 || provider.destroys != 1 {
		t.Fatalf("provisions=%d destroys=%d", provider.provisions, provider.destroys)
	}

	// Attempt 2 is a new run; the same attempt replays the first answer without
	// spending another environment.
	replay := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.Project.ID+"/verification-plans/"+createdBody.Plan.Plan.ID+"/execute", map[string]any{"attempt": 1}, nil)
	if replay.status != http.StatusOK || provider.provisions != 1 {
		t.Fatalf("replay = %d/%d %s", replay.status, provider.provisions, replay.body)
	}
	provider.exec = []verify.CommandResult{{ExitCode: 0}, {ExitCode: 0, Stdout: "SECRET_TOKEN status=200\n"}}
	second := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.Project.ID+"/verification-plans/"+createdBody.Plan.Plan.ID+"/execute", map[string]any{"attempt": 2}, nil)
	if second.status != http.StatusOK {
		t.Fatalf("attempt 2: %d %s", second.status, second.body)
	}
	second.decode(t, &body)
	if body.Run.ID == "" || provider.provisions != 2 {
		t.Fatalf("attempt 2 did not provision a new environment: %+v", body.Run)
	}
}
