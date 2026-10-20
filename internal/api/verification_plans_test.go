package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestVerificationPlanAPILifecycle(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	now := time.Now().UTC()
	plan := verify.ExecutionPlan{
		SchemaVersion: verify.ExecutionPlanSchemaVersion, HypothesisID: "hyp-1", PathID: "path-1",
		AuditID: "audit-1", SnapshotID: "snap-1", SecurityGoal: "sql_injection", Claim: "the name reaches the query",
		Verifier:   verify.PlanVerifier{Adapter: "container", Version: "1.0.0", Capability: "verification"},
		Steps:      []verify.Step{{Kind: verify.StepDynamicProof, Command: []string{"true"}, Expectation: "secret", Contradiction: "400", TimeoutSeconds: 10, RequiresApproval: true}},
		Assertions: []verify.PlanAssertion{{ID: "a1", Kind: "http", Expectation: "secret", Contradiction: "400", Required: true}},
		Environment: verify.PlanEnvironment{
			OS: "linux", Arch: "amd64", Provider: verify.PlanProvider{Name: "docker", Version: "1.0.0"},
			Template: "synthetic", Network: verify.PlanNetwork{Mode: "none"}, SourceReadOnly: true,
			ScratchMB: 32, TTLSeconds: 120, Permissions: []string{"dynamic_exec"},
			Resources: verify.PlanResources{CPUMillis: 100, MemoryMB: 128, DiskMB: 256, MaxProcesses: 8, MaxWrites: 10},
		},
		Scope:     verify.Scope{Repository: "repo-1", SnapshotID: "snap-1", AllowNetwork: false, RequiresHumanApproval: true},
		Budget:    verify.PlanBudget{MaxSeconds: 30, MaxSteps: 1, MaxCommands: 1},
		ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/verification-plans", plan, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	var createdBody struct {
		Plan verify.PlanRecord `json:"plan"`
	}
	created.decode(t, &createdBody)
	if createdBody.Plan.State != verify.PlanPending || createdBody.Plan.Version != 1 {
		t.Fatalf("created = %+v", createdBody.Plan)
	}
	etag := created.header.Get("ETag")

	var list struct {
		Plans []verify.PlanRecord `json:"plans"`
		Total int                 `json:"total"`
	}
	if read := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/verification-plans", nil, nil); read.status != http.StatusOK {
		t.Fatalf("reader list: %d %s", read.status, read.body)
	} else {
		read.decode(t, &list)
		if list.Total != 1 || len(list.Plans) != 1 {
			t.Fatalf("list = %+v", list)
		}
	}
	if denied := doAs(t, env.ts, readerSecret, http.MethodPost, "/api/v1/projects/"+project.ID+"/verification-plans", plan, nil); denied.status != http.StatusForbidden {
		t.Fatalf("reader create = %d %s", denied.status, denied.body)
	}
	decision := map[string]any{
		"decision": "approved", "permissions": []string{"dynamic_exec"},
		"reason": "authorized the synthetic target", "expires_at": now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	decided := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/verification-plans/"+createdBody.Plan.Plan.ID+"/decision", decision, map[string]string{"If-Match": etag})
	if decided.status != http.StatusOK {
		t.Fatalf("decision: %d %s", decided.status, decided.body)
	}
	var decidedBody struct {
		Plan verify.PlanRecord `json:"plan"`
	}
	decided.decode(t, &decidedBody)
	if decidedBody.Plan.State != verify.PlanApproved || decidedBody.Plan.Approval == nil || decidedBody.Plan.Approval.Actor != "admin" {
		t.Fatalf("decided = %+v", decidedBody.Plan)
	}
	if replay := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/verification-plans/"+createdBody.Plan.Plan.ID+"/decision", decision, map[string]string{"If-Match": etag}); replay.status != http.StatusPreconditionFailed {
		t.Fatalf("replay = %d %s", replay.status, replay.body)
	}
}
