package verify

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func validExecutionPlan() ExecutionPlan {
	now := time.Now().UTC()
	return ExecutionPlan{
		SchemaVersion: ExecutionPlanSchemaVersion, ID: "plan-1", ProjectID: "proj-1",
		HypothesisID: "hyp-1", PathID: "path-1", AuditID: "audit-1", SnapshotID: "snap-1",
		KnowledgePin: "rev-1", SecurityGoal: "sql_injection", Claim: "name reaches the token query",
		Verifier: PlanVerifier{Adapter: "container", Version: "1.0.0", Capability: "verification"},
		Steps: []Step{{
			Kind: StepDynamicProof, Command: []string{"sh", "-c", "true"}, Expectation: "the secret appears",
			Contradiction: "the endpoint rejects the input", TimeoutSeconds: 30, RequiresApproval: true,
		}},
		Assertions: []PlanAssertion{{
			ID: "a1", Kind: "http", Expectation: "response contains the secret",
			Contradiction: "response is a 400", Required: true,
		}},
		Environment: PlanEnvironment{
			OS: "linux", Arch: "amd64",
			Provider: PlanProvider{Name: "docker", Version: "1.0.0", Capabilities: []string{"container"}},
			Template: "synthetic-single-service", Network: PlanNetwork{Mode: "none"},
			SourceReadOnly: true, ScratchMB: 64, TTLSeconds: 300,
			Permissions: []string{"dynamic_exec", "read_only_source"},
			Resources:   PlanResources{CPUMillis: 500, MemoryMB: 256, DiskMB: 512, MaxProcesses: 16, MaxWrites: 100},
		},
		Scope: Scope{
			Repository: "repo-1", SnapshotID: "snap-1", AllowNetwork: false,
			RequiresHumanApproval: true, AuthorizedBy: "alice",
		},
		Budget:    PlanBudget{MaxSeconds: 60, MaxSteps: 3, MaxCommands: 3},
		CreatedAt: now.Format(time.RFC3339), ExpiresAt: now.Add(time.Hour).Format(time.RFC3339),
	}
}

func TestExecutionPlanDigestCoversExecutionSemantics(t *testing.T) {
	plan := validExecutionPlan()
	digest := plan.DigestOf()
	if digest == "" {
		t.Fatal("empty digest")
	}
	metadata := plan
	metadata.ID, metadata.CreatedAt = "plan-other", time.Now().UTC().Format(time.RFC3339)
	if metadata.DigestOf() != digest {
		t.Fatal("record metadata changed the digest")
	}
	changes := map[string]func(*ExecutionPlan){
		"claim":      func(p *ExecutionPlan) { p.Claim = "a different claim" },
		"scope":      func(p *ExecutionPlan) { p.Scope.AllowedTargets = []string{"other"} },
		"network":    func(p *ExecutionPlan) { p.Environment.Network.AllowedHosts = []string{"db"} },
		"permission": func(p *ExecutionPlan) { p.Environment.Permissions = append(p.Environment.Permissions, "network") },
		"verifier":   func(p *ExecutionPlan) { p.Verifier.Version = "2.0.0" },
		"assertion":  func(p *ExecutionPlan) { p.Assertions[0].Expectation = "something else" },
		"budget":     func(p *ExecutionPlan) { p.Budget.MaxSteps = 4 },
		"knowledge":  func(p *ExecutionPlan) { p.KnowledgePin = "rev-2" },
		"expires_at": func(p *ExecutionPlan) { p.ExpiresAt = time.Now().Add(2 * time.Hour).Format(time.RFC3339) },
	}
	for name, change := range changes {
		changed := plan
		change(&changed)
		if changed.DigestOf() == digest {
			t.Errorf("%s did not change the digest", name)
		}
	}
}

func TestDecodeExecutionPlanRejectsUnknownFields(t *testing.T) {
	plan := validExecutionPlan()
	raw, _ := json.Marshal(plan)
	var value map[string]any
	_ = json.Unmarshal(raw, &value)
	value["unsupported_field"] = true
	mutated, _ := json.Marshal(value)
	if _, err := DecodeExecutionPlan(mutated); !errors.Is(err, ErrPlanInvalid) {
		t.Fatalf("unknown field = %v", err)
	}
	if _, err := DecodeExecutionPlan(raw); err != nil {
		t.Fatalf("valid plan rejected: %v", err)
	}
}

func TestValidateExecutionPlan(t *testing.T) {
	plan := validExecutionPlan()
	if err := ValidateExecutionPlan(plan); err != nil {
		t.Fatalf("valid plan: %v", err)
	}
	cases := map[string]func(*ExecutionPlan){
		"missing environment": func(p *ExecutionPlan) { p.Environment.OS = "" },
		"network scope":       func(p *ExecutionPlan) { p.Environment.Network.Mode = "allowlist" },
		"ttl":                 func(p *ExecutionPlan) { p.Environment.TTLSeconds = 0 },
		"budget":              func(p *ExecutionPlan) { p.Budget.MaxSeconds = 0 },
		"assertion":           func(p *ExecutionPlan) { p.Assertions[0].Contradiction = "" },
		"expired":             func(p *ExecutionPlan) { p.ExpiresAt = time.Now().Add(-time.Minute).Format(time.RFC3339) },
		"scope snapshot":      func(p *ExecutionPlan) { p.Scope.SnapshotID = "other" },
	}
	for name, change := range cases {
		changed := plan
		change(&changed)
		if err := ValidateExecutionPlan(changed); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
}

func TestApprovalBindsPlanPermissionsAndExpiry(t *testing.T) {
	now := time.Now().UTC()
	plan := validExecutionPlan()
	plan.Digest = plan.DigestOf()
	approval := PlanApproval{
		PlanID: plan.ID, PlanDigest: plan.DigestOf(), Decision: PlanApproved,
		Actor: "alice", ActorRole: "writer", Permissions: []string{"dynamic_exec"},
		Reason: "authorized the synthetic target", DecidedAt: now.Format(time.RFC3339),
		ExpiresAt: now.Add(30 * time.Minute).Format(time.RFC3339),
	}
	approval.Digest = approval.DigestOf()
	approved, state, err := ApplyApproval(plan, approval, now)
	if err != nil || state != PlanApproved || approved.Digest == "" {
		t.Fatalf("approval: %s %v", state, err)
	}
	rejected, state, err := ApplyApproval(plan, func() PlanApproval {
		copy := approval
		copy.Decision = PlanRejected
		copy.Digest = ""
		copy.Digest = copy.DigestOf()
		return copy
	}(), now)
	if err != nil || state != PlanRejected {
		t.Fatalf("rejection: %s %v", state, err)
	}
	_ = rejected

	stale := plan
	stale.Claim = "changed after approval"
	stale.Digest = stale.DigestOf()
	if _, _, err := ApplyApproval(stale, approval, now); !errors.Is(err, ErrPlanStale) {
		t.Fatalf("stale = %v", err)
	}
	expired := approval
	expired.ExpiresAt = now.Add(-time.Minute).Format(time.RFC3339)
	expired.Digest = expired.DigestOf()
	if _, _, err := ApplyApproval(plan, expired, now); !errors.Is(err, ErrPlanExpired) {
		t.Fatalf("expired = %v", err)
	}
	expanded := approval
	expanded.Permissions = []string{"dynamic_exec", "network"}
	expanded.Digest = expanded.DigestOf()
	if _, _, err := ApplyApproval(plan, expanded, now); !errors.Is(err, ErrPlanExpanded) {
		t.Fatalf("expanded = %v", err)
	}
	untrusted := approval
	untrusted.Actor = ""
	untrusted.Digest = untrusted.DigestOf()
	if _, _, err := ApplyApproval(plan, untrusted, now); !errors.Is(err, ErrPlanInvalid) {
		t.Fatalf("untrusted = %v", err)
	}
}

func TestPlanStateTransitionsStayMonotonic(t *testing.T) {
	if !PlanPending.CanTransition(PlanApproved) || !PlanApproved.CanTransition(PlanInvalidated) {
		t.Fatal("expected allowed transition")
	}
	if PlanApproved.CanTransition(PlanRejected) || PlanRejected.CanTransition(PlanApproved) || PlanInvalidated.CanTransition(PlanApproved) {
		t.Fatal("an approval was revived or replaced")
	}
}
