package api

import (
	"net/http"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// TestBudgetAPIShowsTheLedgerAndGrants covers the audit budget boundary: readers
// see the ledger, only a writer may add tokens, the reason is required and the
// ledger version rejects a stale approval.
func TestBudgetAPIShowsTheLedgerAndGrants(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create snapshot: %d %s", created.status, created.body)
	}
	var snapshot snapshotResponse
	created.decode(t, &snapshot)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snapshot.Snapshot.SnapshotID})
	base := "/api/v1/projects/" + project.Project.ID + "/tasks/" + audit.Audit.ID + "/budget"

	read := doAs(t, env.ts, readerSecret, http.MethodGet, base, nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("reader budget: %d %s", read.status, read.body)
	}
	var ledger struct {
		Budget agent.AuditBudget   `json:"budget"`
		Grants []agent.BudgetGrant `json:"grants"`
	}
	read.decode(t, &ledger)
	if ledger.Budget.LimitTokens != agent.DefaultAuditTokenBudget || ledger.Budget.Version != 1 {
		t.Fatalf("budget = %+v, want the 60k default", ledger.Budget)
	}

	if denied := doAs(t, env.ts, readerSecret, http.MethodPost, base+"/grants", map[string]any{"tokens": 5000, "reason": "more"}, nil); denied.status != http.StatusForbidden {
		t.Fatalf("reader grant = %d %s, want 403", denied.status, denied.body)
	}
	if missing := do(t, env.ts, http.MethodPost, base+"/grants", map[string]any{"tokens": 5000, "expected_version": 1}, nil); missing.status != http.StatusBadRequest {
		t.Fatalf("grant without a reason = %d %s, want 400", missing.status, missing.body)
	}
	granted := do(t, env.ts, http.MethodPost, base+"/grants", map[string]any{"tokens": 5000, "reason": "a deeper slice", "expected_version": 1}, nil)
	if granted.status != http.StatusCreated {
		t.Fatalf("grant = %d %s", granted.status, granted.body)
	}
	var after struct {
		Budget agent.AuditBudget `json:"budget"`
		Grant  struct {
			Tokens   int    `json:"tokens"`
			Decision string `json:"decision"`
		} `json:"grant"`
	}
	granted.decode(t, &after)
	if after.Budget.LimitTokens != agent.DefaultAuditTokenBudget+5000 || after.Grant.Tokens != 5000 || after.Grant.Decision != agent.GrantApproved {
		t.Fatalf("after grant = %+v", after)
	}
	if stale := do(t, env.ts, http.MethodPost, base+"/grants", map[string]any{"tokens": 5000, "reason": "again", "expected_version": 1}, nil); stale.status != http.StatusPreconditionFailed || !strings.Contains(string(stale.body), "version_conflict") {
		t.Fatalf("stale grant = %d %s, want 412", stale.status, stale.body)
	}

	other := createProject(t, env.ts, asgFixtureSource(t))
	cross := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+other.Project.ID+"/tasks/"+audit.Audit.ID+"/budget", nil, nil)
	if cross.status != http.StatusNotFound {
		t.Fatalf("cross-project budget = %d %s, want 404", cross.status, cross.body)
	}
}
