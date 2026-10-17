package api

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestProjectTasksShareGraphAndKeepIndependentQueues(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	snapshot := createAuditedSnapshot(t, env.ts)
	projects, err := env.rt.Store.ListProjects(context.Background())
	if err != nil || len(projects) != 1 {
		t.Fatalf("projects: %v %v", projects, err)
	}
	projectID := projects[0].ID
	endpoint := "/api/projects/" + projectID + "/tasks"
	body := map[string]any{"name": "API audit", "objective": "Review request input handling", "snapshot_id": snapshot, "scope": []string{"main.go"}}
	create := func(headers map[string]string) path.Audit {
		response := do(t, env.ts, http.MethodPost, endpoint, body, headers)
		if response.status != http.StatusCreated {
			t.Fatalf("create task: %d %s", response.status, response.body)
		}
		var result struct {
			Task path.Audit `json:"task"`
		}
		response.decode(t, &result)
		return result.Task
	}
	first := create(map[string]string{"Idempotency-Key": "task-first"})
	replay := create(map[string]string{"Idempotency-Key": "task-first"})
	second := create(nil)
	if first.ID != replay.ID || first.ID == second.ID {
		t.Fatalf("task identities: %s %s %s", first.ID, replay.ID, second.ID)
	}
	if first.SnapshotID != second.SnapshotID || first.SCGVersion != second.SCGVersion || first.ASGVersion != second.ASGVersion {
		t.Fatal("tasks did not share their graph versions")
	}
	if first.Name != "API audit" || len(first.Scope) != 1 || first.PathCount == 0 {
		t.Fatalf("task metadata or paths missing: %+v", first)
	}
	paths := auditPaths(t, env.ts, first.ID, "")
	other := auditPaths(t, env.ts, second.ID, "")
	if paths.Paths[0].ID == other.Paths[0].ID || paths.Paths[0].Objectives[0] != body["objective"] {
		t.Fatal("task queue or objective was not isolated")
	}
	prior := verify.Finding{HypothesisID: "hyp-shared-knowledge", SnapshotID: snapshot, AuditID: first.ID, PathID: paths.Paths[0].ID, Title: "Earlier task candidate", Severity: "medium", Status: verify.FindingCandidate}
	if err := env.rt.Store.UpsertFinding(prior); err != nil {
		t.Fatal(err)
	}
	runResponse := do(t, env.ts, http.MethodPost, "/api/audits/"+second.ID+"/runs", map[string]any{"max_runs": 1}, nil)
	if runResponse.status != http.StatusOK {
		t.Fatalf("run with shared knowledge: %d %s", runResponse.status, runResponse.body)
	}
	var batch runBatchResponse
	runResponse.decode(t, &batch)
	if len(batch.Runs) != 1 || len(batch.Runs[0].Task.PriorFindings) != 1 || batch.Runs[0].Task.PriorFindings[0].AuditID != first.ID || batch.Runs[0].Task.PriorFindings[0].Status != "candidate" {
		t.Fatalf("missing or misclassified project knowledge: %+v", batch)
	}

	read := do(t, env.ts, http.MethodGet, "/api/tasks/"+first.ID, nil, nil)
	paused := do(t, env.ts, http.MethodPost, "/api/tasks/"+first.ID+"/pause", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
	if paused.status != http.StatusOK {
		t.Fatalf("pause: %d %s", paused.status, paused.body)
	}
	if _, err := env.rt.Store.ClaimPath(paths.Paths[0].ID, "fixture", path.NowString(time.Now().Add(time.Minute)), []path.Status{path.StatusQueued}, "fixture"); !errors.Is(err, path.ErrNotClaimable) {
		t.Fatalf("paused task claimed: %v", err)
	}
	stale := do(t, env.ts, http.MethodPost, "/api/tasks/"+first.ID+"/resume", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
	if stale.status != http.StatusPreconditionFailed {
		t.Fatalf("stale resume: %d", stale.status)
	}
	resumed := do(t, env.ts, http.MethodPost, "/api/tasks/"+first.ID+"/resume", map[string]any{}, map[string]string{"If-Match": paused.header.Get("ETag")})
	if resumed.status != http.StatusOK {
		t.Fatalf("resume: %d %s", resumed.status, resumed.body)
	}

	otherProject := createProject(t, env.ts, env.source).Project
	wrong := do(t, env.ts, http.MethodPost, "/api/projects/"+otherProject.ID+"/tasks", body, nil)
	if wrong.status != http.StatusBadRequest {
		t.Fatalf("cross-project snapshot accepted: %d", wrong.status)
	}
	listing := do(t, env.ts, http.MethodGet, "/api/projects/"+otherProject.ID+"/tasks", nil, nil)
	var listResult struct {
		Total int `json:"total"`
	}
	listing.decode(t, &listResult)
	if listing.status != http.StatusOK || listResult.Total != 0 {
		t.Fatalf("cross-project tasks leaked: %s", listing.body)
	}
	reader := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint, body, nil)
	if reader.status != http.StatusForbidden {
		t.Fatalf("reader created task: %d", reader.status)
	}
	body["scope"] = []string{"../outside"}
	if response := do(t, env.ts, http.MethodPost, endpoint, body, nil); response.status != http.StatusBadRequest {
		t.Fatalf("escaping scope accepted: %d", response.status)
	}
}

func TestProjectFindingsGradesAndProvenance(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	snapshot := createAuditedSnapshot(t, env.ts)
	projects, _ := env.rt.Store.ListProjects(context.Background())
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snapshot})
	paths := auditPaths(t, env.ts, audit.Audit.ID, "")
	finding := verify.Finding{ID: verify.FindingID("hyp-ui-1"), HypothesisID: "hyp-ui-1", AuditID: audit.Audit.ID, SnapshotID: snapshot, PathID: paths.Paths[0].ID, Title: "fixture finding", Severity: "critical", Status: verify.FindingConfirmed}
	if err := env.rt.Store.UpsertFinding(finding); err != nil {
		t.Fatal(err)
	}
	endpoint := "/api/projects/" + projects[0].ID + "/findings"
	page := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
	var summary struct {
		Counts   map[string]int   `json:"counts"`
		Total    int              `json:"total"`
		Findings []projectFinding `json:"findings"`
	}
	page.decode(t, &summary)
	if page.status != 200 || summary.Counts["high"] != 1 || len(summary.Findings) != 1 || len(summary.Findings[0].Sources) != 1 {
		t.Fatalf("finding summary: %d %s", page.status, page.body)
	}
	read := do(t, env.ts, http.MethodGet, "/api/knowledge/findings/"+finding.ID, nil, nil)
	if read.status != 200 {
		t.Fatalf("knowledge finding: %d %s", read.status, read.body)
	}
	gradeURL := "/api/findings/" + finding.ID + "/severity"
	missing := do(t, env.ts, http.MethodPatch, gradeURL, map[string]any{"severity": "low"}, nil)
	if missing.status != http.StatusPreconditionRequired {
		t.Fatalf("grade without version: %d", missing.status)
	}
	reader := doAs(t, env.ts, readerSecret, http.MethodPatch, gradeURL, map[string]any{"severity": "low"}, map[string]string{"If-Match": read.header.Get("ETag")})
	if reader.status != http.StatusForbidden {
		t.Fatalf("reader graded: %d", reader.status)
	}
	graded := do(t, env.ts, http.MethodPatch, gradeURL, map[string]any{"severity": "low"}, map[string]string{"If-Match": read.header.Get("ETag")})
	if graded.status != 200 {
		t.Fatalf("grade: %d %s", graded.status, graded.body)
	}
	stale := do(t, env.ts, http.MethodPatch, gradeURL, map[string]any{"severity": "high"}, map[string]string{"If-Match": read.header.Get("ETag")})
	if stale.status != http.StatusPreconditionFailed {
		t.Fatalf("stale grade accepted: %d", stale.status)
	}
	page = do(t, env.ts, http.MethodGet, endpoint+"?severity=low&task_id="+audit.Audit.ID, nil, nil)
	page.decode(t, &summary)
	if summary.Counts["low"] != 1 || summary.Total != 1 {
		t.Fatalf("grade not reflected: %s", page.body)
	}
	otherProject := createProject(t, env.ts, env.source).Project
	other := do(t, env.ts, http.MethodGet, "/api/projects/"+otherProject.ID+"/findings", nil, nil)
	if strings.Contains(string(other.body), finding.ID) {
		t.Fatalf("cross-project finding leaked: %s", other.body)
	}
}
