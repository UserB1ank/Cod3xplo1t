package api

import (
	"net/http"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestV1FindingsGroupsVerificationEvidenceCountsAndPagination(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	snapshot := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var captured snapshotResponse
	snapshot.decode(t, &captured)
	snapshotID := captured.Snapshot.SnapshotID
	confirmed := verify.Finding{
		ID: "find-runtime-confirmed", HypothesisID: "hyp-runtime-confirmed", PathID: "path-runtime",
		AuditID: "task-runtime", SnapshotID: snapshotID, Title: "Confirmed runtime issue",
		Severity: "high", Status: verify.FindingConfirmed, Version: 1,
		CreatedAt: "2026-10-18T00:00:00Z", UpdatedAt: "2026-10-18T00:00:00Z",
	}
	evidence, err := verify.NewEvidence(verify.EvidenceSource, "confirmed quote", verify.EvidenceOptions{
		Tool: "fixture-verifier", SnapshotID: snapshotID, FindingID: confirmed.ID, File: "main.go", Line: 12,
		Now: "2026-10-18T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.rt.Store.AppendEvidence([]verify.Evidence{evidence}); err != nil {
		t.Fatal(err)
	}
	confirmed.Supporting = []string{evidence.ID}
	if err := env.rt.Store.UpsertFinding(confirmed); err != nil {
		t.Fatal(err)
	}
	candidate := verify.Finding{
		ID: "find-runtime-candidate", HypothesisID: "hyp-runtime-candidate", PathID: "path-candidate",
		AuditID: "task-runtime", SnapshotID: snapshotID, Title: "Candidate runtime issue",
		Severity: "medium", Status: verify.FindingCandidate, Version: 1,
		CreatedAt: "2026-10-18T00:00:01Z", UpdatedAt: "2026-10-18T00:00:01Z",
	}
	if err := env.rt.Store.UpsertFinding(candidate); err != nil {
		t.Fatal(err)
	}
	page := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/findings?limit=1&offset=0", nil, nil)
	if page.status != 200 {
		t.Fatalf("v1 page: %d %s", page.status, page.body)
	}
	var list struct {
		Findings        []findingRuntimeGroup `json:"findings"`
		Total           int                   `json:"total"`
		ConfirmedCounts map[string]int        `json:"confirmed_counts"`
		CandidateCounts map[string]int        `json:"candidate_counts"`
	}
	page.decode(t, &list)
	if list.Total != 2 || len(list.Findings) != 1 || list.ConfirmedCounts["high"] != 1 || list.CandidateCounts["medium"] != 1 {
		t.Fatalf("v1 list = %+v", list)
	}
	next := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/findings?limit=1&offset=1", nil, nil)
	if next.status != 200 {
		t.Fatalf("v1 next page: %d %s", next.status, next.body)
	}
	next.decode(t, &list)
	if list.Total != 2 || len(list.Findings) != 1 {
		t.Fatalf("v1 next page = %+v", list)
	}
	detail := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/findings/"+confirmed.ID, nil, nil)
	if detail.status != 200 || detail.header.Get("ETag") == "" {
		t.Fatalf("v1 detail: %d %s", detail.status, detail.body)
	}
	var document struct {
		Finding  findingRuntimeGroup `json:"finding"`
		Evidence findingEvidence     `json:"evidence"`
	}
	detail.decode(t, &document)
	if document.Finding.Status != verify.FindingConfirmed || document.Finding.Severity != "high" || len(document.Finding.Sources) != 1 {
		t.Fatalf("v1 detail finding = %+v", document.Finding)
	}
	if len(document.Evidence.Supporting) != 1 || document.Evidence.Supporting[0].ID != evidence.ID || len(document.Evidence.Contradicting) != 0 {
		t.Fatalf("v1 evidence = %+v", document.Evidence)
	}
}
