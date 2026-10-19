package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/reporting"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestReportExportsFixedTaskFindingsThroughArtifactStore(t *testing.T) {
	env := newTestEnv(t, false)
	snapshot := createAuditedSnapshot(t, env.ts)
	projects, _ := env.rt.Store.ListProjects(context.Background())
	projectID := projects[0].ID
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snapshot}).Audit
	paths := auditPaths(t, env.ts, audit.ID, "").Paths
	finding := verify.Finding{ID: "find-report", HypothesisID: "hyp-report", AuditID: audit.ID, SnapshotID: snapshot, PathID: paths[0].ID, Title: "Recorded verification", Severity: "high", Status: verify.FindingConfirmed, Version: 1}
	evidence, err := verify.NewEvidence(verify.EvidenceSource, "fixed report evidence", verify.EvidenceOptions{Tool: "fixture-verifier", ToolVersion: "1.0.0", SnapshotID: snapshot, FindingID: finding.ID})
	if err != nil {
		t.Fatal(err)
	}
	finding.Supporting = []string{evidence.ID}
	if err := env.rt.Store.AppendEvidence([]verify.Evidence{evidence}); err != nil {
		t.Fatal(err)
	}
	if err := env.rt.Store.UpsertFinding(finding); err != nil {
		t.Fatal(err)
	}
	view := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projectID+"/knowledge/views", map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot}, nil)
	var pin struct {
		View struct {
			ID string `json:"view_id"`
		} `json:"view"`
	}
	view.decode(t, &pin)
	endpoint := "/api/v1/projects/" + projectID + "/reports"
	created := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot, "task_id": audit.ID, "view_id": pin.View.ID, "format": "json", "include_candidates": false}, nil)
	if created.status != 202 {
		t.Fatalf("create report: %d %s", created.status, created.body)
	}
	var result struct {
		Report plugin.Invocation `json:"report"`
	}
	created.decode(t, &result)
	readURL := endpoint + "/" + result.Report.ID + "?snapshot_id=" + snapshot
	deadline := time.Now().Add(10 * time.Second)
	for !plugin.Terminal(result.Report.Status) {
		if time.Now().After(deadline) {
			t.Fatal("report did not finish")
		}
		time.Sleep(10 * time.Millisecond)
		read := doAs(t, env.ts, readerSecret, http.MethodGet, readURL, nil, nil)
		if read.status != 200 {
			t.Fatalf("read: %d %s", read.status, read.body)
		}
		read.decode(t, &result)
	}
	if result.Report.Status != "SUCCEEDED" || len(result.Report.Outputs) != 1 {
		t.Fatalf("report = %+v", result.Report)
	}
	ref := result.Report.Outputs[0]
	if ref.Kind != "report.document" || ref.Scope.SnapshotID != snapshot || ref.Producer.PluginID != "builtin.reporter" {
		t.Fatalf("report ref = %+v", ref)
	}
	downloadURL := "/api/v1/projects/" + projectID + "/snapshots/" + snapshot + "/artifacts/" + ref.ID + "/content"
	body := doAs(t, env.ts, readerSecret, http.MethodGet, downloadURL, nil, nil)
	if body.status != 200 || fmt.Sprintf("%x", sha256.Sum256(body.body)) != ref.SHA256 || int64(len(body.body)) != ref.Bytes {
		t.Fatalf("download: %d %s", body.status, body.body)
	}
	var report struct {
		Findings []verify.ReportFinding `json:"findings"`
		Capture  struct {
			Scope artifact.Scope   `json:"scope"`
			Paths []map[string]any `json:"paths"`
		} `json:"capture"`
	}
	body.decode(t, &report)
	if len(report.Findings) != 1 || report.Findings[0].Status != "confirmed" || len(report.Findings[0].Evidence) != 1 || report.Capture.Scope.ProjectID != projectID || len(report.Capture.Paths) == 0 {
		t.Fatalf("report content = %s", body.body)
	}
	finding.Title = "Changed after export"
	if err := env.rt.Store.UpsertFinding(finding); err != nil {
		t.Fatal(err)
	}
	again := do(t, env.ts, http.MethodGet, downloadURL, nil, nil)
	if string(body.body) != string(again.body) {
		t.Fatal("saved report changed after finding update")
	}
}

func TestProjectAndTaskReportsKeepGroupedSourcesAndHistoricalKnowledgeSeparate(t *testing.T) {
	env := newTestEnv(t, false)
	project, snapshot, firstTask, view := reportFixture(t, env)
	secondTask := createOrganizedTask(t, env.ts, project, snapshot, "Second report task")
	scope, err := env.rt.Store.(artifact.Index).ArtifactScope(context.Background(), project, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	directory := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project+"/snapshots/"+snapshot+"/artifacts", nil, nil)
	var inputs struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	directory.decode(t, &inputs)
	if len(inputs.Artifacts) == 0 {
		t.Fatal("missing source artifact")
	}
	producer := artifact.Producer{PluginID: "fixture.scanner", PluginVersion: "1.0.0", InvocationID: "inv-source-first", TaskID: firstTask, ConfigDigest: strings.Repeat("0", 64)}
	first, _, err := env.rt.Findings.Record(context.Background(), findings.RecordInput{Scope: scope, TaskID: firstTask, Producer: producer, CandidateID: "candidate-shared", RuleID: "FILE001", RuleVersion: "1", Title: "Shared candidate", File: "main.go", Line: 1, EvidenceRefs: []string{inputs.Artifacts[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	publisher := publication.NewPublisher(env.rt.Store.(publication.Store))
	pscope := publication.Scope{ProjectID: project, SnapshotID: snapshot}
	_, err = publisher.Publish(context.Background(), publication.Batch{ID: "report-batch-first", Scope: pscope, Producer: producer, Facts: []publication.BatchFact{{ID: "fact-candidate", Kind: "scanner.alert", Label: "Shared candidate"}}})
	if err != nil {
		t.Fatal(err)
	}
	producer.InvocationID = "inv-source-second"
	producer.TaskID = secondTask
	second, _, err := env.rt.Findings.Record(context.Background(), findings.RecordInput{Scope: scope, TaskID: secondTask, Producer: producer, CandidateID: "candidate-shared", RuleID: "FILE001", RuleVersion: "1", Title: "Shared candidate", File: "main.go", Line: 1, EvidenceRefs: []string{inputs.Artifacts[0].ID}})
	if err != nil {
		t.Fatal(err)
	}
	if first.FindingID != second.FindingID {
		t.Fatal("fixture observations did not group")
	}
	_, err = publisher.Publish(context.Background(), publication.Batch{ID: "report-batch-second", Scope: pscope, Producer: producer, BaseRevision: "rev-1", Facts: []publication.BatchFact{{ID: "fact-candidate", Kind: "scanner.alert", Label: "Shared candidate"}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := env.rt.Findings.AssessSeverity(context.Background(), first.FindingID, "medium", "Recorded impact assessment", "fixture", 1); err != nil {
		t.Fatal(err)
	}
	for _, task := range []string{secondTask, ""} {
		created := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project+"/reports", map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot, "task_id": task, "view_id": view, "knowledge_revision": "rev-1", "format": "json", "include_candidates": true}, nil)
		if created.status != 202 {
			t.Fatalf("create: %d %s", created.status, created.body)
		}
		var result struct {
			Report plugin.Invocation `json:"report"`
		}
		created.decode(t, &result)
		inv := waitReport(t, env, result.Report)
		if inv.Status != "SUCCEEDED" {
			t.Fatalf("report: %+v", inv)
		}
		body := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project+"/snapshots/"+snapshot+"/artifacts/"+inv.Outputs[0].ID+"/content", nil, nil)
		var document struct {
			Capture struct {
				Groups []struct {
					Observations  []findings.Observation   `json:"observations"`
					SeverityAudit []findings.SeverityAudit `json:"severity_audit"`
					Membership    map[string]string        `json:"observation_membership"`
				} `json:"groups"`
				Revision publication.Revision `json:"knowledge_revision"`
			} `json:"capture"`
		}
		body.decode(t, &document)
		if len(document.Capture.Groups) != 1 || len(document.Capture.Groups[0].Observations) != 2 || len(document.Capture.Groups[0].SeverityAudit) != 1 || document.Capture.Revision.ID != "rev-1" {
			t.Fatalf("group, audit or revision lost: %s", body.body)
		}
		membership := document.Capture.Groups[0].Membership
		if membership[first.ID] != "included" || membership[second.ID] != "outside_revision" {
			t.Fatalf("historical view mislabeled source observations: %v", membership)
		}
	}
}

func TestCancelledReportRejectsLateDocumentAndFencesSnapshotDeletion(t *testing.T) {
	env := newTestEnv(t, false)
	project, snapshot, task, view := reportFixture(t, env)
	if err := env.rt.Plugins.Close(); err != nil {
		t.Fatal(err)
	}
	index := env.rt.Store.(artifact.Index)
	objects, err := artifact.NewLocal(filepath.Join(env.workspace, "artifacts"), index)
	if err != nil {
		t.Fatal(err)
	}
	executor := reporting.Executor()
	render := executor.Run
	started, release := make(chan struct{}), make(chan struct{})
	var unblock sync.Once
	defer unblock.Do(func() { close(release) })
	executor.Run = func(ctx context.Context, inv plugin.Invocation, inputs [][]byte) ([]byte, error) {
		close(started)
		select {
		case <-release:
		case <-time.After(20 * time.Second):
			return nil, context.DeadlineExceeded
		}
		// Simulate an executor that ignores cancellation and returns late output.
		return render(context.Background(), inv, inputs)
	}
	host, err := plugin.NewHost(plugin.Deps{Catalog: env.rt.PluginCatalog, Repository: env.rt.Store.(plugin.Repository), Artifacts: objects, Scopes: index, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { unblock.Do(func() { close(release) }); _ = host.Close() })
	server := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer, WithPlugins(host), WithGraph(env.rt.Graph), WithASG(env.rt.ASG), WithAudit(env.rt.Audit), WithAuth(testAuthenticator(t)))
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)
	request := map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot, "task_id": task, "view_id": view, "format": "json"}
	created := do(t, ts, http.MethodPost, "/api/v1/projects/"+project+"/reports", request, nil)
	if created.status != 202 {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	var response struct {
		Report plugin.Invocation `json:"report"`
	}
	created.decode(t, &response)
	select {
	case <-started:
	case <-time.After(10 * time.Second):
		t.Fatal("report never started")
	}
	if r := do(t, ts, http.MethodDelete, "/api/snapshots/"+snapshot, nil, nil); r.status != 409 {
		t.Fatalf("active snapshot deleted: %d %s", r.status, r.body)
	}
	url := "/api/v1/projects/" + project + "/snapshots/" + snapshot + "/plugin-invocations/" + response.Report.ID
	read := do(t, ts, http.MethodGet, url, nil, nil)
	cancelled := do(t, ts, http.MethodPost, url+"/cancel", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
	if cancelled.status != 200 {
		t.Fatalf("cancel: %d %s", cancelled.status, cancelled.body)
	}
	unblock.Do(func() { close(release) })
	if err := host.Close(); err != nil {
		t.Fatal(err)
	}
	final, err := host.GetStatus(context.Background(), response.Report.Request.Scope, response.Report.ID)
	if err != nil || final.Status != "CANCELLED" || len(final.Outputs) != 0 {
		t.Fatalf("late result accepted: %+v %v", final, err)
	}
	content := "/api/v1/projects/" + project + "/snapshots/" + snapshot + "/artifacts/artifact-" + final.ID + "-document/content"
	if r := do(t, ts, http.MethodGet, content, nil, nil); r.status != 404 {
		t.Fatalf("late artifact visible: %d", r.status)
	}
}

func TestPostgresReportsAuthorizeScopeFailBudgetsAndSurviveRestart(t *testing.T) {
	reportsAuthorizeAndSurviveRestart(t, postgresConfig(t))
}
func TestReportsAuthorizeScopeFailBudgetsAndSurviveRestart(t *testing.T) {
	workspace := t.TempDir()
	reportsAuthorizeAndSurviveRestart(t, app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "reports.db")})
}
func reportsAuthorizeAndSurviveRestart(t *testing.T, config app.Config) {
	t.Helper()
	rt, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	project, snapshot, task, view := reportFixture(t, env)
	endpoint := "/api/v1/projects/" + project + "/reports"
	request := map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot, "task_id": task, "view_id": view, "format": "json", "include_candidates": true}
	if r := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint, request, nil); r.status != 403 {
		t.Fatalf("reader generated report: %d", r.status)
	}
	if r := doAs(t, env.ts, "", http.MethodGet, endpoint+"?snapshot_id="+snapshot, nil, nil); r.status != 401 {
		t.Fatalf("anonymous read: %d", r.status)
	}
	otherProject := createProject(t, env.ts, newTestSource(t)).Project.ID
	if r := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+otherProject+"/reports", request, nil); r.status != 404 {
		t.Fatalf("cross-project create: %d", r.status)
	}
	request["budget"] = map[string]any{"max_input_bytes": 1}
	if r := do(t, env.ts, http.MethodPost, endpoint, request, nil); r.status != 413 {
		t.Fatalf("input budget: %d %s", r.status, r.body)
	}
	request["budget"] = map[string]any{"max_output_bytes": 1}
	failed := do(t, env.ts, http.MethodPost, endpoint, request, nil)
	if failed.status != 202 {
		t.Fatalf("create bounded report: %d %s", failed.status, failed.body)
	}
	var result struct {
		Report plugin.Invocation `json:"report"`
	}
	failed.decode(t, &result)
	if inv := waitReport(t, env, result.Report); inv.Status != "FAILED" || inv.ErrorCode != "budget_exceeded" || len(inv.Outputs) != 0 {
		t.Fatalf("budget published: %+v", inv)
	}
	delete(request, "budget")
	created := do(t, env.ts, http.MethodPost, endpoint, request, map[string]string{"Idempotency-Key": "fixed-report-replay"})
	if created.status != 202 {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	created.decode(t, &result)
	saved := waitReport(t, env, result.Report)
	if saved.Status != "SUCCEEDED" || len(saved.Outputs) != 1 {
		t.Fatalf("saved: %+v", saved)
	}
	replay := do(t, env.ts, http.MethodPost, endpoint, request, map[string]string{"Idempotency-Key": "fixed-report-replay"})
	var replayed struct {
		Report plugin.Invocation `json:"report"`
	}
	replay.decode(t, &replayed)
	if replayed.Report.ID != saved.ID {
		t.Fatal("replay generated a new report")
	}
	url := "/api/v1/projects/" + project + "/snapshots/" + snapshot + "/artifacts/" + saved.Outputs[0].ID + "/content"
	original := doAs(t, env.ts, readerSecret, http.MethodGet, url, nil, nil)
	if original.status != 200 {
		t.Fatalf("download: %d %s", original.status, original.body)
	}
	if r := doAs(t, env.ts, "", http.MethodGet, url, nil, nil); r.status != 401 {
		t.Fatalf("anonymous download: %d", r.status)
	}
	wrong := strings.Replace(url, project, otherProject, 1)
	if r := do(t, env.ts, http.MethodGet, wrong, nil, nil); r.status != 404 {
		t.Fatalf("cross-project download: %d", r.status)
	}
	readWrong := strings.Replace(endpoint, project, otherProject, 1) + "/" + saved.ID + "?snapshot_id=" + snapshot
	if r := do(t, env.ts, http.MethodGet, readWrong, nil, nil); r.status != 404 {
		t.Fatalf("cross-project report: %d", r.status)
	}
	// A process crash leaves a persisted RUNNING record with no terminal write.
	pending := saved
	pending.ID = "report-restart-pending"
	pending.Request.ID = pending.ID
	pending.Status = "RUNNING"
	pending.Version = 2
	pending.Outputs = []artifact.Ref{}
	requestBytes, _ := json.Marshal(pending.Request)
	pending.RequestDigest = fmt.Sprintf("%x", sha256.Sum256(requestBytes))
	if _, _, err := env.rt.Store.(plugin.Repository).CreateInvocation(context.Background(), pending); err != nil {
		t.Fatal(err)
	}
	env.ts.Close()
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	rt, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env = serveTestEnv(t, rt, false)
	after := do(t, env.ts, http.MethodGet, url, nil, nil)
	if after.status != 200 || string(original.body) != string(after.body) {
		t.Fatal("report changed across restart")
	}
	interrupted := do(t, env.ts, http.MethodGet, endpoint+"/"+pending.ID+"?snapshot_id="+snapshot, nil, nil)
	interrupted.decode(t, &result)
	if interrupted.status != 200 || result.Report.Status != "FAILED" || result.Report.ErrorCode != "host_restarted" || len(result.Report.Outputs) != 0 {
		t.Fatalf("interrupted report displayed success: %d %s", interrupted.status, interrupted.body)
	}
	seen := map[string]bool{}
	cursor := ""
	for {
		page := do(t, env.ts, http.MethodGet, endpoint+"?snapshot_id="+snapshot+"&limit=1&cursor="+cursor, nil, nil)
		var list struct {
			Reports []plugin.Invocation `json:"reports"`
			Cursor  string              `json:"next_cursor"`
		}
		page.decode(t, &list)
		if page.status != 200 {
			t.Fatalf("list: %d %s", page.status, page.body)
		}
		for _, inv := range list.Reports {
			if seen[inv.ID] {
				t.Fatal("duplicate paginated report")
			}
			seen[inv.ID] = true
		}
		if list.Cursor == "" {
			break
		}
		cursor = list.Cursor
	}
	if len(seen) != 3 || !seen[saved.ID] {
		t.Fatalf("report directory lost rows: %v", seen)
	}
}

func TestReportAggregatesAllPagesAndPreservesFormatAndCandidatePolicy(t *testing.T) {
	env := newTestEnv(t, false)
	project, snapshot, task, view := reportFixture(t, env)
	for i := range 1102 {
		status := verify.FindingCandidate
		if i == 1101 {
			status = verify.FindingBlocked
		}
		f := verify.Finding{ID: fmt.Sprintf("find-page-%04d", i), HypothesisID: fmt.Sprintf("hyp-page-%04d", i), AuditID: task, SnapshotID: snapshot, Title: fmt.Sprintf("Recorded observation %04d", i), Severity: "medium", Status: status, Version: 1}
		if err := env.rt.Store.UpsertFinding(f); err != nil {
			t.Fatal(err)
		}
	}
	for _, config := range []struct {
		format     string
		candidates bool
		count      int
	}{{"json", false, 1}, {"json", true, 1102}, {"md", true, 1102}, {"sarif", true, 1102}} {
		t.Run(fmt.Sprintf("%s-candidates-%v", config.format, config.candidates), func(t *testing.T) {
			created := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project+"/reports", map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot, "task_id": task, "view_id": view, "format": config.format, "include_candidates": config.candidates}, nil)
			if created.status != 202 {
				t.Fatalf("create: %d %s", created.status, created.body)
			}
			var response struct {
				Report plugin.Invocation `json:"report"`
			}
			created.decode(t, &response)
			inv := waitReport(t, env, response.Report)
			if inv.Status != "SUCCEEDED" || len(inv.Outputs) != 1 {
				t.Fatalf("report: %+v", inv)
			}
			ref := inv.Outputs[0]
			body := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project+"/snapshots/"+snapshot+"/artifacts/"+ref.ID+"/content", nil, nil)
			if body.status != 200 {
				t.Fatalf("download: %d %s", body.status, body.body)
			}
			if config.format == "md" {
				if !strings.Contains(string(body.body), "- findings: 1102") || !strings.Contains(body.header.Get("Content-Type"), "text/markdown") {
					t.Fatal("Markdown omitted findings or used wrong media type")
				}
				return
			}
			var doc map[string]any
			body.decode(t, &doc)
			if config.format == "json" {
				if len(doc["findings"].([]any)) != config.count {
					t.Fatalf("findings: %d", len(doc["findings"].([]any)))
				}
			} else {
				if doc["version"] != "2.1.0" {
					t.Fatal("invalid SARIF version")
				}
				run := doc["runs"].([]any)[0].(map[string]any)
				results := run["results"].([]any)
				if len(results) != config.count {
					t.Fatalf("SARIF count: %d", len(results))
				}
				for _, result := range results {
					properties := result.(map[string]any)["properties"].(map[string]any)
					if properties["severity"] != "medium" || properties["status"] == nil {
						t.Fatal("SARIF did not preserve severity separately from verdict")
					}
				}
			}
		})
	}
}

func waitReport(t *testing.T, env *testEnv, inv plugin.Invocation) plugin.Invocation {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	result, err := env.rt.Plugins.Wait(ctx, inv.Request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	// Status is also required to be readable through the authenticated API.
	r := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+inv.Request.Scope.ProjectID+"/reports/"+inv.ID+"?snapshot_id="+inv.Request.Scope.SnapshotID, nil, nil)
	if r.status != 200 {
		t.Fatalf("read report: %d %s", r.status, r.body)
	}
	var document struct {
		Report plugin.Invocation `json:"report"`
	}
	if err := json.Unmarshal(r.body, &document); err != nil {
		t.Fatal(err)
	}
	if document.Report.Status != result.Status {
		t.Fatal("API disagrees with stored report status")
	}
	return result
}

func reportFixture(t *testing.T, env *testEnv) (string, string, string, string) {
	t.Helper()
	snapshot := createAuditedSnapshot(t, env.ts)
	projects, err := env.rt.Store.ListProjects(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snapshot}).Audit
	view := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+projects[0].ID+"/knowledge/views", map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot}, nil)
	if view.status != 200 {
		t.Fatalf("view: %d %s", view.status, view.body)
	}
	var pin struct {
		View struct {
			ID string `json:"view_id"`
		} `json:"view"`
	}
	view.decode(t, &pin)
	return projects[0].ID, snapshot, audit.ID, pin.View.ID
}

func TestReportRefusesUnsupportedVerdictsAndMissingEvidence(t *testing.T) {
	env := newTestEnv(t, false)
	project, snapshot, task, view := reportFixture(t, env)
	finding := verify.Finding{ID: "find-missing-report", HypothesisID: "hyp-missing-report", AuditID: task, SnapshotID: snapshot, Title: "Unsupported verdict", Status: verify.FindingConfirmed, Version: 1}
	if err := env.rt.Store.UpsertFinding(finding); err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"api_version": "codexploit/v1", "snapshot_id": snapshot, "task_id": task, "view_id": view, "format": "md"}
	for _, evidence := range [][]string{nil, {"evidence-does-not-exist"}} {
		finding.Supporting = evidence
		if err := env.rt.Store.UpsertFinding(finding); err != nil {
			t.Fatal(err)
		}
		r := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project+"/reports", request, nil)
		if r.status != 409 {
			t.Fatalf("missing evidence accepted: %d %s", r.status, r.body)
		}
	}
	list := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project+"/reports?snapshot_id="+snapshot, nil, nil)
	var result struct {
		Reports []plugin.Invocation `json:"reports"`
	}
	list.decode(t, &result)
	if len(result.Reports) != 0 {
		t.Fatal("failed capture created a successful report")
	}
}
