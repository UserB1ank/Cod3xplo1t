package api

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin/wire"
	"github.com/open-mcp-ai/Codexploit/internal/scanner"
)

func scannerPackageForAPI(t *testing.T) string {
	t.Helper()
	goBin, err := exec.LookPath("go")
	if err != nil {
		t.Fatalf("go toolchain is required: %v", err)
	}
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	name := "scanner"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	binary := filepath.Join(t.TempDir(), name)
	command := exec.Command(goBin, "build", "-trimpath", "-o", binary, "./cmd/scanner")
	command.Dir = root
	command.Env = os.Environ()
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("build scanner: %v\n%s", err, output)
	}
	packages := t.TempDir()
	directory := filepath.Join(packages, "codexploit.static-patterns@1.0.0")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), scanner.Manifest(), 0o600); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, name), raw, 0o700); err != nil {
		t.Fatal(err)
	}
	return packages
}

func TestProcessScannerRunsPublishesAndShowsSourcesThroughAuthenticatedAPI(t *testing.T) {
	packages := scannerPackageForAPI(t)
	rt, err := app.Build(context.Background(), app.Config{Workspace: t.TempDir(), DBPath: "memory", PluginPackages: packages})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	env := serveTestEnv(t, rt, false)
	source := t.TempDir()
	writeFile(t, source, "main.go", "package main\n\nimport \"os/exec\"\n\nfunc run(input string) {\n\texec.Command(\"sh\", \"-c\", input)\n}\n")
	writeFile(t, source, "go.mod", "module example.test/scanner\n\ngo 1.26\n")
	env.source = source
	project := createProject(t, env.ts, source).Project

	catalogResponse := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/plugins", nil, nil)
	if catalogResponse.status != 200 {
		t.Fatalf("catalog: %d %s", catalogResponse.status, catalogResponse.body)
	}
	var catalog struct {
		Plugins []plugin.Record `json:"plugins"`
	}
	catalogResponse.decode(t, &catalog)
	var scannerRecord *plugin.Record
	for i := range catalog.Plugins {
		if catalog.Plugins[i].Manifest.ID == scanner.ID {
			scannerRecord = &catalog.Plugins[i]
		}
	}
	if scannerRecord == nil || !scannerRecord.Installed || !scannerRecord.Executable {
		t.Fatalf("scanner was not installed and executable: %+v", catalog.Plugins)
	}

	snapshotCall := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	if snapshotCall.status != 201 {
		t.Fatalf("snapshot: %d %s", snapshotCall.status, snapshotCall.body)
	}
	var snapshot snapshotResponse
	snapshotCall.decode(t, &snapshot)
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID
	registered := do(t, env.ts, http.MethodPost, prefix+"/artifacts", nil, nil)
	var directory struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &directory)
	var input artifact.Ref
	for _, ref := range directory.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	if input.ID == "" {
		t.Fatal("source tar was not registered")
	}
	request := plugin.Request{
		APIVersion:    "codexploit/v1",
		ID:            "inv-api-scanner",
		PluginID:      scannerRecord.Manifest.ID,
		PluginVersion: scannerRecord.Manifest.Version,
		PackageDigest: scannerRecord.PackageDigest,
		Scope:         input.Scope,
		Inputs:        []artifact.Ref{input},
		Config:        json.RawMessage(`{"max_alerts":10}`),
	}
	started := do(t, env.ts, http.MethodPost, prefix+"/plugin-invocations", request, nil)
	if started.status != 202 {
		t.Fatalf("start: %d %s", started.status, started.body)
	}
	var invocationResponse struct {
		Invocation plugin.Invocation `json:"invocation"`
	}
	started.decode(t, &invocationResponse)
	invocationEndpoint := prefix + "/plugin-invocations/" + request.ID
	deadline := time.Now().Add(30 * time.Second)
	for {
		read := doAs(t, env.ts, readerSecret, http.MethodGet, invocationEndpoint, nil, nil)
		if read.status != 200 {
			t.Fatalf("status: %d %s", read.status, read.body)
		}
		read.decode(t, &invocationResponse)
		if plugin.Terminal(invocationResponse.Invocation.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("scanner invocation did not settle")
		}
		time.Sleep(10 * time.Millisecond)
	}
	invocation := invocationResponse.Invocation
	if invocation.Status != "SUCCEEDED" {
		t.Fatalf("invocation = %+v", invocation)
	}
	var native artifact.Ref
	for _, ref := range invocation.Outputs {
		if ref.Kind == "scanner.alerts" {
			native = ref
		}
	}
	if native.ID == "" {
		t.Fatalf("native report missing: %+v", invocation.Outputs)
	}
	nativeResponse := doAs(t, env.ts, readerSecret, http.MethodGet, prefix+"/artifacts/"+native.ID+"/content", nil, nil)
	if nativeResponse.status != 200 || !strings.Contains(string(nativeResponse.body), wire.ScannerReportFormat) {
		t.Fatalf("native report: %d %s", nativeResponse.status, nativeResponse.body)
	}
	resultResponse := doAs(t, env.ts, readerSecret, http.MethodGet, invocationEndpoint+"/result", nil, nil)
	if resultResponse.status != 200 {
		t.Fatalf("result: %d %s", resultResponse.status, resultResponse.body)
	}
	var document struct {
		Candidates []struct {
			ID           string `json:"id"`
			Title        string `json:"title"`
			SeverityHint string `json:"severity_hint"`
			File         string `json:"file"`
			Line         int    `json:"line"`
		} `json:"candidates"`
	}
	resultResponse.decode(t, &document)
	if len(document.Candidates) != 1 || document.Candidates[0].File != "main.go" || document.Candidates[0].SeverityHint != "high" {
		t.Fatalf("candidates = %+v", document.Candidates)
	}

	published := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/knowledge/publications", map[string]any{
		"api_version":   "codexploit/v1",
		"snapshot_id":   snapshot.Snapshot.SnapshotID,
		"invocation_id": invocation.ID,
		"batch_id":      "batch-api-scanner",
		"base_revision": "rev-0",
	}, nil)
	if published.status != 201 {
		t.Fatalf("publish: %d %s", published.status, published.body)
	}
	var receipt struct {
		Publication struct {
			Revision string `json:"revision"`
			Facts    int    `json:"facts"`
			View     struct {
				ID string `json:"view_id"`
			} `json:"view"`
		} `json:"publication"`
	}
	published.decode(t, &receipt)
	if receipt.Publication.Revision != "rev-1" || receipt.Publication.Facts != 1 || receipt.Publication.View.ID == "" {
		t.Fatalf("receipt = %+v", receipt.Publication)
	}
	facts := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/knowledge/revisions/"+receipt.Publication.View.ID+"/facts", nil, nil)
	if facts.status != 200 || !strings.Contains(string(facts.body), "scanner.alert") || !strings.Contains(string(facts.body), scanner.ID) {
		t.Fatalf("facts: %d %s", facts.status, facts.body)
	}

	grouped := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/projects/"+project.ID+"/findings", nil, nil)
	if grouped.status != 200 {
		t.Fatalf("findings: %d %s", grouped.status, grouped.body)
	}
	var library struct {
		Findings        []projectFinding `json:"findings"`
		Total           int              `json:"total"`
		CandidateCounts map[string]int   `json:"candidate_counts"`
		ConfirmedCounts map[string]int   `json:"confirmed_counts"`
	}
	grouped.decode(t, &library)
	if library.Total != 1 || len(library.Findings) != 1 || library.CandidateCounts["ungraded"] != 1 || library.ConfirmedCounts["high"] != 0 {
		t.Fatalf("library = %+v", library)
	}
	group := library.Findings[0]
	if group.FingerprintVersion != "1" || len(group.Fingerprint) != 32 || len(group.Sources) != 1 {
		t.Fatalf("group = %+v", group)
	}
	observationSource := group.Sources[0]
	if observationSource.RuleID != "CP001" || observationSource.Producer == nil || observationSource.Producer.PluginID != scanner.ID || observationSource.File != "main.go" || len(observationSource.EvidenceRefs) != 1 {
		t.Fatalf("source = %+v", observationSource)
	}
	retried := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/knowledge/publications", map[string]any{
		"api_version":   "codexploit/v1",
		"snapshot_id":   snapshot.Snapshot.SnapshotID,
		"invocation_id": invocation.ID,
		"batch_id":      "batch-api-scanner-retry",
		"base_revision": receipt.Publication.Revision,
	}, nil)
	if retried.status != 201 {
		t.Fatalf("retry publish: %d %s", retried.status, retried.body)
	}
	retriedGroups := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/projects/"+project.ID+"/findings", nil, nil)
	retriedGroups.decode(t, &library)
	if library.Total != 1 || len(library.Findings) != 1 || len(library.Findings[0].Sources) != 1 || library.CandidateCounts["ungraded"] != 1 {
		t.Fatalf("retry inflated the group: %+v", library)
	}

	v1List := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/findings", nil, nil)
	if v1List.status != 200 {
		t.Fatalf("v1 list: %d %s", v1List.status, v1List.body)
	}
	var v1Page struct {
		Findings []struct {
			FindingID          string `json:"finding_id"`
			FingerprintVersion string `json:"fingerprint_version"`
			Status             string `json:"status"`
			Sources            []struct {
				RuleID string `json:"rule_id"`
			} `json:"sources"`
		} `json:"findings"`
		Total           int            `json:"total"`
		CandidateCounts map[string]int `json:"candidate_counts"`
	}
	v1List.decode(t, &v1Page)
	if v1Page.Total != 1 || len(v1Page.Findings) != 1 || v1Page.Findings[0].Status != "candidate" || v1Page.Findings[0].Sources[0].RuleID != "CP001" || v1Page.CandidateCounts["ungraded"] != 1 {
		t.Fatalf("v1 page = %+v", v1Page)
	}
	findingID := v1Page.Findings[0].FindingID
	detail := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/findings/"+findingID, nil, nil)
	if detail.status != 200 || detail.header.Get("ETag") == "" {
		t.Fatalf("v1 detail: %d %s", detail.status, detail.body)
	}
	if !strings.Contains(string(detail.body), "CP001") || !strings.Contains(string(detail.body), "sources") {
		t.Fatalf("v1 detail body: %s", detail.body)
	}
	gradePath := "/api/v1/projects/" + project.ID + "/findings/" + findingID + "/severity"
	noReason := do(t, env.ts, http.MethodPatch, gradePath, map[string]any{"severity": "medium"}, map[string]string{"If-Match": detail.header.Get("ETag")})
	if noReason.status != 400 {
		t.Fatalf("missing reason: %d %s", noReason.status, noReason.body)
	}
	reader := doAs(t, env.ts, readerSecret, http.MethodPatch, gradePath, map[string]any{"severity": "medium", "reason": "reachable"}, map[string]string{"If-Match": detail.header.Get("ETag")})
	if reader.status != 403 {
		t.Fatalf("reader grade: %d %s", reader.status, reader.body)
	}
	graded := do(t, env.ts, http.MethodPatch, gradePath, map[string]any{"severity": "medium", "reason": "reachable from the public route"}, map[string]string{"If-Match": detail.header.Get("ETag")})
	if graded.status != 200 {
		t.Fatalf("v1 grade: %d %s", graded.status, graded.body)
	}
	var gradedGroup struct {
		Finding struct {
			ID            string `json:"finding_id"`
			Status        string `json:"status"`
			Severity      string `json:"severity"`
			Version       int64  `json:"version"`
			SeverityAudit []struct {
				Reason string `json:"reason"`
				Actor  string `json:"actor"`
			} `json:"severity_audit"`
		} `json:"finding"`
	}
	graded.decode(t, &gradedGroup)
	if gradedGroup.Finding.Status != "candidate" || gradedGroup.Finding.Severity != "medium" || gradedGroup.Finding.Version != 2 || len(gradedGroup.Finding.SeverityAudit) != 1 || gradedGroup.Finding.SeverityAudit[0].Reason == "" {
		t.Fatalf("graded = %+v", gradedGroup.Finding)
	}
	stale := do(t, env.ts, http.MethodPatch, gradePath, map[string]any{"severity": "low", "reason": "stale"}, map[string]string{"If-Match": detail.header.Get("ETag")})
	if stale.status != 412 {
		t.Fatalf("stale grade: %d %s", stale.status, stale.body)
	}
	crossProject := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/project-other/findings/"+findingID, nil, nil)
	if crossProject.status != 404 {
		t.Fatalf("cross-project detail: %d %s", crossProject.status, crossProject.body)
	}
}
