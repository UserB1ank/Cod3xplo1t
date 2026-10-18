package api

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestPostgresFixedPublicationPagesKeepSourcesAndScopeAcrossRebuild(t *testing.T) {
	cfg := postgresConfig(t)
	open := func() *testEnv {
		rt, err := app.Build(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return serveTestEnv(t, rt, false)
	}
	env := open()
	setup := newPublicationSetup(t, env)
	a := setup.analyze(t, "inv-source-a")
	first := setup.publish(t, a.ID, "", "source-a", "rev-0")
	if first.status != 201 {
		t.Fatalf("first: %d %s", first.status, first.body)
	}
	endpoint := "/api/v1/projects/" + setup.projectID + "/knowledge/revisions/"
	pageURL := endpoint + first.Publication.View.ID + "/facts?snapshot_id=" + setup.snapshotID + "&limit=1"
	before := doAs(t, env.ts, readerSecret, "GET", pageURL, nil, nil)
	b := setup.analyze(t, "inv-source-b")
	second := setup.publish(t, b.ID, "", "source-b", "rev-1")
	if second.status != 201 {
		t.Fatalf("second: %d %s", second.status, second.body)
	}
	var oldPage struct {
		Facts []json.RawMessage `json:"facts"`
		Next  string            `json:"next_cursor"`
	}
	before.decode(t, &oldPage)
	if before.status != 200 || len(oldPage.Facts) != 1 || oldPage.Next == "" {
		t.Fatalf("paging: %d %s", before.status, before.body)
	}
	seen := map[string]bool{}
	cursor := ""
	for range 1000 {
		r := doAs(t, env.ts, readerSecret, "GET", endpoint+second.Publication.View.ID+"/facts?snapshot_id="+setup.snapshotID+"&limit=1&cursor="+url.QueryEscape(cursor), nil, nil)
		var page struct {
			Facts []struct {
				ID           string `json:"id"`
				Observations []struct {
					Producer artifact.Producer `json:"producer"`
				} `json:"observations"`
			} `json:"facts"`
			Next string `json:"next_cursor"`
		}
		r.decode(t, &page)
		if r.status != 200 {
			t.Fatalf("page: %d %s", r.status, r.body)
		}
		for _, fact := range page.Facts {
			if seen[fact.ID] || len(fact.Observations) != 2 {
				t.Fatalf("lost or duplicated sources: %s", r.body)
			}
			seen[fact.ID] = true
			producers := map[string]bool{}
			for _, observation := range fact.Observations {
				producers[observation.Producer.InvocationID] = true
				if observation.Producer.TaskID != "" {
					t.Fatal("direct source invented a task")
				}
			}
			if !producers[a.ID] || !producers[b.ID] {
				t.Fatalf("wrong sources: %s", r.body)
			}
		}
		cursor = page.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) < 2 || cursor != "" {
		t.Fatal("fixed revision pages did not finish")
	}
	other := createProject(t, env.ts, t.TempDir()).Project
	wrong := doAs(t, env.ts, readerSecret, "GET", "/api/v1/projects/"+other.ID+"/knowledge/revisions/"+second.Publication.View.ID+"/facts?snapshot_id="+setup.snapshotID, nil, nil)
	if wrong.status != 404 {
		t.Fatalf("cross-project revision: %d %s", wrong.status, wrong.body)
	}
	stale := setup.publish(t, b.ID, "", "stale", "rev-0")
	if stale.status != 409 || stale.Code != "version_conflict" {
		t.Fatalf("stale: %d %s", stale.status, stale.body)
	}
	replay := setup.publish(t, a.ID, "", "source-a", "rev-0")
	if replay.status != 201 || replay.Publication.Revision != "rev-1" {
		t.Fatalf("replay: %d %s", replay.status, replay.body)
	}
	changed := setup.publish(t, b.ID, "", "source-a", "rev-0")
	if changed.status != 409 || changed.Code != "batch_conflict" {
		t.Fatalf("changed batch: %d %s", changed.status, changed.body)
	}
	env.ts.Close()
	if err := env.rt.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt := open()
	after := doAs(t, rebuilt.ts, readerSecret, "GET", pageURL, nil, nil)
	if after.status != 200 || !bytes.Equal(before.body, after.body) {
		t.Fatalf("fixed page changed: %d %s", after.status, after.body)
	}
	continued := doAs(t, rebuilt.ts, readerSecret, "GET", pageURL+"&cursor="+url.QueryEscape(oldPage.Next), nil, nil)
	if continued.status != 200 {
		t.Fatalf("cursor lost on restart: %d %s", continued.status, continued.body)
	}
}

func TestPostgresParserInvocationPersistsAcrossRuntimeRebuild(t *testing.T) {
	cfg := postgresConfig(t)
	open := func() *testEnv {
		rt, err := app.Build(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return serveTestEnv(t, rt, false)
	}
	env := open()
	env.source = t.TempDir()
	writeFile(t, env.source, "main.go", "package main\nfunc main() {}\n")
	project := createProject(t, env.ts, env.source).Project
	captured := do(t, env.ts, "POST", "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	if captured.status != 201 {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID
	registered := do(t, env.ts, "POST", prefix+"/artifacts", nil, nil)
	var directory struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	registered.decode(t, &directory)
	var archive artifact.Ref
	for _, ref := range directory.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			archive = ref
		}
	}
	if archive.ID == "" {
		t.Fatalf("source archive: %d %s", registered.status, registered.body)
	}
	inv := executePluginHTTP(t, env, prefix, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-pg-parser", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: archive.Scope, Inputs: []artifact.Ref{archive}, Config: json.RawMessage(`{}`)})
	if inv.Status != "SUCCEEDED" || len(inv.Outputs) == 0 {
		t.Fatalf("parser: %+v", inv)
	}
	before := do(t, env.ts, "GET", prefix+"/plugin-invocations/"+inv.ID, nil, nil)
	env.ts.Close()
	if err := env.rt.Close(); err != nil {
		t.Fatal(err)
	}
	reopened := open()
	after := do(t, reopened.ts, "GET", prefix+"/plugin-invocations/"+inv.ID, nil, nil)
	if before.status != 200 || after.status != 200 || string(before.body) != string(after.body) {
		t.Fatalf("invocation changed after restart: %d %s", after.status, after.body)
	}
}

func TestPostgresKnowledgeDirectoryPaginatesWithActualHead(t *testing.T) {
	rt, err := app.Build(context.Background(), postgresConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	setup := newPublicationSetup(t, serveTestEnv(t, rt, false))
	inv := setup.analyze(t, "inv-directory")
	for i, base := range []string{"rev-0", "rev-1", "rev-2"} {
		r := setup.publish(t, inv.ID, "", fmt.Sprintf("directory-%d", i), base)
		if r.status != 201 {
			t.Fatalf("publish: %d %s", r.status, r.body)
		}
	}
	endpoint := "/api/v1/projects/" + setup.projectID + "/knowledge/revisions?snapshot_id=" + setup.snapshotID + "&limit=1"
	cursor := ""
	seen := map[string]bool{}
	for range 4 {
		r := do(t, setup.env.ts, "GET", endpoint+"&cursor="+cursor, nil, nil)
		var page struct {
			Head      string `json:"head_revision"`
			Next      string `json:"next_cursor"`
			Revisions []struct {
				ID string `json:"revision"`
			} `json:"revisions"`
		}
		r.decode(t, &page)
		if r.status != 200 || page.Head != "rev-3" {
			t.Fatalf("directory lost actual head: %d %s", r.status, r.body)
		}
		for _, revision := range page.Revisions {
			if seen[revision.ID] {
				t.Fatal("duplicate directory page")
			}
			seen[revision.ID] = true
		}
		cursor = page.Next
		if cursor == "" {
			break
		}
	}
	if len(seen) != 3 {
		t.Fatalf("directory omitted revisions: %v", seen)
	}
}

func TestPostgresDirectAnalysisPublishesQueryableGraphAndPaths(t *testing.T) {
	cfg := postgresConfig(t)
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	env.source = t.TempDir()
	writeFile(t, env.source, "go.mod", "module example.invalid/fixture\n\ngo 1.22\n")
	writeFile(t, env.source, "main.go", `package main
import ("net/http"; "os/exec")
func sink(s string) { exec.Command(s).Run() }
func Handler(w http.ResponseWriter, r *http.Request) { sink(r.URL.Query().Get("cmd")) }
func main() { http.HandleFunc("/run", Handler) }
`)
	project := createProject(t, env.ts, env.source).Project
	captured := do(t, env.ts, "POST", "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	if captured.status != 201 {
		t.Fatalf("capture: %s", captured.body)
	}
	sid := snapshot.Snapshot.SnapshotID
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + sid
	var directory struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	do(t, env.ts, "POST", prefix+"/artifacts", nil, nil).decode(t, &directory)
	var archive artifact.Ref
	for _, ref := range directory.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			archive = ref
		}
	}
	parser := executePluginHTTP(t, env, prefix, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-pg-parse", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: archive.Scope, Inputs: []artifact.Ref{archive}, Config: json.RawMessage(`{}`)})
	var catalog struct {
		Plugins []plugin.Record `json:"plugins"`
	}
	do(t, env.ts, "GET", "/api/v1/plugins", nil, nil).decode(t, &catalog)
	entries := map[string]plugin.Record{}
	for _, record := range catalog.Plugins {
		entries[record.Manifest.ID] = record
	}
	run := func(id, tool string, inputs []artifact.Ref) plugin.Invocation {
		record := entries[tool]
		if !record.Executable {
			t.Fatalf("%s is not installed", tool)
		}
		result := executePluginHTTP(t, env, prefix, plugin.Request{APIVersion: "codexploit/v1", ID: id, PluginID: tool, PluginVersion: record.Manifest.Version, PackageDigest: record.PackageDigest, Scope: archive.Scope, Inputs: inputs, Config: json.RawMessage(`{}`)})
		if result.Status != "SUCCEEDED" && result.Status != "PARTIAL" {
			t.Fatalf("%s failed: %s", tool, result.ErrorCode)
		}
		return result
	}
	var code artifact.Ref
	for _, ref := range parser.Outputs {
		if ref.Kind == "code.facts" {
			code = ref
		}
	}
	semantic := run("inv-pg-semantic", plugin.SemanticID, []artifact.Ref{archive, code})
	var security, native artifact.Ref
	for _, ref := range semantic.Outputs {
		if ref.Kind == "security.facts" {
			security = ref
		}
		if ref.SchemaID == "codexploit/builtin-native/v1" {
			native = ref
		}
	}
	paths := run("inv-pg-paths", "builtin.discovery-paths", []artifact.Ref{security, native})
	publication := do(t, env.ts, "POST", "/api/v1/projects/"+project.ID+"/knowledge/publications", map[string]any{"api_version": "codexploit/v1", "snapshot_id": sid, "invocation_id": paths.ID, "batch_id": "batch-pg-paths", "base_revision": "rev-0"}, nil)
	if publication.status != 201 {
		t.Fatalf("publish: %d %s", publication.status, publication.body)
	}
	base := "/api/v1/projects/" + project.ID + "/knowledge/views"
	opened := do(t, env.ts, "POST", base, map[string]any{"api_version": "codexploit/v1", "snapshot_id": sid, "layers": []string{"scg", "asg", "paths"}}, nil)
	if opened.status != 200 {
		t.Fatalf("open fixed view: %d %s", opened.status, opened.body)
	}
	var view knowledgeViewResponse
	opened.decode(t, &view)
	for _, layer := range []string{"scg", "asg", "paths"} {
		if view.View.Layers[layer].Status != knowledge.StatusAvailable {
			t.Fatalf("layer %s: %s", layer, opened.body)
		}
	}
	listed := doAs(t, env.ts, readerSecret, "GET", base+"/"+view.View.ID+"/paths?limit=1", nil, nil)
	var page knowledge.PathPage
	listed.decode(t, &page)
	if listed.status != 200 || page.Meta.Total == 0 || len(page.Paths) != 1 {
		t.Fatalf("real path index missing: %d %s", listed.status, listed.body)
	}
	if len(page.Audits) != 0 {
		t.Fatalf("direct analysis created an execution task: %s", listed.body)
	}
	pathViewResponse := do(t, env.ts, "POST", base, map[string]any{"api_version": "codexploit/v1", "snapshot_id": sid, "layers": []string{"paths"}}, nil)
	var pathView knowledgeViewResponse
	pathViewResponse.decode(t, &pathView)
	pathOnly := doAs(t, env.ts, readerSecret, "GET", base+"/"+pathView.View.ID+"/paths?limit=1", nil, nil)
	var pathOnlyPage knowledge.PathPage
	pathOnly.decode(t, &pathOnlyPage)
	if pathOnly.status != 200 || pathOnlyPage.Meta.Total != page.Meta.Total {
		t.Fatalf("paths require an unrequested ASG layer: %d %s", pathOnly.status, pathOnly.body)
	}
	record := entries["builtin.discovery-paths"]
	limited := executePluginHTTP(t, env, prefix, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-pg-limited", PluginID: record.Manifest.ID, PluginVersion: record.Manifest.Version, PackageDigest: record.PackageDigest, Scope: archive.Scope, Inputs: []artifact.Ref{security, native}, Config: json.RawMessage(`{"max_paths":1}`)})
	if limited.Status != "PARTIAL" {
		t.Fatalf("expected explicit truncated coverage: %+v", limited)
	}
	published := do(t, env.ts, "POST", "/api/v1/projects/"+project.ID+"/knowledge/publications", map[string]any{"api_version": "codexploit/v1", "snapshot_id": sid, "invocation_id": limited.ID, "batch_id": "batch-limited", "base_revision": "rev-1"}, nil)
	if published.status != 201 {
		t.Fatalf("partial publication: %d %s", published.status, published.body)
	}
	limitedURL := base + "/" + view.View.ID + "/paths?analysis_id=" + limited.ID
	limitedPage := doAs(t, env.ts, readerSecret, "GET", limitedURL, nil, nil)
	var result knowledge.PathPage
	limitedPage.decode(t, &result)
	if limitedPage.status != 200 || len(result.Paths) != 1 || !result.Meta.Truncated || result.Meta.TruncationReason != "analysis_coverage" {
		t.Fatalf("coverage disappeared: %d %s", limitedPage.status, limitedPage.body)
	}
	provenanceURL := base + "/" + view.View.ID + "/provenance?fact_id=" + result.Paths[0].EntryNodeID
	provenance := doAs(t, env.ts, readerSecret, "GET", provenanceURL, nil, nil)
	if provenance.status != 200 || !bytes.Contains(provenance.body, []byte(limited.ID)) {
		t.Fatalf("direct provenance: %d %s", provenance.status, provenance.body)
	}
	env.ts.Close()
	if err := env.rt.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	reopened := serveTestEnv(t, rebuilt, false)
	after := doAs(t, reopened.ts, readerSecret, "GET", limitedURL, nil, nil)
	if after.status != 200 || !bytes.Equal(after.body, limitedPage.body) {
		t.Fatalf("pinned paths changed on rebuild: %d %s", after.status, after.body)
	}
}
