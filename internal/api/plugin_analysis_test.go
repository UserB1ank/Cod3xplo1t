package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func executePluginHTTP(t *testing.T, env *testEnv, prefix string, request plugin.Request) plugin.Invocation {
	t.Helper()
	r := do(t, env.ts, http.MethodPost, prefix+"/plugin-invocations", request, nil)
	if r.status != 202 {
		t.Fatalf("execute: %d %s", r.status, r.body)
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		r = doAs(t, env.ts, readerSecret, http.MethodGet, prefix+"/plugin-invocations/"+request.ID, nil, nil)
		var result struct {
			Invocation plugin.Invocation `json:"invocation"`
		}
		r.decode(t, &result)
		if r.status != 200 {
			t.Fatalf("read: %d %s", r.status, r.body)
		}
		if plugin.Terminal(result.Invocation.Status) {
			return result.Invocation
		}
		if time.Now().After(deadline) {
			t.Fatal("plugin did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestSemanticPluginConsumesParserFactsAndKeepsCanonicalIDs(t *testing.T) {
	workspace := t.TempDir()
	cfg := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	writeFile(t, env.source, "main.go", `package main
import ("net/http"; "os/exec")
func sink(s string) { exec.Command(s).Run() }
func Handler(w http.ResponseWriter, r *http.Request) { sink(r.URL.Query().Get("cmd")) }
func main() { http.HandleFunc("/run", Handler) }
`)
	project := createProject(t, env.ts, env.source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snap snapshotResponse
	captured.decode(t, &snap)
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snap.Snapshot.SnapshotID
	registered := do(t, env.ts, http.MethodPost, prefix+"/artifacts", nil, nil)
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
	parser := executePluginHTTP(t, env, prefix, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-parser-before-semantic", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: archive.Scope, Inputs: []artifact.Ref{archive}, Config: json.RawMessage(`{}`)})
	var facts artifact.Ref
	for _, ref := range parser.Outputs {
		if ref.Kind == "code.facts" {
			facts = ref
		}
	}
	var catalog struct {
		Plugins []plugin.Record `json:"plugins"`
	}
	do(t, env.ts, http.MethodGet, "/api/v1/plugins", nil, nil).decode(t, &catalog)
	var semantic plugin.Record
	for _, entry := range catalog.Plugins {
		if entry.Manifest.ID == "builtin.security-semantics" {
			semantic = entry
		}
	}
	if !semantic.Executable {
		t.Fatal("semantic analyzer is not installed")
	}
	done := executePluginHTTP(t, env, prefix, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-semantic", PluginID: semantic.Manifest.ID, PluginVersion: semantic.Manifest.Version, PackageDigest: semantic.PackageDigest, Scope: archive.Scope, Inputs: []artifact.Ref{archive, facts}, Config: json.RawMessage(`{}`)})
	if done.Status != "SUCCEEDED" && done.Status != "PARTIAL" {
		t.Fatalf("semantic: %+v", done)
	}
	var envelope struct {
		Invocation struct {
			Analysis struct {
				Status  string         `json:"status"`
				Outputs []artifact.Ref `json:"outputs"`
			} `json:"analysis"`
		} `json:"invocation"`
	}
	do(t, env.ts, http.MethodGet, prefix+"/plugin-invocations/"+done.ID, nil, nil).decode(t, &envelope)
	if envelope.Invocation.Analysis.Status == "" || len(envelope.Invocation.Analysis.Outputs) != 2 {
		t.Fatal("missing standardized AnalysisResult")
	}
	var normalized []byte
	for _, ref := range done.Outputs {
		if ref.Kind == "security.facts" {
			r := do(t, env.ts, http.MethodGet, prefix+"/artifacts/"+ref.ID+"/content", nil, nil)
			normalized = r.body
		}
	}
	var result struct {
		CanonicalIDs []string          `json:"canonical_ids"`
		Nodes        []json.RawMessage `json:"nodes"`
	}
	if json.Unmarshal(normalized, &result) != nil || len(result.Nodes) == 0 || len(result.CanonicalIDs) == 0 {
		t.Fatalf("no real semantic facts: %s", normalized)
	}
	// The parser and semantic adapter must agree on existing symbol identities.
	raw := do(t, env.ts, http.MethodGet, prefix+"/artifacts/"+facts.ID+"/content", nil, nil)
	var parsed struct {
		Files []struct {
			Symbols []struct {
				ID   string `json:"symbol_id"`
				Name string `json:"name"`
			} `json:"symbols"`
		} `json:"files"`
	}
	raw.decode(t, &parsed)
	var handler string
	for _, file := range parsed.Files {
		for _, symbol := range file.Symbols {
			if symbol.Name == "Handler" {
				handler = symbol.ID
			}
		}
	}
	found := false
	for _, id := range result.CanonicalIDs {
		if id == handler {
			found = true
		}
	}
	if handler == "" || !found {
		t.Fatalf("canonical Handler missing: %q in %v", handler, result.CanonicalIDs)
	}
	var paths plugin.Record
	for _, entry := range catalog.Plugins {
		if entry.Manifest.ID == "builtin.discovery-paths" {
			paths = entry
		}
	}
	inputs := []artifact.Ref{}
	for _, ref := range done.Outputs {
		if ref.Kind == "security.facts" {
			inputs = append(inputs, ref)
		}
	}
	for _, ref := range done.Outputs {
		if ref.Kind == "report.document" {
			inputs = append(inputs, ref)
		}
	}
	pathResult := executePluginHTTP(t, env, prefix, plugin.Request{APIVersion: "codexploit/v1", ID: "inv-api-paths", PluginID: paths.Manifest.ID, PluginVersion: paths.Manifest.Version, PackageDigest: paths.PackageDigest, Scope: archive.Scope, Inputs: inputs, Config: json.RawMessage(`{}`)})
	if pathResult.Status != "SUCCEEDED" && pathResult.Status != "PARTIAL" {
		t.Fatalf("path execution: %+v", pathResult)
	}
	endpoint := prefix + "/plugin-invocations/inv-api-paths/result"
	response := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint, nil, nil)
	if response.status != 200 {
		t.Fatalf("normalized result: %d %s", response.status, response.body)
	}
	var discovery struct {
		Candidates []struct {
			Status string `json:"status"`
			ID     string `json:"id"`
		} `json:"candidates"`
		Paths []json.RawMessage `json:"paths"`
	}
	response.decode(t, &discovery)
	if len(discovery.Candidates) == 0 || discovery.Candidates[0].Status != "candidate" || len(discovery.Paths) == 0 {
		t.Fatalf("candidate observations: %s", response.body)
	}
	env.ts.Close()
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	rt, err = app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env = serveTestEnv(t, rt, false)
	restored := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint, nil, nil)
	if restored.status != 200 || string(restored.body) != string(response.body) {
		t.Fatalf("result changed after restart: %d %s", restored.status, restored.body)
	}
	wrong := do(t, env.ts, http.MethodGet, "/api/v1/projects/other/snapshots/"+snap.Snapshot.SnapshotID+"/plugin-invocations/inv-api-paths/result", nil, nil)
	if wrong.status != 404 {
		t.Fatalf("cross-project result: %d %s", wrong.status, wrong.body)
	}
	if r := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"status": "confirmed"}, nil); r.status != 405 {
		t.Fatalf("tool could mutate verdict: %d %s", r.status, r.body)
	}
}
