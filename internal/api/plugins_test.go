package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestPluginInvocationAndOutputsRemainReadableAfterRestart(t *testing.T) {
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	rt, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	project := createProject(t, env.ts, env.source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
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
	request := plugin.Request{APIVersion: "codexploit/v1", ID: "inv-api-parser", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: input.Scope, Inputs: []artifact.Ref{input}, Config: json.RawMessage(`{}`)}
	started := do(t, env.ts, http.MethodPost, prefix+"/plugin-invocations", request, nil)
	if started.status != 202 {
		t.Fatalf("start: %d %s", started.status, started.body)
	}
	endpoint := prefix + "/plugin-invocations/" + request.ID
	var result struct {
		Invocation plugin.Invocation `json:"invocation"`
	}
	deadline := time.Now().Add(20 * time.Second)
	for {
		r := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint, nil, nil)
		if r.status != 200 {
			t.Fatalf("status: %d %s", r.status, r.body)
		}
		r.decode(t, &result)
		if plugin.Terminal(result.Invocation.Status) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("parse did not finish")
		}
		time.Sleep(10 * time.Millisecond)
	}
	if result.Invocation.Coverage.ParsedFiles != 2 || len(result.Invocation.Outputs) != 2 {
		t.Fatalf("real parse: %+v", result.Invocation)
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
	read := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
	read.decode(t, &result)
	if read.status != 200 || len(result.Invocation.Outputs) != 2 {
		t.Fatalf("restart: %d %s", read.status, read.body)
	}
	for _, ref := range result.Invocation.Outputs {
		r := do(t, env.ts, http.MethodGet, prefix+"/artifacts/"+ref.ID+"/content", nil, nil)
		if r.status != 200 || !strings.Contains(string(r.body), "main.go") {
			t.Fatalf("output: %d %s", r.status, r.body)
		}
	}
	wrong := strings.Replace(endpoint, project.ID, "project-elsewhere", 1)
	if r := do(t, env.ts, http.MethodGet, wrong, nil, nil); r.status != 404 {
		t.Fatalf("project escape: %d %s", r.status, r.body)
	}
}

func TestActivePluginInvocationBlocksSnapshotRetirement(t *testing.T) {
	env := newTestEnv(t, false)
	writeFile(t, env.source, "main.go", "package main\n"+strings.Repeat("var X int\n", 50000))
	project := createProject(t, env.ts, env.source).Project
	r := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snap snapshotResponse
	r.decode(t, &snap)
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snap.Snapshot.SnapshotID
	r = do(t, env.ts, http.MethodPost, prefix+"/artifacts", nil, nil)
	var page struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	r.decode(t, &page)
	var input artifact.Ref
	for _, ref := range page.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			input = ref
		}
	}
	req := plugin.Request{APIVersion: "codexploit/v1", ID: "inv-active", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: input.Scope, Inputs: []artifact.Ref{input}, Config: json.RawMessage(`{}`), Budget: plugin.Budget{MaxASTNodes: 500000, MaxOutputBytes: 64 << 20}}
	r = do(t, env.ts, http.MethodPost, prefix+"/plugin-invocations", req, nil)
	if r.status != 202 {
		t.Fatalf("start: %d %s", r.status, r.body)
	}
	r = do(t, env.ts, http.MethodDelete, "/api/snapshots/"+snap.Snapshot.SnapshotID, nil, nil)
	if r.status != 409 {
		t.Fatalf("active snapshot retired: %d %s", r.status, r.body)
	}
	endpoint := prefix + "/plugin-invocations/" + req.ID
	for range 5 {
		read := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
		if read.status != 200 {
			t.Fatalf("status: %d %s", read.status, read.body)
		}
		r = do(t, env.ts, http.MethodPost, endpoint+"/cancel", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
		if r.status == 412 {
			continue
		}
		if r.status != 200 {
			t.Fatalf("cancel: %d %s", r.status, r.body)
		}
		return
	}
	t.Fatal("cancel CAS never settled")
}

func TestRegisteredPluginVersionsSurviveRestartWithoutBecomingInstalled(t *testing.T) {
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	rt, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	raw, err := contracts.Files.ReadFile("examples/plugin.json")
	if err != nil {
		t.Fatal(err)
	}
	request := map[string]any{"api_version": "codexploit/v1", "manifest": json.RawMessage(raw), "package_digest": strings.Repeat("1", 64), "source": "offline fixture"}
	for range 2 {
		r := do(t, env.ts, http.MethodPost, "/api/v1/plugins", request, nil)
		if r.status != 201 {
			t.Fatalf("register: %d %s", r.status, r.body)
		}
	}
	request["package_digest"] = strings.Repeat("2", 64)
	if r := do(t, env.ts, http.MethodPost, "/api/v1/plugins", request, nil); r.status != 409 {
		t.Fatalf("package replacement: %d %s", r.status, r.body)
	}
	if r := doAs(t, env.ts, readerSecret, http.MethodPost, "/api/v1/plugins", request, nil); r.status != 403 {
		t.Fatalf("reader registration: %d", r.status)
	}
	request["manifest"] = json.RawMessage(strings.Replace(string(raw), "codexploit/v1", "codexploit/v99", 1))
	if r := do(t, env.ts, http.MethodPost, "/api/v1/plugins", request, nil); r.status != 400 {
		t.Fatalf("invalid protocol: %d %s", r.status, r.body)
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
	r := do(t, env.ts, http.MethodGet, "/api/v1/plugins", nil, nil)
	var page struct {
		Plugins []struct {
			Manifest      struct{ ID string }
			Executable    bool
			Reason        string
			PackageDigest string `json:"package_digest"`
		} `json:"plugins"`
	}
	r.decode(t, &page)
	if r.status != 200 || len(page.Plugins) != 4 {
		t.Fatalf("persisted catalog: %d %s", r.status, r.body)
	}
	for _, entry := range page.Plugins {
		if entry.Manifest.ID == "team.scanner.example" && (entry.Executable || entry.Reason == "" || entry.PackageDigest != strings.Repeat("1", 64)) {
			t.Fatalf("external manifest executable: %s", r.body)
		}
	}
}

func TestPluginCatalogListsTheInstalledGoParser(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	read := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/plugins", nil, nil)
	var page struct {
		Plugins []struct {
			Manifest      struct{ ID, Version string }
			PackageDigest string `json:"package_digest"`
			Executable    bool
			Reason        string
		} `json:"plugins"`
	}
	read.decode(t, &page)
	var installed bool
	for _, entry := range page.Plugins {
		if entry.Manifest.ID == plugin.BuiltinID && entry.Manifest.Version == plugin.BuiltinVersion && entry.Executable && len(entry.PackageDigest) == 64 {
			installed = true
		}
	}
	if read.status != 200 || len(page.Plugins) != 3 || !installed {
		t.Fatalf("installed catalog: %d %s", read.status, read.body)
	}
}
