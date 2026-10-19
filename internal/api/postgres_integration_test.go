package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
)

// The opt-in suite runs against an independent real PostgreSQL database. The
// normal three-OS suite still exercises the complete SQLite and memory modes.
func postgresConfig(t *testing.T) app.Config {
	t.Helper()
	file := testpostgres.DSNFile(t)
	return app.Config{Workspace: t.TempDir(), StorageDriver: "postgres", PostgresDSNFile: file}
}

func TestPostgresExecutionStatusIsRedactedAndRequiresAdmin(t *testing.T) {
	cfg := postgresConfig(t)
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close() })
	ts := httptest.NewServer(NewServer(rt.Store, rt.Manager, rt.Analyzer, WithAuth(testAuthenticator(t))).Handler())
	t.Cleanup(ts.Close)
	path := "/api/v1/storage/status"
	if r := doAs(t, ts, "", "GET", path, nil, nil); r.status != 401 {
		t.Fatalf("anonymous status: %d", r.status)
	}
	if r := doAs(t, ts, readerSecret, "GET", path, nil, nil); r.status != 403 {
		t.Fatalf("reader status: %d", r.status)
	}
	status := do(t, ts, "GET", path, nil, nil)
	if status.status != 200 {
		t.Fatalf("status: %d %s", status.status, status.body)
	}
	var result struct {
		Driver, Profile, Readiness string
		Capabilities               map[string]bool
		Locations                  map[string]string
	}
	status.decode(t, &result)
	if result.Driver != "postgres" || result.Profile != "execution" || result.Readiness != "ready" || !result.Capabilities["sources"] || !result.Capabilities["tasks"] || !result.Capabilities["workflows"] || !result.Capabilities["findings"] || !result.Capabilities["identity"] || !result.Capabilities["settings"] {
		t.Fatalf("false capabilities: %s", status.body)
	}
	if result.Locations["accounts"] != "postgres" || result.Locations["model_settings"] != "postgres" || result.Locations["settings_key"] != "external_file" {
		t.Fatalf("shared locations: %s", status.body)
	}
	if err := rt.Store.Close(); err != nil {
		t.Fatal(err)
	}
	unavailable := do(t, ts, "GET", path, nil, nil)
	if unavailable.status != 503 {
		t.Fatalf("closed database ready: %d %s", unavailable.status, unavailable.body)
	}
	var broken map[string]any
	if json.Unmarshal(unavailable.body, &broken) != nil || broken["readiness"] != "unavailable" {
		t.Fatalf("unavailable status: %s", unavailable.body)
	}
	dsn, err := os.ReadFile(cfg.PostgresDSNFile)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{string(dsn), cfg.PostgresDSNFile, cfg.Workspace, "database:5432", "sql:", "password"} {
		if strings.Contains(string(status.body)+string(unavailable.body), forbidden) {
			t.Fatal("storage status disclosed connection or workspace details")
		}
	}
}

func TestPostgresSourceSnapshotArtifactsAndCAS(t *testing.T) {
	cfg := postgresConfig(t)
	root := t.TempDir()
	writeFile(t, root, "service/main.go", "package main\nfunc main() {}\n")
	open := func() (*app.Runtime, *httptest.Server) {
		rt, err := app.Build(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(NewServer(rt.Store, rt.Manager, rt.Analyzer, WithAuth(testAuthenticator(t)), WithLocalSourceRoot(root)).Handler())
		t.Cleanup(func() { ts.Close(); rt.Close() })
		return rt, ts
	}
	rt, ts := open()
	create := do(t, ts, "POST", "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "Catalog sources"}, nil)
	if create.status != 201 {
		t.Fatalf("project: %s", create.body)
	}
	var project projectResponse
	create.decode(t, &project)
	id := project.Project.ID
	if r := addLocalSource(t, ts, id, "src-folder", "/repos/service"); r.status != 201 {
		t.Fatalf("folder: %s", r.body)
	}
	git := map[string]any{"api_version": "codexploit/v1", "id": "src-git", "project_id": id, "name": "Git source", "kind": "git_repository", "location": "https://example.invalid/catalog.git", "ref": "refs/heads/main"}
	if r := do(t, ts, "POST", "/api/v1/projects/"+id+"/sources", git, nil); r.status != 201 {
		t.Fatalf("git: %s", r.body)
	}
	if r := do(t, ts, "POST", "/api/v1/projects/"+id+"/sources", git, nil); r.status != 409 {
		t.Fatalf("duplicate source: %d %s", r.status, r.body)
	}
	if r := do(t, ts, "PATCH", "/api/projects/"+id, map[string]string{"name": "Renamed"}, map[string]string{"If-Match": create.header.Get("ETag")}); r.status != 200 {
		t.Fatalf("CAS: %d %s", r.status, r.body)
	}
	if r := do(t, ts, "PATCH", "/api/projects/"+id, map[string]string{"name": "Stale"}, map[string]string{"If-Match": create.header.Get("ETag")}); r.status != 412 {
		t.Fatalf("stale CAS: %d %s", r.status, r.body)
	}
	endpoint := "/api/v1/sources/src-folder/snapshots"
	for _, body := range []map[string]any{{"project_id": "other", "source_version": 1}, {"project_id": id, "source_version": 2}} {
		if r := do(t, ts, "POST", endpoint, body, nil); r.status != 400 && r.status != 412 {
			t.Fatalf("invalid capture: %d %s", r.status, r.body)
		}
	}
	capture := do(t, ts, "POST", endpoint, map[string]any{"project_id": id, "source_version": 1}, nil)
	if capture.status != 201 {
		t.Fatalf("capture: %d %s", capture.status, capture.body)
	}
	var snapshot snapshotResponse
	capture.decode(t, &snapshot)
	artifactURL := "/api/v1/projects/" + id + "/snapshots/" + snapshot.Snapshot.SnapshotID + "/artifacts"
	before := do(t, ts, "GET", artifactURL, nil, nil)
	if before.status != 200 {
		t.Fatalf("artifacts: %s", before.body)
	}
	if r := do(t, ts, "GET", "/api/v1/projects/other/snapshots/"+snapshot.Snapshot.SnapshotID+"/artifacts", nil, nil); r.status != 404 {
		t.Fatalf("scope: %d %s", r.status, r.body)
	}
	ts.Close()
	rt.Close()
	_, reopened := open()
	after := do(t, reopened, "GET", artifactURL, nil, nil)
	if after.status != 200 || string(before.body) != string(after.body) {
		t.Fatalf("artifact index changed after rebuild: %d %s", after.status, after.body)
	}
	sources := do(t, reopened, "GET", "/api/v1/projects/"+id+"/sources", nil, nil)
	var page struct {
		Sources []storage.SourceDefinition `json:"sources"`
	}
	sources.decode(t, &page)
	if sources.status != 200 || len(page.Sources) != 2 {
		t.Fatalf("source catalog: %s", sources.body)
	}
	if _, err := os.Stat(filepath.Join(cfg.Workspace, "codexploit.db")); !os.IsNotExist(err) {
		t.Fatal("PostgreSQL created a SQLite fallback")
	}
	deleted := do(t, reopened, "DELETE", "/api/snapshots/"+snapshot.Snapshot.SnapshotID, nil, nil)
	if deleted.status != 204 {
		t.Fatalf("delete catalog snapshot: %d %s", deleted.status, deleted.body)
	}
	if r := do(t, reopened, "GET", artifactURL, nil, nil); r.status != 404 {
		t.Fatalf("deleted artifacts remained visible: %d %s", r.status, r.body)
	}
}

func TestPostgresProjectPersistsAcrossRuntimeRebuild(t *testing.T) {
	cfg := postgresConfig(t)
	open := func() (*app.Runtime, *httptest.Server) {
		rt, err := app.Build(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		ts := httptest.NewServer(NewServer(rt.Store, rt.Manager, rt.Analyzer, WithAuth(testAuthenticator(t))).Handler())
		t.Cleanup(func() { ts.Close(); rt.Close() })
		return rt, ts
	}
	rt, ts := open()
	created := do(t, ts, http.MethodPost, "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "PostgreSQL catalog"}, nil)
	if created.status != 201 {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	var result projectResponse
	created.decode(t, &result)
	ts.Close()
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	_, reopened := open()
	read := do(t, reopened, http.MethodGet, "/api/projects/"+result.Project.ID, nil, nil)
	var got storage.Project
	read.decode(t, &got)
	if read.status != 200 || got.ID != result.Project.ID || got.Name != result.Project.Name || got.Version != result.Project.Version {
		t.Fatalf("reopened catalog changed: %d %s", read.status, read.body)
	}
}
