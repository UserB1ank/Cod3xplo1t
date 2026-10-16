package main

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/api"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestCLIBuildRegistersAndRemoveDeletesStoredSnapshot(t *testing.T) {
	workspace, db := scgWorkspace(t)
	id := buildSCG(t, scgFixture(t), workspace, db)
	rt, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	ctx := context.Background()
	if _, err := rt.Store.GetSnapshot(ctx, id); err != nil {
		t.Fatalf("CLI snapshot is not registered: %v", err)
	}
	if _, err := rt.Store.GetManifest(ctx, id); err != nil {
		t.Fatalf("CLI manifest is not registered: %v", err)
	}
	if _, err := captureStdout(t, func() error {
		return runSnapshots(ctx, []string{"remove", "--workspace", workspace, "--db", db, "--id", id})
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Store.GetSnapshot(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("snapshot after delete: %v", err)
	}
	if _, err := rt.Store.GraphSummary(ctx, id); !errors.Is(err, storage.ErrNotFound) {
		t.Fatalf("graph survived CLI delete: %v", err)
	}
}

func TestRegisterStatelessSnapshotMakesItVisibleToAPI(t *testing.T) {
	ctx := context.Background()
	workspace, db := scgWorkspace(t)
	source := scgFixture(t)
	stateless, err := app.Build(ctx, app.Config{Workspace: workspace, DBPath: "memory"})
	if err != nil {
		t.Fatal(err)
	}
	snap, err := stateless.Manager.Create(ctx, repository.Source{Raw: source})
	if err != nil {
		stateless.Close()
		t.Fatal(err)
	}
	manifest, err := stateless.Analyzer.Analyze(ctx, snap)
	if err != nil {
		stateless.Close()
		t.Fatal(err)
	}
	if err := manifest.WriteTo(snap); err != nil {
		stateless.Close()
		t.Fatal(err)
	}
	if err := stateless.Close(); err != nil {
		t.Fatal(err)
	}
	for range 2 {
		if _, err := captureStdout(t, func() error {
			return runSnapshots(ctx, []string{"register", "--workspace", workspace, "--db", db, "--id", snap.SnapshotID, "--source", source, "--json"})
		}); err != nil {
			t.Fatal(err)
		}
	}
	rt, err := app.Build(ctx, app.Config{Workspace: workspace, DBPath: db})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	projects, err := rt.Store.ListProjects(ctx)
	if err != nil || len(projects) != 1 {
		t.Fatalf("projects=%v err=%v", projects, err)
	}
	if _, err := rt.Store.RenameProject(ctx, projects[0].ID, "reviewed name", projects[0].Version); err != nil {
		t.Fatal(err)
	}
	if _, err := rt.Snapshots.Register(ctx, snap, source); err != nil {
		t.Fatal(err)
	}
	project, err := rt.Store.GetProject(ctx, projects[0].ID)
	if err != nil || project.Name != "reviewed name" {
		t.Fatalf("registration overwrote project metadata: %+v %v", project, err)
	}
	auth, err := api.NewAuthenticatorWithOptions(nil, api.WithAnonymousAccess(api.CapRead))
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(api.NewServer(rt.Store, rt.Manager, rt.Analyzer, api.WithAuth(auth)).Handler())
	defer server.Close()
	resp, err := server.Client().Get(server.URL + "/api/snapshots")
	if err != nil {
		t.Fatal(err)
	}
	var result struct {
		Snapshots []storage.SnapshotRecord `json:"snapshots"`
	}
	err = json.NewDecoder(resp.Body).Decode(&result)
	resp.Body.Close()
	if err != nil || resp.StatusCode != http.StatusOK || len(result.Snapshots) != 1 || result.Snapshots[0].SnapshotID != snap.SnapshotID {
		t.Fatalf("API snapshots=%+v status=%d err=%v", result, resp.StatusCode, err)
	}
	resp, err = server.Client().Get(server.URL + "/api/snapshots/" + snap.SnapshotID + "/manifest")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("API manifest=%d", resp.StatusCode)
	}
}
