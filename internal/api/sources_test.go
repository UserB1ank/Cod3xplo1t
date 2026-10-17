package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
)

func TestLocalSourceCanBeCreatedAndListedThroughAuthenticatedAPI(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	endpoint := "/api/v1/projects/" + project.ID + "/sources"
	created := do(t, env.ts, http.MethodPost, endpoint, map[string]any{
		"api_version": "codexploit/v1", "id": "src-working-files", "project_id": project.ID,
		"name": "Current working files", "kind": "local_folder", "location": "/repos/service", "ref": "",
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create source: %d %s", created.status, created.body)
	}
	listing := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
	var result struct {
		Sources []struct {
			ID, Name, Kind, Location string
			Version                  int
		} `json:"sources"`
	}
	listing.decode(t, &result)
	if listing.status != http.StatusOK || len(result.Sources) != 1 || result.Sources[0].ID != "src-working-files" || result.Sources[0].Kind != "local_folder" || result.Sources[0].Location != "/repos/service" || result.Sources[0].Version != 1 {
		t.Fatalf("registered source not readable: %d %s", listing.status, listing.body)
	}
}

func TestLocalSourceAPIRejectsUnauthorizedOrOutOfScopeCaptures(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	first := createProject(t, env.ts, env.source).Project
	second := createProject(t, env.ts, newTestSource(t)).Project
	root := t.TempDir()
	writeFile(t, root, "service/main.go", "package main\n")
	ts := localSourceServer(t, env, root)
	if r := addLocalSource(t, ts, first.ID, "src-owner", "/repos/service"); r.status != 201 {
		t.Fatalf("source: %d %s", r.status, r.body)
	}
	endpoint := "/api/v1/projects/" + first.ID + "/sources"
	reader := doAs(t, ts, readerSecret, http.MethodPost, endpoint, map[string]any{}, nil)
	anonymous := doAs(t, ts, "", http.MethodGet, endpoint, nil, nil)
	if reader.status != 403 || anonymous.status != 401 {
		t.Fatalf("source authorization: reader=%d anonymous=%d", reader.status, anonymous.status)
	}
	for _, location := range []string{"/repos/../outside", "/repos//service", "/repos/service/", "/data/private"} {
		if r := addLocalSource(t, ts, first.ID, "src-invalid", location); r.status != 400 {
			t.Fatalf("invalid location %q accepted: %d %s", location, r.status, r.body)
		}
	}
	for _, body := range []map[string]any{
		{"project_id": second.ID, "source_version": 1, "skip_analysis": true},
		{"project_id": first.ID, "source_version": 2, "skip_analysis": true},
	} {
		r := do(t, ts, http.MethodPost, "/api/v1/sources/src-owner/snapshots", body, nil)
		if r.status != 400 && r.status != 412 {
			t.Fatalf("out of scope capture accepted: %d %s", r.status, r.body)
		}
	}
	t.Run("source_directory_cannot_follow_an_escaping_link", func(t *testing.T) {
		outside := t.TempDir()
		writeFile(t, outside, "secret.go", "package private\n")
		if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
			t.Skipf("symlinks unavailable: %v", err)
		}
		if r := addLocalSource(t, ts, first.ID, "src-linked", "/repos/linked"); r.status != 201 {
			t.Fatalf("definition: %d %s", r.status, r.body)
		}
		r := do(t, ts, http.MethodPost, "/api/v1/sources/src-linked/snapshots", map[string]any{"project_id": first.ID, "source_version": 1, "skip_analysis": true}, nil)
		if r.status != 400 {
			t.Fatalf("escaping directory accepted: %d %s", r.status, r.body)
		}
	})
	listing := do(t, ts, http.MethodGet, "/api/snapshots?project_id="+first.ID, nil, nil)
	var page struct {
		Snapshots []map[string]any `json:"snapshots"`
	}
	listing.decode(t, &page)
	if listing.status != 200 || len(page.Snapshots) != 0 {
		t.Fatalf("failed captures published metadata: %d %s", listing.status, listing.body)
	}
}

func TestLocalSourceSnapshotCanBeCapturedAgainAfterDeletion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace, root := t.TempDir(), t.TempDir()
			writeFile(t, root, "service/main.go", "package main\n")
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, runtime, false)
			project := createProject(t, env.ts, env.source).Project
			ts := localSourceServer(t, env, root)
			if r := addLocalSource(t, ts, project.ID, "src-recapture", "/repos/service"); r.status != 201 {
				t.Fatalf("source: %s", r.body)
			}
			capture := func() string {
				r := do(t, ts, http.MethodPost, "/api/v1/sources/src-recapture/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "skip_analysis": true}, nil)
				if r.status != 201 {
					t.Fatalf("capture: %d %s", r.status, r.body)
				}
				var body struct {
					Snapshot struct {
						ID string `json:"snapshot_id"`
					} `json:"snapshot"`
				}
				r.decode(t, &body)
				return body.Snapshot.ID
			}
			id := capture()
			if r := do(t, ts, http.MethodDelete, "/api/snapshots/"+id, nil, nil); r.status != 204 {
				t.Fatalf("delete: %d %s", r.status, r.body)
			}
			if got := capture(); got != id {
				t.Fatalf("unchanged source changed identity: %s", got)
			}
			if r := do(t, ts, http.MethodGet, "/api/snapshots/"+id, nil, nil); r.status != 200 {
				t.Fatalf("recapture returned unusable snapshot: %d %s", r.status, r.body)
			}
		})
	}
}

func TestProjectCanStartWithExplicitSourcesWithoutLegacyInput(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "Multi-source project"}, nil)
	if created.status != 201 {
		t.Fatalf("create project: %d %s", created.status, created.body)
	}
	var project struct {
		Project struct {
			ID     string `json:"id"`
			Source string `json:"source"`
		} `json:"project"`
	}
	created.decode(t, &project)
	if project.Project.ID == "" || project.Project.Source != "" {
		t.Fatalf("unexpected default input: %s", created.body)
	}
	for _, id := range []string{"src-first", "src-second"} {
		if r := addLocalSource(t, env.ts, project.Project.ID, id, "/repos/"+id); r.status != 201 {
			t.Fatalf("add source: %d %s", r.status, r.body)
		}
	}
	read := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project.Project.ID+"/sources", nil, nil)
	var listing struct {
		Sources []map[string]any `json:"sources"`
	}
	read.decode(t, &listing)
	if read.status != 200 || len(listing.Sources) != 2 {
		t.Fatalf("multiple sources unavailable: %d %s", read.status, read.body)
	}
}

func TestLocalSourceLatestSnapshotFollowsRecapturedContent(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace, root := t.TempDir(), t.TempDir()
			writeFile(t, root, "service/main.go", "package main\nconst version = 1\n")
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, runtime, false)
			project := createProject(t, env.ts, env.source).Project
			ts := localSourceServer(t, env, root)
			if r := addLocalSource(t, ts, project.ID, "src-current", "/repos/service"); r.status != 201 {
				t.Fatalf("source: %d %s", r.status, r.body)
			}
			capture := func() string {
				r := do(t, ts, http.MethodPost, "/api/v1/sources/src-current/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "skip_analysis": true}, nil)
				if r.status != 201 {
					t.Fatalf("capture: %d %s", r.status, r.body)
				}
				var body snapshotResponse
				r.decode(t, &body)
				return body.Snapshot.SnapshotID
			}
			original := capture()
			writeFile(t, root, "service/main.go", "package main\nconst version = 2\n")
			if capture() == original {
				t.Fatal("changed source did not create a new snapshot")
			}
			writeFile(t, root, "service/main.go", "package main\nconst version = 1\n")
			if capture() != original {
				t.Fatal("restored contents did not reuse their immutable snapshot")
			}
			listing := do(t, ts, http.MethodGet, "/api/v1/projects/"+project.ID+"/sources", nil, nil)
			var body struct {
				Sources []struct {
					Snapshot string `json:"snapshot"`
					Revision int    `json:"revision"`
				} `json:"sources"`
			}
			listing.decode(t, &body)
			if listing.status != 200 || len(body.Sources) != 1 || body.Sources[0].Snapshot != original || body.Sources[0].Revision != 2 {
				t.Fatalf("latest source did not reflect the recaptured contents: %d %s", listing.status, listing.body)
			}
		})
	}
}

func TestTaskKeepsItsSourceSnapshotAfterFolderChangesAndRestart(t *testing.T) {
	t.Parallel()
	workspace, root := t.TempDir(), t.TempDir()
	writeFile(t, root, "service/go.mod", "module example.invalid/service\n\ngo 1.24\n")
	writeFile(t, root, "service/main.go", "package main\nfunc main() {}\n")
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	first := serveTestEnv(t, runtime, false)
	project := createProject(t, first.ts, first.source).Project
	ts := localSourceServer(t, first, root)
	if r := addLocalSource(t, ts, project.ID, "src-pinned", "/repos/service"); r.status != 201 {
		t.Fatalf("source: %d %s", r.status, r.body)
	}
	capture := func() string {
		r := do(t, ts, http.MethodPost, "/api/v1/sources/src-pinned/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "build_graph": true, "build_asg": true}, nil)
		if r.status != 201 {
			t.Fatalf("capture: %d %s", r.status, r.body)
		}
		var body struct {
			Snapshot struct {
				ID string `json:"snapshot_id"`
			} `json:"snapshot"`
		}
		r.decode(t, &body)
		return body.Snapshot.ID
	}
	original := capture()
	created := do(t, ts, http.MethodPost, "/api/projects/"+project.ID+"/tasks", map[string]any{"name": "Pinned folder task", "objective": "Review code", "source_id": "src-pinned", "snapshot_id": original}, nil)
	if created.status != 201 {
		t.Fatalf("task: %d %s", created.status, created.body)
	}
	var task struct {
		Task struct {
			ID     string `json:"audit_id"`
			Source string `json:"source_id"`
		} `json:"task"`
	}
	created.decode(t, &task)
	if task.Task.Source != "src-pinned" {
		t.Fatalf("task source missing: %s", created.body)
	}
	writeFile(t, root, "service/main.go", "package main\nfunc main() { println(2) }\n")
	updated := capture()
	if updated == original {
		t.Fatal("changed contents reused the original snapshot")
	}
	ts.Close()
	first.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	second := serveTestEnv(t, runtime, false)
	read := do(t, second.ts, http.MethodGet, "/api/tasks/"+task.Task.ID, nil, nil)
	var pinned struct {
		Snapshot string `json:"snapshot_id"`
		Source   string `json:"source_id"`
		Version  int    `json:"source_version"`
	}
	read.decode(t, &pinned)
	if read.status != 200 || pinned.Snapshot != original || pinned.Source != "src-pinned" || pinned.Version != 1 {
		t.Fatalf("task changed after reopen: %d %s", read.status, read.body)
	}
	list := do(t, second.ts, http.MethodGet, "/api/v1/projects/"+project.ID+"/sources", nil, nil)
	var sources struct {
		Sources []struct {
			Snapshot string `json:"snapshot"`
			Revision int    `json:"revision"`
		} `json:"sources"`
	}
	list.decode(t, &sources)
	if list.status != 200 || len(sources.Sources) != 1 || sources.Sources[0].Snapshot != updated || sources.Sources[0].Revision != 2 {
		t.Fatalf("latest source snapshot lost: %d %s", list.status, list.body)
	}
}

func localSourceServer(t *testing.T, env *testEnv, root string) *httptest.Server {
	t.Helper()
	server := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer,
		WithAuth(testAuthenticator(t)), WithLocalSourceRoot(root),
		WithGraph(env.rt.Graph), WithBuilder(env.rt.Builder), WithASG(env.rt.ASG), WithASGBuilder(env.rt.ASGBuilder), WithAudit(env.rt.Audit))
	ts := httptest.NewServer(server.Handler())
	t.Cleanup(ts.Close)
	return ts
}

func addLocalSource(t *testing.T, ts *httptest.Server, project, id, location string) response {
	t.Helper()
	return do(t, ts, http.MethodPost, "/api/v1/projects/"+project+"/sources", map[string]any{
		"api_version": "codexploit/v1", "id": id, "project_id": project,
		"name": id, "kind": "local_folder", "location": location, "ref": "",
	}, nil)
}

func TestRegisteredLocalSourceCapturesSnapshotInItsProject(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	root := t.TempDir()
	writeFile(t, root, "service/main.go", "package main\nconst current = true\n")
	ts := localSourceServer(t, env, root)
	if created := addLocalSource(t, ts, project.ID, "src-service", "/repos/service"); created.status != 201 {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	captured := do(t, ts, http.MethodPost, "/api/v1/sources/src-service/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "skip_analysis": true}, nil)
	if captured.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	// Read the wire fields with their public names, independently of server DTOs.
	var body map[string]any
	captured.decode(t, &body)
	snapshot := body["snapshot"].(map[string]any)
	if snapshot["project_id"] != project.ID || snapshot["source_id"] != "src-service" || snapshot["source_version"] != float64(1) || snapshot["vcs"] != "none" || snapshot["files"] != float64(1) {
		t.Fatalf("incorrect snapshot scope: %s", captured.body)
	}
	listing := do(t, ts, http.MethodGet, "/api/snapshots?project_id="+project.ID, nil, nil)
	var page struct {
		Snapshots []map[string]any `json:"snapshots"`
	}
	listing.decode(t, &page)
	if listing.status != 200 || len(page.Snapshots) != 1 || page.Snapshots[0]["snapshot_id"] != snapshot["snapshot_id"] {
		t.Fatalf("snapshot not registered in project: %d %s", listing.status, listing.body)
	}
}

func TestLocalSourceRemainsReadableAfterDatabaseReopen(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	first := serveTestEnv(t, runtime, false)
	project := createProject(t, first.ts, first.source).Project
	endpoint := "/api/v1/projects/" + project.ID + "/sources"
	created := do(t, first.ts, http.MethodPost, endpoint, map[string]any{
		"api_version": "codexploit/v1", "id": "src-persistent", "project_id": project.ID,
		"name": "Persistent input", "kind": "local_folder", "location": "/repos/service", "ref": "",
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	first.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	second := serveTestEnv(t, runtime, false)
	read := do(t, second.ts, http.MethodGet, endpoint, nil, nil)
	var result struct {
		Sources []struct {
			ID string `json:"id"`
		} `json:"sources"`
	}
	read.decode(t, &result)
	if read.status != 200 || len(result.Sources) != 1 || result.Sources[0].ID != "src-persistent" {
		t.Fatalf("source lost after reopen: %d %s", read.status, read.body)
	}
}
