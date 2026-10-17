package api

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

func TestArtifactAPIScopeIntegrityBudgetsAndPagination(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace := t.TempDir()
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, runtime, false)
			project := createProject(t, env.ts, newTestSource(t)).Project
			capture := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
			var snapshot snapshotResponse
			capture.decode(t, &snapshot)
			if capture.status != 201 {
				t.Fatalf("capture: %d %s", capture.status, capture.body)
			}
			endpoint := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID + "/artifacts"
			published := do(t, env.ts, http.MethodPost, endpoint, nil, nil)
			var page struct {
				Artifacts []artifact.Ref `json:"artifacts"`
			}
			published.decode(t, &page)
			if published.status != 200 || len(page.Artifacts) != 2 {
				t.Fatalf("publish: %d %s", published.status, published.body)
			}
			if strings.Contains(string(published.body), workspace) || strings.Contains(string(published.body), "physical_path") {
				t.Fatal("physical storage path leaked")
			}
			for range 2 {
				if r := do(t, env.ts, http.MethodPost, endpoint, nil, nil); r.status != 200 {
					t.Fatalf("duplicate publication: %d %s", r.status, r.body)
				}
			}
			ref := page.Artifacts[0]
			content := endpoint + "/" + ref.ID + "/content"
			if r := doAs(t, env.ts, "", http.MethodGet, content, nil, nil); r.status != 401 {
				t.Fatalf("anonymous read: %d", r.status)
			}
			if r := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint, nil, nil); r.status != 403 {
				t.Fatalf("reader publication: %d", r.status)
			}
			other := createProject(t, env.ts, newTestSource(t)).Project
			wrong := strings.Replace(content, project.ID, other.ID, 1)
			if r := do(t, env.ts, http.MethodGet, wrong, nil, nil); r.status != 404 {
				t.Fatalf("wrong project: %d %s", r.status, r.body)
			}
			if r := do(t, env.ts, http.MethodGet, endpoint+"/artifact-unpublished/content", nil, nil); r.status != 404 {
				t.Fatalf("unpublished read: %d", r.status)
			}
			if r := do(t, env.ts, http.MethodGet, content+"?max_bytes=1", nil, nil); r.status != 413 {
				t.Fatalf("budget: %d", r.status)
			}
			if r := do(t, env.ts, http.MethodGet, content+"?max_bytes=-1", nil, nil); r.status != 400 {
				t.Fatalf("invalid budget: %d", r.status)
			}
			if r := do(t, env.ts, http.MethodGet, endpoint+"/"+ref.ID, nil, nil); r.status != 200 || !strings.Contains(string(r.body), `"availability": "verified"`) {
				t.Fatalf("verify: %d %s", r.status, r.body)
			}
			cursor := ""
			seen := map[string]bool{}
			for range 3 {
				r := do(t, env.ts, http.MethodGet, endpoint+"?limit=1&cursor="+cursor, nil, nil)
				var chunk struct {
					Artifacts []artifact.Ref `json:"artifacts"`
					Next      string         `json:"next_cursor"`
				}
				r.decode(t, &chunk)
				if r.status != 200 {
					t.Fatalf("page: %s", r.body)
				}
				for _, v := range chunk.Artifacts {
					if seen[v.ID] {
						t.Fatal("repeated artifact")
					}
					seen[v.ID] = true
				}
				cursor = chunk.Next
			}
			if len(seen) != 2 {
				t.Fatalf("pagination returned %d refs", len(seen))
			}
			// Simulate same-size bit rot in the content service. Both stat and download
			// must fail before a successful response, without exposing the disk path.
			if err := os.WriteFile(filepath.Join(workspace, "artifacts", "objects", ref.SHA256), bytes.Repeat([]byte("x"), int(ref.Bytes)), 0o600); err != nil {
				t.Fatal(err)
			}
			for _, url := range []string{content, endpoint + "/" + ref.ID} {
				r := do(t, env.ts, http.MethodGet, url, nil, nil)
				if r.status != 409 || !strings.Contains(string(r.body), "artifact_integrity") || strings.Contains(string(r.body), workspace) {
					t.Fatalf("corruption: %d %s", r.status, r.body)
				}
			}
			if err := os.Remove(filepath.Join(workspace, "artifacts", "objects", ref.SHA256)); err != nil {
				t.Fatal(err)
			}
			if r := do(t, env.ts, http.MethodGet, content, nil, nil); r.status != 404 {
				t.Fatalf("missing content: %d", r.status)
			}
			if r := do(t, env.ts, http.MethodDelete, "/api/snapshots/"+snapshot.Snapshot.SnapshotID, nil, nil); r.status != 204 {
				t.Fatalf("retire: %d %s", r.status, r.body)
			}
			if r := do(t, env.ts, http.MethodGet, content, nil, nil); r.status != 404 {
				t.Fatalf("retired read: %d", r.status)
			}
		})
	}
}

func TestSnapshotSourceArchiveContainsTheFrozenFiles(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	if created.status != 201 {
		t.Fatalf("capture: %d %s", created.status, created.body)
	}
	var snapshot snapshotResponse
	created.decode(t, &snapshot)
	endpoint := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID + "/artifacts"
	// Existing/CLI snapshots can explicitly register their retained frozen copy.
	published := do(t, env.ts, http.MethodPost, endpoint, nil, nil)
	if published.status != 200 {
		t.Fatalf("publish: %d %s", published.status, published.body)
	}
	var page struct {
		Artifacts []struct {
			ID     string
			Schema string `json:"schema_id"`
		} `json:"artifacts"`
	}
	published.decode(t, &page)
	archiveID := ""
	for _, ref := range page.Artifacts {
		if ref.Schema == "codexploit/source-tar/v1" {
			archiveID = ref.ID
		}
	}
	if archiveID == "" {
		t.Fatalf("source archive missing: %s", published.body)
	}
	writeFile(t, env.source, "main.go", "changed live source\n")
	read := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint+"/"+archiveID+"/content", nil, nil)
	if read.status != 200 {
		t.Fatalf("download: %d %s", read.status, read.body)
	}
	tr := tar.NewReader(bytes.NewReader(read.body))
	files := map[string]string{}
	for {
		header, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if header.Typeflag != tar.TypeReg {
			t.Fatalf("unsafe entry: %+v", header)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatal(err)
		}
		files[header.Name] = string(data)
	}
	if len(files) != 4 || files["Dockerfile"] != "FROM scratch\n" || files["internal/svc/svc.go"] != "package svc\n\nfunc Start() { Serve() }\n\nfunc Serve() {}\n" || files["main.go"] == "changed live source\n" {
		t.Fatalf("frozen archive: %+v", files)
	}
}

func TestArtifactCatalogAndContentSurviveDatabaseReopen(t *testing.T) {
	workspace, root := t.TempDir(), t.TempDir()
	writeFile(t, root, "service/main.go", "package main\n")
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	project := createProject(t, env.ts, newTestSource(t)).Project
	ts := localSourceServer(t, env, root)
	if r := addLocalSource(t, ts, project.ID, "src-persisted-artifacts", "/repos/service"); r.status != 201 {
		t.Fatalf("source: %s", r.body)
	}
	captured := do(t, ts, http.MethodPost, "/api/v1/sources/src-persisted-artifacts/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "skip_analysis": true}, nil)
	if captured.status != 201 {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	endpoint := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID + "/artifacts"
	listing := do(t, ts, http.MethodGet, endpoint, nil, nil)
	var before struct {
		Artifacts []struct{ ID string } `json:"artifacts"`
	}
	listing.decode(t, &before)
	if listing.status != 200 || len(before.Artifacts) == 0 {
		t.Fatalf("directory: %d %s", listing.status, listing.body)
	}
	contentPath := endpoint + "/" + before.Artifacts[0].ID + "/content"
	original := do(t, ts, http.MethodGet, contentPath, nil, nil)
	ts.Close()
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	reopened := serveTestEnv(t, runtime, false)
	listing = do(t, reopened.ts, http.MethodGet, endpoint, nil, nil)
	content := do(t, reopened.ts, http.MethodGet, contentPath, nil, nil)
	if listing.status != 200 || content.status != 200 || string(content.body) != string(original.body) {
		t.Fatalf("reopen: directory=%d content=%d %s", listing.status, content.status, content.body)
	}
}

func TestCapturedSourcePublishesAReadableFileManifest(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	root := t.TempDir()
	writeFile(t, root, "service/main.go", "package main\n")
	ts := localSourceServer(t, env, root)
	if r := addLocalSource(t, ts, project.ID, "src-artifacts", "/repos/service"); r.status != 201 {
		t.Fatalf("source: %d %s", r.status, r.body)
	}
	captured := do(t, ts, http.MethodPost, "/api/v1/sources/src-artifacts/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "skip_analysis": true}, nil)
	if captured.status != 201 {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	endpoint := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID + "/artifacts"
	listing := doAs(t, ts, readerSecret, http.MethodGet, endpoint, nil, nil)
	var page struct {
		Artifacts []struct {
			ID, Kind string
			Bytes    int64
			Scope    struct {
				Project  string `json:"project_id"`
				Source   string `json:"source_id"`
				Snapshot string `json:"snapshot_id"`
			} `json:"scope"`
		} `json:"artifacts"`
	}
	listing.decode(t, &page)
	if listing.status != 200 || len(page.Artifacts) == 0 {
		t.Fatalf("artifact directory: %d %s", listing.status, listing.body)
	}
	ref := page.Artifacts[0]
	if ref.Kind != "source.snapshot" || ref.Scope.Project != project.ID || ref.Scope.Source != "src-artifacts" || ref.Scope.Snapshot != snapshot.Snapshot.SnapshotID || ref.Bytes <= 0 {
		t.Fatalf("invalid reference: %s", listing.body)
	}
	content := doAs(t, ts, readerSecret, http.MethodGet, endpoint+"/"+ref.ID+"/content", nil, nil)
	var manifest struct {
		Files []struct {
			Path   string
			Bytes  int64
			SHA256 string `json:"sha256"`
		} `json:"files"`
	}
	content.decode(t, &manifest)
	if content.status != 200 || len(manifest.Files) != 1 || manifest.Files[0].Path != "main.go" || manifest.Files[0].Bytes != 13 || manifest.Files[0].SHA256 != "df1d036cbbf3df46e2045071e082245ece204c7f53ecf0a4e022bff9bb228f47" {
		t.Fatalf("file manifest: %d %s", content.status, content.body)
	}
}
