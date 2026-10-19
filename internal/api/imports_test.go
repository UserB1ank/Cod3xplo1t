package api

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"io/fs"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
)

func zipImportFixture(t *testing.T, files map[string]string) []byte {
	t.Helper()
	var output bytes.Buffer
	writer := zip.NewWriter(&output)
	for name, content := range files {
		entry, err := writer.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := entry.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return output.Bytes()
}

func TestArchiveImportScopesExclusionsAndIdempotentPersistence(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			config := app.Config{Workspace: t.TempDir(), DBPath: "memory"}
			if backend == "sqlite" {
				config.DBPath = filepath.Join(config.Workspace, "catalog.db")
			}
			testImportPersistence(t, config, backend == "sqlite")
		})
	}
}

func TestPostgresArchiveImportPersistsAcrossRuntimeRebuild(t *testing.T) {
	testImportPersistence(t, postgresConfig(t), true)
}

func testImportPersistence(t *testing.T, config app.Config, rebuild bool, directory ...bool) {
	rt, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	var created projectResponse
	do(t, env.ts, "POST", "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "Persistent upload"}, nil).decode(t, &created)
	project := created.Project
	fixtureFiles := map[string]string{"code/main.go": "package main\nfunc main() {}\n", "code/.env": "SYNTHETIC_ONLY=1\n", "code/.git/config": "synthetic test metadata", "code/node_modules/noise.js": "fixture"}
	archive := zipImportFixture(t, fixtureFiles)
	contentType := "application/octet-stream"
	format := "zip"
	if len(directory) > 0 && directory[0] {
		archive, contentType = directoryBody(t, fixtureFiles)
		format = "directory"
	}
	headers := map[string]string{"Content-Type": contentType}
	endpoint := "/api/v1/projects/" + project.ID + "/imports/src-persistent?name=Upload&format=" + format
	if result := doAs(t, env.ts, readerSecret, "POST", endpoint, archive, headers); result.status != 403 {
		t.Fatalf("reader upload: %d", result.status)
	}
	if result := doAs(t, env.ts, "", "POST", endpoint, archive, headers); result.status != 401 {
		t.Fatalf("anonymous upload: %d", result.status)
	}
	result := do(t, env.ts, "POST", endpoint, archive, headers)
	if result.status != 201 {
		t.Fatalf("upload: %d %s", result.status, result.body)
	}
	var initial snapshotResponse
	result.decode(t, &initial)
	if initial.Snapshot.Files != 1 {
		t.Fatalf("excluded files entered snapshot: %s", result.body)
	}
	if replay := do(t, env.ts, "POST", endpoint, archive, headers); replay.status != 201 {
		t.Fatalf("replay: %d %s", replay.status, replay.body)
	}
	changed := zipImportFixture(t, map[string]string{"main.go": "package changed\n"})
	changedType := "application/octet-stream"
	if format == "directory" {
		changed, changedType = directoryBody(t, map[string]string{"main.go": "package changed\n"})
	}
	if conflict := do(t, env.ts, "POST", endpoint, changed, map[string]string{"Content-Type": changedType}); conflict.status != 409 {
		t.Fatalf("changed immutable upload: %d %s", conflict.status, conflict.body)
	}
	var other projectResponse
	do(t, env.ts, "POST", "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "Other scope"}, nil).decode(t, &other)
	if cross := do(t, env.ts, "POST", "/api/v1/projects/"+other.Project.ID+"/imports/src-persistent?name=Cross&format="+format, archive, headers); cross.status != 409 {
		t.Fatalf("cross-project source takeover: %d %s", cross.status, cross.body)
	}
	if rebuild {
		env.ts.Close()
		if err := rt.Close(); err != nil {
			t.Fatal(err)
		}
		rt, err = app.Build(context.Background(), config)
		if err != nil {
			t.Fatal(err)
		}
		env = serveTestEnv(t, rt, false)
	}
	listing := do(t, env.ts, "GET", "/api/v1/projects/"+project.ID+"/sources", nil, nil)
	var sources struct {
		Sources []struct {
			Snapshot string `json:"snapshot"`
			Import   struct {
				Skipped int `json:"skipped"`
			} `json:"import"`
		} `json:"sources"`
	}
	listing.decode(t, &sources)
	if len(sources.Sources) != 1 || sources.Sources[0].Snapshot != initial.Snapshot.SnapshotID || sources.Sources[0].Import.Skipped != 3 {
		t.Fatalf("import ledger not durable: %s", listing.body)
	}
	artifacts := do(t, env.ts, "GET", "/api/v1/projects/"+project.ID+"/snapshots/"+initial.Snapshot.SnapshotID+"/artifacts", nil, nil)
	if artifacts.status != 200 {
		t.Fatalf("imported artifacts after rebuild: %d %s", artifacts.status, artifacts.body)
	}
}

func TestEncryptedOrUnsafeZipNeverPublishes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		mode  fs.FileMode
		flags uint16
	}{
		{"main.go", 0644, 1}, {"../escape.go", 0644, 0}, {"/absolute.go", 0644, 0},
		{"C:/drive.go", 0644, 0}, {"folder\\escape.go", 0644, 0}, {"link.go", fs.ModeSymlink | 0777, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, false)
			project := createProject(t, env.ts, env.source).Project
			var content bytes.Buffer
			writer := zip.NewWriter(&content)
			header := &zip.FileHeader{Name: tc.name, Flags: tc.flags, Method: zip.Store}
			header.SetMode(tc.mode)
			entry, err := writer.CreateHeader(header)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := entry.Write([]byte("package main\n")); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			result := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/imports/src-unsafe?name=Unsafe&format=zip", content.Bytes(), nil)
			if result.status != 400 {
				t.Fatalf("unsafe zip accepted: %d %s", result.status, result.body)
			}
			listing := do(t, env.ts, http.MethodGet, "/api/snapshots?project_id="+project.ID, nil, nil)
			var page struct {
				Snapshots []any `json:"snapshots"`
			}
			listing.decode(t, &page)
			if len(page.Snapshots) != 0 {
				t.Fatalf("unsafe zip published metadata: %s", listing.body)
			}
		})
	}
}

func TestTarImportSupportsPlainAndGzipArchives(t *testing.T) {
	for _, format := range []string{"tar", "tar.gz"} {
		t.Run(format, func(t *testing.T) {
			env := newTestEnv(t, false)
			project := createProject(t, env.ts, env.source).Project
			var content bytes.Buffer
			writer := tar.NewWriter(&content)
			code := "package main\nfunc main() {}\n"
			if err := writer.WriteHeader(&tar.Header{Name: "main.go", Mode: 0644, Size: int64(len(code))}); err != nil {
				t.Fatal(err)
			}
			if _, err := writer.Write([]byte(code)); err != nil {
				t.Fatal(err)
			}
			if err := writer.Close(); err != nil {
				t.Fatal(err)
			}
			archive := content.Bytes()
			if format == "tar.gz" {
				var compressed bytes.Buffer
				gz := gzip.NewWriter(&compressed)
				if _, err := gz.Write(archive); err != nil {
					t.Fatal(err)
				}
				if err := gz.Close(); err != nil {
					t.Fatal(err)
				}
				archive = compressed.Bytes()
			}
			result := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/imports/src-tar?name=Tar&format="+format, archive, map[string]string{"Content-Type": "application/octet-stream"})
			if result.status != 201 {
				t.Fatalf("import %s: %d %s", format, result.status, result.body)
			}
			var snapshot snapshotResponse
			result.decode(t, &snapshot)
			if snapshot.Snapshot.Files != 1 {
				t.Fatalf("archive files: %s", result.body)
			}
		})
	}
}

func TestTruncatedTarDoesNotPublishASnapshot(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	var content bytes.Buffer
	writer := tar.NewWriter(&content)
	code := "package main\n"
	if err := writer.WriteHeader(&tar.Header{Name: "main.go", Mode: 0644, Size: int64(len(code))}); err != nil {
		t.Fatal(err)
	}
	if _, err := writer.Write([]byte(code)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	truncated := content.Bytes()[:content.Len()-1024]
	result := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/imports/src-truncated?name=Broken&format=tar", truncated, nil)
	if result.status != 400 {
		t.Fatalf("truncated tar accepted: %d %s", result.status, result.body)
	}
	listing := do(t, env.ts, http.MethodGet, "/api/snapshots?project_id="+project.ID, nil, nil)
	var page struct {
		Snapshots []any `json:"snapshots"`
	}
	listing.decode(t, &page)
	if len(page.Snapshots) != 0 {
		t.Fatalf("failed upload published a snapshot: %s", listing.body)
	}
}

func TestArchiveImportCreatesRealSourceSnapshotAndGraph(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{"api_version": "codexploit/v1", "name": "Uploaded project"}, nil)
	var project projectResponse
	created.decode(t, &project)
	archive := zipImportFixture(t, map[string]string{
		"service/go.mod":  "module example.invalid/upload\n\ngo 1.24\n",
		"service/main.go": "package main\nfunc main() { serve() }\nfunc serve() {}\n",
	})
	result := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.Project.ID+"/imports/src-upload?format=zip&name=Uploaded&build_graph=true", archive, map[string]string{"Content-Type": "application/zip"})
	if result.status != http.StatusCreated {
		t.Fatalf("import: %d %s", result.status, result.body)
	}
	var snapshot snapshotResponse
	result.decode(t, &snapshot)
	if snapshot.Snapshot.Files != 2 || snapshot.Snapshot.SourceID != "src-upload" {
		t.Fatalf("import did not publish the real source snapshot: %s", result.body)
	}
	graph := do(t, env.ts, http.MethodGet, "/api/snapshots/"+snapshot.Snapshot.SnapshotID+"/graph", nil, nil)
	if graph.status != http.StatusOK {
		t.Fatalf("imported source graph: %d %s", graph.status, graph.body)
	}
	listing := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project.Project.ID+"/sources", nil, nil)
	var sources struct {
		Sources []struct {
			Kind string `json:"kind"`
		} `json:"sources"`
	}
	listing.decode(t, &sources)
	if listing.status != http.StatusOK || len(sources.Sources) != 1 || sources.Sources[0].Kind != "uploaded_archive" {
		t.Fatalf("uploaded source not persisted: %d %s", listing.status, listing.body)
	}
	raw, err := contracts.Files.ReadFile("source.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var contract jsonschema.Schema
	if err := json.Unmarshal(raw, &contract); err != nil {
		t.Fatal(err)
	}
	schema, err := contract.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	var document struct {
		Sources []any `json:"sources"`
	}
	listing.decode(t, &document)
	if err := schema.Validate(document.Sources[0]); err != nil {
		t.Fatalf("published source violates its public schema: %v", err)
	}
}
