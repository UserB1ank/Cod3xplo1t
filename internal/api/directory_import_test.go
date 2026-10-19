package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"mime/multipart"
	"os"
	"path/filepath"
	"testing"
)

func TestDirectoryImportPersistsAcrossRuntimeRebuild(t *testing.T) {
	workspace := t.TempDir()
	testImportPersistence(t, app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "catalog.db")}, true, true)
}

func TestPostgresDirectoryImportPersistsAcrossRuntimeRebuild(t *testing.T) {
	testImportPersistence(t, postgresConfig(t), true, true)
}

func directoryBody(t *testing.T, files map[string]string) ([]byte, string) {
	t.Helper()
	var body bytes.Buffer
	w := multipart.NewWriter(&body)
	entries := []map[string]any{}
	for name, code := range files {
		entries = append(entries, map[string]any{"path": name, "size": len(code), "sha256": fmt.Sprintf("%x", sha256.Sum256([]byte(code)))})
	}
	manifest, _ := json.Marshal(map[string]any{"files": entries, "excluded": []string{}})
	part, err := w.CreateFormField("manifest")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := part.Write(manifest); err != nil {
		t.Fatal(err)
	}
	for name, code := range files {
		part, err := w.CreateFormFile("files", name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := part.Write([]byte(code)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return body.Bytes(), w.FormDataContentType()
}

func TestDirectoryImportRejectsChangedMissingExtraAndUnsafeFiles(t *testing.T) {
	for _, mode := range []string{"changed", "missing", "extra", "traversal", "case-conflict", "file-directory-conflict", "over-budget"} {
		t.Run(mode, func(t *testing.T) {
			env := newTestEnv(t, false)
			project := createProject(t, env.ts, env.source).Project
			files := map[string]string{"main.go": "package main\n"}
			switch mode {
			case "traversal":
				files["../escape.go"] = "invalid"
			case "case-conflict":
				files["MAIN.go"] = "invalid"
			case "file-directory-conflict":
				files["main.go/child.go"] = "invalid"
			case "over-budget":
				files["huge.go"] = string(bytes.Repeat([]byte("x"), (4<<20)+1))
			}
			body, contentType := directoryBody(t, files)
			switch mode {
			case "changed":
				body = bytes.Replace(body, []byte("package main\n"), []byte("package vary\n"), 1)
			case "missing":
				boundary := bytes.Index(body, []byte("Content-Disposition: form-data; name=\"files\""))
				body = body[:boundary]
			case "extra":
				body = bytes.Replace(body, []byte("filename=\"main.go\""), []byte("filename=\"extra.go\""), 1)
			}
			result := do(t, env.ts, "POST", "/api/v1/projects/"+project.ID+"/imports/src-invalid?name=Invalid&format=directory", body, map[string]string{"Content-Type": contentType})
			want := 400
			if mode == "over-budget" {
				want = 413
			}
			if result.status != want {
				t.Fatalf("%s accepted: %d %s", mode, result.status, result.body)
			}
			snapshots, err := env.rt.Store.ListSnapshots(t.Context(), project.ID)
			if err != nil || len(snapshots) != 0 {
				t.Fatalf("failed import published snapshot: %v %v", snapshots, err)
			}
		})
	}
}

func TestDirectoryImportPreservesRelativePathsAndIdempotence(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	endpoint := "/api/v1/projects/" + project.ID + "/imports/src-directory?name=Directory&format=directory&build_graph=true"
	files := map[string]string{"internal/服务 main.go": "package service\nfunc Serve() {}\n"}
	body, contentType := directoryBody(t, files)
	result := do(t, env.ts, "POST", endpoint, body, map[string]string{"Content-Type": contentType})
	if result.status != 201 {
		t.Fatalf("directory: %d %s", result.status, result.body)
	}
	var snapshot snapshotResponse
	result.decode(t, &snapshot)
	if snapshot.Snapshot.Files != 1 {
		t.Fatalf("files: %s", result.body)
	}
	body, contentType = directoryBody(t, files) // a fresh multipart boundary must still replay
	replay := do(t, env.ts, "POST", endpoint, body, map[string]string{"Content-Type": contentType})
	if replay.status != 201 {
		t.Fatalf("replay: %d %s", replay.status, replay.body)
	}
	var repeated snapshotResponse
	replay.decode(t, &repeated)
	if repeated.Snapshot.SnapshotID != snapshot.Snapshot.SnapshotID {
		t.Fatal("replay changed fixed input")
	}
	snap, err := env.rt.Manager.Load(snapshot.Snapshot.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	if content, err := os.ReadFile(filepath.Join(snap.TreeDir(), "internal", "服务 main.go")); err != nil || string(content) != files["internal/服务 main.go"] {
		t.Fatalf("relative path lost: %q %v", content, err)
	}
}
