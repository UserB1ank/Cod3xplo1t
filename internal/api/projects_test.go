package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

type testAuditInputResponse struct {
	APIVersion string               `json:"api_version"`
	Input      storage.ProjectInput `json:"input"`
}

func readAuditInput(t *testing.T, ts *httptest.Server, projectID string) storage.ProjectInput {
	t.Helper()
	resp := do(t, ts, http.MethodGet, "/api/v1/projects/"+projectID+"/audit-input", nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("audit input: %d %s", resp.status, resp.body)
	}
	var body testAuditInputResponse
	resp.decode(t, &body)
	if body.APIVersion != "codexploit/v1" || body.Input.ProjectID != projectID {
		t.Fatalf("unexpected audit input: %s", resp.body)
	}
	return body.Input
}

func TestCreateProjectSavesOneSourceInputAndEditsDetailsWithCAS(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	root := t.TempDir()
	writeFile(t, root, "service/main.go", "package main\nfunc main() {}\n")
	ts := localSourceServer(t, env, root)

	created := do(t, ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Single source audit", "description": "one repository",
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create project: %d %s", created.status, created.body)
	}
	var project projectResponse
	created.decode(t, &project)
	if project.Project.Description != "one repository" || project.AuditInput == nil || project.AuditInput.State != storage.ProjectInputImporting {
		t.Fatalf("created project did not carry its input: %s", created.body)
	}
	input := readAuditInput(t, ts, project.Project.ID)
	if input.State != storage.ProjectInputImporting || input.SourceID != "" || input.Version != 1 {
		t.Fatalf("initial input = %+v", input)
	}

	if added := addLocalSource(t, ts, project.Project.ID, "src-single", "/repos/service"); added.status != http.StatusCreated {
		t.Fatalf("first source: %d %s", added.status, added.body)
	}
	input = readAuditInput(t, ts, project.Project.ID)
	if input.SourceID != "src-single" || input.SourceKind != "local_folder" || input.State != storage.ProjectInputImporting {
		t.Fatalf("first source did not bind the input: %+v", input)
	}
	if second := addLocalSource(t, ts, project.Project.ID, "src-second", "/repos/service"); second.status != http.StatusConflict {
		t.Fatalf("second source accepted: %d %s", second.status, second.body)
	}

	capture := do(t, ts, http.MethodPost, "/api/v1/sources/src-single/snapshots", map[string]any{
		"project_id": project.Project.ID, "source_version": 1, "skip_analysis": true,
	}, nil)
	if capture.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", capture.status, capture.body)
	}
	var snapshot snapshotResponse
	capture.decode(t, &snapshot)
	input = readAuditInput(t, ts, project.Project.ID)
	if input.State != storage.ProjectInputReady || input.SnapshotID != snapshot.Snapshot.SnapshotID || input.Files != 1 {
		t.Fatalf("ready input = %+v", input)
	}
	if third := addLocalSource(t, ts, project.Project.ID, "src-third", "/repos/service"); third.status != http.StatusConflict {
		t.Fatalf("source accepted after ready: %d %s", third.status, third.body)
	}

	patched := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]any{
		"name": "Renamed audit", "description": "edited description",
	}, map[string]string{"If-Match": created.header.Get("ETag")})
	if patched.status != http.StatusOK {
		t.Fatalf("patch: %d %s", patched.status, patched.body)
	}
	var updated storage.Project
	patched.decode(t, &updated)
	if updated.Name != "Renamed audit" || updated.Description != "edited description" || updated.Source != "" {
		t.Fatalf("edited project = %+v", updated)
	}
	stale := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]any{"name": "Stale"},
		map[string]string{"If-Match": created.header.Get("ETag")})
	if stale.status != http.StatusPreconditionFailed {
		t.Fatalf("stale patch = %d %s", stale.status, stale.body)
	}
	reader := doAs(t, ts, readerSecret, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]any{"name": "Reader"},
		map[string]string{"If-Match": patched.header.Get("ETag")})
	if reader.status != http.StatusForbidden {
		t.Fatalf("reader patch = %d %s", reader.status, reader.body)
	}
	// The source binding is not part of the editable management fields: an
	// unknown field is rejected instead of silently ignored.
	withSource := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]any{
		"name": "Moved", "source": "/repos/other",
	}, map[string]string{"If-Match": patched.header.Get("ETag")})
	if withSource.status != http.StatusBadRequest {
		t.Fatalf("source edit accepted: %d %s", withSource.status, withSource.body)
	}
}

func TestProjectDirectoryReportsRealInputState(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	legacy := createProject(t, env.ts, env.source)
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "New project",
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create: %s", created.body)
	}
	var audit projectResponse
	created.decode(t, &audit)

	resp := do(t, env.ts, http.MethodGet, "/api/v1/projects", nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("directory: %d %s", resp.status, resp.body)
	}
	var directory struct {
		Projects []struct {
			Project    storage.Project       `json:"project"`
			AuditInput *storage.ProjectInput `json:"audit_input"`
		} `json:"projects"`
	}
	resp.decode(t, &directory)
	if len(directory.Projects) != 2 {
		t.Fatalf("directory entries = %d: %s", len(directory.Projects), resp.body)
	}
	byID := map[string]*storage.ProjectInput{}
	for _, entry := range directory.Projects {
		byID[entry.Project.ID] = entry.AuditInput
	}
	if input := byID[audit.Project.ID]; input == nil || input.State != storage.ProjectInputImporting {
		t.Fatalf("new project input = %+v", input)
	}
	if input := byID[legacy.Project.ID]; input != nil {
		t.Fatalf("legacy project gained an input: %+v", input)
	}
	legacyInput := readAuditInput(t, env.ts, legacy.Project.ID)
	if legacyInput.State != storage.ProjectInputLegacy {
		t.Fatalf("legacy input state = %+v", legacyInput)
	}
}

func TestFailedImportIsRecordedAndCanBeRetried(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Retry import",
	}, nil)
	var project projectResponse
	created.decode(t, &project)
	endpoint := "/api/v1/projects/" + project.Project.ID + "/imports/src-retry?name=Retry&format=zip"
	bad := do(t, env.ts, http.MethodPost, endpoint, []byte("this is not a zip"), map[string]string{"Content-Type": "application/octet-stream"})
	if bad.status != http.StatusBadRequest {
		t.Fatalf("bad import: %d %s", bad.status, bad.body)
	}
	input := readAuditInput(t, env.ts, project.Project.ID)
	if input.State != storage.ProjectInputFailed || input.FailureCode == "" || input.SourceID != "src-retry" {
		t.Fatalf("failed input = %+v", input)
	}

	archive := zipImportFixture(t, map[string]string{"main.go": "package main\n"})
	retry := do(t, env.ts, http.MethodPost, endpoint, archive, map[string]string{"Content-Type": "application/octet-stream"})
	if retry.status != http.StatusCreated {
		t.Fatalf("retry: %d %s", retry.status, retry.body)
	}
	input = readAuditInput(t, env.ts, project.Project.ID)
	if input.State != storage.ProjectInputReady || input.FailureCode != "" || input.SnapshotID == "" {
		t.Fatalf("ready retry input = %+v", input)
	}
	// A changed payload with the same source id is still the old immutable
	// source conflict, and must not mark the ready input as failed.
	changed := zipImportFixture(t, map[string]string{"main.go": "package changed\n"})
	conflict := do(t, env.ts, http.MethodPost, endpoint, changed, map[string]string{"Content-Type": "application/octet-stream"})
	if conflict.status != http.StatusConflict {
		t.Fatalf("changed import: %d %s", conflict.status, conflict.body)
	}
	if after := readAuditInput(t, env.ts, project.Project.ID); after.State != storage.ProjectInputReady || after.SnapshotID != input.SnapshotID {
		t.Fatalf("ready input changed after conflict: %+v", after)
	}
}

func TestProjectDeletionIsWriterOnlyIdempotentAndRecoverable(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	root := t.TempDir()
	writeFile(t, root, "service/main.go", "package main\n")
	ts := localSourceServer(t, env, root)
	created := do(t, ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Delete me",
	}, nil)
	var project projectResponse
	created.decode(t, &project)
	if added := addLocalSource(t, ts, project.Project.ID, "src-delete", "/repos/service"); added.status != http.StatusCreated {
		t.Fatalf("source: %d %s", added.status, added.body)
	}
	// A live import is an active reference; the deletion must say so rather than
	// removing rows under the uploader.
	if live := do(t, ts, http.MethodDelete, "/api/v1/projects/"+project.Project.ID, nil, nil); live.status != http.StatusConflict {
		t.Fatalf("delete during import: %d %s", live.status, live.body)
	}
	if capture := do(t, ts, http.MethodPost, "/api/v1/sources/src-delete/snapshots", map[string]any{
		"project_id": project.Project.ID, "source_version": 1, "skip_analysis": true,
	}, nil); capture.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", capture.status, capture.body)
	}
	if reader := doAs(t, ts, readerSecret, http.MethodDelete, "/api/v1/projects/"+project.Project.ID, nil, nil); reader.status != http.StatusForbidden {
		t.Fatalf("reader delete: %d %s", reader.status, reader.body)
	}
	if deleted := doAs(t, ts, writerSecret, http.MethodDelete, "/api/v1/projects/"+project.Project.ID, nil, nil); deleted.status != http.StatusNoContent {
		t.Fatalf("writer delete: %d %s", deleted.status, deleted.body)
	}
	if read := do(t, ts, http.MethodGet, "/api/projects/"+project.Project.ID, nil, nil); read.status != http.StatusNotFound {
		t.Fatalf("deleted project still readable: %d %s", read.status, read.body)
	}
	if again := doAs(t, ts, writerSecret, http.MethodDelete, "/api/v1/projects/"+project.Project.ID, nil, nil); again.status != http.StatusNoContent {
		t.Fatalf("idempotent delete: %d %s", again.status, again.body)
	}
	if late := addLocalSource(t, ts, project.Project.ID, "src-late", "/repos/service"); late.status != http.StatusNotFound {
		t.Fatalf("late source: %d %s", late.status, late.body)
	}
	directory := do(t, ts, http.MethodGet, "/api/v1/projects", nil, nil)
	var body struct {
		Projects []struct {
			Project storage.Project `json:"project"`
		} `json:"projects"`
	}
	directory.decode(t, &body)
	for _, entry := range body.Projects {
		if entry.Project.ID == project.Project.ID {
			t.Fatalf("deleted project remains in the directory: %s", directory.body)
		}
	}
}

func TestLegacyProjectInputsRemainCompatibleAndDeletable(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	legacy := createProject(t, env.ts, env.source)
	root := t.TempDir()
	writeFile(t, root, "service/main.go", "package main\n")
	ts := localSourceServer(t, env, root)
	for _, id := range []string{"src-legacy-one", "src-legacy-two"} {
		if added := addLocalSource(t, ts, legacy.Project.ID, id, "/repos/service"); added.status != http.StatusCreated {
			t.Fatalf("legacy source %s: %d %s", id, added.status, added.body)
		}
	}
	if deleted := doAs(t, ts, writerSecret, http.MethodDelete, "/api/v1/projects/"+legacy.Project.ID, nil, nil); deleted.status != http.StatusNoContent {
		t.Fatalf("legacy delete: %d %s", deleted.status, deleted.body)
	}
}

func TestProjectDeletionSurvivesRestart(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Restart delete",
	}, nil)
	var project projectResponse
	created.decode(t, &project)
	archive := zipImportFixture(t, map[string]string{"main.go": "package main\n"})
	endpoint := "/api/v1/projects/" + project.Project.ID + "/imports/src-restart?name=Restart&format=zip"
	if imported := do(t, env.ts, http.MethodPost, endpoint, archive, map[string]string{"Content-Type": "application/octet-stream"}); imported.status != http.StatusCreated {
		t.Fatalf("import: %d %s", imported.status, imported.body)
	}
	if deleted := doAs(t, env.ts, writerSecret, http.MethodDelete, "/api/v1/projects/"+project.Project.ID, nil, nil); deleted.status != http.StatusNoContent {
		t.Fatalf("delete: %d %s", deleted.status, deleted.body)
	}
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env = serveTestEnv(t, runtime, false)
	if read := do(t, env.ts, http.MethodGet, "/api/projects/"+project.Project.ID, nil, nil); read.status != http.StatusNotFound {
		t.Fatalf("deleted project reappeared after restart: %d %s", read.status, read.body)
	}
	if again := doAs(t, env.ts, writerSecret, http.MethodDelete, "/api/v1/projects/"+project.Project.ID, nil, nil); again.status != http.StatusNoContent {
		t.Fatalf("restart delete replay: %d %s", again.status, again.body)
	}
	var raw map[string]json.RawMessage
	if read := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project.Project.ID+"/audit-input", nil, nil); read.status != http.StatusNotFound {
		read.decode(t, &raw)
		t.Fatalf("deleted project input still readable: %d %s", read.status, read.body)
	}
}

func TestProjectCreateIsIdempotentAndDirectoryIsReadableByReader(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	headers := map[string]string{"Idempotency-Key": "project-create-fixture-key"}
	first := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Idempotent project", "description": "same request",
	}, headers)
	if first.status != http.StatusCreated {
		t.Fatalf("first create: %d %s", first.status, first.body)
	}
	second := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Idempotent project", "description": "same request",
	}, headers)
	if second.status != http.StatusCreated || second.header.Get("Idempotent-Replay") != "true" {
		t.Fatalf("replay: %d %v %s", second.status, second.header, second.body)
	}
	var a, b projectResponse
	first.decode(t, &a)
	second.decode(t, &b)
	if a.Project.ID != b.Project.ID {
		t.Fatalf("idempotent create produced two projects: %s / %s", a.Project.ID, b.Project.ID)
	}
	// Different body with the same key is a client error, not a second project.
	conflict := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{
		"api_version": "codexploit/v1", "name": "Different body",
	}, headers)
	if conflict.status != http.StatusConflict {
		t.Fatalf("key reuse = %d %s", conflict.status, conflict.body)
	}
	if reader := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects", nil, nil); reader.status != http.StatusOK {
		t.Fatalf("reader directory = %d %s", reader.status, reader.body)
	}
	if anon := doAs(t, env.ts, "", http.MethodGet, "/api/v1/projects", nil, nil); anon.status != http.StatusUnauthorized {
		t.Fatalf("anonymous directory = %d %s", anon.status, anon.body)
	}
}

func TestProjectDeletionLeavesOtherProjectsIntact(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	create := func(name string) projectResponse {
		resp := do(t, env.ts, http.MethodPost, "/api/v1/projects", map[string]any{
			"api_version": "codexploit/v1", "name": name,
		}, nil)
		if resp.status != http.StatusCreated {
			t.Fatalf("create %s: %d %s", name, resp.status, resp.body)
		}
		var project projectResponse
		resp.decode(t, &project)
		archive := zipImportFixture(t, map[string]string{"main.go": "package main\n"})
		endpoint := "/api/v1/projects/" + project.Project.ID + "/imports/src-" + name + "?name=" + name + "&format=zip"
		if imported := do(t, env.ts, http.MethodPost, endpoint, archive, map[string]string{"Content-Type": "application/octet-stream"}); imported.status != http.StatusCreated {
			t.Fatalf("import %s: %d %s", name, imported.status, imported.body)
		}
		return project
	}
	first, second := create("first"), create("second")
	if deleted := doAs(t, env.ts, writerSecret, http.MethodDelete, "/api/v1/projects/"+first.Project.ID, nil, nil); deleted.status != http.StatusNoContent {
		t.Fatalf("delete first: %d %s", deleted.status, deleted.body)
	}
	if read := do(t, env.ts, http.MethodGet, "/api/projects/"+second.Project.ID, nil, nil); read.status != http.StatusOK {
		t.Fatalf("second project removed: %d %s", read.status, read.body)
	}
	if input := readAuditInput(t, env.ts, second.Project.ID); input.State != storage.ProjectInputReady {
		t.Fatalf("second input changed: %+v", input)
	}
}
