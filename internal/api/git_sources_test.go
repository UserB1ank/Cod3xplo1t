package api

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/testgit"
)

func TestGitSourceDefinitionCanBeRegisteredAndRead(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	endpoint := "/api/v1/projects/" + project.ID + "/sources"
	created := do(t, env.ts, http.MethodPost, endpoint, map[string]any{
		"api_version": "codexploit/v1", "id": "src-git", "project_id": project.ID,
		"name": "Git service", "kind": "git_repository", "location": "https://forge.example.invalid/team/service.git", "ref": "main",
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("register Git source: %d %s", created.status, created.body)
	}
	listed := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
	var body struct {
		Sources []struct {
			Kind, Ref string
		} `json:"sources"`
	}
	listed.decode(t, &body)
	if listed.status != 200 || len(body.Sources) != 1 || body.Sources[0].Kind != "git_repository" || body.Sources[0].Ref != "main" {
		t.Fatalf("Git definition not readable: %d %s", listed.status, listed.body)
	}
}

func TestGitSourceDefinitionRejectsInvalidLocationsAndUnknownCredentials(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source).Project
	for _, location := range []string{"https://forge.example.invalid:bad/service.git", "https://forge.example.invalid/service.git\n", "https://user:fixture@forge.example.invalid/service.git"} {
		r := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/sources", map[string]any{
			"api_version": "codexploit/v1", "id": "src-invalid", "project_id": project.ID,
			"name": "Invalid Git", "kind": "git_repository", "location": location, "ref": "main",
		}, nil)
		if r.status != 400 {
			t.Fatalf("invalid URL accepted: %d %s", r.status, r.body)
		}
	}
	r := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/sources", map[string]any{
		"api_version": "codexploit/v1", "id": "src-private", "project_id": project.ID,
		"name": "Private Git", "kind": "git_repository", "location": "https://forge.example.invalid/service.git", "ref": "main", "credential_ref": "missing-reference",
	}, nil)
	var failure struct {
		Code string `json:"code"`
	}
	r.decode(t, &failure)
	if r.status != 400 || failure.Code != "credential_unavailable" {
		t.Fatalf("unknown credential not classified: %d %s", r.status, r.body)
	}
}

func TestGitCaptureFailuresHaveSafeDistinctPublicErrors(t *testing.T) {
	t.Parallel()
	public := testgit.New(t, "")
	public.Commit(t, "package main\n")
	private := testgit.New(t, "Bearer synthetic-private-fixture")
	private.Commit(t, "package main\n")
	for _, tc := range []struct {
		name, location, ref, code string
		network                   bool
		status                    int
	}{
		{"network", public.URL, "main", "network_disabled", false, 403},
		{"revision", public.URL, "absent-commit", "git_revision_not_found", true, 404},
		{"access", private.URL, "main", "git_access_denied", true, 403},
		{"fetch", public.URL + "/missing", "main", "git_fetch_failed", true, 503},
	} {
		t.Run(tc.name, func(t *testing.T) {
			env := newTestEnv(t, tc.network)
			env.rt.Manager.GitCAFile = public.CAFile
			project := createProject(t, env.ts, env.source).Project
			created := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/sources", map[string]any{
				"api_version": "codexploit/v1", "id": "src-git", "project_id": project.ID, "name": "Git service", "kind": "git_repository", "location": tc.location, "ref": tc.ref,
			}, nil)
			if created.status != 201 {
				t.Fatalf("source: %d %s", created.status, created.body)
			}
			r := do(t, env.ts, http.MethodPost, "/api/v1/sources/src-git/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "skip_analysis": true}, nil)
			var failure struct {
				Code string `json:"code"`
			}
			r.decode(t, &failure)
			if r.status != tc.status || failure.Code != tc.code {
				t.Fatalf("failure not classified: %d %s", r.status, r.body)
			}
			if strings.Contains(string(r.body), public.Dir) || strings.Contains(string(r.body), "synthetic-private-fixture") {
				t.Fatalf("private diagnostics leaked: %s", r.body)
			}
		})
	}
}

func TestGitSourceTaskRemainsPinnedWhenRemoteBranchMoves(t *testing.T) {
	t.Parallel()
	remote := testgit.New(t, "")
	firstCommit := remote.Commit(t, "package main\nimport \"net/http\"\nfunc handler(w http.ResponseWriter, r *http.Request) { w.Write([]byte(r.URL.Path)) }\nfunc main() { http.HandleFunc(\"/echo\", handler) }\n")
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "store.db"), AllowNetwork: true, GitCAFile: remote.CAFile}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, true)
	project := createProject(t, env.ts, env.source).Project
	created := do(t, env.ts, http.MethodPost, "/api/v1/projects/"+project.ID+"/sources", map[string]any{
		"api_version": "codexploit/v1", "id": "src-remote", "project_id": project.ID,
		"name": "Remote service", "kind": "git_repository", "location": remote.URL, "ref": "main",
	}, nil)
	if created.status != 201 {
		t.Fatalf("source: %d %s", created.status, created.body)
	}
	capture := func() string {
		r := do(t, env.ts, http.MethodPost, "/api/v1/sources/src-remote/snapshots", map[string]any{"project_id": project.ID, "source_version": 1, "build_graph": true, "build_asg": true}, nil)
		if r.status != 201 {
			t.Fatalf("capture: %d %s", r.status, r.body)
		}
		var body struct {
			Snapshot struct {
				ID     string `json:"snapshot_id"`
				Commit string `json:"commit"`
				Ref    string `json:"requested_ref"`
			} `json:"snapshot"`
		}
		r.decode(t, &body)
		if body.Snapshot.Ref != "main" {
			t.Fatalf("requested ref lost: %s", r.body)
		}
		return body.Snapshot.ID
	}
	original := capture()
	taskResponse := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/tasks", map[string]any{"name": "Pinned Git task", "objective": "Review HTTP paths", "source_id": "src-remote", "snapshot_id": original}, nil)
	if taskResponse.status != 201 {
		t.Fatalf("task: %d %s", taskResponse.status, taskResponse.body)
	}
	var task struct {
		Task struct {
			ID string `json:"audit_id"`
		} `json:"task"`
	}
	taskResponse.decode(t, &task)
	remote.Commit(t, "package main\nfunc main() {}\n")
	if capture() == original {
		t.Fatal("branch move reused the old snapshot")
	}
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	reopened := serveTestEnv(t, runtime, true)
	read := do(t, reopened.ts, http.MethodGet, "/api/tasks/"+task.Task.ID, nil, nil)
	var pinned struct {
		Snapshot string `json:"snapshot_id"`
		Source   string `json:"source_id"`
	}
	read.decode(t, &pinned)
	if read.status != 200 || pinned.Snapshot != original || pinned.Source != "src-remote" {
		t.Fatalf("task binding changed: %d %s", read.status, read.body)
	}
	read = do(t, reopened.ts, http.MethodGet, "/api/snapshots/"+original, nil, nil)
	var details struct {
		Snapshot struct {
			Commit string `json:"commit"`
		} `json:"snapshot"`
	}
	read.decode(t, &details)
	if read.status != 200 || details.Snapshot.Commit != firstCommit {
		t.Fatalf("original commit changed: %d %s", read.status, read.body)
	}
}
