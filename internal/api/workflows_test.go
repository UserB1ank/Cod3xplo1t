package api

import (
	"context"
	"encoding/json"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
	"net/http"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

func workflowSpecFixture() map[string]any {
	return map[string]any{"api_version": "codexploit/v1", "id": "workflow-discovery", "version": "1.0.0", "name": "Discovery workflow", "description": "Synthetic workflow fixture", "inputs": []string{"source.snapshot"}, "nodes": []any{map[string]any{"id": "parse", "plugin_id": plugin.BuiltinID, "plugin_version": plugin.BuiltinVersion, "needs": []string{}, "config": map[string]any{}, "timeout_seconds": 60}}}
}

func TestWorkflowVersionCanBeSavedExportedAndReadAfterRestart(t *testing.T) {
	workspace := t.TempDir()
	cfg := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	project := createProject(t, env.ts, env.source).Project
	endpoint := "/api/v1/projects/" + project.ID + "/workflows"
	spec := workflowSpecFixture()
	response := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": spec, "expected_head": ""}, nil)
	if response.status != 201 {
		t.Fatalf("save: %d %s", response.status, response.body)
	}
	var saved struct {
		Workflow struct {
			Digest string          `json:"digest"`
			Spec   json.RawMessage `json:"spec"`
		} `json:"workflow"`
	}
	response.decode(t, &saved)
	if len(saved.Workflow.Digest) != 64 {
		t.Fatalf("missing immutable digest: %s", response.body)
	}
	path := endpoint + "/workflow-discovery/versions/1.0.0"
	exported := doAs(t, env.ts, readerSecret, http.MethodGet, path+"/export", nil, nil)
	if exported.status != 200 {
		t.Fatalf("export: %d %s", exported.status, exported.body)
	}
	var copy map[string]any
	exported.decode(t, &copy)
	if copy["version"] != "1.0.0" || copy["id"] != "workflow-discovery" {
		t.Fatalf("wrong exported definition: %s", exported.body)
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
	read := doAs(t, env.ts, readerSecret, http.MethodGet, path, nil, nil)
	var restored struct {
		Workflow struct {
			Digest string          `json:"digest"`
			Spec   json.RawMessage `json:"spec"`
		} `json:"workflow"`
	}
	read.decode(t, &restored)
	if read.status != 200 || restored.Workflow.Digest != saved.Workflow.Digest || string(restored.Workflow.Spec) != string(saved.Workflow.Spec) {
		t.Fatalf("restart changed version: %d %s", read.status, read.body)
	}
}

func TestWorkflowVersionsRejectStaleHeadsInvalidDefinitionsAndCrossProjectReads(t *testing.T) {
	for _, database := range []string{"memory", "sqlite"} {
		t.Run(database, func(t *testing.T) {
			workspace := t.TempDir()
			db := "memory"
			if database == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			rt, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, rt, false)
			p := createProject(t, env.ts, env.source).Project
			endpoint := "/api/v1/projects/" + p.ID + "/workflows"
			save := func(spec map[string]any, head string) response {
				return do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": spec, "expected_head": head}, nil)
			}
			spec := workflowSpecFixture()
			initial := save(spec, "")
			var receipt struct {
				Workflow struct {
					Digest string `json:"digest"`
				} `json:"workflow"`
			}
			initial.decode(t, &receipt)
			spec["version"] = "1.1.0"
			if r := save(spec, "stale"); r.status != 409 {
				t.Fatalf("stale head: %d %s", r.status, r.body)
			}
			next := save(spec, receipt.Workflow.Digest)
			if next.status != 201 {
				t.Fatalf("new version: %d %s", next.status, next.body)
			}
			var latest struct {
				Workflow struct {
					Digest string `json:"digest"`
				} `json:"workflow"`
			}
			next.decode(t, &latest)
			old := workflowSpecFixture()
			old["name"] = "Changed immutable version"
			if r := save(old, receipt.Workflow.Digest); r.status != 409 {
				t.Fatalf("changed old version: %d %s", r.status, r.body)
			}
			if r := save(workflowSpecFixture(), ""); r.status != 201 {
				t.Fatalf("idempotent retry: %d %s", r.status, r.body)
			}
			malformed := workflowSpecFixture()
			malformed["unexpected"] = true
			if r := save(malformed, ""); r.status != 400 {
				t.Fatalf("schema: %d %s", r.status, r.body)
			}
			if r := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": spec}, nil); r.status != 403 {
				t.Fatalf("reader wrote: %d", r.status)
			}
			if r := doAs(t, env.ts, "", http.MethodGet, endpoint+"/workflow-discovery/versions/1.0.0", nil, nil); r.status != 401 {
				t.Fatalf("anonymous read: %d", r.status)
			}
			if r := do(t, env.ts, http.MethodGet, "/api/v1/projects/another-project/workflows/workflow-discovery/versions/1.0.0", nil, nil); r.status != 404 {
				t.Fatalf("scope escape: %d", r.status)
			}
			spec["version"] = "0.9.0"
			if r := save(spec, latest.Workflow.Digest); r.status != 409 {
				t.Fatalf("non advancing version: %d %s", r.status, r.body)
			}
		})
	}
}

func TestWorkflowCompilesFixedSnapshotPlanWithoutExecutingPlugins(t *testing.T) {
	workspace := t.TempDir()
	cfg := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	p := createProject(t, env.ts, env.source).Project
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+p.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	var snap snapshotResponse
	captured.decode(t, &snap)
	artifactsPath := "/api/v1/projects/" + p.ID + "/snapshots/" + snap.Snapshot.SnapshotID + "/artifacts"
	registered := do(t, env.ts, http.MethodPost, artifactsPath, nil, nil)
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
	if input.ID == "" {
		t.Fatalf("missing source input: %s", registered.body)
	}
	endpoint := "/api/v1/projects/" + p.ID + "/workflows"
	saved := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": workflowSpecFixture(), "expected_head": ""}, nil)
	if saved.status != 201 {
		t.Fatalf("save: %s", saved.body)
	}
	compiledPath := endpoint + "/workflow-discovery/versions/1.0.0/compile"
	request := map[string]any{"api_version": "codexploit/v1", "snapshot_id": input.Scope.SnapshotID, "inputs": []string{input.ID}, "language": "Go", "knowledge_revision": "rev-0"}
	denied := doAs(t, env.ts, readerSecret, http.MethodPost, compiledPath, request, nil)
	if denied.status != 403 {
		t.Fatalf("reader compiled: %d", denied.status)
	}
	compiled := do(t, env.ts, http.MethodPost, compiledPath, request, nil)
	if compiled.status != 201 {
		t.Fatalf("compile: %d %s", compiled.status, compiled.body)
	}
	var receipt struct {
		Plan workflow.Plan `json:"plan"`
	}
	compiled.decode(t, &receipt)
	plan := receipt.Plan
	if len(plan.Digest) != 64 || len(plan.Nodes) != 1 || plan.Inputs[0] != input || plan.Nodes[0].Inputs[0].From != "root" || plan.Workflow.Spec.Version != "1.0.0" || plan.Knowledge.Revision != "rev-0" {
		t.Fatalf("unpinned plan: %s", compiled.body)
	}
	planPath := "/api/v1/projects/" + p.ID + "/workflow-plans/" + plan.ID
	for _, ref := range directory.Artifacts {
		if ref.Kind == "source.snapshot" && ref.SchemaID != "codexploit/source-tar/v1" {
			wrong := map[string]any{"api_version": "codexploit/v1", "snapshot_id": input.Scope.SnapshotID, "inputs": []string{ref.ID}, "language": "Go"}
			if r := do(t, env.ts, http.MethodPost, compiledPath, wrong, nil); r.status != 422 {
				t.Fatalf("wrong source schema: %d %s", r.status, r.body)
			}
		}
	}
	invalid := map[string]any{"api_version": "codexploit/v1", "snapshot_id": input.Scope.SnapshotID, "inputs": []string{input.ID, input.ID}, "language": "Go"}
	if r := do(t, env.ts, http.MethodPost, compiledPath, invalid, nil); r.status != 422 {
		t.Fatalf("ambiguous roots: %d %s", r.status, r.body)
	}
	for _, tc := range []struct {
		field string
		value any
	}{{"language", "Rust"}, {"max_input_bytes", int64(1)}, {"max_input_bytes", int64(-1)}, {"knowledge_revision", "rev-999"}, {"inputs", []string{"missing-artifact"}}} {
		bad := map[string]any{}
		for k, v := range request {
			bad[k] = v
		}
		bad[tc.field] = tc.value
		if r := do(t, env.ts, http.MethodPost, compiledPath, bad, nil); r.status != 422 {
			t.Fatalf("invalid %s: %d %s", tc.field, r.status, r.body)
		}
	}
	pub := publication.NewPublisher(rt.Store.(publication.Store))
	revision, err := pub.Publish(context.Background(), publication.Batch{ID: "batch-workflow", Scope: publication.Scope{ProjectID: p.ID, SnapshotID: input.Scope.SnapshotID}, BaseRevision: "rev-0", Producer: artifact.Producer{PluginID: "fixture.publisher", PluginVersion: "1.0.0", InvocationID: "fixture-invocation", ConfigDigest: strings.Repeat("a", 64)}})
	if err != nil {
		t.Fatal(err)
	}
	latestRequest := map[string]any{}
	for k, v := range request {
		latestRequest[k] = v
	}
	latestRequest["knowledge_revision"] = "latest"
	latestCompiled := do(t, env.ts, http.MethodPost, compiledPath, latestRequest, nil)
	var latestPlan struct {
		Plan workflow.Plan `json:"plan"`
	}
	latestCompiled.decode(t, &latestPlan)
	if latestCompiled.status != 201 || latestPlan.Plan.Knowledge.Revision != revision.ID || latestPlan.Plan.Knowledge.Digest != revision.Digest || latestPlan.Plan.ID == plan.ID {
		t.Fatalf("latest resolution: %d %s", latestCompiled.status, latestCompiled.body)
	}
	spec := workflowSpecFixture()
	spec["version"] = "1.1.0"
	spec["name"] = "New template"
	if r := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": spec, "expected_head": plan.Workflow.Digest}, nil); r.status != 201 {
		t.Fatalf("edit: %s", r.body)
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
	read := doAs(t, env.ts, readerSecret, http.MethodGet, planPath, nil, nil)
	var restored struct {
		Plan workflow.Plan `json:"plan"`
	}
	read.decode(t, &restored)
	if read.status != 200 || !reflect.DeepEqual(restored.Plan, plan) {
		t.Fatalf("plan changed after template edit or restart: %d %s", read.status, read.body)
	}
	if r := do(t, env.ts, http.MethodGet, strings.Replace(planPath, p.ID, "another-project", 1), nil, nil); r.status != 404 {
		t.Fatalf("plan project escape: %d", r.status)
	}
	invocations := do(t, env.ts, http.MethodGet, strings.TrimSuffix(artifactsPath, "/artifacts")+"/plugin-invocations", nil, nil)
	if strings.Contains(string(invocations.body), `"invocation_id"`) {
		t.Fatalf("compiler executed a plugin: %s", invocations.body)
	}
	again := do(t, env.ts, http.MethodPost, compiledPath, request, nil)
	var repeated struct {
		Plan workflow.Plan `json:"plan"`
	}
	again.decode(t, &repeated)
	if again.status != 201 || !reflect.DeepEqual(repeated.Plan, plan) {
		t.Fatalf("recompile changed fixed plan: %d %s", again.status, again.body)
	}
	deleted := do(t, env.ts, http.MethodDelete, "/api/snapshots/"+input.Scope.SnapshotID, nil, nil)
	if deleted.status != 204 {
		t.Fatalf("delete snapshot: %d %s", deleted.status, deleted.body)
	}
	if r := do(t, env.ts, http.MethodGet, planPath, nil, nil); r.status != 404 {
		t.Fatalf("deleted snapshot plan readable: %d", r.status)
	}
	if r := do(t, env.ts, http.MethodPost, compiledPath, request, nil); r.status != 404 {
		t.Fatalf("compiled deleted snapshot: %d %s", r.status, r.body)
	}

}

func TestWorkflowDirectoryAndValidationExposeProjectScopedFieldDiagnostics(t *testing.T) {
	env := newTestEnv(t, false)
	p := createProject(t, env.ts, env.source).Project
	endpoint := "/api/v1/projects/" + p.ID + "/workflows"
	spec := workflowSpecFixture()
	save := do(t, env.ts, http.MethodPost, endpoint, map[string]any{"api_version": "codexploit/v1", "spec": spec}, nil)
	if save.status != 201 {
		t.Fatal(string(save.body))
	}
	list := doAs(t, env.ts, readerSecret, http.MethodGet, endpoint+"?limit=1", nil, nil)
	var page struct {
		Workflows []workflow.Entry `json:"workflows"`
		Next      string           `json:"next_cursor"`
	}
	list.decode(t, &page)
	if list.status != 200 || len(page.Workflows) != 1 || page.Workflows[0].HeadDigest != page.Workflows[0].Digest {
		t.Fatalf("directory: %d %s", list.status, list.body)
	}
	spec["nodes"].([]any)[0].(map[string]any)["config"] = map[string]any{"include_comments": "wrong"}
	validated := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint+"/validate", map[string]any{"api_version": "codexploit/v1", "spec": spec}, nil)
	var result workflow.Validation
	validated.decode(t, &result)
	if validated.status != 200 || result.Valid || len(result.Diagnostics) != 1 || result.Diagnostics[0].Path != "/nodes/0/config/include_comments" {
		t.Fatalf("field validation: %d %s", validated.status, validated.body)
	}
	if r := do(t, env.ts, http.MethodGet, "/api/v1/projects/absent/workflows", nil, nil); r.status != 404 {
		t.Fatalf("absent project: %d", r.status)
	}
}
