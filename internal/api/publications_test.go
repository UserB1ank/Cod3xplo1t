package api

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestTaskPublishesRealAnalysisIntoAnImmutableKnowledgeRevision(t *testing.T) {
	env := newTestEnv(t, false)
	writeFile(t, env.source, "main.go", `package main
import("net/http";"os/exec")
func run(s string){exec.Command(s).Run()}
func Handler(w http.ResponseWriter,r *http.Request){run(r.URL.Query().Get("cmd"))}
func main(){http.HandleFunc("/run",Handler)}
`)
	project := createProject(t, env.ts, env.source).Project
	var snap snapshotResponse
	do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"build_graph": true, "build_asg": true}, nil).decode(t, &snap)
	task := createOrganizedTask(t, env.ts, project.ID, snap.Snapshot.SnapshotID, "Semantic review")
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snap.Snapshot.SnapshotID
	var directory struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	do(t, env.ts, http.MethodPost, prefix+"/artifacts", nil, nil).decode(t, &directory)
	var archive artifact.Ref
	for _, ref := range directory.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			archive = ref
		}
	}
	req := plugin.Request{APIVersion: "codexploit/v1", ID: "inv-publication-parser", PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(), Scope: archive.Scope, Inputs: []artifact.Ref{archive}, Config: json.RawMessage(`{}`)}
	parsed := executePluginHTTP(t, env, prefix, req)
	var catalog struct {
		Plugins []plugin.Record `json:"plugins"`
	}
	do(t, env.ts, http.MethodGet, "/api/v1/plugins", nil, nil).decode(t, &catalog)
	for _, entry := range catalog.Plugins {
		if entry.Manifest.ID == plugin.SemanticID {
			req.PluginID = entry.Manifest.ID
			req.PluginVersion = entry.Manifest.Version
			req.PackageDigest = entry.PackageDigest
		}
	}
	req.ID = "inv-publication-semantic"
	for _, ref := range parsed.Outputs {
		if ref.Kind == "code.facts" {
			req.Inputs = append(req.Inputs, ref)
		}
	}
	analyzed := executePluginHTTP(t, env, prefix, req)
	if analyzed.Status != "SUCCEEDED" && analyzed.Status != "PARTIAL" {
		t.Fatalf("analysis failed: %s", analyzed.ErrorCode)
	}
	endpoint := "/api/v1/projects/" + project.ID + "/knowledge/publications"
	body := map[string]any{"api_version": "codexploit/v1", "snapshot_id": snap.Snapshot.SnapshotID, "invocation_id": analyzed.ID, "task_id": task, "batch_id": "batch-semantic", "base_revision": "rev-0"}
	response := do(t, env.ts, http.MethodPost, endpoint, body, nil)
	if response.status != 201 {
		t.Fatalf("publish: %d %s", response.status, response.body)
	}
	var receipt struct {
		Publication struct {
			Status string `json:"status"`
			View   struct {
				ID       string `json:"view_id"`
				Revision string `json:"revision"`
			} `json:"view"`
		} `json:"publication"`
	}
	response.decode(t, &receipt)
	if receipt.Publication.Status != "published" || receipt.Publication.View.Revision != "rev-1" || receipt.Publication.View.ID == "" {
		t.Fatalf("missing committed revision: %s", response.body)
	}
	facts := doAs(t, env.ts, readerSecret, http.MethodGet, "/api/v1/projects/"+project.ID+"/knowledge/revisions/"+receipt.Publication.View.ID+"/facts?snapshot_id="+snap.Snapshot.SnapshotID, nil, nil)
	if facts.status != 200 {
		t.Fatalf("facts: %d %s", facts.status, facts.body)
	}
	var page struct {
		Facts []struct {
			ID           string `json:"id"`
			Observations []struct {
				Producer artifact.Producer `json:"producer"`
			} `json:"observations"`
		} `json:"facts"`
	}
	facts.decode(t, &page)
	if len(page.Facts) == 0 || len(page.Facts[0].Observations) != 1 || page.Facts[0].Observations[0].Producer.TaskID != task {
		t.Fatalf("missing task provenance: %s", facts.body)
	}
}

type publicationSetup struct {
	env        *testEnv
	projectID  string
	snapshotID string
	prefix     string
	scope      artifact.Scope
	archive    artifact.Ref
	codeFacts  []artifact.Ref
	semantic   plugin.Record
}

func newPublicationSetup(t *testing.T, env *testEnv) *publicationSetup {
	t.Helper()
	if env == nil {
		env = newTestEnv(t, false)
	}
	writeFile(t, env.source, "main.go", `package main
import("net/http";"os/exec")
func run(s string){exec.Command(s).Run()}
func Handler(w http.ResponseWriter,r *http.Request){run(r.URL.Query().Get("cmd"))}
func main(){http.HandleFunc("/run",Handler)}
`)
	project := createProject(t, env.ts, env.source).Project
	var snapshot snapshotResponse
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.ID+"/snapshots", map[string]any{"build_graph": true, "build_asg": true}, nil)
	if captured.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", captured.status, captured.body)
	}
	captured.decode(t, &snapshot)
	prefix := "/api/v1/projects/" + project.ID + "/snapshots/" + snapshot.Snapshot.SnapshotID
	var directory struct {
		Artifacts []artifact.Ref `json:"artifacts"`
	}
	do(t, env.ts, http.MethodPost, prefix+"/artifacts", nil, nil).decode(t, &directory)
	var archive artifact.Ref
	for _, ref := range directory.Artifacts {
		if ref.SchemaID == "codexploit/source-tar/v1" {
			archive = ref
		}
	}
	if archive.ID == "" {
		t.Fatal("no source archive was published")
	}
	var catalog struct {
		Plugins []plugin.Record `json:"plugins"`
	}
	do(t, env.ts, http.MethodGet, "/api/v1/plugins", nil, nil).decode(t, &catalog)
	var semantic plugin.Record
	for _, entry := range catalog.Plugins {
		if entry.Manifest.ID == plugin.SemanticID {
			semantic = entry
		}
	}
	if semantic.Manifest.ID == "" {
		t.Fatal("semantic plugin is not installed")
	}
	parsed := executePluginHTTP(t, env, prefix, plugin.Request{
		APIVersion: "codexploit/v1", ID: "inv-publication-parser",
		PluginID: plugin.BuiltinID, PluginVersion: plugin.BuiltinVersion, PackageDigest: plugin.BuiltinPackageDigest(),
		Scope: archive.Scope, Inputs: []artifact.Ref{archive}, Config: json.RawMessage(`{}`),
	})
	setup := &publicationSetup{env: env, projectID: project.ID, snapshotID: snapshot.Snapshot.SnapshotID, prefix: prefix, scope: archive.Scope, archive: archive, semantic: semantic}
	for _, ref := range parsed.Outputs {
		if ref.Kind == "code.facts" {
			setup.codeFacts = append(setup.codeFacts, ref)
		}
	}
	if len(setup.codeFacts) == 0 {
		t.Fatal("parser produced no code facts")
	}
	return setup
}

func (s *publicationSetup) analyze(t *testing.T, id string) plugin.Invocation {
	t.Helper()
	invocation := executePluginHTTP(t, s.env, s.prefix, plugin.Request{
		APIVersion: "codexploit/v1", ID: id,
		PluginID: s.semantic.Manifest.ID, PluginVersion: s.semantic.Manifest.Version, PackageDigest: s.semantic.PackageDigest,
		Scope: s.scope, Inputs: append([]artifact.Ref{s.archive}, s.codeFacts...), Config: json.RawMessage(`{}`),
	})
	if invocation.Status != "SUCCEEDED" && invocation.Status != "PARTIAL" {
		t.Fatalf("analysis %s: %s", id, invocation.ErrorCode)
	}
	return invocation
}

type publishResponse struct {
	status int
	body   []byte
	errorResponse
	Publication struct {
		Status   string `json:"status"`
		Revision string `json:"revision"`
		Facts    int    `json:"facts"`
		View     struct {
			ID       string `json:"view_id"`
			Revision string `json:"revision"`
		} `json:"view"`
	} `json:"publication"`
}

func (s *publicationSetup) publish(t *testing.T, invocation, task, batch, base string) publishResponse {
	t.Helper()
	response := do(t, s.env.ts, http.MethodPost, "/api/v1/projects/"+s.projectID+"/knowledge/publications", map[string]any{
		"api_version": "codexploit/v1", "snapshot_id": s.snapshotID, "invocation_id": invocation,
		"task_id": task, "batch_id": batch, "base_revision": base,
	}, nil)
	var decoded publishResponse
	decoded.status = response.status
	decoded.body = response.body
	_ = json.Unmarshal(response.body, &decoded)
	return decoded
}

type revisionFacts struct {
	Revision struct {
		Revision string `json:"revision"`
	} `json:"revision"`
	Facts []struct {
		ID           string `json:"id"`
		Observations []struct {
			Producer struct {
				PluginID string `json:"plugin_id"`
				TaskID   string `json:"task_id"`
			} `json:"producer"`
		} `json:"observations"`
	} `json:"facts"`
	Next string `json:"next_cursor"`
}

func (s *publicationSetup) facts(t *testing.T, viewID string) revisionFacts {
	t.Helper()
	response := doAs(t, s.env.ts, readerSecret, http.MethodGet,
		"/api/v1/projects/"+s.projectID+"/knowledge/revisions/"+viewID+"/facts?snapshot_id="+s.snapshotID, nil, nil)
	if response.status != http.StatusOK {
		t.Fatalf("facts: %d %s", response.status, response.body)
	}
	var page revisionFacts
	response.decode(t, &page)
	return page
}

func TestTwoTasksShareRevisionsWithoutReplacingAnEarlierView(t *testing.T) {
	setup := newPublicationSetup(t, nil)
	taskA := createOrganizedTask(t, setup.env.ts, setup.projectID, setup.snapshotID, "Task A")
	taskB := createOrganizedTask(t, setup.env.ts, setup.projectID, setup.snapshotID, "Task B")
	invocationA := setup.analyze(t, "inv-publication-a")
	invocationB := setup.analyze(t, "inv-publication-b")

	first := setup.publish(t, invocationA.ID, taskA, "batch-a", "rev-0")
	if first.status != http.StatusCreated || first.Publication.Revision != "rev-1" || first.Publication.View.ID == "" {
		t.Fatalf("first publication: %d %s", first.status, first.body)
	}
	second := setup.publish(t, invocationB.ID, taskB, "batch-b", "rev-1")
	if second.status != http.StatusCreated || second.Publication.Revision != "rev-2" {
		t.Fatalf("second publication: %d %s", second.status, second.body)
	}

	// The earlier revision keeps serving exactly what it published: a newer
	// publication cannot replace an open view.
	earlier := setup.facts(t, first.Publication.View.ID)
	latest := setup.facts(t, second.Publication.View.ID)
	if len(earlier.Facts) == 0 || len(latest.Facts) != len(earlier.Facts) {
		t.Fatalf("facts: earlier=%d latest=%d", len(earlier.Facts), len(latest.Facts))
	}
	for _, fact := range earlier.Facts {
		if len(fact.Observations) != 1 || fact.Observations[0].Producer.TaskID != taskA {
			t.Fatalf("earlier revision was rewritten: %+v", fact)
		}
	}
	tasks := map[string]bool{}
	for _, fact := range latest.Facts {
		if len(fact.Observations) != 2 {
			t.Fatalf("latest fact has %d observations: %+v", len(fact.Observations), fact)
		}
		for _, observation := range fact.Observations {
			tasks[observation.Producer.TaskID] = true
		}
	}
	if !tasks[taskA] || !tasks[taskB] {
		t.Fatalf("two tasks do not share the facts: %+v", tasks)
	}

	// A stale base revision is refused; a replay of batch-a returns rev-1.
	stale := setup.publish(t, invocationA.ID, taskA, "batch-stale", "rev-0")
	if stale.status != http.StatusConflict || stale.Code != "version_conflict" {
		t.Fatalf("stale base: %d %s", stale.status, stale.body)
	}
	replay := setup.publish(t, invocationA.ID, taskA, "batch-a", "rev-0")
	if replay.status != http.StatusCreated || replay.Publication.Revision != "rev-1" {
		t.Fatalf("replay: %d %s", replay.status, replay.body)
	}

	// Project and snapshot isolation.
	other := createProject(t, setup.env.ts, newTestSource(t)).Project
	foreign := doAs(t, setup.env.ts, readerSecret, http.MethodGet,
		"/api/v1/projects/"+other.ID+"/knowledge/revisions/"+first.Publication.View.ID+"/facts", nil, nil)
	if foreign.status != http.StatusNotFound {
		t.Fatalf("foreign project view: %d %s", foreign.status, foreign.body)
	}
	wrongSnapshot := doAs(t, setup.env.ts, readerSecret, http.MethodGet,
		"/api/v1/projects/"+setup.projectID+"/knowledge/revisions/"+first.Publication.View.ID+"/facts?snapshot_id=snap-other", nil, nil)
	if wrongSnapshot.status != http.StatusNotFound {
		t.Fatalf("wrong snapshot: %d %s", wrongSnapshot.status, wrongSnapshot.body)
	}
	reader := doAs(t, setup.env.ts, readerSecret, http.MethodPost,
		"/api/v1/projects/"+setup.projectID+"/knowledge/publications",
		map[string]any{"api_version": "codexploit/v1", "snapshot_id": setup.snapshotID, "invocation_id": invocationA.ID, "batch_id": "batch-reader", "base_revision": "rev-2"}, nil)
	if reader.status != http.StatusForbidden {
		t.Fatalf("reader published: %d %s", reader.status, reader.body)
	}
}

func TestPublishedRevisionsSurviveADatabaseReopen(t *testing.T) {
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	setup := newPublicationSetup(t, serveTestEnv(t, runtime, false))
	task := createOrganizedTask(t, setup.env.ts, setup.projectID, setup.snapshotID, "Durable task")
	invocation := setup.analyze(t, "inv-publication-durable")
	first := setup.publish(t, invocation.ID, task, "batch-durable", "rev-0")
	if first.status != http.StatusCreated || first.Publication.Revision != "rev-1" {
		t.Fatalf("publish: %d %s", first.status, first.body)
	}
	before := setup.facts(t, first.Publication.View.ID)
	setup.env.ts.Close()
	setup.env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}

	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	reopened := serveTestEnv(t, runtime, false)
	after := newPublicationSetupView(t, reopened, setup.projectID, setup.snapshotID)
	page := doAs(t, reopened.ts, readerSecret, http.MethodGet,
		"/api/v1/projects/"+setup.projectID+"/knowledge/revisions/"+first.Publication.View.ID+"/facts?snapshot_id="+setup.snapshotID, nil, nil)
	if page.status != http.StatusOK {
		t.Fatalf("reopened facts: %d %s", page.status, page.body)
	}
	var decoded revisionFacts
	page.decode(t, &decoded)
	if len(decoded.Facts) != len(before.Facts) || decoded.Revision.Revision != "rev-1" {
		t.Fatalf("reopened revision changed: %d facts vs %d", len(decoded.Facts), len(before.Facts))
	}
	list := doAs(t, reopened.ts, readerSecret, http.MethodGet,
		"/api/v1/projects/"+after.projectID+"/knowledge/revisions?snapshot_id="+setup.snapshotID, nil, nil)
	var listed struct {
		Revisions []struct {
			Revision string `json:"revision"`
		} `json:"revisions"`
	}
	list.decode(t, &listed)
	if list.status != http.StatusOK || len(listed.Revisions) != 1 || listed.Revisions[0].Revision != "rev-1" {
		t.Fatalf("reopened list: %d %s", list.status, list.body)
	}
}

func newPublicationSetupView(t *testing.T, env *testEnv, projectID, snapshotID string) *publicationSetup {
	t.Helper()
	return &publicationSetup{env: env, projectID: projectID, snapshotID: snapshotID}
}
