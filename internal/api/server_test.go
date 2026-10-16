package api

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

// Test credentials. Secrets are long enough to pass the configuration checks;
// they are test values and never used anywhere else.
const (
	adminSecret  = "test-admin-secret-0123456789"
	admin2Secret = "test-admin2-secret-0123456789"
	readerSecret = "test-reader-secret-0123456789"
)

// testAuthenticator builds the three tokens the table-driven API tests use.
func testAuthenticator(t *testing.T) *Authenticator {
	t.Helper()
	auth, err := NewAuthenticator([]Token{
		{Name: "admin", Role: "admin", Secret: adminSecret},
		{Name: "second", Role: "admin", Secret: admin2Secret},
		{Name: "reader", Role: "reader", Secret: readerSecret},
	})
	if err != nil {
		t.Fatalf("NewAuthenticator: %v", err)
	}
	return auth
}

// testEnv is a runtime served over httptest, with a local repository fixture.
type testEnv struct {
	ts        *httptest.Server
	rt        *app.Runtime
	source    string
	workspace string
}

// newTestServer wires a full runtime over an in-memory store and a temp
// workspace, then serves it through httptest.
//
// The agent is configured here, not only in the P5 tests: a server with a dead
// agent would make every existing audit fixture exercise a 501 path, which is not
// the environment those tests describe.
func newTestEnv(t *testing.T, allowNetwork bool) *testEnv {
	t.Helper()
	rt, err := app.Build(context.Background(), app.Config{
		Workspace:    filepath.Join(t.TempDir(), "work"),
		DBPath:       "memory",
		AllowNetwork: allowNetwork,
		Agent: app.AgentConfig{
			Enabled:            true,
			Runtime:            app.AgentRuntimeScripted,
			ScriptedAnswerJSON: agentTestPlaceholderAnswer(t),
			MaxToolCalls:       30,
		},
	})
	if err != nil {
		t.Fatalf("app.Build: %v", err)
	}
	if rt.Agent == nil || rt.AgentRegistry == nil {
		t.Fatalf("the configured agent was not wired")
	}
	// A fixed script cannot know the security goal the graph derives from a path,
	// so the adapter answers the task it receives. See echoRuntime in agent_test.go.
	rt.Agent.Runtime = &echoRuntime{Answer: agentTestAnswer}
	env := serveTestEnv(t, rt, allowNetwork)
	env.source = newTestSource(t)
	return env
}

// newTestSource writes the small repository every P1 test snapshots.
func newTestSource(t *testing.T) string {
	t.Helper()
	source := t.TempDir()
	writeFile(t, source, "go.mod", "module example.invalid/app\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.9.1\n")
	writeFile(t, source, "main.go", `package main

import "example.invalid/app/internal/svc"

func main() {
	svc.Start()
}
`)
	writeFile(t, source, "internal/svc/svc.go", `package svc

func Start() { Serve() }

func Serve() {}
`)
	writeFile(t, source, "Dockerfile", "FROM scratch\n")
	return source
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	p := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

type response struct {
	status int
	body   []byte
	header http.Header
}

func (r response) decode(t *testing.T, dst any) {
	t.Helper()
	if err := json.Unmarshal(r.body, dst); err != nil {
		t.Fatalf("decode %s: %v", r.body, err)
	}
}

// do sends an authenticated request as the admin token; doAs picks a token.
func do(t *testing.T, ts *httptest.Server, method, path string, body any, headers map[string]string) response {
	t.Helper()
	return doAs(t, ts, adminSecret, method, path, body, headers)
}

func doAs(t *testing.T, ts *httptest.Server, token, method, path string, body any, headers map[string]string) response {
	t.Helper()
	var reader io.Reader
	if body != nil {
		switch v := body.(type) {
		case string:
			reader = strings.NewReader(v)
		case []byte:
			reader = bytes.NewReader(v)
		default:
			data, err := json.Marshal(v)
			if err != nil {
				t.Fatal(err)
			}
			reader = bytes.NewReader(data)
		}
	}
	req, err := http.NewRequest(method, ts.URL+path, reader)
	if err != nil {
		t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := ts.Client().Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response{status: resp.StatusCode, body: data, header: resp.Header}
}

func createProject(t *testing.T, ts *httptest.Server, source string) projectResponse {
	t.Helper()
	resp := do(t, ts, http.MethodPost, "/api/projects", map[string]string{"source": source}, nil)
	if resp.status != http.StatusCreated {
		t.Fatalf("create project: status %d body %s", resp.status, resp.body)
	}
	var out projectResponse
	resp.decode(t, &out)
	if out.Project.ID == "" {
		t.Fatalf("project id is empty: %s", resp.body)
	}
	return out
}

func TestHealth(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	resp := do(t, ts, http.MethodGet, "/healthz", nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("status %d: %s", resp.status, resp.body)
	}
	var out map[string]any
	resp.decode(t, &out)
	if out["status"] != "ok" {
		t.Fatalf("unexpected health body: %s", resp.body)
	}
}

func TestProjectSnapshotManifestFlow(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts, source := env.ts, env.source
	project := createProject(t, ts, source)

	create := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create snapshot: status %d body %s", create.status, create.body)
	}
	var created snapshotResponse
	create.decode(t, &created)
	if created.Snapshot.SnapshotID == "" || created.Manifest == nil {
		t.Fatalf("incomplete snapshot response: %s", create.body)
	}
	if created.Existing {
		t.Error("a fresh snapshot reported itself as pre-existing")
	}
	if created.Snapshot.Files != 4 {
		t.Errorf("snapshot files = %d, want 4 (go.mod, main.go, svc.go, Dockerfile)", created.Snapshot.Files)
	}
	if created.Manifest.PrimaryLanguage != "Go" {
		t.Errorf("primary language = %q, want Go", created.Manifest.PrimaryLanguage)
	}
	if len(created.Manifest.Frameworks) != 1 || created.Manifest.Frameworks[0] != "Gin" {
		t.Errorf("frameworks = %v, want [Gin]", created.Manifest.Frameworks)
	}
	if len(created.Snapshot.Limitations) == 0 {
		t.Error("snapshot carries no coverage limitations")
	}

	snapID := created.Snapshot.SnapshotID
	get := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID, nil, nil)
	if get.status != http.StatusOK {
		t.Fatalf("get snapshot: status %d body %s", get.status, get.body)
	}
	var fetched snapshotResponse
	get.decode(t, &fetched)
	if fetched.Snapshot.Commit != created.Snapshot.Commit || fetched.Snapshot.ProjectID != project.Project.ID {
		t.Errorf("unexpected snapshot: %+v", fetched.Snapshot)
	}

	mf := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/manifest", nil, nil)
	if mf.status != http.StatusOK {
		t.Fatalf("get manifest: status %d body %s", mf.status, mf.body)
	}
	var manifest analysis.Manifest
	mf.decode(t, &manifest)
	if manifest.SnapshotID != snapID || manifest.AnalysisID != created.Manifest.AnalysisID {
		t.Errorf("unexpected manifest: %+v", manifest)
	}
	if len(manifest.Dependencies.Packages) == 0 || manifest.Dependencies.Packages[0].Name != "github.com/gin-gonic/gin" {
		t.Errorf("manifest dependencies missing: %+v", manifest.Dependencies.Packages)
	}

	list := do(t, ts, http.MethodGet, "/api/snapshots?project_id="+project.Project.ID, nil, nil)
	if list.status != http.StatusOK {
		t.Fatalf("list snapshots: status %d body %s", list.status, list.body)
	}
	var listed struct {
		Snapshots []map[string]any `json:"snapshots"`
	}
	list.decode(t, &listed)
	if len(listed.Snapshots) != 1 {
		t.Fatalf("listed %d snapshots: %s", len(listed.Snapshots), list.body)
	}
	if listed.Snapshots[0]["manifest_present"] != true {
		t.Errorf("manifest state not reported: %s", list.body)
	}

	projects := do(t, ts, http.MethodGet, "/api/projects", nil, nil)
	var projectList struct {
		Projects []map[string]any `json:"projects"`
	}
	projects.decode(t, &projectList)
	if len(projectList.Projects) != 1 {
		t.Fatalf("listed %d projects", len(projectList.Projects))
	}
	single := do(t, ts, http.MethodGet, "/api/projects/"+project.Project.ID, nil, nil)
	if single.status != http.StatusOK {
		t.Fatalf("get project: status %d body %s", single.status, single.body)
	}

	del := do(t, ts, http.MethodDelete, "/api/snapshots/"+snapID, nil, nil)
	if del.status != http.StatusNoContent {
		t.Fatalf("delete snapshot: status %d body %s", del.status, del.body)
	}
	if after := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID, nil, nil); after.status != http.StatusNotFound {
		t.Errorf("snapshot still readable after delete: %d %s", after.status, after.body)
	}
	if again := do(t, ts, http.MethodDelete, "/api/snapshots/"+snapID, nil, nil); again.status != http.StatusNotFound {
		t.Errorf("second delete status = %d, want 404", again.status)
	}
	// The frozen tree must be gone from the workspace as well, which is what
	// proves the read-only snapshot was unfrozen before deletion.
	if _, err := os.Stat(filepath.Join(env.workspace, "snapshots", snapID)); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("snapshot directory still present after delete: %v", err)
	}
}

func TestProjectCreationIsDeterministic(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts, source := env.ts, env.source
	first := createProject(t, ts, source)
	second := do(t, ts, http.MethodPost, "/api/projects", map[string]string{"source": source}, nil)
	if second.status != http.StatusOK {
		t.Fatalf("second create: status %d body %s", second.status, second.body)
	}
	var out projectResponse
	second.decode(t, &out)
	if out.Project.ID != first.Project.ID || !out.Existing {
		t.Errorf("project creation is not idempotent: %+v vs %+v", out, first)
	}
	if out.Project.Name == "" {
		t.Error("project name was not derived")
	}
}

func TestSnapshotCreationIsRepeatableAndHonoursIdempotencyKey(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts, source := env.ts, env.source
	project := createProject(t, ts, source)
	path := "/api/projects/" + project.Project.ID + "/snapshots"

	first := do(t, ts, http.MethodPost, path, map[string]any{}, nil)
	if first.status != http.StatusCreated {
		t.Fatalf("first create: %d %s", first.status, first.body)
	}
	// Repeating the request is safe: the same snapshot id comes back, and the
	// server reports that it already existed.
	repeat := do(t, ts, http.MethodPost, path, map[string]any{}, nil)
	if repeat.status != http.StatusOK {
		t.Fatalf("repeat create: %d %s", repeat.status, repeat.body)
	}
	var firstBody, repeatBody snapshotResponse
	first.decode(t, &firstBody)
	repeat.decode(t, &repeatBody)
	if firstBody.Snapshot.SnapshotID != repeatBody.Snapshot.SnapshotID {
		t.Errorf("same source produced %s and %s", firstBody.Snapshot.SnapshotID, repeatBody.Snapshot.SnapshotID)
	}
	if !repeatBody.Existing {
		t.Error("repeat create did not report the snapshot as existing")
	}

	// With an idempotency key the original response is replayed verbatim.
	headers := map[string]string{"Idempotency-Key": "snapshot-42"}
	cached := do(t, ts, http.MethodPost, path, map[string]any{}, headers)
	replay := do(t, ts, http.MethodPost, path, map[string]any{}, headers)
	if replay.status != cached.status {
		t.Errorf("replay status %d != %d", replay.status, cached.status)
	}
	if string(replay.body) != string(cached.body) {
		t.Errorf("replay body differs:\n%s\n%s", replay.body, cached.body)
	}
	if replay.header.Get("Idempotent-Replay") != "true" {
		t.Errorf("replay header missing: %v", replay.header)
	}
}

func TestSkipAnalysisFreezesWithoutManifest(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts, source := env.ts, env.source
	project := createProject(t, ts, source)
	create := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{"skip_analysis": true}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.status, create.body)
	}
	var body snapshotResponse
	create.decode(t, &body)
	if body.Manifest != nil {
		t.Error("manifest was produced despite skip_analysis")
	}
	mf := do(t, ts, http.MethodGet, "/api/snapshots/"+body.Snapshot.SnapshotID+"/manifest", nil, nil)
	if mf.status != http.StatusNotFound {
		t.Errorf("manifest status = %d, want 404", mf.status)
	}
}

func TestRequestValidationAndErrors(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts, source := env.ts, env.source
	project := createProject(t, ts, source)

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
	}{
		{"bad json", http.MethodPost, "/api/projects", "{not json", http.StatusBadRequest},
		{"unknown field", http.MethodPost, "/api/projects", `{"source":"x","nope":1}`, http.StatusBadRequest},
		{"missing source", http.MethodPost, "/api/projects", map[string]any{}, http.StatusBadRequest},
		{"missing path", http.MethodPost, "/api/projects", map[string]string{"source": "/nope/does/not/exist"}, http.StatusNotFound},
		{"remote source without network", http.MethodPost, "/api/projects", map[string]string{"source": "https://example.invalid/org/repo.git"}, http.StatusForbidden},
		{"unknown project", http.MethodGet, "/api/projects/proj-missing", nil, http.StatusNotFound},
		{"unknown snapshot", http.MethodGet, "/api/snapshots/snap-00000000000000000000000000000000", nil, http.StatusNotFound},
		{"invalid snapshot id", http.MethodGet, "/api/snapshots/not-an-id", nil, http.StatusNotFound},
		{"unknown manifest", http.MethodGet, "/api/snapshots/snap-00000000000000000000000000000000/manifest", nil, http.StatusNotFound},
		{"snapshot for unknown project", http.MethodPost, "/api/projects/proj-missing/snapshots", map[string]any{}, http.StatusNotFound},
		{"delete unknown snapshot", http.MethodDelete, "/api/snapshots/snap-00000000000000000000000000000000", nil, http.StatusNotFound},
		{"method not allowed", http.MethodPut, "/api/projects/" + project.Project.ID, map[string]any{}, http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, ts, tc.method, tc.path, tc.body, nil)
			if resp.status != tc.want {
				t.Fatalf("status = %d, want %d (body %s)", resp.status, tc.want, resp.body)
			}
			if tc.want >= 400 && !strings.Contains(resp.header.Get("Content-Type"), "application/json") {
				t.Errorf("error response is not JSON: %v", resp.header)
			}
		})
	}
}

func TestOversizedBodyIsRejected(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	huge := fmt.Sprintf(`{"source":%q}`, strings.Repeat("a", maxBodyBytes+1024))
	resp := do(t, ts, http.MethodPost, "/api/projects", huge, nil)
	if resp.status != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413 (body %s)", resp.status, resp.body)
	}
}

func TestRefusesNetworkForRemoteSources(t *testing.T) {
	t.Parallel()
	// The manager is built without network access; the server must not bypass it.
	rt, err := app.Build(context.Background(), app.Config{
		Workspace: filepath.Join(t.TempDir(), "work"),
		DBPath:    "memory",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	if rt.Manager.AllowNetwork {
		t.Fatal("test precondition: manager allows network")
	}
	if _, err := rt.Manager.Resolve(context.Background(), repository.Source{Raw: "https://example.invalid/org/repo.git"}); err == nil {
		t.Fatal("manager resolved a remote source without network access")
	}
}

func TestGraphEndpoints(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	project := createProject(t, ts, env.source)

	// One request produces the whole chain: snapshot, manifest and graph.
	create := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.status, create.body)
	}
	var created snapshotResponse
	create.decode(t, &created)
	if created.Graph == nil || created.Graph.Symbols == 0 {
		t.Fatalf("graph was not built: %s", create.body)
	}
	if created.Graph.Resolution.Total() == 0 {
		t.Errorf("graph has no resolved call accounting: %+v", created.Graph.Resolution)
	}
	snapID := created.Snapshot.SnapshotID

	// The summary is idempotent: rebuilding without force returns the stored graph.
	again := do(t, ts, http.MethodPost, "/api/snapshots/"+snapID+"/graph", map[string]any{}, nil)
	if again.status != http.StatusOK {
		t.Fatalf("second build: %d %s", again.status, again.body)
	}
	var second struct {
		Built bool        `json:"built"`
		Graph scg.Summary `json:"graph"`
	}
	again.decode(t, &second)
	if second.Built {
		t.Error("a stored graph was rebuilt without force")
	}
	forced := do(t, ts, http.MethodPost, "/api/snapshots/"+snapID+"/graph", map[string]any{"force": true}, nil)
	if forced.status != http.StatusCreated {
		t.Fatalf("forced rebuild: %d %s", forced.status, forced.body)
	}

	summary := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/graph", nil, nil)
	if summary.status != http.StatusOK {
		t.Fatalf("summary: %d %s", summary.status, summary.body)
	}

	modules := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/modules", nil, nil)
	if modules.status != http.StatusOK {
		t.Fatalf("modules: %d %s", modules.status, modules.body)
	}
	var modulePage graph.ModulePage
	modules.decode(t, &modulePage)
	if len(modulePage.Modules) == 0 {
		t.Fatalf("no modules returned: %s", modules.body)
	}

	symbols := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/symbols?name=Start&limit=10", nil, nil)
	if symbols.status != http.StatusOK {
		t.Fatalf("symbols: %d %s", symbols.status, symbols.body)
	}
	var page graph.SymbolPage
	symbols.decode(t, &page)
	if page.Total != 1 || len(page.Symbols) != 1 {
		t.Fatalf("symbols = %d/%d, want the Start symbol: %s", len(page.Symbols), page.Total, symbols.body)
	}
	startID := page.Symbols[0].ID

	one := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/symbols/"+startID, nil, nil)
	if one.status != http.StatusOK {
		t.Fatalf("get symbol: %d %s", one.status, one.body)
	}
	// Qualified names contain slashes, so they are a query parameter instead of a
	// path segment; the lookup is exact.
	byName := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/symbols?qualified_name=example.invalid/app/internal/svc.Start", nil, nil)
	if byName.status != http.StatusOK {
		t.Fatalf("symbol lookup by qualified name: %d %s", byName.status, byName.body)
	}
	var byNamePage graph.SymbolPage
	byName.decode(t, &byNamePage)
	if byNamePage.Total != 1 || byNamePage.Symbols[0].ID != startID {
		t.Errorf("qualified name lookup returned %+v", byNamePage.Symbols)
	}

	callees := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/symbols/"+startID+"/callees?max_depth=2", nil, nil)
	if callees.status != http.StatusOK {
		t.Fatalf("callees: %d %s", callees.status, callees.body)
	}
	var neighbourhood graph.Neighborhood
	callees.decode(t, &neighbourhood)
	if len(neighbourhood.Nodes) == 0 {
		t.Fatalf("no callees returned: %s", callees.body)
	}
	if neighbourhood.Meta.SnapshotID != snapID || neighbourhood.Meta.GraphVersion == "" {
		t.Errorf("neighbourhood lost provenance: %+v", neighbourhood.Meta)
	}
	serveID := ""
	for _, node := range neighbourhood.Nodes {
		if node.Symbol.Name == "Serve" {
			serveID = node.Symbol.ID
		}
	}
	if serveID == "" {
		t.Fatalf("Serve was not reached: %s", callees.body)
	}

	callers := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/symbols/"+serveID+"/callers?max_depth=2", nil, nil)
	if callers.status != http.StatusOK {
		t.Fatalf("callers: %d %s", callers.status, callers.body)
	}

	paths := do(t, ts, http.MethodPost, "/api/snapshots/"+snapID+"/graph/paths",
		map[string]any{"source": startID, "sink": serveID, "max_paths": 3}, nil)
	if paths.status != http.StatusOK {
		t.Fatalf("paths: %d %s", paths.status, paths.body)
	}
	var pathSet graph.PathSet
	paths.decode(t, &pathSet)
	if len(pathSet.Paths) != 1 || pathSet.Paths[0].Length != 1 {
		t.Fatalf("paths = %+v, want one direct route", pathSet.Paths)
	}

	slice := do(t, ts, http.MethodPost, "/api/snapshots/"+snapID+"/graph/slice",
		map[string]any{"symbol_id": serveID, "include": "callers", "max_lines": 20}, nil)
	if slice.status != http.StatusOK {
		t.Fatalf("slice: %d %s", slice.status, slice.body)
	}
	var codeSlice graph.CodeSlice
	slice.decode(t, &codeSlice)
	if len(codeSlice.Sections) == 0 {
		t.Fatalf("empty slice: %s", slice.body)
	}
	body := ""
	for _, section := range codeSlice.Sections {
		body += strings.Join(section.Lines, "\n")
	}
	if !strings.Contains(body, "func Serve()") {
		t.Errorf("slice does not contain the declaration: %s", body)
	}

	unresolved := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/unresolved-calls", nil, nil)
	if unresolved.status != http.StatusOK {
		t.Fatalf("unresolved calls: %d %s", unresolved.status, unresolved.body)
	}
}

func TestGraphEndpointErrors(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	project := createProject(t, ts, env.source)
	create := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.status, create.body)
	}
	var created snapshotResponse
	create.decode(t, &created)
	snapID := created.Snapshot.SnapshotID

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
		code   string
	}{
		{"summary without graph", http.MethodGet, "/api/snapshots/" + snapID + "/graph", nil, http.StatusNotFound, "graph_missing"},
		{"modules without graph", http.MethodGet, "/api/snapshots/" + snapID + "/modules", nil, http.StatusNotFound, "not_found"},
		{"unknown snapshot", http.MethodGet, "/api/snapshots/snap-00000000000000000000000000000000/graph", nil, http.StatusNotFound, "graph_missing"},
		{"paths without source", http.MethodPost, "/api/snapshots/" + snapID + "/graph/paths", map[string]any{"sink": "sym-x"}, http.StatusBadRequest, "invalid_request"},
		{"slice without selector", http.MethodPost, "/api/snapshots/" + snapID + "/graph/slice", map[string]any{}, http.StatusBadRequest, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, ts, tc.method, tc.path, tc.body, nil)
			if resp.status != tc.want {
				t.Fatalf("status = %d, want %d (%s)", resp.status, tc.want, resp.body)
			}
			var errBody errorResponse
			resp.decode(t, &errBody)
			if errBody.Code != tc.code {
				t.Errorf("code = %q, want %q (%s)", errBody.Code, tc.code, resp.body)
			}
		})
	}

	// A server without the graph service must say so instead of pretending the
	// snapshot has no graph.
	// Authenticated but deliberately without the graph service: authentication
	// runs first, so this is the only way to observe the 501 path.
	bare := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer,
		WithAuth(testAuthenticator(t)),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	bareTS := httptest.NewServer(bare.Handler())
	defer bareTS.Close()
	resp := do(t, bareTS, http.MethodGet, "/api/snapshots/"+snapID+"/graph", nil, nil)
	if resp.status != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (%s)", resp.status, resp.body)
	}
}
