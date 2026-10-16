package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
)

// asgFixtureSource writes a Go service with a real attack surface: a gin route
// registration whose handler reads a query parameter and calls a database and a
// file, plus an authentication middleware registered on the same router. The
// extractor needs all four shapes (entry point, input, sink, control) to produce
// a document worth asserting on.
func asgFixtureSource(t *testing.T) string {
	t.Helper()
	source := t.TempDir()
	writeFile(t, source, "go.mod", "module example.invalid/svc\n\ngo 1.24\n\nrequire github.com/gin-gonic/gin v1.9.1\n")
	writeFile(t, source, "main.go", `package main

import (
	"database/sql"
	"net/http"
	"os"

	"github.com/gin-gonic/gin"
)

func AuthRequired() gin.HandlerFunc {
	return func(c *gin.Context) {
		if c.GetHeader("Authorization") == "" {
			c.AbortWithStatus(http.StatusUnauthorized)
		}
	}
}

func Report(c *gin.Context) {
	db, err := sql.Open("sqlite", "app.db")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	row := db.QueryRow("SELECT secret FROM tokens WHERE name = ?", c.Query("name"))
	var secret string
	if err := row.Scan(&secret); err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	body, err := os.ReadFile("config/app.yaml")
	if err != nil {
		c.String(http.StatusInternalServerError, err.Error())
		return
	}
	c.String(http.StatusOK, secret+string(body))
}

func main() {
	r := gin.Default()
	r.Use(AuthRequired())
	r.GET("/users/:id", Report)
	r.Run(":8080")
}
`)
	return source
}

// createASGSnapshot freezes the fixture and builds its graph in one request, so
// the attack-surface tests start from a snapshot that has an SCG.
func createASGSnapshot(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	project := createProject(t, ts, asgFixtureSource(t))
	create := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create snapshot: %d %s", create.status, create.body)
	}
	var created snapshotResponse
	create.decode(t, &created)
	if created.Graph == nil || created.Snapshot.SnapshotID == "" {
		t.Fatalf("fixture produced no graph: %s", create.body)
	}
	return created.Snapshot.SnapshotID
}

func TestASGBuildAndQuery(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createASGSnapshot(t, ts)

	// A snapshot without an ASG says so, and says how to fix it.
	missing := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg", nil, nil)
	if missing.status != http.StatusNotFound {
		t.Fatalf("summary before build = %d, want 404 (%s)", missing.status, missing.body)
	}
	var missingBody errorResponse
	missing.decode(t, &missingBody)
	if missingBody.Code != "asg_missing" {
		t.Errorf("code = %q, want asg_missing", missingBody.Code)
	}

	// The build produces the document and stores it next to the frozen tree.
	build := do(t, ts, http.MethodPost, "/api/snapshots/"+snapID+"/asg", map[string]any{"force": false}, nil)
	if build.status != http.StatusCreated {
		t.Fatalf("build = %d, want 201 (%s)", build.status, build.body)
	}
	var built asgResponse
	build.decode(t, &built)
	if !built.Built || built.ASG == nil {
		t.Fatalf("build response = %s", build.body)
	}
	if built.ASG.NodesByKind[string(asg.NodeEntryPoint)] == 0 {
		t.Errorf("attack surface has no entry point: %s", build.body)
	}
	if built.ASG.NodesByKind[string(asg.NodeSensitiveOperation)] == 0 {
		t.Errorf("attack surface has no sensitive operation: %s", build.body)
	}
	if len(built.ASG.Limitations) == 0 {
		t.Error("summary carries no limitations")
	}
	if built.ASG.Coverage.CallSitesExamined == 0 {
		t.Error("summary reports no coverage")
	}
	if built.ASG.EvidenceCounts[string(asg.StatusObserved)] == 0 {
		t.Errorf("summary has no observed evidence: %s", build.body)
	}
	assertASGArtifact(t, env.workspace, snapID)

	// Without force the stored document is returned instead of rebuilt.
	again := do(t, ts, http.MethodPost, "/api/snapshots/"+snapID+"/asg", map[string]any{}, nil)
	if again.status != http.StatusOK {
		t.Fatalf("second build = %d, want 200 (%s)", again.status, again.body)
	}
	var second asgResponse
	again.decode(t, &second)
	if second.Built {
		t.Error("a stored attack surface was rebuilt without force")
	}
	if second.ASG == nil || second.ASG.ASGVersion != built.ASG.ASGVersion {
		t.Errorf("second build returned a different document: %s", again.body)
	}

	summary := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg", nil, nil)
	if summary.status != http.StatusOK {
		t.Fatalf("summary = %d %s", summary.status, summary.body)
	}
	var stored asg.Summary
	summary.decode(t, &stored)
	if stored.ASGVersion != built.ASG.ASGVersion || stored.Nodes != built.ASG.Nodes {
		t.Errorf("stored summary differs from the build response: %+v", stored)
	}

	nodes := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg/nodes?kind=EntryPoint", nil, nil)
	if nodes.status != http.StatusOK {
		t.Fatalf("nodes = %d %s", nodes.status, nodes.body)
	}
	var page graph.ASGNodePage
	nodes.decode(t, &page)
	if page.Total == 0 || len(page.Nodes) == 0 {
		t.Fatalf("no entry point node returned: %s", nodes.body)
	}
	if page.Nodes[0].Kind != asg.NodeEntryPoint {
		t.Errorf("kind filter was not honoured: %+v", page.Nodes[0])
	}
	if page.Meta.SnapshotID != snapID {
		t.Errorf("node page lost provenance: %+v", page.Meta)
	}
	entryID := page.Nodes[0].ID

	// One node resolves the SCG facts it came from, which is what makes a claim
	// reviewable.
	node := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg/nodes/"+entryID, nil, nil)
	if node.status != http.StatusOK {
		t.Fatalf("node = %d %s", node.status, node.body)
	}
	var view graph.ASGNodeView
	node.decode(t, &view)
	if view.Node.ID != entryID {
		t.Errorf("node view returned %s, want %s", view.Node.ID, entryID)
	}
	if len(view.DerivedFrom) == 0 {
		t.Fatalf("node view resolved no evidence: %s", node.body)
	}
	resolved := false
	for _, ref := range view.DerivedFrom {
		if ref.Label != "" {
			resolved = true
		}
	}
	if !resolved {
		t.Errorf("derived_from entries carry no resolved label: %s", node.body)
	}
	if len(view.Outgoing) == 0 {
		t.Errorf("node view has no outgoing edge: %s", node.body)
	}

	entryPoints := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg/entrypoints", nil, nil)
	if entryPoints.status != http.StatusOK {
		t.Fatalf("entrypoints = %d %s", entryPoints.status, entryPoints.body)
	}
	var routes struct {
		EntryPoints []graph.ASGEntryPointView `json:"entry_points"`
		Total       int                       `json:"total"`
		Meta        graph.ASGMeta             `json:"meta"`
		Limitations []string                  `json:"limitations"`
		Coverage    asg.Coverage              `json:"coverage"`
		Evidence    map[string]int            `json:"evidence_counts"`
	}
	entryPoints.decode(t, &routes)
	if routes.Total == 0 || len(routes.EntryPoints) == 0 {
		t.Fatalf("no entry point returned: %s", entryPoints.body)
	}
	route := routes.EntryPoints[0]
	if !strings.Contains(route.EntryPoint.Label, "/users/:id") {
		t.Errorf("route table lost the path: %+v", route.EntryPoint)
	}
	if route.EntryPoint.Detail["framework"] != "gin" {
		t.Errorf("route table lost the framework: %+v", route.EntryPoint.Detail)
	}
	if route.Boundary == nil || route.Boundary.Subject == "" {
		t.Errorf("route table lost the trust boundary: %s", entryPoints.body)
	}
	if len(route.Controls) == 0 && len(route.Sinks) == 0 {
		t.Errorf("route carries neither a control nor a sink: %s", entryPoints.body)
	}
	// An attack-surface answer without its coverage is not usable, so the
	// response must carry the summary numbers as well.
	if len(routes.Limitations) == 0 || routes.Coverage.CallSitesExamined == 0 || len(routes.Evidence) == 0 {
		t.Errorf("entry-point answer dropped its coverage: %s", entryPoints.body)
	}

	edges := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg/edges?kind=REACHES", nil, nil)
	if edges.status != http.StatusOK {
		t.Fatalf("edges = %d %s", edges.status, edges.body)
	}
	var edgePage graph.ASGEdgePage
	edges.decode(t, &edgePage)
	if len(edgePage.Edges) == 0 {
		t.Fatalf("no REACHES edge returned: %s", edges.body)
	}
	for _, e := range edgePage.Edges {
		if e.Kind != asg.EdgeReaches {
			t.Errorf("kind filter was not honoured: %+v", e)
		}
	}

	// A filtered edge request narrows by endpoint, which is how a reviewer walks
	// outward from one node.
	fromEdges := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg/edges?kind=REACHES&from="+entryID, nil, nil)
	if fromEdges.status != http.StatusOK {
		t.Fatalf("edges from node = %d %s", fromEdges.status, fromEdges.body)
	}
	fromEdges.decode(t, &edgePage)
	if len(edgePage.Edges) == 0 {
		t.Errorf("no edge from %s: %s", entryID, fromEdges.body)
	}
}

// assertASGArtifact checks that the ASG document was written next to the frozen
// tree, under its own content-addressed name.
func assertASGArtifact(t *testing.T, workspace, snapshotID string) {
	t.Helper()
	dir := filepath.Join(workspace, "snapshots", snapshotID)
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read snapshot directory: %v", err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "asg-") && strings.HasSuffix(entry.Name(), ".json") {
			return
		}
	}
	t.Errorf("no ASG artifact in %s: %v", dir, entries)
}

func TestSnapshotCreateCanBuildASG(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	project := createProject(t, ts, asgFixtureSource(t))

	// build_graph and build_asg in one request produce the whole chain.
	create := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create: %d %s", create.status, create.body)
	}
	var created snapshotResponse
	create.decode(t, &created)
	if created.ASG == nil || created.ASG.Nodes == 0 {
		t.Fatalf("snapshot response carries no attack surface: %s", create.body)
	}
	if created.ASG.NodesByKind[string(asg.NodeEntryPoint)] == 0 {
		t.Errorf("attack surface has no entry point: %s", create.body)
	}

	// A snapshot with no SCG cannot have an attack surface: the request is
	// refused with the fix, not answered with an empty surface. A fresh project
	// is used because the snapshot above already has a stored graph.
	fresh := createProject(t, ts, asgFixtureSource(t))
	bare := do(t, ts, http.MethodPost, "/api/projects/"+fresh.Project.ID+"/snapshots",
		map[string]any{"build_asg": true}, nil)
	if bare.status != http.StatusConflict {
		t.Fatalf("build_asg without an SCG = %d, want 409 (%s)", bare.status, bare.body)
	}
	var conflict errorResponse
	bare.decode(t, &conflict)
	if conflict.Code != "scg_missing" {
		t.Errorf("code = %q, want scg_missing", conflict.Code)
	}
	if !strings.Contains(conflict.Error, "graph first") {
		t.Errorf("message is not actionable: %q", conflict.Error)
	}
}

func TestASGEndpointErrors(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createASGSnapshot(t, ts)

	// A snapshot frozen without any analysis can never have an SCG, so the build
	// is a 409 rather than a 404: the snapshot exists.
	project := createProject(t, ts, asgFixtureSource(t))
	skip := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"skip_analysis": true}, nil)
	if skip.status != http.StatusCreated {
		t.Fatalf("skip_analysis create: %d %s", skip.status, skip.body)
	}
	var skipped snapshotResponse
	skip.decode(t, &skipped)
	noGraph := skipped.Snapshot.SnapshotID

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		want   int
		code   string
	}{
		{"summary before build", http.MethodGet, "/api/snapshots/" + noGraph + "/asg", nil, http.StatusNotFound, "asg_missing"},
		{"nodes before build", http.MethodGet, "/api/snapshots/" + noGraph + "/asg/nodes", nil, http.StatusNotFound, "asg_missing"},
		{"entrypoints before build", http.MethodGet, "/api/snapshots/" + noGraph + "/asg/entrypoints", nil, http.StatusNotFound, "asg_missing"},
		{"edges before build", http.MethodGet, "/api/snapshots/" + noGraph + "/asg/edges", nil, http.StatusNotFound, "asg_missing"},
		{"build without graph", http.MethodPost, "/api/snapshots/" + noGraph + "/asg", map[string]any{}, http.StatusConflict, "scg_missing"},
		{"unknown node kind", http.MethodGet, "/api/snapshots/" + snapID + "/asg/nodes?kind=Nope", nil, http.StatusBadRequest, "invalid_request"},
		{"unknown edge kind", http.MethodGet, "/api/snapshots/" + snapID + "/asg/edges?kind=NOPE", nil, http.StatusBadRequest, "invalid_request"},
		{"unknown snapshot", http.MethodGet, "/api/snapshots/snap-00000000000000000000000000000000/asg", nil, http.StatusNotFound, "asg_missing"},
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

	// The build is a write and is gated as one; the reads are not.
	readerBuild := doAs(t, ts, readerSecret, http.MethodPost, "/api/snapshots/"+snapID+"/asg", map[string]any{}, nil)
	if readerBuild.status != http.StatusForbidden {
		t.Errorf("reader build = %d, want 403 (%s)", readerBuild.status, readerBuild.body)
	}
	noToken := doAs(t, ts, "", http.MethodGet, "/api/snapshots/"+snapID+"/asg", nil, nil)
	if noToken.status != http.StatusUnauthorized {
		t.Errorf("unauthenticated read = %d, want 401 (%s)", noToken.status, noToken.body)
	}
	noTokenBuild := doAs(t, ts, "", http.MethodPost, "/api/snapshots/"+snapID+"/asg", map[string]any{}, nil)
	if noTokenBuild.status != http.StatusUnauthorized {
		t.Errorf("unauthenticated build = %d, want 401 (%s)", noTokenBuild.status, noTokenBuild.body)
	}

	// A server without the ASG service answers 501 instead of pretending the
	// snapshot has no attack surface. Authentication runs first, so the bare
	// server still needs the test authenticator.
	bare := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer,
		WithAuth(testAuthenticator(t)),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	bareTS := httptest.NewServer(bare.Handler())
	defer bareTS.Close()
	unavailable := do(t, bareTS, http.MethodPost, "/api/snapshots/"+snapID+"/asg", map[string]any{}, nil)
	if unavailable.status != http.StatusNotImplemented {
		t.Fatalf("status = %d, want 501 (%s)", unavailable.status, unavailable.body)
	}
	var unavailableBody errorResponse
	unavailable.decode(t, &unavailableBody)
	if unavailableBody.Code != "asg_unavailable" {
		t.Errorf("code = %q, want asg_unavailable", unavailableBody.Code)
	}
}

// TestUnknownASGNodeIsNotFoundNotAsgMissing pins the distinction between "this
// snapshot has no attack surface" and "the attack surface has no such node":
// collapsing them tells an operator to rebuild when the id was simply wrong.
func TestUnknownASGNodeIsNotFoundNotAsgMissing(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createASGSnapshot(t, ts)
	if build := do(t, ts, http.MethodPost, "/api/snapshots/"+snapID+"/asg", map[string]any{}, nil); build.status != http.StatusCreated {
		t.Fatalf("build ASG: %d %s", build.status, build.body)
	}

	unknown := do(t, ts, http.MethodGet, "/api/snapshots/"+snapID+"/asg/nodes/asgn-00000000000000000000000000000000", nil, nil)
	if unknown.status != http.StatusNotFound {
		t.Fatalf("unknown node = %d, want 404 (%s)", unknown.status, unknown.body)
	}
	var body errorResponse
	unknown.decode(t, &body)
	if body.Code != "not_found" {
		t.Errorf("unknown node code = %q, want not_found", body.Code)
	}

	// A snapshot with no ASG at all still answers asg_missing.
	secondSnapID := createASGSnapshot(t, ts)
	missing := do(t, ts, http.MethodGet, "/api/snapshots/"+secondSnapID+"/asg/nodes/asgn-00000000000000000000000000000000", nil, nil)
	if missing.status != http.StatusNotFound {
		t.Fatalf("missing ASG = %d, want 404 (%s)", missing.status, missing.body)
	}
	missing.decode(t, &body)
	if body.Code != "asg_missing" {
		t.Errorf("missing ASG code = %q, want asg_missing", body.Code)
	}
}
