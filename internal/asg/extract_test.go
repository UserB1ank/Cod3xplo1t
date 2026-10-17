package asg_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const snapshotID = "snap-0123456789abcdef0123456789abcdef"

// serviceFixture is a small web service with the shapes a real attack surface
// has: two frameworks' route registrations, a CLI flag, a message consumer,
// query/path/body/file inputs, six kinds of sink, and five kinds of control.
var serviceFixture = map[string]string{
	"go.mod": "module example.invalid/svc\n\ngo 1.24\n",
	"main.go": `package main

import "example.invalid/svc/web"

func main() {
	web.Run()
}
`,
	"web/server.go": `package web

import (
	"database/sql"
	"encoding/json"
	"flag"
	"net/http"
	"os"
	"os/exec"
	"net/url"
	"path/filepath"
	"time"

	"github.com/gin-gonic/gin"
)

var listenAddr = flag.String("listen", ":8080", "address to listen on")

func Run() {
	r := gin.Default()
	r.Use(authenticate())
	r.GET("/users/:id", showUser)
	r.POST("/users", createUser)

	mux := http.NewServeMux()
	mux.HandleFunc("/health", health)

	consumer := newConsumer()
	consumer.Consume("events")

	_ = listenAddr
	mux.ListenAndServe()
}

func showUser(c *gin.Context) {
	id := c.Param("id")
	db := openDB()
	rows := db.Query("SELECT name FROM users WHERE id = ?", id)
	filepath.Clean(id)
	logQuery(rows)
}

func createUser(c *gin.Context) {
	var payload User
	body := c.Request.Body
	json.NewDecoder(body).Decode(&payload)
	ValidateUser(payload)
	if !payload.Can("write") {
		return
	}
	writeReport(payload)
	runHook(url.QueryEscape(payload.Name))
}

func ValidateUser(u User) bool { return u.Name != "" }

func health(w http.ResponseWriter, r *http.Request) {
	raw := r.URL.Query().Get("verbose")
	config, _ := os.ReadFile("config.json")
	os.WriteFile("/tmp/health.out", config, 0o644)
	http.Get("https://example.invalid/status")
	exec.Command("sh", "-c", raw)
	_ = w
}

type User struct {
	Name string
}

func (u User) Can(action string) bool { return action != "" }

func authenticate() gin.HandlerFunc { return nil }

func writeReport(u User) {
	_ = u
}

func runHook(name string) {
	_ = name
}

func logQuery(rows *sql.Rows) {
	_ = rows
}

func openDB() *sql.DB { return nil }

func newConsumer() *consumer { return &consumer{} }

type consumer struct{}

func (c *consumer) Consume(topic string) { _ = topic }

func (c *consumer) ListenAndServe() { _ = time.Second }

func (c *consumer) Subscribe(topic string) { _ = topic }
`,
}

// buildASG builds the SCG of the fixture, stores it and derives the ASG.
func buildASG(t *testing.T) (*asg.Document, *graph.ASGService) {
	t.Helper()
	tree := t.TempDir()
	for rel, content := range serviceFixture {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	builder := scg.NewBuilder(gofrontend.New())
	g, err := builder.BuildTree(context.Background(), snapshotID, tree)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	store := storage.NewMemory()
	ctx := context.Background()
	if err := store.ReplaceGraph(ctx, snapshotID, g); err != nil {
		t.Fatalf("ReplaceGraph: %v", err)
	}
	svc := graph.NewService(store, nil)
	doc, err := asg.NewBuilder(svc).Build(ctx, snapshotID)
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	return doc, graph.NewASGService(store, svc)
}

func nodesOfKind(doc *asg.Document, kind asg.NodeKind) []asg.Node {
	var out []asg.Node
	for _, n := range doc.Nodes {
		if n.Kind == kind {
			out = append(out, n)
		}
	}
	return out
}

func subjects(nodes []asg.Node) []string {
	out := make([]string, 0, len(nodes))
	for _, n := range nodes {
		out = append(out, n.Subject)
	}
	sort.Strings(out)
	return out
}

func findNode(t *testing.T, doc *asg.Document, kind asg.NodeKind, contains string) asg.Node {
	t.Helper()
	for _, n := range nodesOfKind(doc, kind) {
		if strings.Contains(n.Subject, contains) {
			return n
		}
	}
	t.Fatalf("no %s node matching %q; have %v", kind, contains, subjects(nodesOfKind(doc, kind)))
	return asg.Node{}
}

func TestExtractFindsTheAttackSurface(t *testing.T) {
	t.Parallel()
	doc, _ := buildASG(t)

	entries := subjects(nodesOfKind(doc, asg.NodeEntryPoint))
	want := []string{
		"http_route:GET /users/:id",
		"http_route:POST /users",
		"http_route:ANY /health",
		"message_consumer:Consume:events",
		"cli_command:listen",
	}
	for _, w := range want {
		found := false
		for _, s := range entries {
			if strings.Contains(s, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("entry point %q not found; got %v", w, entries)
		}
	}

	inputs := subjects(nodesOfKind(doc, asg.NodeAttackerControlledInput))
	for _, w := range []string{"input:path_param:id", "input:query_param:verbose", "input:body:", "input:file_content:"} {
		found := false
		for _, s := range inputs {
			if strings.Contains(s, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("input %q not found; got %v", w, inputs)
		}
	}

	sinks := subjects(nodesOfKind(doc, asg.NodeSensitiveOperation))
	for _, w := range []string{
		"sink:sql_execution", "sink:file_write", "sink:process_execution",
		"sink:network_request", "sink:deserialization",
	} {
		if !contains(sinks, w) {
			t.Errorf("sink %q not found; got %v", w, sinks)
		}
	}

	controls := subjects(nodesOfKind(doc, asg.NodeSecurityControl))
	for _, w := range []string{
		"control:authentication:", "control:authorization:", "control:input_validation:",
		"control:encoding:", "control:path_normalization:", "control:parameterization:sql_placeholders",
	} {
		found := false
		for _, s := range controls {
			if strings.Contains(s, w) {
				found = true
			}
		}
		if !found {
			t.Errorf("control %q not found; got %v", w, controls)
		}
	}

	assets := subjects(nodesOfKind(doc, asg.NodeAsset))
	for _, w := range []string{
		"asset:database_table:users", "asset:command:sh",
		"asset:file_path:/tmp/health.out", "asset:endpoint:https://example.invalid/status",
	} {
		if !contains(assets, w) {
			t.Errorf("asset %q not found; got %v", w, assets)
		}
	}

	boundaries := subjects(nodesOfKind(doc, asg.NodeTrustBoundary))
	for _, w := range []string{"boundary:network", "boundary:message", "boundary:process"} {
		if !contains(boundaries, w) {
			t.Errorf("boundary %q not found; got %v", w, boundaries)
		}
	}
}

func TestEntryPointsCarryTheirHandlerAndFramework(t *testing.T) {
	t.Parallel()
	doc, _ := buildASG(t)

	showUser := findNode(t, doc, asg.NodeEntryPoint, "GET /users/:id")
	if got := showUser.Detail["framework"]; got != "gin" {
		t.Errorf("framework = %q, want gin (receiver provenance gin.Default): %+v", got, showUser.Detail)
	}
	if got := showUser.Detail["handler"]; !strings.Contains(got, "showUser") {
		t.Errorf("handler = %q, want the resolved showUser symbol", got)
	}
	if got := showUser.Detail["handler_symbol_id"]; !strings.HasPrefix(got, "sym-") {
		t.Errorf("handler symbol id = %q", got)
	}
	if got := showUser.Detail["boundary"]; got != asg.BoundaryNetwork {
		t.Errorf("boundary = %q", got)
	}

	health := findNode(t, doc, asg.NodeEntryPoint, "ANY /health")
	if got := health.Detail["framework"]; got != "net/http" {
		t.Errorf("health framework = %q, want net/http (receiver provenance http.NewServeMux)", got)
	}

	consumer := findNode(t, doc, asg.NodeEntryPoint, "message_consumer")
	if got := consumer.Detail["boundary"]; got != asg.BoundaryMessage {
		t.Errorf("consumer boundary = %q, want message", got)
	}
	if got := consumer.Detail["destination"]; got != "events" {
		t.Errorf("consumer destination = %q, want events", got)
	}

	cli := findNode(t, doc, asg.NodeEntryPoint, "cli_command")
	if got := cli.Detail["boundary"]; got != asg.BoundaryProcess {
		t.Errorf("cli boundary = %q, want process", got)
	}

	// A route-shaped call whose receiver provenance is unknown must say so
	// instead of guessing a framework.
	for _, n := range nodesOfKind(doc, asg.NodeEntryPoint) {
		if attr := n.Detail["framework_attribution"]; attr == "unknown" {
			if n.Detail["framework_candidates"] == "" {
				t.Errorf("unknown attribution without candidates: %+v", n.Detail)
			}
		}
	}
}

func TestReachabilityLinksEntryPointsToSinks(t *testing.T) {
	t.Parallel()
	doc, _ := buildASG(t)

	showUser := findNode(t, doc, asg.NodeEntryPoint, "GET /users/:id")
	var reaches, protected, crosses, derived int
	reachedSubjects := map[string]bool{}
	for _, e := range doc.Edges {
		if e.From != showUser.ID {
			continue
		}
		switch e.Kind {
		case asg.EdgeReaches:
			reaches++
			for _, n := range doc.Nodes {
				if n.ID == e.To {
					reachedSubjects[n.Subject] = true
				}
			}
		case asg.EdgeProtectedBy:
			protected++
		case asg.EdgeCrosses:
			crosses++
		}
	}
	if reaches == 0 {
		t.Fatalf("no REACHES edge from the route; subjects: %v", reachedSubjects)
	}
	if !reachedSubjects["sink:sql_execution"] {
		t.Errorf("the SQL sink in the handler was not reached: %v", reachedSubjects)
	}
	if !reachedSubjects["input:path_param:id"] {
		t.Errorf("the path parameter read by the handler was not reached: %v", reachedSubjects)
	}
	// The middleware registered before the route is an observed protection.
	if protected == 0 {
		t.Error("no PROTECTED_BY edge for the route, although r.Use(...) is registered before it")
	}
	if crosses != 1 {
		t.Errorf("crosses = %d, want exactly one boundary crossing per entry point", crosses)
	}
	// The observed protection must be distinguishable from an inferred one.
	sawObserved := false
	for _, e := range doc.Edges {
		if e.From == showUser.ID && e.Kind == asg.EdgeProtectedBy && e.Evidence == asg.StatusObserved {
			sawObserved = true
		}
	}
	if !sawObserved {
		t.Error("middleware protection is not marked observed")
	}

	for _, e := range doc.Edges {
		if e.Kind == asg.EdgeDerivedFrom {
			derived++
		}
	}
	if derived == 0 {
		t.Error("no DERIVED_FROM edges: the attack surface cites nothing")
	}
	if got := showUser.Detail["reachable_sinks"]; got == "" || got == "0" {
		t.Errorf("reachable_sinks = %q, want a count", got)
	}
}

func TestEveryClaimCitesSCGEvidence(t *testing.T) {
	t.Parallel()
	doc, _ := buildASG(t)

	if len(doc.Nodes) == 0 || len(doc.Edges) == 0 {
		t.Fatal("empty document")
	}
	for _, n := range doc.Nodes {
		if len(n.SCGRefs) == 0 {
			t.Errorf("node %s (%s) has no SCG evidence", n.ID, n.Subject)
		}
		if n.Generator == "" {
			t.Errorf("node %s does not name its rule", n.ID)
		}
		if n.Evidence != asg.StatusObserved && n.Evidence != asg.StatusInferred {
			t.Errorf("node %s has evidence %q, which no rule produces in P3", n.ID, n.Evidence)
		}
	}
	for _, e := range doc.Edges {
		if len(e.SCGRefs) == 0 {
			t.Errorf("edge %s (%s) has no SCG evidence", e.ID, e.Kind)
		}
	}
	if err := doc.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if doc.Coverage.CallSitesExamined == 0 || doc.Coverage.SymbolsExamined == 0 {
		t.Errorf("coverage is empty: %+v", doc.Coverage)
	}
	joined := strings.Join(doc.Limitations, "\n")
	for _, want := range []string{
		"reachability, not dataflow",
		"not evidence that it is effective",
		"SUPPORTED_BY and VERIFIED_BY",
		"not necessarily attacker-controlled",
		"name-based",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("limitations do not mention %q:\n%s", want, joined)
		}
	}
}

func TestExtractionIsDeterministicAndVersioned(t *testing.T) {
	t.Parallel()
	first, _ := buildASG(t)
	second, _ := buildASG(t)

	first.BuiltAt, second.BuiltAt = "", ""
	first.BuildDurationMS, second.BuildDurationMS = 0, 0
	a, err := first.JSON()
	if err != nil {
		t.Fatal(err)
	}
	b, err := second.JSON()
	if err != nil {
		t.Fatal(err)
	}
	if string(a) != string(b) {
		t.Error("two extractions of the same snapshot differ")
	}
	if first.ASGVersion != second.ASGVersion || !strings.HasPrefix(first.ASGVersion, "asg-") {
		t.Errorf("asg version is not stable: %q vs %q", first.ASGVersion, second.ASGVersion)
	}
	// The version must identify the rule set and the SCG it read.
	base := asg.Version(snapshotID, first.SCGVersion, first.Engine, first.RulesetHash)
	if base != first.ASGVersion {
		t.Errorf("version = %q, want hash(snapshot, scg, engine, ruleset) = %q", first.ASGVersion, base)
	}
	if other := asg.Version(snapshotID, first.SCGVersion, first.Engine, "different-rules"); other == first.ASGVersion {
		t.Error("asg version ignores the rule set")
	}
	if other := asg.Version(snapshotID, "graph-different", first.Engine, first.RulesetHash); other == first.ASGVersion {
		t.Error("asg version ignores the SCG version")
	}
	if doc, err := json.Marshal(first); err != nil || len(doc) == 0 {
		t.Errorf("document is not serialisable: %v", err)
	}
}

func TestUnattributableRouteIsRecordedWithoutFabrication(t *testing.T) {
	t.Parallel()
	tree := t.TempDir()
	files := map[string]string{
		"go.mod": "module example.invalid/odd\n\ngo 1.24\n",
		"main.go": `package main

func main() {
	unknownRouter()
	notARoute("5m", job)
}

func unknownRouter() {}

func notARoute(interval string, f func()) {}

func job() {}
`,
	}
	for rel, content := range files {
		p := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	scgBuilder := scg.NewBuilder(gofrontend.New())
	g, err := scgBuilder.BuildTree(context.Background(), snapshotID, tree)
	if err != nil {
		t.Fatal(err)
	}
	store := storage.NewMemory()
	ctx := context.Background()
	if err := store.ReplaceGraph(ctx, snapshotID, g); err != nil {
		t.Fatal(err)
	}
	doc, err := asg.NewBuilder(graph.NewService(store, nil)).Build(ctx, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	// Neither call is a route registration: no entry point may be invented.
	if entries := nodesOfKind(doc, asg.NodeEntryPoint); len(entries) != 0 {
		t.Errorf("entry points invented from non-registration calls: %v", subjects(entries))
	}
}

func TestExtractionRefusesASnapshotWithoutAGraph(t *testing.T) {
	t.Parallel()
	store := storage.NewMemory()
	_, err := asg.NewBuilder(graph.NewService(store, nil)).Build(context.Background(), snapshotID)
	if err == nil {
		t.Fatal("extraction succeeded on a snapshot with no SCG")
	}
	if !strings.Contains(err.Error(), "no source code graph") {
		t.Errorf("error = %v, want ErrNoSCG", err)
	}
}

func TestASGQueryServiceExposesTheRouteTable(t *testing.T) {
	t.Parallel()
	doc, svc := buildASG(t)
	ctx := context.Background()

	if err := svcReplaceASG(t, svc, doc); err != nil {
		t.Fatalf("ReplaceASG: %v", err)
	}
	summary, err := svc.Summary(ctx, snapshotID)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	if summary.NodesByKind[string(asg.NodeEntryPoint)] == 0 || summary.Nodes != len(doc.Nodes) {
		t.Errorf("summary = %+v", summary)
	}

	page, err := svc.Nodes(ctx, snapshotID, graph.ASGNodeQuery{Kinds: []asg.NodeKind{asg.NodeSensitiveOperation}, Limit: 100})
	if err != nil {
		t.Fatalf("Nodes: %v", err)
	}
	if page.Total == 0 || len(page.Nodes) == 0 {
		t.Fatalf("no sinks listed: %+v", page)
	}
	if page.Meta.ASGVersion != doc.ASGVersion {
		t.Errorf("meta lost the ASG version: %+v", page.Meta)
	}

	entry, err := svc.Node(ctx, snapshotID, findNode(t, doc, asg.NodeEntryPoint, "GET /users/:id").ID)
	if err != nil {
		t.Fatalf("Node: %v", err)
	}
	if len(entry.Outgoing) == 0 || len(entry.DerivedFrom) == 0 {
		t.Fatalf("node view has no edges or evidence: %+v", entry)
	}
	resolved := false
	for _, ref := range entry.DerivedFrom {
		if ref.Kind == "call_site" && ref.Line > 0 {
			resolved = true
		}
	}
	if !resolved {
		t.Errorf("DERIVED_FROM references were not resolved to SCG facts: %+v", entry.DerivedFrom)
	}

	entries, err := svc.EntryPoints(ctx, snapshotID, 50, 0)
	if err != nil {
		t.Fatalf("EntryPoints: %v", err)
	}
	var users *graph.ASGEntryPointView
	for i := range entries.EntryPoints {
		if strings.Contains(entries.EntryPoints[i].EntryPoint.Subject, "GET /users/:id") {
			users = &entries.EntryPoints[i]
		}
	}
	if users == nil {
		t.Fatalf("route missing from the route table: %+v", entries.EntryPoints)
	}
	if users.Boundary == nil || users.Boundary.Subject != "boundary:network" {
		t.Errorf("boundary = %+v", users.Boundary)
	}
	if len(users.Sinks) == 0 || len(users.Inputs) == 0 {
		t.Errorf("route table has no sinks or inputs: %+v", users)
	}
	if users.ObservedControls == 0 {
		t.Error("the middleware registration is not reported as an observed control")
	}

	edges, err := svc.Edges(ctx, snapshotID, nil, nil, []asg.EdgeKind{asg.EdgeReaches}, 100)
	if err != nil {
		t.Fatalf("Edges: %v", err)
	}
	if len(edges.Edges) == 0 {
		t.Error("no REACHES edges listed")
	}
	for _, e := range edges.Edges {
		if e.Kind != asg.EdgeReaches {
			t.Errorf("kind filter leaked %s", e.Kind)
		}
	}

	if _, err := svc.Summary(ctx, "snap-fedcba9876543210fedcba9876543210"); err == nil {
		t.Error("summary of an unknown snapshot succeeded")
	}
}

// svcReplaceASG stores the document through the store the service reads.
func svcReplaceASG(t *testing.T, svc *graph.ASGService, doc *asg.Document) error {
	t.Helper()
	return svc.Store.ReplaceASG(context.Background(), doc.SnapshotID, doc)
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}
