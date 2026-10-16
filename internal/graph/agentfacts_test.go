package graph_test

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const agentSnapID = "snap-0123456789abcdef0123456789abcdef"

// agentFixtureFiles is a small web service with the shapes a real path has: two
// frameworks' routes, a CLI flag, a message consumer, several input kinds and
// several sink kinds. One line of the handler contains multi-byte runes so the
// slice's rune-boundary truncation is exercised by the real fixture.
var agentFixtureFiles = map[string]string{
	"go.mod": "module example.invalid/svc\n\ngo 1.24\n",
	"main.go": `package main

import "example.invalid/svc/web"

func main() {
	web.Run()
}
`,
	// Two declarations share one line on purpose: their recorded windows are
	// identical, which is what exercises the slice's window-level deduplication.
	"web/pair.go": `package web

var twin = 1; func twinFn() int { return twin }
`,
	"web/server.go": `package web

import (
	"database/sql"
	"encoding/json"
	"flag"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"

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
	// 入力はここで検証する — 検証はユーザー入力に対して行われる
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

func (c *consumer) ListenAndServe() {}

func (c *consumer) Subscribe(topic string) { _ = topic }
`,
}

// agentResolver serves one snapshot record whose frozen tree lives in a temp
// directory, which is what the slice service needs to read source.
type agentResolver struct{ dir string }

func (r agentResolver) Load(id string) (*repository.Snapshot, error) {
	if id != agentSnapID {
		return nil, repository.ErrSnapshotNotFound
	}
	return &repository.Snapshot{SnapshotID: id, Dir: r.dir}, nil
}

// agentFixture is one real graph: SCG stored, ASG derived and stored, and an audit
// whose queued paths were generated from them by the real engine.
type agentFixture struct {
	store   *storage.Memory
	scg     *graph.Service
	asg     *graph.ASGService
	audit   *path.Service
	graph   *scg.Graph
	auditID string
	paths   []path.Path
}

func newAgentFixture(t *testing.T) *agentFixture {
	t.Helper()
	dir := t.TempDir()
	tree := filepath.Join(dir, repository.TreeDirName)
	for rel, content := range agentFixtureFiles {
		target := filepath.Join(tree, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ctx := context.Background()
	built, err := scg.NewBuilder(gofrontend.New()).BuildTree(ctx, agentSnapID, tree)
	if err != nil {
		t.Fatalf("BuildTree: %v", err)
	}
	store := storage.NewMemory()
	if err := store.ReplaceGraph(ctx, agentSnapID, built); err != nil {
		t.Fatalf("ReplaceGraph: %v", err)
	}
	scgService := graph.NewService(store, agentResolver{dir: dir})
	document, err := asg.NewBuilder(scgService).Build(ctx, agentSnapID)
	if err != nil {
		t.Fatalf("asg.Build: %v", err)
	}
	if err := store.ReplaceASG(ctx, agentSnapID, document); err != nil {
		t.Fatalf("ReplaceASG: %v", err)
	}
	asgService := graph.NewASGService(store, scgService)
	facts := graph.NewPathFacts(scgService, asgService, store)
	auditService := path.NewService(store, path.NewEngine(facts, facts))
	result, err := auditService.CreateAudit(ctx, path.CreateAuditRequest{
		SnapshotID: agentSnapID,
		Budget:     path.DefaultBudget(),
		Limits:     path.DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	if len(result.Paths) == 0 {
		t.Fatal("the fixture produced no paths")
	}
	return &agentFixture{
		store: store, scg: scgService, asg: asgService, audit: auditService,
		graph: built, auditID: result.Audit.ID, paths: result.Paths,
	}
}

// pathWithSymbol returns one generated path that names a symbol the snapshot can
// resolve, together with that symbol.
func (f *agentFixture) pathWithSymbol(t *testing.T) (path.Path, scg.Symbol) {
	t.Helper()
	for _, p := range f.paths {
		for _, ref := range p.SCGRefs {
			if !strings.HasPrefix(ref, "sym-") {
				continue
			}
			sym, _, err := f.scg.Symbol(context.Background(), agentSnapID, ref, graph.Options{})
			if err == nil {
				return p, *sym
			}
		}
	}
	t.Fatalf("no generated path names a resolvable symbol; refs: %v", pathRefs(f.paths))
	return path.Path{}, scg.Symbol{}
}

func pathRefs(paths []path.Path) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, p.ID+"="+strings.Join(p.SCGRefs, ","))
	}
	sort.Strings(out)
	return out
}

// symbolID returns the stored id of a qualified name.
func (f *agentFixture) symbolID(t *testing.T, qualified string) string {
	t.Helper()
	for _, sym := range f.graph.Symbols {
		if sym.QualifiedName == qualified {
			return sym.ID
		}
	}
	t.Fatalf("symbol %q is not in the fixture graph", qualified)
	return ""
}

// fileLines returns the lines of one fixture file.
func fileLines(t *testing.T, rel string) []string {
	t.Helper()
	content, ok := agentFixtureFiles[rel]
	if !ok {
		t.Fatalf("no fixture file %q", rel)
	}
	return strings.Split(content, "\n")
}

// declarationContent is what the slice service reads for a symbol: its recorded
// declaration window, joined the way the agent receives it.
func declarationContent(t *testing.T, sym scg.Symbol) string {
	t.Helper()
	lines := fileLines(t, sym.File)
	if sym.StartLine < 1 || sym.EndLine > len(lines) {
		t.Fatalf("symbol %s window %d-%d is outside %s (%d lines)", sym.ID, sym.StartLine, sym.EndLine, sym.File, len(lines))
	}
	return strings.Join(lines[sym.StartLine-1:sym.EndLine], "\n")
}

func testFacts(scgService *graph.Service, asgService *graph.ASGService) *graph.AgentFacts {
	facts := graph.NewAgentFacts(scgService, asgService, agent.BuildOptions{AllowedTools: graph.AgentToolNames()})
	stamp := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
	facts.Now = func() time.Time { return stamp }
	return facts
}

func TestBuildTaskCarriesThePathAndItsSlice(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	p, sym := fixture.pathWithSymbol(t)
	facts := testFacts(fixture.scg, fixture.asg)
	policy := agent.DefaultExplorationPolicy()

	task, err := facts.BuildTask(context.Background(), p, policy)
	if err != nil {
		t.Fatalf("BuildTask: %v", err)
	}
	if err := agent.ValidateTask(task); err != nil {
		t.Fatalf("the built task does not validate: %v", err)
	}
	if task.SchemaVersion != agent.SchemaVersion {
		t.Errorf("schema version = %d, want %d", task.SchemaVersion, agent.SchemaVersion)
	}
	if task.PathID != p.ID || task.SnapshotID != p.SnapshotID || task.AuditID != p.AuditID {
		t.Errorf("ids = %q/%q/%q, want %q/%q/%q", task.PathID, task.SnapshotID, task.AuditID, p.ID, p.SnapshotID, p.AuditID)
	}
	if task.SecurityGoal != strings.Join(p.Objectives, "; ") {
		t.Errorf("security goal = %q, want the path objectives %v", task.SecurityGoal, p.Objectives)
	}
	if !strings.Contains(task.PathSummary, p.EntrySubject) || !strings.Contains(task.PathSummary, p.TargetSubject) {
		t.Errorf("path summary %q does not name both ends", task.PathSummary)
	}
	if !strings.Contains(task.PathSummary, string(p.PathStatus)) {
		t.Errorf("path summary %q does not state the path status %q", task.PathSummary, p.PathStatus)
	}

	if got := task.SourceSinkRefs; got.EntryNodeID != p.EntryNodeID || got.TargetNodeID != p.TargetNodeID ||
		got.EntrySubject != p.EntrySubject || got.TargetSubject != p.TargetSubject ||
		strings.Join(got.SCGRefs, ",") != strings.Join(p.SCGRefs, ",") ||
		strings.Join(got.ASGRefs, ",") != strings.Join(p.ASGRefs, ",") {
		t.Errorf("source sink refs were not copied: %+v", got)
	}
	if strings.Join(task.UnresolvedQuestions, "|") != strings.Join(p.OpenQuestions, "|") {
		t.Errorf("unresolved questions were not copied: %v", task.UnresolvedQuestions)
	}

	if len(task.MinimalCodeSlice) == 0 {
		t.Fatal("the task carries no code slice")
	}
	found := false
	for _, section := range task.MinimalCodeSlice {
		if section.Symbol == sym.QualifiedName && strings.Contains(section.Content, "func showUser") {
			found = true
		}
		if section.File == "" && section.Content != "" {
			t.Errorf("a section with content has no file: %+v", section)
		}
	}
	if !found {
		t.Errorf("the slice does not carry %s: %+v", sym.QualifiedName, task.MinimalCodeSlice)
	}

	if len(task.EvidenceRefs) == 0 {
		t.Fatal("the task carries no evidence refs")
	}
	if len(task.EvidenceRefs) > agent.DefaultBuildOptions().MaxEvidenceRefs {
		t.Errorf("evidence refs = %d, above the bound", len(task.EvidenceRefs))
	}
	seen := map[string]bool{}
	ends := map[string]bool{p.EntryNodeID: false, p.TargetNodeID: false}
	for _, ref := range task.EvidenceRefs {
		if seen[ref.ID] {
			t.Errorf("evidence ref %s appears twice", ref.ID)
		}
		seen[ref.ID] = true
		if ref.Kind == "" {
			t.Errorf("evidence ref %s has no kind", ref.ID)
		}
		if _, ok := ends[ref.ID]; ok {
			ends[ref.ID] = true
		}
		if ref.File != "" && ref.Line <= 0 {
			t.Errorf("evidence ref %s has a file without a line: %+v", ref.ID, ref)
		}
	}
	for id, present := range ends {
		if !present {
			t.Errorf("the path end %s is missing from the evidence refs", id)
		}
	}

	if got := strings.Join(task.Exploration.AllowedTools, ","); got != strings.Join(graph.AgentToolNames(), ",") {
		t.Errorf("advertised tools = %q, want the registered toolset %v", got, graph.AgentToolNames())
	}
	if task.Budget.TimeoutSeconds != policy.TimeoutSeconds || task.Budget.TokenBudget != policy.TokenBudget {
		t.Errorf("budget = %+v, want the policy's %d/%d", task.Budget, policy.TimeoutSeconds, policy.TokenBudget)
	}
	if want := agent.NowString(time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)); task.CreatedAt != want {
		t.Errorf("created_at = %q, want the injected clock %q", task.CreatedAt, want)
	}
	if len(task.Limitations) == 0 || len(task.Limitations) > 12 {
		t.Errorf("limitations = %v, want a bounded non-empty list", task.Limitations)
	}
}

func TestBuildTaskAdvertisesNothingWhenNoToolIsAllowed(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	p, _ := fixture.pathWithSymbol(t)
	facts := graph.NewAgentFacts(fixture.scg, fixture.asg, agent.BuildOptions{})

	task, err := facts.BuildTask(context.Background(), p, agent.DefaultExplorationPolicy())
	if err != nil {
		t.Fatalf("BuildTask: %v", err)
	}
	if err := agent.ValidateTask(task); err != nil {
		t.Fatalf("the built task does not validate: %v", err)
	}
	if len(task.Exploration.AllowedTools) != 0 {
		t.Errorf("allowed tools = %v, want none: an unconfigured toolset advertises nothing", task.Exploration.AllowedTools)
	}
	for _, name := range graph.AgentToolNames() {
		if task.Exploration.Allows(name) {
			t.Errorf("tool %s is advertised to a run that must not call it", name)
		}
	}
}

func TestBuildTaskRejectsAPathWithoutAnEnd(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	p, _ := fixture.pathWithSymbol(t)
	facts := testFacts(fixture.scg, fixture.asg)

	broken := p
	broken.EntryNodeID = ""
	if _, err := facts.BuildTask(context.Background(), broken, agent.DefaultExplorationPolicy()); err == nil {
		t.Fatal("BuildTask accepted a path with no entry node: ValidateTask must be enforced")
	}

	noSnapshot := p
	noSnapshot.SnapshotID = ""
	if _, err := facts.BuildTask(context.Background(), noSnapshot, agent.DefaultExplorationPolicy()); err == nil {
		t.Fatal("BuildTask accepted a path with no snapshot id")
	}
}

func TestCodeSliceRespectsItsLineAndSectionBounds(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	p, sym := fixture.pathWithSymbol(t)
	facts := testFacts(fixture.scg, fixture.asg)
	ctx := context.Background()

	// The line budget cuts the declaration and says so.
	sections, err := facts.CodeSlice(ctx, agent.SliceRequest{
		SnapshotID: agentSnapID, PathID: p.ID, SymbolIDs: []string{sym.ID}, MaxLines: 3, MaxSections: 2,
	})
	if err != nil {
		t.Fatalf("CodeSlice: %v", err)
	}
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1: %+v", len(sections), sections)
	}
	used := 0
	totalRunes := 0
	for _, section := range sections {
		used += section.EndLine - section.StartLine + 1
		totalRunes += utf8.RuneCountInString(section.Content)
	}
	if used > 3 {
		t.Errorf("the slice used %d line(s), above the bound of 3", used)
	}
	lines := fileLines(t, sym.File)
	want := strings.Join(lines[sym.StartLine-1:sym.StartLine-1+used], "\n")
	if totalRunes != utf8.RuneCountInString(want) {
		t.Errorf("total runes = %d, want %d (%q)", totalRunes, utf8.RuneCountInString(want), want)
	}
	if !strings.Contains(sections[0].Reason, "truncated to 3 of") ||
		!strings.Contains(sections[0].Reason, "task line budget of 3") {
		t.Errorf("the cut is not explained: %q", sections[0].Reason)
	}

	// The section cap holds even with more symbols than slots.
	other := fixture.symbolID(t, "example.invalid/svc/web.health")
	sections, err = facts.CodeSlice(ctx, agent.SliceRequest{
		SnapshotID: agentSnapID, SymbolIDs: []string{sym.ID, other}, MaxLines: 200, MaxSections: 1,
	})
	if err != nil {
		t.Fatalf("CodeSlice: %v", err)
	}
	if len(sections) > 1 {
		t.Errorf("sections = %d, want at most 1", len(sections))
	}
}

func TestCodeSliceDeduplicatesAndReportsSkips(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	_, sym := fixture.pathWithSymbol(t)
	facts := testFacts(fixture.scg, fixture.asg)
	ctx := context.Background()

	sections, err := facts.CodeSlice(ctx, agent.SliceRequest{
		SnapshotID: agentSnapID, SymbolIDs: []string{sym.ID, sym.ID}, MaxLines: 240, MaxSections: 6,
	})
	if err != nil {
		t.Fatalf("CodeSlice: %v", err)
	}
	if len(sections) != 1 {
		t.Errorf("a repeated symbol produced %d section(s), want 1: %+v", len(sections), sections)
	}

	// Two different symbols can share one recorded window (the fixture declares a
	// var and a function on one line). The second window is already covered by the
	// first, so the agent is not handed the same source twice.
	twin := fixture.symbolID(t, "example.invalid/svc/web.twin")
	twinFn := fixture.symbolID(t, "example.invalid/svc/web.twinFn")
	sections, err = facts.CodeSlice(ctx, agent.SliceRequest{
		SnapshotID: agentSnapID, SymbolIDs: []string{twin, twinFn}, MaxLines: 240, MaxSections: 6,
	})
	if err != nil {
		t.Fatalf("CodeSlice: %v", err)
	}
	if len(sections) != 1 {
		t.Errorf("two symbols over one window produced %d section(s), want 1: %+v", len(sections), sections)
	}

	// A symbol the snapshot cannot resolve is reported, and the resolvable one is
	// still delivered.
	sections, err = facts.CodeSlice(ctx, agent.SliceRequest{
		SnapshotID: agentSnapID, SymbolIDs: []string{"sym-does-not-exist", sym.ID}, MaxLines: 240, MaxSections: 6,
	})
	if err != nil {
		t.Fatalf("CodeSlice: %v", err)
	}
	if len(sections) != 2 {
		t.Fatalf("sections = %d, want the declaration plus one skip notice: %+v", len(sections), sections)
	}
	content, notice := 0, 0
	for _, section := range sections {
		if section.Content != "" {
			content++
		}
		if strings.Contains(section.Reason, "sym-does-not-exist") {
			notice++
		}
	}
	if content != 1 || notice != 1 {
		t.Errorf("content sections = %d, skip notices = %d: %+v", content, notice, sections)
	}
}

func TestCodeSliceCutsContentOnARuneBoundary(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	_, sym := fixture.pathWithSymbol(t)
	facts := testFacts(fixture.scg, fixture.asg)
	facts.MaxSectionRunes = 40

	sections, err := facts.CodeSlice(context.Background(), agent.SliceRequest{
		SnapshotID: agentSnapID, SymbolIDs: []string{sym.ID}, MaxLines: 240, MaxSections: 2,
	})
	if err != nil {
		t.Fatalf("CodeSlice: %v", err)
	}
	if len(sections) != 1 {
		t.Fatalf("sections = %d, want 1", len(sections))
	}
	section := sections[0]
	if !utf8.ValidString(section.Content) {
		t.Fatalf("the cut split a rune: %q", section.Content)
	}
	if got := utf8.RuneCountInString(section.Content); got != 40 {
		t.Errorf("content = %d rune(s), want the cap of 40: %q", got, section.Content)
	}
	if !strings.HasPrefix(declarationContent(t, sym), section.Content) {
		t.Errorf("the cut content is not a prefix of the declaration: %q", section.Content)
	}
	if !strings.Contains(section.Reason, "rune") {
		t.Errorf("the rune cut is not explained: %q", section.Reason)
	}
	if !strings.Contains(section.Content, "入") {
		t.Errorf("the multi-byte fixture line was not reached: %q", section.Content)
	}
}

func TestTaskLimitationsCarryTheResolutionMixAndTheStandards(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	facts := testFacts(fixture.scg, fixture.asg)
	ctx := context.Background()

	limitations, err := facts.TaskLimitations(ctx, agentSnapID)
	if err != nil {
		t.Fatalf("TaskLimitations: %v", err)
	}
	if len(limitations) == 0 || len(limitations) > 12 {
		t.Fatalf("limitations = %v, want a bounded non-empty list", limitations)
	}
	if !sort.StringsAreSorted(limitations) {
		t.Errorf("limitations are not sorted: %v", limitations)
	}
	seen := map[string]bool{}
	for _, limitation := range limitations {
		if seen[limitation] {
			t.Errorf("limitation appears twice: %q", limitation)
		}
		seen[limitation] = true
	}

	summary, err := fixture.scg.Summary(ctx, agentSnapID)
	if err != nil {
		t.Fatalf("Summary: %v", err)
	}
	resolved := summary.Resolution.Resolved + summary.Resolution.ResolvedBestEffort
	unresolved := summary.Resolution.Ambiguous + summary.Resolution.Dynamic +
		summary.Resolution.External + summary.Resolution.Unsupported
	if resolved == 0 || unresolved == 0 {
		t.Fatalf("the fixture is not discriminating: resolved=%d unresolved=%d", resolved, unresolved)
	}
	joined := strings.Join(limitations, "\n")
	if !strings.Contains(joined, "left "+itoa(unresolved)+" unresolved") {
		t.Errorf("the resolution mix does not state %d unresolved call site(s): %v", unresolved, limitations)
	}
	if !strings.Contains(joined, "resolved "+itoa(resolved)+" of "+itoa(resolved+unresolved)) {
		t.Errorf("the resolution mix does not state %d of %d resolved: %v", resolved, resolved+unresolved, limitations)
	}
	if !strings.Contains(joined, "call-graph reachability, not dataflow") {
		t.Errorf("the standard reachability statement is missing: %v", limitations)
	}
	if !strings.Contains(joined, "a control's presence on a path is not its effectiveness") {
		t.Errorf("the standard control statement is missing: %v", limitations)
	}

	asgSummary, err := fixture.asg.Summary(ctx, agentSnapID)
	if err != nil {
		t.Fatalf("ASG Summary: %v", err)
	}
	if len(asgSummary.Limitations) == 0 {
		t.Fatal("the fixture attack surface states no limitations")
	}
	copied := 0
	for i, limitation := range asgSummary.Limitations {
		if i >= 5 {
			break
		}
		if strings.Contains(joined, limitation) {
			copied++
		}
	}
	if copied != min(5, len(asgSummary.Limitations)) {
		t.Errorf("only %d of the attack surface's first %d limitation(s) were carried forward", copied, min(5, len(asgSummary.Limitations)))
	}
}

func TestTaskLimitationsDegradeWithoutASummary(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	facts := testFacts(fixture.scg, fixture.asg)

	limitations, err := facts.TaskLimitations(context.Background(), "snap-unknown")
	if err != nil {
		t.Fatalf("TaskLimitations on an unknown snapshot: %v", err)
	}
	joined := strings.Join(limitations, "\n")
	if !strings.Contains(joined, "call-graph summary could not be read") ||
		!strings.Contains(joined, "attack-surface summary could not be read") {
		t.Errorf("the missing summaries are not reported: %v", limitations)
	}
	if !strings.Contains(joined, "not dataflow") {
		t.Errorf("the standard statements were dropped: %v", limitations)
	}
}

func itoa(value int) string { return strconv.Itoa(value) }
