package graph_test

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// agentToolRegistry builds the real registry over the real fixture.
func agentToolRegistry(t *testing.T, fixture *agentFixture) *agent.Registry {
	t.Helper()
	registry := agent.NewRegistry()
	graph.RegisterAgentTools(registry, fixture.scg, fixture.asg, fixture.audit, fixture.store)
	return registry
}

// agentToolArgs is one valid argument map per tool, so every test can exercise the
// whole toolset without inventing arguments twice.
func agentToolArgs(t *testing.T, fixture *agentFixture) map[string]map[string]string {
	t.Helper()
	p, sym := fixture.pathWithSymbol(t)
	return map[string]map[string]string{
		graph.ToolGetSymbol: {"snapshot_id": agentSnapID, "symbol_id": sym.ID},
		graph.ToolListSymbols: {
			"snapshot_id": agentSnapID, "name_contains": "showUser", "limit": "5",
		},
		graph.ToolGetCallers: {"snapshot_id": agentSnapID, "symbol_id": sym.ID, "max_depth": "2"},
		graph.ToolGetCallees: {"snapshot_id": agentSnapID, "symbol_id": sym.ID, "max_depth": "2"},
		graph.ToolFindCallPaths: {
			"snapshot_id": agentSnapID, "source_symbol_id": sym.ID, "sink_symbol_id": sym.ID, "max_paths": "3",
		},
		graph.ToolGetCodeSlice: {"snapshot_id": agentSnapID, "symbol_id": sym.ID, "include": "calls", "max_lines": "30"},
		graph.ToolGraphSummary: {"snapshot_id": agentSnapID},
		graph.ToolGetPath:      {"path_id": p.ID},
		graph.ToolListAuditPaths: {
			"audit_id": fixture.auditID, "limit": "5",
		},
		graph.ToolListHypotheses: {"audit_id": fixture.auditID, "limit": "5"},
	}
}

func lookupTool(t *testing.T, registry *agent.Registry, name string) agent.ToolExecutor {
	t.Helper()
	tool, ok := registry.Lookup(name)
	if !ok {
		t.Fatalf("tool %s is not registered", name)
	}
	return tool
}

func callTool(t *testing.T, registry *agent.Registry, name string, args map[string]string) agent.ToolResult {
	t.Helper()
	result, err := lookupTool(t, registry, name).Call(context.Background(), args)
	if err != nil {
		t.Fatalf("%s: unexpected error: %v", name, err)
	}
	return result
}

func TestAgentToolNamesMatchTheRegisteredToolset(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	registry := agentToolRegistry(t, fixture)

	names := graph.AgentToolNames()
	if !sort.StringsAreSorted(names) {
		t.Errorf("the advertised tool names are not sorted: %v", names)
	}
	if len(names) != 10 {
		t.Errorf("advertised tools = %d, want 10: %v", len(names), names)
	}
	registered := registry.Names()
	if strings.Join(registered, ",") != strings.Join(names, ",") {
		t.Errorf("registered tools %v do not match the advertised %v", registered, names)
	}
	seen := map[string]bool{}
	for _, name := range names {
		if seen[name] {
			t.Errorf("tool %s is advertised twice", name)
		}
		seen[name] = true
		description := lookupTool(t, registry, name).Describe()
		if strings.TrimSpace(description) == "" {
			t.Errorf("tool %s has no description", name)
		}
		if strings.Contains(description, "\n") {
			t.Errorf("tool %s describes itself in more than one line: %q", name, description)
		}
	}

	// A copy, so a caller cannot reorder the contract for everyone.
	names[0] = "mutated"
	if graph.AgentToolNames()[0] == "mutated" {
		t.Error("AgentToolNames returns the package slice instead of a copy")
	}
}

func TestAgentToolsAnswerAValidArgument(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	registry := agentToolRegistry(t, fixture)
	p, sym := fixture.pathWithSymbol(t)

	for name, args := range agentToolArgs(t, fixture) {
		result := callTool(t, registry, name, args)
		if !result.OK {
			t.Errorf("%s: not ok: %s", name, result.Error)
			continue
		}
		if strings.TrimSpace(result.Result) == "" {
			t.Errorf("%s: returned an empty answer", name)
		}
		if result.Tool != name {
			t.Errorf("%s: result names the tool %q", name, result.Tool)
		}
	}

	// The answers a caller depends on are actually there.
	if result := callTool(t, registry, graph.ToolGetSymbol,
		map[string]string{"snapshot_id": agentSnapID, "symbol_id": sym.ID}); !strings.Contains(result.Result, "showUser") {
		t.Errorf("get_symbol does not name the symbol: %s", result.Result)
	}
	if result := callTool(t, registry, graph.ToolGetCodeSlice,
		map[string]string{"snapshot_id": agentSnapID, "symbol_id": sym.ID}); !strings.Contains(result.Result, "func showUser") {
		t.Errorf("get_code_slice does not return source: %s", result.Result)
	}
	if result := callTool(t, registry, graph.ToolGraphSummary,
		map[string]string{"snapshot_id": agentSnapID}); !strings.Contains(result.Result, "resolution") {
		t.Errorf("graph_summary does not carry the resolution mix: %s", result.Result)
	}
	if result := callTool(t, registry, graph.ToolGetPath,
		map[string]string{"path_id": p.ID}); !strings.Contains(result.Result, p.EntryNodeID) {
		t.Errorf("get_path does not carry the path: %s", result.Result)
	}
	if result := callTool(t, registry, graph.ToolGetCallers,
		map[string]string{"snapshot_id": agentSnapID, "symbol_id": sym.ID}); !result.OK {
		t.Errorf("get_callers: %s", result.Error)
	}

	// A valid query that finds nothing is an empty answer, not a failure.
	result := callTool(t, registry, graph.ToolListHypotheses, map[string]string{"audit_id": "audit-nobody"})
	if !result.OK {
		t.Errorf("an empty hypothesis list must be a valid empty answer: %s", result.Error)
	}
	if !strings.Contains(result.Result, `"total":0`) {
		t.Errorf("the empty page does not report its total: %s", result.Result)
	}
}

func TestAgentToolsRejectABadArgumentWithoutFailing(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	registry := agentToolRegistry(t, fixture)
	ctx := context.Background()

	for _, name := range graph.AgentToolNames() {
		result, err := lookupTool(t, registry, name).Call(ctx, map[string]string{"nonsense": "1"})
		if err != nil {
			t.Errorf("%s: a bad argument must not fail the call: %v", name, err)
			continue
		}
		if result.OK {
			t.Errorf("%s: accepted an argument it does not define", name)
		}
		if !strings.Contains(result.Error, agent.ErrInvalidArgument.Error()) {
			t.Errorf("%s: error %q does not name the invalid argument", name, result.Error)
		}
	}

	// The type of an argument is checked, not coerced.
	result := callTool(t, registry, graph.ToolListSymbols, map[string]string{"snapshot_id": agentSnapID, "limit": "many"})
	if result.OK || !strings.Contains(result.Error, "must be an integer") {
		t.Errorf("a non-integer limit was not rejected: %+v", result)
	}

	// An unknown kind must not silently widen the search.
	result = callTool(t, registry, graph.ToolListSymbols, map[string]string{"snapshot_id": agentSnapID, "kind": "wormhole"})
	if result.OK || !strings.Contains(result.Error, "unknown kind") {
		t.Errorf("an unknown kind was not rejected: %+v", result)
	}

	// An unscoped hypothesis query would scan every claim in the platform.
	result = callTool(t, registry, graph.ToolListHypotheses, map[string]string{"limit": "5"})
	if result.OK || !strings.Contains(result.Error, "is required") {
		t.Errorf("an unscoped hypothesis query was accepted: %+v", result)
	}

	// A slice needs a selector, and the selector must be one the service knows.
	result = callTool(t, registry, graph.ToolGetCodeSlice, map[string]string{"snapshot_id": agentSnapID})
	if result.OK || !strings.Contains(result.Error, "symbol_id or file is required") {
		t.Errorf("get_code_slice accepted a slice with no selector: %+v", result)
	}
	result = callTool(t, registry, graph.ToolGetCodeSlice,
		map[string]string{"snapshot_id": agentSnapID, "file": "web/server.go", "include": "everything"})
	if result.OK || !strings.Contains(result.Error, "unknown include") {
		t.Errorf("get_code_slice accepted an unknown include: %+v", result)
	}

	// A missing service is reported, not dereferenced.
	unwired := agent.NewRegistry()
	graph.RegisterAgentTools(unwired, fixture.scg, fixture.asg, fixture.audit, nil)
	result = callTool(t, unwired, graph.ToolListHypotheses, map[string]string{"audit_id": "audit-any"})
	if result.OK || !strings.Contains(result.Error, "not configured") {
		t.Errorf("a tool without its store must say so: %+v", result)
	}
}

func TestAgentToolsReportWhenACapWasHit(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	registry := agentToolRegistry(t, fixture)
	symbolID := fixture.symbolID(t, "example.invalid/svc/web.showUser")

	result := callTool(t, registry, graph.ToolListSymbols, map[string]string{"snapshot_id": agentSnapID, "limit": "100000"})
	if !result.OK {
		t.Fatalf("list_symbols: %s", result.Error)
	}
	if !strings.Contains(result.Result, "capped at") {
		t.Errorf("a clamped limit is not reported: %s", result.Result)
	}

	result = callTool(t, registry, graph.ToolGetCallers,
		map[string]string{"snapshot_id": agentSnapID, "symbol_id": symbolID, "max_depth": "99"})
	if !result.OK {
		t.Fatalf("get_callers: %s", result.Error)
	}
	if !strings.Contains(result.Result, "capped at") {
		t.Errorf("a clamped depth is not reported: %s", result.Result)
	}

	// A big slice request is still bounded by the tool cap, and says so.
	result = callTool(t, registry, graph.ToolGetCodeSlice,
		map[string]string{"snapshot_id": agentSnapID, "file": "web/server.go", "start_line": "1", "end_line": "200", "max_lines": "5000"})
	if !result.OK {
		t.Fatalf("get_code_slice: %s", result.Error)
	}
	if !strings.Contains(result.Result, "capped at") {
		t.Errorf("a clamped line budget is not reported: %s", result.Result)
	}
}

func TestAgentToolsAreReadOnlyAndBounded(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	registry := agentToolRegistry(t, fixture)
	ctx := context.Background()
	args := agentToolArgs(t, fixture)

	beforeHypotheses, beforeHypothesisTotal, err := fixture.store.ListHypotheses(agent.HypothesisQuery{AuditID: fixture.auditID, Limit: 100})
	if err != nil {
		t.Fatalf("ListHypotheses: %v", err)
	}
	beforePaths, beforePathTotal, err := fixture.audit.Paths(path.PathQuery{AuditID: fixture.auditID, Limit: 100})
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	beforePathState := map[string]path.Path{}
	for _, p := range beforePaths {
		beforePathState[p.ID] = p
	}

	for name, toolArgs := range args {
		result, err := lookupTool(t, registry, name).Call(ctx, toolArgs)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !result.OK {
			t.Fatalf("%s: %s", name, result.Error)
		}
		if len(result.Result) > agent.MaxToolResultChars {
			t.Errorf("%s returned %d characters, above the protocol cap", name, len(result.Result))
		}
	}

	afterHypotheses, afterHypothesisTotal, err := fixture.store.ListHypotheses(agent.HypothesisQuery{AuditID: fixture.auditID, Limit: 100})
	if err != nil {
		t.Fatalf("ListHypotheses: %v", err)
	}
	afterPaths, afterPathTotal, err := fixture.audit.Paths(path.PathQuery{AuditID: fixture.auditID, Limit: 100})
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	if afterHypothesisTotal != beforeHypothesisTotal || len(afterHypotheses) != len(beforeHypotheses) {
		t.Errorf("the toolset changed stored hypotheses: %d -> %d", beforeHypothesisTotal, afterHypothesisTotal)
	}
	if afterPathTotal != beforePathTotal || len(afterPaths) != len(beforePaths) {
		t.Errorf("the toolset changed stored paths: %d -> %d", beforePathTotal, afterPathTotal)
	}
	for _, p := range afterPaths {
		was, ok := beforePathState[p.ID]
		if !ok {
			t.Errorf("the toolset created path %s", p.ID)
			continue
		}
		if p.Status != was.Status || p.LeaseOwner != was.LeaseOwner || p.Attempts != was.Attempts || p.Version != was.Version {
			t.Errorf("the toolset changed path %s: %+v -> %+v", p.ID, was, p)
		}
	}
}

// TestAgentToolAnswersAreJSONOrText keeps the two answer shapes honest: a
// structured answer must parse, and a text answer must carry source.
func TestAgentToolAnswersAreJSONOrText(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	registry := agentToolRegistry(t, fixture)
	p, sym := fixture.pathWithSymbol(t)

	structured := map[string]map[string]string{
		graph.ToolGetSymbol:      {"snapshot_id": agentSnapID, "symbol_id": sym.ID},
		graph.ToolListSymbols:    {"snapshot_id": agentSnapID},
		graph.ToolGetCallees:     {"snapshot_id": agentSnapID, "symbol_id": sym.ID},
		graph.ToolFindCallPaths:  {"snapshot_id": agentSnapID, "source_symbol_id": sym.ID, "sink_symbol_id": sym.ID},
		graph.ToolGraphSummary:   {"snapshot_id": agentSnapID},
		graph.ToolGetPath:        {"path_id": p.ID},
		graph.ToolListAuditPaths: {"audit_id": fixture.auditID},
		graph.ToolListHypotheses: {"audit_id": fixture.auditID},
	}
	for name, toolArgs := range structured {
		result := callTool(t, registry, name, toolArgs)
		var decoded map[string]any
		if err := json.Unmarshal([]byte(result.Result), &decoded); err != nil {
			t.Errorf("%s did not return JSON: %v (%s)", name, err, result.Result)
			continue
		}
		if decoded["tool"] != name {
			t.Errorf("%s: envelope names the tool %v", name, decoded["tool"])
		}
	}

	result := callTool(t, registry, graph.ToolGetCodeSlice, map[string]string{"snapshot_id": agentSnapID, "symbol_id": sym.ID})
	if !strings.Contains(result.Result, "func showUser") {
		t.Errorf("get_code_slice did not return source text: %s", result.Result)
	}
}
