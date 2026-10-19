package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func aliasFixtureTask() Task {
	return Task{
		SchemaVersion: SchemaVersionObligations,
		SnapshotID:    "snap-1",
		PathID:        "path-1",
		AuditID:       "audit-1",
		SecurityGoal:  "establish whether input reaches the sink",
		PathSummary:   "entry point http_route:GET /users/:id reaches sink:sql_execution",
		SourceSinkRefs: SourceSinkRefs{
			EntryNodeID: "entry-1", EntrySubject: "http_route:GET /users/:id",
			TargetNodeID: "sink-1", TargetSubject: "sink:sql_execution",
			Inputs: []string{"id"}, Controls: []string{"none recorded"},
			SCGRefs: []string{"sym-2", "call-1"},
		},
		MinimalCodeSlice: []SliceSection{{
			File: "web/server.go", Symbol: "sym-2", StartLine: 10, EndLine: 20,
			Content: "package web\nfunc showUser() {}\n",
		}},
		EvidenceRefs: []EvidenceRef{{
			Kind: "call_site", ID: "fact-1", Summary: "the input reaches the query", File: "web/server.go", Line: 12,
		}},
		Obligations: []Obligation{
			{ID: "ob-1", Kind: ObligationSource, Subject: "the id parameter", Question: "is it attacker controlled?", Evidence: []string{"fact-1"}},
			{ID: "ob-2", Kind: ObligationFlow, Subject: "the query", Question: "does the value reach it?"},
			{ID: "ob-3", Kind: ObligationControl, Subject: "validation", Question: "is a control effective?"},
			{ID: "ob-4", Kind: ObligationSink, Subject: "the query", Question: "is the sink sensitive?"},
		},
		Exploration: func() ExplorationPolicy {
			policy := DefaultExplorationPolicy()
			policy.AllowedTools = []string{"graph.query"}
			return policy
		}(),
		Budget:              Budget{TokenBudget: 4096},
		UnresolvedQuestions: []string{"is the value validated upstream?"},
		Limitations:         []string{"dynamic dispatch is not resolved"},
	}
}

func TestAliasTableIsDeterministicAndCollisionFree(t *testing.T) {
	task := aliasFixtureTask()
	first, second := NewAliasTable(task), NewAliasTable(task)
	firstJSON, _ := json.Marshal(first)
	secondJSON, _ := json.Marshal(second)
	if string(firstJSON) != string(secondJSON) {
		t.Fatalf("alias table is not deterministic:\n%s\n%s", firstJSON, secondJSON)
	}
	seenAlias, seenID := map[string]bool{}, map[string]bool{}
	for _, entry := range first.Entries {
		if seenAlias[entry.Alias] || seenID[entry.ID] {
			t.Fatalf("duplicate alias or id: %+v", entry)
		}
		seenAlias[entry.Alias], seenID[entry.ID] = true, true
	}
	want := map[string]string{"path-1": "P1", "audit-1": "A1", "fact-1": "E1", "entry-1": "S1", "sink-1": "S2", "sym-2": "S3", "call-1": "C1"}
	for id, alias := range want {
		got, ok := first.Alias(id)
		if !ok || got != alias {
			t.Errorf("alias of %s = %q/%v, want %q", id, got, ok, alias)
		}
		if resolved, ok := first.Resolve(alias); !ok || resolved != id {
			t.Errorf("resolve %s = %q/%v, want %q", alias, resolved, ok, id)
		}
	}
}

func TestAliasTableResolvesOnlyIDArguments(t *testing.T) {
	table := NewAliasTable(aliasFixtureTask())
	args := map[string]string{"symbol_id": "S1", "query": "S1", "snapshot_id": "snap-1"}
	resolved, err := table.ResolveArgs(args)
	if err != nil {
		t.Fatalf("ResolveArgs: %v", err)
	}
	if resolved["symbol_id"] != "entry-1" {
		t.Errorf("symbol_id = %q, want canonical entry-1", resolved["symbol_id"])
	}
	if resolved["query"] != "S1" {
		t.Errorf("free-text query was rewritten to %q", resolved["query"])
	}
	if resolved["snapshot_id"] != "snap-1" {
		t.Errorf("snapshot_id was rewritten to %q", resolved["snapshot_id"])
	}
	if _, err := table.ResolveArgs(map[string]string{"symbol_id": "S9"}); err == nil {
		t.Fatal("an unknown alias was accepted")
	}
}

func TestAliasTableProjectsOnlyKnownIDFields(t *testing.T) {
	table := NewAliasTable(aliasFixtureTask())
	raw := `{"id":"entry-1","summary":"entry-1 is the entry","refs":["entry-1","fact-1"],"tags":["entry-1"]}`
	projected := table.ProjectJSON(raw)
	if !strings.Contains(projected, `"id":"S1"`) || !strings.Contains(projected, `"refs":["S1","E1"]`) {
		t.Fatalf("ids were not projected: %s", projected)
	}
	if !strings.Contains(projected, `"summary":"entry-1 is the entry"`) || !strings.Contains(projected, `"tags":["entry-1"]`) {
		t.Fatalf("free text was rewritten: %s", projected)
	}
	if got := table.ProjectJSON("not json"); got != "not json" {
		t.Fatalf("non-JSON result changed: %q", got)
	}
}

func TestAliasTableResolvesAnswerReferencesOnly(t *testing.T) {
	table := NewAliasTable(aliasFixtureTask())
	raw := []byte(`{"supporting_evidence":[{"kind":"source","ref":"E1","summary":"E1 is an alias"}],"notes":"E1","requested_expansion":{"target_node_id":"S2","purpose":"x"}}`)
	resolved := table.ResolveAnswer(raw)
	var answer map[string]any
	if err := json.Unmarshal(resolved, &answer); err != nil {
		t.Fatal(err)
	}
	evidence := answer["supporting_evidence"].([]any)[0].(map[string]any)
	if evidence["ref"] != "fact-1" {
		t.Errorf("ref = %v, want canonical fact-1", evidence["ref"])
	}
	if evidence["summary"] != "E1 is an alias" || answer["notes"] != "E1" {
		t.Errorf("prose was rewritten: %v", resolved)
	}
	expansion := answer["requested_expansion"].(map[string]any)
	if expansion["target_node_id"] != "sink-1" {
		t.Errorf("target_node_id = %v, want canonical sink-1", expansion["target_node_id"])
	}
}
