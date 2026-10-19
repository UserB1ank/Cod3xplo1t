package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// The golden set exists so the stopping behaviour of the orchestrator can be
// measured without a model. Every scenario is a script: the same steps always
// produce the same events, the same counters and the same stop reason, which is
// what makes a change to the loop comparable with the baseline before it.
//
// A scenario carries its expectations. Adding a case means adding a file, not
// editing a test: the runner below is the only code that knows how a scenario is
// executed.

const (
	goldenCategorySeededVuln  = "seeded_vuln"
	goldenCategoryKnownSafe   = "known_safe"
	goldenCategoryUndecidable = "undecidable"
	goldenCategoryBoundary    = "boundary"

	// goldenCategoryMinimum is the documented coverage of the set: five cases per
	// category, so no category can be quietly emptied.
	goldenCategoryMinimum = 5
)

// goldenToolSpec is one tool a scenario can call. The result is returned verbatim
// and the refs are what the orchestrator counts as evidence, which is how novelty
// becomes measurable from a script.
type goldenToolSpec struct {
	Result string   `json:"result"`
	Refs   []string `json:"refs"`
}

// goldenStep is one scripted action. Only the field the kind selects is read.
type goldenStep struct {
	Kind    string            `json:"kind"`
	Summary string            `json:"summary"`
	Detail  map[string]string `json:"detail"`
	Tool    string            `json:"tool"`
	Args    map[string]string `json:"args"`
	Answer  json.RawMessage   `json:"answer"`
}

// goldenExpect is the terminal state a scenario must produce. Counters are exact:
// a split that changes how many exchanges a run takes is a behaviour change and
// must be visible in the fixture.
type goldenExpect struct {
	Status       string `json:"status"`
	StopReason   string `json:"stop_reason"`
	ToolCalls    int    `json:"tool_calls"`
	Rounds       int    `json:"rounds"`
	Exchanges    int    `json:"exchanges"`
	InvalidCalls int    `json:"invalid_calls"`
	Truncations  int    `json:"truncations"`
	Novelty      []int  `json:"novelty"`
}

// goldenScenario is one fixture file.
type goldenScenario struct {
	Name         string                    `json:"name"`
	Category     string                    `json:"category"`
	Description  string                    `json:"description"`
	MaxToolCalls int                       `json:"max_tool_calls"`
	AllowedTools []string                  `json:"allowed_tools"`
	Tools        map[string]goldenToolSpec `json:"tools"`
	Steps        []goldenStep              `json:"steps"`
	Expect       goldenExpect              `json:"expect"`
}

// goldenTool is a deterministic tool: it returns a fixed result and fixed refs,
// so an exchange costs no time and produces no randomness.
type goldenTool struct {
	name   string
	result string
	refs   []string
}

var _ ToolExecutor = (*goldenTool)(nil)

func (t *goldenTool) Name() string     { return t.name }
func (t *goldenTool) Describe() string { return "deterministic golden tool" }

func (t *goldenTool) Call(_ context.Context, _ map[string]string) (ToolResult, error) {
	return ToolResult{Tool: t.name, OK: true, Result: t.result, Refs: append([]string(nil), t.refs...)}, nil
}

// goldenOutcome is one scenario's result, reduced to what a benchmark compares.
type goldenOutcome struct {
	Name         string  `json:"name"`
	Category     string  `json:"category"`
	Status       string  `json:"status"`
	StopReason   string  `json:"stop_reason"`
	ToolCalls    int     `json:"tool_calls"`
	Expansions   int     `json:"expansions"`
	Rounds       int     `json:"rounds"`
	Exchanges    int     `json:"exchanges"`
	InputTokens  int     `json:"input_tokens"`
	OutputTokens int     `json:"output_tokens"`
	InvalidCalls int     `json:"invalid_calls"`
	Truncations  int     `json:"truncations"`
	Novelty      []int   `json:"novelty"`
	EventDigest  string  `json:"event_digest"`
	Answer       *Answer `json:"answer,omitempty"`
}

// goldenBaseline is the machine-readable summary a benchmark run writes.
type goldenBaseline struct {
	SchemaVersion int             `json:"schema_version"`
	Scenarios     []goldenOutcome `json:"scenarios"`
}

// loadGoldenScenarios reads every fixture once, in a stable order.
func loadGoldenScenarios(t *testing.T) []goldenScenario {
	t.Helper()
	paths, err := filepath.Glob(filepath.Join("testdata", "golden", "*.json"))
	if err != nil {
		t.Fatalf("glob golden fixtures: %v", err)
	}
	sort.Strings(paths)
	scenarios := make([]goldenScenario, 0, len(paths))
	for _, file := range paths {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("read %s: %v", file, err)
		}
		var scenario goldenScenario
		decoder := json.NewDecoder(strings.NewReader(string(raw)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&scenario); err != nil {
			t.Fatalf("decode %s: %v", file, err)
		}
		scenario.Name = goldenFirstNonEmpty(scenario.Name, strings.TrimSuffix(filepath.Base(file), ".json"))
		scenarios = append(scenarios, scenario)
	}
	return scenarios
}

// runGoldenScenario executes one fixture twice over a fresh harness and returns
// both outcomes. Running it twice is the determinism check, not a duplicate: a
// loop that reads a clock, a map order or a random id fails here.
func runGoldenScenario(t *testing.T, scenario goldenScenario) (goldenOutcome, goldenOutcome) {
	t.Helper()
	first, err := runGoldenOnce(t, scenario)
	if err != nil {
		t.Fatalf("%s: first run: %v", scenario.Name, err)
	}
	second, err := runGoldenOnce(t, scenario)
	if err != nil {
		t.Fatalf("%s: second run: %v", scenario.Name, err)
	}
	return first, second
}

func runGoldenOnce(t *testing.T, scenario goldenScenario) (goldenOutcome, error) {
	t.Helper()
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	tasks := &runnerTestTasks{}

	registry := NewRegistry()
	for name, spec := range scenario.Tools {
		registry.Register(&goldenTool{name: name, result: spec.Result, refs: spec.Refs})
	}

	steps := make([]ScriptStep, 0, len(scenario.Steps))
	for i, step := range scenario.Steps {
		switch step.Kind {
		case "note":
			steps = append(steps, ScriptNoteDetail(step.Summary, step.Detail))
		case "tool":
			steps = append(steps, ScriptTool(ToolRequest{
				CallID: fmt.Sprintf("call-%02d", i), Tool: step.Tool, Args: step.Args,
			}))
		case "answer":
			if len(step.Answer) == 0 {
				return goldenOutcome{}, fmt.Errorf("step %d: answer is empty", i)
			}
			steps = append(steps, ScriptRawAnswer(step.Answer))
		default:
			return goldenOutcome{}, fmt.Errorf("step %d: unknown kind %q", i, step.Kind)
		}
	}

	policy := runnerTestPolicy()
	if scenario.MaxToolCalls > 0 {
		policy.MaxToolCalls = scenario.MaxToolCalls
	}
	policy.AllowedTools = append([]string(nil), scenario.AllowedTools...)

	runner := runnerTestRunner(store, paths, tasks,
		NewScriptedRuntime("scripted-golden", "1.0", steps), registry, policy)

	run, err := runner.RunOnce(context.Background(), "audit-1")
	if err != nil {
		return goldenOutcome{}, err
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 1000})
	if err != nil {
		return goldenOutcome{}, err
	}

	outcome := goldenOutcome{
		Name: scenario.Name, Category: scenario.Category,
		Status: string(run.Status), StopReason: run.StopReason,
		ToolCalls: run.ToolCalls, Expansions: run.Expansions,
		InputTokens: run.InputTokens, OutputTokens: run.OutputTokens,
		EventDigest: goldenEventDigest(events),
		Answer:      run.Answer,
	}
	if run.Metrics != nil {
		outcome.Rounds = run.Metrics.Rounds
		outcome.Exchanges = run.Metrics.Exchanges
		outcome.InvalidCalls = run.Metrics.InvalidCalls
		outcome.Truncations = run.Metrics.Truncations
		outcome.Novelty = append([]int(nil), run.Metrics.Novelty...)
	}
	return outcome, nil
}

// goldenEventDigest reduces the event log to what a replay must reproduce. Ids and
// timestamps are deterministic too, but the digest deliberately ignores them: the
// log's shape, order and payload are the behaviour, and a changed event id scheme
// is not.
func goldenEventDigest(events []Event) string {
	var builder strings.Builder
	for _, event := range events {
		detail, _ := json.Marshal(event.Detail)
		fmt.Fprintf(&builder, "%d|%s|%s|%s|%s|%s\n",
			event.Seq, event.Type, event.CallID, event.Tool, event.Summary, detail)
	}
	return Digest(builder.String())
}

// TestGoldenScenarios is the regression gate: every fixture runs twice, must be
// byte-identical between the runs, and must produce the counters it declares.
func TestGoldenScenarios(t *testing.T) {
	scenarios := loadGoldenScenarios(t)
	if len(scenarios) < 20 {
		t.Fatalf("golden set holds %d scenarios, want at least 20", len(scenarios))
	}
	perCategory := map[string]int{}
	for _, scenario := range scenarios {
		perCategory[scenario.Category]++
	}
	for _, category := range []string{goldenCategorySeededVuln, goldenCategoryKnownSafe, goldenCategoryUndecidable, goldenCategoryBoundary} {
		if perCategory[category] < goldenCategoryMinimum {
			t.Errorf("category %q holds %d scenarios, want at least %d", category, perCategory[category], goldenCategoryMinimum)
		}
	}

	for _, scenario := range scenarios {
		scenario := scenario
		t.Run(scenario.Name, func(t *testing.T) {
			first, second := runGoldenScenario(t, scenario)
			if !reflect.DeepEqual(first, second) {
				t.Fatalf("replay diverged\nfirst:  %+v\nsecond: %+v", first, second)
			}
			assertGoldenExpect(t, scenario.Expect, first)
			t.Logf("%-32s %-12s %-14s %-30s calls=%-3d rounds=%-3d tokens=%d/%d novelty=%v",
				first.Name, first.Category, first.Status, first.StopReason,
				first.ToolCalls, first.Rounds, first.InputTokens, first.OutputTokens, first.Novelty)
		})
	}
}

func assertGoldenExpect(t *testing.T, want goldenExpect, got goldenOutcome) {
	t.Helper()
	if want.Status == "" {
		t.Fatalf("scenario has no expected status")
	}
	checks := []struct {
		name      string
		want, got any
	}{
		{"status", want.Status, got.Status},
		{"stop_reason", want.StopReason, got.StopReason},
		{"tool_calls", want.ToolCalls, got.ToolCalls},
		{"rounds", want.Rounds, got.Rounds},
		{"exchanges", want.Exchanges, got.Exchanges},
		{"invalid_calls", want.InvalidCalls, got.InvalidCalls},
		{"truncations", want.Truncations, got.Truncations},
	}
	for _, check := range checks {
		if !reflect.DeepEqual(check.want, check.got) {
			t.Errorf("%s = %v, want %v", check.name, check.got, check.want)
		}
	}
	// An absent list and an empty list mean the same thing here: no exchange was
	// executed, so there is no novelty sample to compare.
	if want.Novelty != nil && !equalInts(want.Novelty, got.Novelty) {
		t.Errorf("novelty = %v, want %v", got.Novelty, want.Novelty)
	}
}

// TestGoldenBaseline writes the machine-readable summary the benchmark target
// consumes. It is skipped unless AGENT_BENCH_OUT names a file, so a normal test
// run never writes into the tree.
func TestGoldenBaseline(t *testing.T) {
	out := strings.TrimSpace(os.Getenv("AGENT_BENCH_OUT"))
	if out == "" {
		t.Skip("AGENT_BENCH_OUT is not set")
	}
	baseline := goldenBaseline{SchemaVersion: 1}
	for _, scenario := range loadGoldenScenarios(t) {
		first, second := runGoldenScenario(t, scenario)
		if !reflect.DeepEqual(first, second) {
			t.Fatalf("%s: replay diverged", scenario.Name)
		}
		baseline.Scenarios = append(baseline.Scenarios, first)
		t.Logf("%-32s %-12s %-14s %-30s calls=%-3d rounds=%-3d tokens=%d/%d novelty=%v",
			first.Name, first.Category, first.Status, first.StopReason,
			first.ToolCalls, first.Rounds, first.InputTokens, first.OutputTokens, first.Novelty)
	}
	encoded, err := json.MarshalIndent(baseline, "", "  ")
	if err != nil {
		t.Fatalf("marshal baseline: %v", err)
	}
	if err := os.WriteFile(out, append(encoded, '\n'), 0o644); err != nil {
		t.Fatalf("write %s: %v", out, err)
	}
	t.Logf("wrote %d scenarios to %s", len(baseline.Scenarios), out)
}

func goldenFirstNonEmpty(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}
