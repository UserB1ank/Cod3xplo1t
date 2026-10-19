package agent

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// TestPiWorkerHelper is a worker process for the bridge tests. It is the test
// binary itself, re-executed with an environment switch, so the Go bridge can be
// exercised without Node.
func TestPiWorkerHelper(t *testing.T) {
	mode := os.Getenv("CODEXPLOIT_PI_HELPER")
	if mode == "" {
		t.Skip("helper process only")
	}
	scanner := bufio.NewScanner(os.Stdin)
	scanner.Buffer(make([]byte, 64<<10), 2<<20)
	write := func(value any) {
		encoded, _ := json.Marshal(value)
		fmt.Fprintln(os.Stdout, string(encoded))
	}
	read := func() map[string]any {
		if !scanner.Scan() {
			os.Exit(0)
		}
		var frame map[string]any
		_ = json.Unmarshal(scanner.Bytes(), &frame)
		return frame
	}
	if mode == "no-hello" {
		os.Exit(0)
	}
	hello := map[string]any{"type": "hello", "v": 1, "worker": "helper", "pi_version": "0", "node": "go"}
	if mode == "bad-hello" {
		hello["v"] = 99
	}
	write(hello)
	if mode == "no-hello" {
		os.Exit(0)
	}
	_ = read() // init: private, never echoed
	start := read()
	if mode == "bad-generation" {
		write(map[string]any{"type": "request_permit", "run_id": start["run_id"], "generation": 999, "seq": 1})
		time.Sleep(200 * time.Millisecond)
		os.Exit(0)
	}
	runID, generation := start["run_id"], start["generation"]
	task, _ := start["task"].(string)
	goal := ""
	if index := strings.Index(task, "\nGOAL\n"); index >= 0 {
		rest := task[index+len("\nGOAL\n"):]
		if end := strings.Index(rest, "\n\n"); end >= 0 {
			goal = strings.TrimSpace(rest[:end])
		}
	}
	kinds := []string{}
	section := ""
	if index := strings.Index(task, "\nOBLIGATIONS"); index >= 0 {
		section = task[index:]
	}
	for _, match := range regexp.MustCompile(`(?m)^- ([a-z_]+) — `).FindAllStringSubmatch(section, -1) {
		kinds = append(kinds, match[1])
	}
	seq := 0
	next := func() int { seq++; return seq }

	if mode == "stream-before-settled" {
		write(map[string]any{"type": "request_permit", "run_id": runID, "generation": generation, "seq": next(), "request_id": "r1"})
		read()
		os.Exit(0)
	}

	write(map[string]any{"type": "request_permit", "run_id": runID, "generation": generation, "seq": next(),
		"request_id": "r1", "round_id": "round-1", "model": "test", "input_tokens_estimate": 10, "max_output_tokens": 10})
	permit := read()
	if permit["decision"] != "continue" {
		os.Exit(2)
	}
	write(map[string]any{"type": "tool_request", "run_id": runID, "generation": generation, "seq": next(),
		"request_id": "t1", "round_id": "round-1", "call_id": "call-1", "tool": "get_code_slice",
		"args": map[string]any{"symbol_id": "S1"}})
	toolResult := read()
	if path := os.Getenv("CODEXPLOIT_PI_RESULT_FILE"); path != "" {
		_ = os.WriteFile(path, []byte(fmt.Sprint(toolResult["result"])), 0o600)
	}
	answer := map[string]any{
		"schema_version": 2, "security_goal": goal,
		"hypothesis":          map[string]any{"statement": "worker bridge test", "status": "inconclusive", "confidence": "low"},
		"supporting_evidence": []any{}, "contradicting_evidence": []any{},
		"next_action": "stop", "finding_candidate": false,
	}
	obligations := make([]any, 0, len(kinds))
	for _, kind := range kinds {
		obligations = append(obligations, map[string]any{"kind": kind, "verdict": "unknown", "blocker": "budget", "reason": "test"})
	}
	answer["obligations"] = obligations
	write(map[string]any{"type": "answer_proposed", "run_id": runID, "generation": generation, "seq": next(), "request_id": "a1", "raw": answer})
	reply := read()
	status := "completed"
	if reply["decision"] != "accepted" {
		status = "failed"
	}
	write(map[string]any{"type": "settled", "run_id": runID, "generation": generation, "seq": next(), "status": status})
	os.Exit(0)
}

func piTestConfig(mode string) PiConfig {
	return PiConfig{
		Name: "pi", Command: []string{os.Args[0], "-test.run=TestPiWorkerHelper"},
		Init:    json.RawMessage(`{"model":{"api_key":"synthetic"}}`),
		Env:     []string{"CODEXPLOIT_PI_HELPER=" + mode},
		Tools:   []ToolDescriptor{{Name: "get_code_slice", Version: "1", InputSchema: json.RawMessage(`{"type":"object","properties":{"symbol_id":{"type":"string"}},"additionalProperties":false}`)}},
		Timeout: 10 * time.Second,
	}
}

// runPiScenario drives the Pi adapter through the real Runner with the helper as
// the worker.
func runPiScenario(t *testing.T, mode string) (*Run, *runnerTestTool, string) {
	t.Helper()
	fixture := aliasFixtureTask()
	fixture.Exploration.AllowedTools = []string{"get_code_slice"}
	resultFile := t.TempDir() + "/result.txt"
	config := piTestConfig(mode)
	config.Env = append(config.Env, "CODEXPLOIT_PI_RESULT_FILE="+resultFile)
	runtime, err := NewPiRuntime(config)
	if err != nil {
		t.Fatal(err)
	}
	tool := &runnerTestTool{name: "get_code_slice", result: `{"slice":"func main()"}`}
	registry := NewRegistry()
	registry.Register(tool)
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	run, err := runnerTestRunner(store, paths, &aliasTaskBuilder{task: fixture}, runtime, registry, fixture.Exploration).
		RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	modelResult := ""
	if raw, err := os.ReadFile(resultFile); err == nil {
		modelResult = string(raw)
	}
	return run, tool, modelResult
}

func TestPiRuntimeRunsTheWorkerProtocol(t *testing.T) {
	run, tool, modelResult := runPiScenario(t, "ok")
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s (%q)", run.Status, run.Error)
	}
	if tool.calls != 1 {
		t.Fatalf("tool calls = %d, want 1", tool.calls)
	}
	if got := tool.args[0]["symbol_id"]; got != "entry-1" {
		t.Errorf("tool received %q, want the host-resolved canonical id", got)
	}
	var envelope struct {
		OK     bool           `json:"ok"`
		Result string         `json:"result"`
		Budget *BudgetReceipt `json:"budget"`
	}
	if err := json.Unmarshal([]byte(modelResult), &envelope); err != nil {
		t.Fatalf("worker did not receive the host envelope: %v (%s)", err, modelResult)
	}
	if !envelope.OK || envelope.Budget == nil || envelope.Budget.ObligationsTotal != 4 {
		t.Fatalf("worker envelope = %+v", envelope)
	}
	if run.Metrics == nil || run.Metrics.ModelRequests != 1 || run.Metrics.Source != MetricsSourceReported {
		t.Fatalf("metrics = %+v, want one reported model request", run.Metrics)
	}
}

func TestPiRuntimeRejectsAWorkerThatNeverGreets(t *testing.T) {
	run, _, _ := runPiScenario(t, "no-hello")
	if run.Status != RunFailed || !strings.Contains(run.Error, "hello") {
		t.Fatalf("run = %s/%q, want a hello failure", run.Status, run.Error)
	}
}

func TestPiRuntimeRejectsAStaleGeneration(t *testing.T) {
	run, _, _ := runPiScenario(t, "bad-generation")
	if run.Status != RunFailed || !strings.Contains(run.Error, "generation") {
		t.Fatalf("run = %s/%q, want a stale generation failure", run.Status, run.Error)
	}
}

func TestPiRuntimeRejectsAStreamBeforeSettled(t *testing.T) {
	run, _, _ := runPiScenario(t, "stream-before-settled")
	if run.Status != RunFailed || !strings.Contains(run.Error, "settled") {
		t.Fatalf("run = %s/%q, want a settled failure", run.Status, run.Error)
	}
}
