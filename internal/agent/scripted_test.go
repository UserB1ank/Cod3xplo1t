package agent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// adapterCollectRun drains a handle and returns its events and terminal result. The
// timeout matters: an adapter that never closes its stream must fail the test
// instead of hanging the suite, which is the failure mode these tests exist to
// catch.
func adapterCollectRun(t *testing.T, handle *Handle, timeout time.Duration) ([]RuntimeEvent, RuntimeResult) {
	t.Helper()
	type collected struct {
		events []RuntimeEvent
		result RuntimeResult
	}
	done := make(chan collected, 1)
	go func() {
		var events []RuntimeEvent
		for event := range handle.Events {
			events = append(events, event)
		}
		done <- collected{events: events, result: <-handle.Done}
	}()
	select {
	case got := <-done:
		return got.events, got.result
	case <-time.After(timeout):
		t.Fatalf("run did not finish within %s: the adapter is stuck", timeout)
		return nil, RuntimeResult{}
	}
}

// adapterTestTask is the smallest task ValidateTask accepts, so an adapter test fails
// for an adapter reason and never for a malformed question.
func adapterTestTask() Task {
	return Task{
		SchemaVersion: SchemaVersion,
		SnapshotID:    "snap-1",
		PathID:        "path-1",
		AuditID:       "audit-1",
		SecurityGoal:  "sql_injection",
		PathSummary:   "upload handler reaches the query sink",
		SourceSinkRefs: SourceSinkRefs{
			EntryNodeID:  "entry-1",
			TargetNodeID: "sink-1",
			Inputs:       []string{"input-1"},
		},
		MinimalCodeSlice: []SliceSection{
			{File: "handlers/upload.go", Symbol: "Upload", StartLine: 10, EndLine: 14, Content: "db.Query(name)"},
		},
		EvidenceRefs: []EvidenceRef{
			{Kind: EvidenceSource, ID: "ev-1", Summary: "route registration", File: "main.go", Line: 9},
		},
		UnresolvedQuestions: []string{"is the name parameterised?"},
		Exploration: ExplorationPolicy{
			AllowedTools: []string{"code.slice", "graph.query"},
		}.Normalize(),
		Budget:    Budget{TimeoutSeconds: 30, TokenBudget: 1000},
		CreatedAt: NowString(time.Now()),
	}
}

// adapterTestAnswer is a protocol-valid answer for task: candidate status, one cited
// piece of evidence. A test that needs an invalid answer changes one field, which
// keeps the failure it is testing legible.
func adapterTestAnswer(task Task) Answer {
	return Answer{
		SchemaVersion: SchemaVersion,
		SecurityGoal:  task.SecurityGoal,
		Hypothesis: HypothesisDraft{
			Statement:  "the upload name reaches the query without parameterisation",
			Status:     HypothesisCandidate,
			Confidence: "medium",
		},
		SupportingEvidence: []AnswerEvidence{
			{Kind: EvidenceSource, Ref: "ev-1", File: "handlers/upload.go", Line: 12, Summary: "the slice concatenates the name"},
		},
		NextAction:       "request a deeper dataflow slice",
		FindingCandidate: false,
	}
}

func adapterEventOfType(events []RuntimeEvent, eventType string) *RuntimeEvent {
	for i := range events {
		if events[i].Type == eventType {
			return &events[i]
		}
	}
	return nil
}

func adapterCountEvents(events []RuntimeEvent, eventType string) int {
	count := 0
	for _, event := range events {
		if event.Type == eventType {
			count++
		}
	}
	return count
}

func adapterEventTypes(events []RuntimeEvent) string {
	types := make([]string, 0, len(events))
	for _, event := range events {
		types = append(types, event.Type)
	}
	return strings.Join(types, ",")
}

func TestScriptedRuntimeReplaysSteps(t *testing.T) {
	task := adapterTestTask()
	answer := adapterTestAnswer(task)
	runtime := NewScriptedRuntime("scripted", "1", []ScriptStep{
		ScriptNote("scanning the minimal slice"),
		ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query", Args: map[string]string{"symbol": "sym-1"}}),
		ScriptExpansion(ExpansionAsk{TargetNodeID: "node-2", Purpose: "confirm the sink", ExpectedGain: "one hop", EstimatedCost: "1 hop"}),
		ScriptAnswer(answer),
	})

	caps := runtime.Capabilities()
	if !caps.ToolCalls || !caps.Expansions || !caps.Streaming {
		t.Fatalf("capabilities must advertise tool calls, expansions and streaming: %+v", caps)
	}
	if caps.TokenUsage {
		t.Error("a script has no token usage to report")
	}
	if caps.Resume {
		t.Error("a script has no checkpoint to resume from")
	}

	handle, err := runtime.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 10*time.Second)
	if result.Err != nil {
		t.Fatalf("run failed: %v", result.Err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit code = %d, want 0", result.ExitCode)
	}
	if got := adapterEventTypes(events); got != "note,tool_requested,expansion_requested,output_received" {
		t.Fatalf("event sequence = %s", got)
	}

	note := adapterEventOfType(events, runtimeEventNote)
	if note == nil || note.Summary != "scanning the minimal slice" {
		t.Fatalf("summary note missing or wrong: %+v", note)
	}

	toolEvent := adapterEventOfType(events, EventToolRequested)
	if toolEvent == nil || toolEvent.Tool == nil {
		t.Fatalf("tool request event missing: %+v", toolEvent)
	}
	if err := ValidateToolRequest(*toolEvent.Tool, task.Exploration, 0); err != nil {
		t.Fatalf("an allowlisted request must validate: %v", err)
	}

	expansion := adapterEventOfType(events, EventExpansionAsked)
	if expansion == nil || expansion.Expansion == nil || expansion.Expansion.TargetNodeID != "node-2" {
		t.Fatalf("expansion request missing or wrong: %+v", expansion)
	}

	output := adapterEventOfType(events, EventOutputReceived)
	if output == nil || output.Answer == nil {
		t.Fatalf("output event missing an answer: %+v", output)
	}
	if result.Answer == nil || result.Answer.Hypothesis.Statement != answer.Hypothesis.Statement {
		t.Fatalf("terminal answer = %+v, want the scripted answer", result.Answer)
	}
}

// TestScriptedRuntimeEmitsEachResultOnce pins the channel contract the
// orchestrator relies on: Events closes and Done carries exactly one result, so a
// consumer never blocks on a second read.
func TestScriptedRuntimeEmitsEachResultOnce(t *testing.T) {
	task := adapterTestTask()
	runtime := NewScriptedRuntime("scripted", "1", []ScriptStep{ScriptAnswer(adapterTestAnswer(task))})
	handle, err := runtime.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 10*time.Second)
	if result.Err != nil {
		t.Fatalf("run failed: %v", result.Err)
	}
	if len(events) != 1 {
		t.Fatalf("events = %v, want exactly the output event", adapterEventTypes(events))
	}
	if _, ok := <-handle.Done; ok {
		t.Error("Done carried a second result")
	}
	if _, ok := <-handle.Events; ok {
		t.Error("Events was not closed")
	}
	// Cancelling after the run finished must stay safe: the orchestrator may
	// cancel a run whose result it has already consumed.
	handle.Cancel()
	handle.Cancel()
}

func TestScriptedRuntimeCancellationMidRun(t *testing.T) {
	task := adapterTestTask()
	steps := make([]ScriptStep, 0, 50)
	for i := 0; i < 50; i++ {
		steps = append(steps, ScriptNote("step"))
	}
	runtime := NewScriptedRuntime("scripted", "1", steps)
	runtime.StepDelay = 20 * time.Millisecond

	handle, err := runtime.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	select {
	case <-handle.Events:
	case <-time.After(10 * time.Second):
		t.Fatal("no event arrived before cancellation")
	}
	handle.Cancel()
	handle.Cancel() // idempotent by contract

	events, result := adapterCollectRun(t, handle, 10*time.Second)
	if !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("result error = %v, want context.Canceled", result.Err)
	}
	if result.ExitCode != -1 {
		t.Fatalf("exit code = %d, want -1 for a cancelled run", result.ExitCode)
	}
	if result.Answer != nil {
		t.Error("a cancelled run must not carry an answer")
	}
	if len(events)+1 >= len(steps) {
		t.Fatalf("run emitted %d events before and after cancellation; it did not stop", len(events)+1)
	}
}

func TestScriptedRuntimeHonoursDeadline(t *testing.T) {
	task := adapterTestTask()
	runtime := NewScriptedRuntime("scripted", "1", []ScriptStep{
		ScriptNote("first"),
		ScriptAnswer(adapterTestAnswer(task)),
	})
	runtime.StepDelay = 200 * time.Millisecond

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Millisecond)
	defer cancel()
	handle, err := runtime.Start(ctx, task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, result := adapterCollectRun(t, handle, 10*time.Second)
	if !errors.Is(result.Err, context.DeadlineExceeded) {
		t.Fatalf("result error = %v, want context.DeadlineExceeded", result.Err)
	}
	if result.ExitCode != -1 {
		t.Fatalf("exit code = %d, want -1 for a timed-out run", result.ExitCode)
	}
}

func TestScriptedRuntimeRejectsMalformedAnswer(t *testing.T) {
	task := adapterTestTask()
	runtime := NewScriptedRuntime("scripted", "1", []ScriptStep{
		ScriptRawAnswer([]byte("{not json at all")),
	})
	handle, err := runtime.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 10*time.Second)
	if !errors.Is(result.Err, ErrInvalidAnswer) {
		t.Fatalf("result error = %v, want ErrInvalidAnswer", result.Err)
	}
	if result.Answer != nil {
		t.Error("a rejected answer must not be reported as a result")
	}
	if rejected := adapterEventOfType(events, EventOutputRejected); rejected == nil {
		t.Fatalf("no output_rejected event; got %s", adapterEventTypes(events))
	}
}

// TestScriptedRuntimeRejectsConfirmedAnswer is the policy check: a run may claim
// candidate, inconclusive or refuted, but never confirmed. Confirmation belongs to
// verification, and the adapter must not be able to route around it.
func TestScriptedRuntimeRejectsConfirmedAnswer(t *testing.T) {
	task := adapterTestTask()
	answer := adapterTestAnswer(task)
	answer.Hypothesis.Status = HypothesisConfirmed
	runtime := NewScriptedRuntime("scripted", "1", []ScriptStep{ScriptAnswer(answer)})

	handle, err := runtime.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 10*time.Second)
	if !errors.Is(result.Err, ErrInvalidAnswer) {
		t.Fatalf("result error = %v, want ErrInvalidAnswer", result.Err)
	}
	if result.Answer != nil {
		t.Fatal("an answer claiming confirmation must not reach the orchestrator as a result")
	}
	rejected := adapterEventOfType(events, EventOutputRejected)
	if rejected == nil {
		t.Fatalf("no output_rejected event; got %s", adapterEventTypes(events))
	}
	if !strings.Contains(rejected.Detail["error"], HypothesisConfirmed) {
		t.Errorf("rejection reason %q should name the offending status", rejected.Detail["error"])
	}
}

// TestScriptedRuntimeToolOutsideAllowlist shows the adapter does not police tool
// requests: it emits what the script says, and the orchestrator's gate rejects it.
// That division is the security property of this layer, not a convenience.
func TestScriptedRuntimeToolOutsideAllowlist(t *testing.T) {
	task := adapterTestTask()
	runtime := NewScriptedRuntime("scripted", "1", []ScriptStep{
		ScriptTool(ToolRequest{CallID: "call-9", Tool: "shell.exec", Args: map[string]string{"cmd": "rm -rf /"}}),
	})
	handle, err := runtime.Start(context.Background(), task)
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	events, result := adapterCollectRun(t, handle, 10*time.Second)
	if result.Err != nil {
		t.Fatalf("emitting a request must not fail the run by itself: %v", result.Err)
	}
	requested := adapterEventOfType(events, EventToolRequested)
	if requested == nil || requested.Tool == nil {
		t.Fatalf("the request was not emitted; got %s", adapterEventTypes(events))
	}
	err = ValidateToolRequest(*requested.Tool, task.Exploration, 0)
	if !errors.Is(err, ErrUnsupportedTool) {
		t.Fatalf("ValidateToolRequest = %v, want ErrUnsupportedTool", err)
	}
}

func TestScriptedRuntimeRejectsInvalidTask(t *testing.T) {
	runtime := NewScriptedRuntime("scripted", "1", nil)
	if _, err := runtime.Start(context.Background(), Task{}); !errors.Is(err, ErrInvalidTask) {
		t.Fatalf("Start with an empty task = %v, want ErrInvalidTask", err)
	}
}

func TestScriptedRuntimeRejectsUnknownStep(t *testing.T) {
	runtime := NewScriptedRuntime("scripted", "1", []ScriptStep{{Kind: "teleport"}})
	handle, err := runtime.Start(context.Background(), adapterTestTask())
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	_, result := adapterCollectRun(t, handle, 10*time.Second)
	if !errors.Is(result.Err, ErrScriptStepInvalid) {
		t.Fatalf("result error = %v, want ErrScriptStepInvalid", result.Err)
	}
}
