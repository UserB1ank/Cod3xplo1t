package graph_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// TestGraphAssemblyRunsAnAgentOverARealPath is the end-to-end check of the whole
// graph-side assembly: the runner claims through AgentCoordinator, delivers a task
// built by AgentFacts, executes a tool through the registered read-only toolset,
// stores the hypothesis and completes the path without leaving a lease.
//
// The other paths of the audit are paused first so the claimed path — and
// therefore the security goal a valid answer must echo — is the one under test.
func TestGraphAssemblyRunsAnAgentOverARealPath(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	p, sym := fixture.pathWithSymbol(t)
	ctx := context.Background()
	for _, other := range fixture.paths {
		if other.ID == p.ID {
			continue
		}
		if _, err := fixture.audit.Pause(other.ID, "test", "only the path under test stays queued"); err != nil {
			t.Fatalf("pausing path %s: %v", other.ID, err)
		}
	}

	registry := agentToolRegistry(t, fixture)
	facts := testFacts(fixture.scg, fixture.asg)
	policy := agent.DefaultExplorationPolicy()
	policy.AllowedTools = graph.AgentToolNames()
	runtime := agent.NewScriptedRuntime("scripted", "test", []agent.ScriptStep{
		agent.ScriptTool(agent.ToolRequest{
			CallID: "call-1", Tool: graph.ToolGetSymbol,
			Args: map[string]string{"snapshot_id": agentSnapID, "symbol_id": sym.ID},
		}),
		agent.ScriptAnswer(agent.Answer{
			SchemaVersion: agent.SchemaVersion,
			SecurityGoal:  strings.Join(p.Objectives, "; "),
			Hypothesis: agent.HypothesisDraft{
				Statement:  "the handler reaches the sensitive operation without an observed control",
				Status:     agent.HypothesisCandidate,
				Confidence: "medium",
			},
			SupportingEvidence: []agent.AnswerEvidence{{
				Kind: agent.EvidenceSource, Ref: sym.ID, Summary: "the handler symbol",
			}},
			NextAction: "verify the dataflow from the input to the sink",
		}),
	})
	runner := &agent.Runner{
		Store:    fixture.store,
		Registry: registry,
		Runtime:  runtime,
		Tasks:    facts,
		Paths:    graph.NewAgentCoordinator(fixture.audit, "worker-1"),
		Policy:   policy,
		Owner:    "worker-1",
		Now:      func() time.Time { return time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC) },
	}

	run, err := runner.RunOnce(ctx, fixture.auditID)
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != agent.RunSucceeded || run.StopReason != agent.StopCompleted {
		t.Fatalf("run = %s/%s, want SUCCEEDED/completed: %s", run.Status, run.StopReason, run.Error)
	}
	if run.PathID != p.ID {
		t.Fatalf("the run took path %s, want the only queued one %s", run.PathID, p.ID)
	}
	if run.ToolCalls != 1 {
		t.Errorf("tool calls = %d, want 1", run.ToolCalls)
	}
	if run.Task.SecurityGoal != strings.Join(p.Objectives, "; ") {
		t.Errorf("the delivered task goal = %q", run.Task.SecurityGoal)
	}

	// The tool answer reached the adapter, which is what proves the advertised
	// allowlist and the registry agree at run time.
	events, err := fixture.store.ListRunEvents(agent.EventQuery{RunID: run.ID})
	if err != nil {
		t.Fatalf("ListRunEvents: %v", err)
	}
	var results, allowed int
	for _, event := range events {
		switch event.Type {
		case agent.EventToolAllowed:
			allowed++
		case agent.EventToolResult:
			results++
			if event.Tool != graph.ToolGetSymbol || event.Detail["ok"] != "true" {
				t.Errorf("tool result event = %+v", event)
			}
		}
	}
	if allowed != 1 || results != 1 {
		t.Errorf("tool exchange events = %d allowed / %d results, want 1/1", allowed, results)
	}

	// The run settled the path through the coordinator: claim, complete, no lease.
	settled, _, err := fixture.audit.Path(p.ID)
	if err != nil {
		t.Fatalf("Path: %v", err)
	}
	if settled.Status != path.StatusHypothesisFormed {
		t.Errorf("path status = %q, want HYPOTHESIS_FORMED", settled.Status)
	}
	if settled.LeaseOwner != "" || settled.LeaseUntil != "" {
		t.Errorf("a completed run left a lease behind: %+v", settled)
	}

	hypotheses, total, err := fixture.store.ListHypotheses(agent.HypothesisQuery{PathID: p.ID})
	if err != nil {
		t.Fatalf("ListHypotheses: %v", err)
	}
	if total != 1 || len(hypotheses) != 1 {
		t.Fatalf("hypotheses = %d, want the run's one claim", total)
	}
	if hypotheses[0].RunID != run.ID || hypotheses[0].SecurityGoal != run.Task.SecurityGoal {
		t.Errorf("stored hypothesis = %+v", hypotheses[0])
	}
}

// TestGraphAssemblyReportsAnEmptyQueue keeps the empty-queue contract end to end:
// a finished audit is agent.ErrNotFound, not a failed run.
func TestGraphAssemblyReportsAnEmptyQueue(t *testing.T) {
	t.Parallel()
	fixture := newAgentFixture(t)
	ctx := context.Background()
	for _, p := range fixture.paths {
		if _, err := fixture.audit.Cancel(p.ID, "test", "drained on purpose"); err != nil {
			t.Fatalf("cancelling path %s: %v", p.ID, err)
		}
	}
	runner := &agent.Runner{
		Store:    fixture.store,
		Registry: agentToolRegistry(t, fixture),
		Runtime:  agent.NewScriptedRuntime("scripted", "test", nil),
		Tasks:    testFacts(fixture.scg, fixture.asg),
		Paths:    graph.NewAgentCoordinator(fixture.audit, "worker-1"),
		Policy:   agent.DefaultExplorationPolicy(),
		Owner:    "worker-1",
	}
	run, err := runner.RunOnce(ctx, fixture.auditID)
	if run != nil {
		t.Errorf("an empty queue produced a run: %+v", run)
	}
	if !errors.Is(err, agent.ErrNotFound) {
		t.Errorf("an empty queue = %v, want agent.ErrNotFound", err)
	}
}
