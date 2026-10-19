package agent

import (
	"context"
	"testing"
)

// TestSoftBudgetWarningIsEmittedOnce covers the soft tier: crossing 80% is a
// recorded warning, not a stop, and repeated usage does not repeat it.
func TestSoftBudgetWarningIsEmittedOnce(t *testing.T) {
	store := newRunnerTestStore()
	runner := runnerTestRunner(store, newRunnerTestPaths(runnerTestPath("audit-1", "path-1")), &runnerTestTasks{}, nil, nil, runnerTestPolicy())
	run := Run{ID: "run-soft", AuditID: "audit-1", PathID: "path-1", SnapshotID: "snap-1", Status: RunRunning, Version: 1}
	if err := store.CreateRun(run); err != nil {
		t.Fatal(err)
	}
	session := &runnerSession{
		runner: runner, run: &run, policy: ExplorationPolicy{TokenBudget: 100}, status: RunRunning,
		usageSeen: map[string]bool{}, reservations: map[string]int{}, batchResults: map[string]batchCallRecord{},
	}
	if stop := session.applyEvent(context.Background(), RuntimeEvent{Type: "note", Summary: "usage", RequestID: "r1", InputTokens: 70, OutputTokens: 15}); stop {
		t.Fatal("the soft warning stopped the run")
	}
	events, err := store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	warnings := 0
	for _, event := range events {
		if event.Type == EventBudgetSoftLimit {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("soft warnings = %d, want one", warnings)
	}
	if stop := session.applyEvent(context.Background(), RuntimeEvent{Type: "note", Summary: "usage", RequestID: "r2", InputTokens: 5, OutputTokens: 5}); stop {
		t.Fatal("the second soft usage stopped the run")
	}
	events, _ = store.ListRunEvents(EventQuery{RunID: run.ID, Limit: 50})
	warnings = 0
	for _, event := range events {
		if event.Type == EventBudgetSoftLimit {
			warnings++
		}
	}
	if warnings != 1 {
		t.Fatalf("soft warnings after another report = %d, want one", warnings)
	}
}
