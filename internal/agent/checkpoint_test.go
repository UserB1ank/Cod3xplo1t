package agent

import (
	"strings"
	"testing"
	"time"
)

func checkpointFixture() CheckpointInput {
	task := aliasFixtureTask()
	return CheckpointInput{
		Run: Run{ID: "run-1", PathID: "path-1", AuditID: "audit-1", SnapshotID: "snap-1", Version: 3,
			Pin: &RuntimePin{Runtime: "llm", ConfigVersion: "config-1"}},
		Task:     task,
		Evidence: []string{" fact-1 ", "fact-2", "fact-1", ""},
		Usage:    CheckpointUsage{InputTokens: 120, OutputTokens: 40, ToolCalls: 3},
		Reason:   "the tool budget of 30 is exhausted",
		Now:      time.Date(2026, 10, 20, 1, 0, 0, 0, time.UTC),
		ID:       "checkpoint-fixed",
	}
}

func TestBuildCheckpointIsDeterministicAndCarriesTheOpenWork(t *testing.T) {
	first, err := BuildCheckpoint(checkpointFixture())
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildCheckpoint(checkpointFixture())
	if err != nil {
		t.Fatal(err)
	}
	if first.Digest != second.Digest || first.ID != second.ID {
		t.Fatalf("checkpoint is not deterministic: %s vs %s", first.Digest, second.Digest)
	}
	if err := first.Validate(); err != nil {
		t.Fatalf("built checkpoint does not validate: %v", err)
	}
	if len(first.Evidence) != 2 || first.Evidence[0] != "fact-1" || first.Evidence[1] != "fact-2" {
		t.Fatalf("evidence = %v, want deduplicated sorted refs", first.Evidence)
	}
	if first.Usage.InputTokens != 120 || first.Usage.ToolCalls != 3 {
		t.Fatalf("usage = %+v", first.Usage)
	}
	joined := strings.Join(first.Frontier, "\n")
	for _, want := range []string{"source_is_attacker_controlled:", "flow_reaches_sink:", "control_ineffective_or_absent:", "sink_is_sensitive:", "is the value validated upstream?"} {
		if !strings.Contains(joined, want) {
			t.Errorf("frontier is missing %q: %v", want, first.Frontier)
		}
	}
	if first.Pin == nil || first.Pin.ConfigVersion != "config-1" {
		t.Fatalf("pin = %+v, want the run's fixed pin", first.Pin)
	}
}

func TestCheckpointFrontierIsNeverEmptyWithoutInventingEvidence(t *testing.T) {
	task := aliasFixtureTask()
	task.SchemaVersion = SchemaVersion
	task.Obligations = nil
	task.UnresolvedQuestions = nil
	checkpoint, err := BuildCheckpoint(CheckpointInput{
		Run:  Run{ID: "run-1", PathID: "path-1", SnapshotID: "snap-1"},
		Task: task, Reason: "budget", Now: time.Now().UTC(), ID: "checkpoint-empty",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(checkpoint.Frontier) != 1 || !strings.Contains(checkpoint.Frontier[0], "continue the analysis") {
		t.Fatalf("frontier = %v, want the explicit continue entry", checkpoint.Frontier)
	}
	if len(checkpoint.Evidence) != 0 {
		t.Fatalf("evidence = %v, want no invented refs", checkpoint.Evidence)
	}
}

func TestCheckpointRejectsTamperingAndMissingContext(t *testing.T) {
	checkpoint, err := BuildCheckpoint(checkpointFixture())
	if err != nil {
		t.Fatal(err)
	}
	tampered := checkpoint
	tampered.Usage.ToolCalls++
	if err := tampered.Validate(); err == nil || !strings.Contains(err.Error(), "digest") {
		t.Fatalf("tampered usage: %v, want a digest failure", err)
	}
	noReason := checkpointFixture()
	noReason.Reason = ""
	if _, err := BuildCheckpoint(noReason); err == nil {
		t.Fatal("a checkpoint without a reason was accepted")
	}
	wrongPath := checkpointFixture()
	wrongPath.Task.PathID = "path-2"
	if _, err := BuildCheckpoint(wrongPath); err == nil {
		t.Fatal("a task from another path was accepted")
	}
}
