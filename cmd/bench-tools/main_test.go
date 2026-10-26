package main

import (
	"strings"
	"testing"
)

func TestGoldenToolSetHasIndependentGroundTruth(t *testing.T) {
	plan := scenarios()
	if len(plan) != 5 {
		t.Fatalf("scenarios = %d, want 5", len(plan))
	}
	seen := map[string]bool{}
	for _, item := range plan {
		if item.ID == "" || item.Question == "" || item.Expected == "" || len(item.Evidence) == 0 || item.NewTool == "" || seen[item.ID] {
			t.Fatalf("invalid or duplicate scenario: %+v", item)
		}
		seen[item.ID] = true
	}
}

func TestAnswerAndEvidenceMustMatchTheScenario(t *testing.T) {
	answer, evidence, ok := parseAnswer(`{"answer":"handler.py:3/4","evidence":["file:handler.py"]}`)
	if !ok || answer != "handler.py:3/4" || !containsAll(evidence, []string{"file:handler.py"}) {
		t.Fatalf("valid answer rejected: %q %v %t", answer, evidence, ok)
	}
	if _, _, ok := parseAnswer(`{"answer":"handler.py:3/4","evidence":[],"extra":1}`); ok {
		t.Fatal("invalid answer shape was accepted")
	}
	if containsAll([]string{"file:other.py"}, []string{"file:handler.py"}) {
		t.Fatal("wrong evidence was accepted")
	}
	if !answersEqual("sr-42; control effectiveness unassessed", "sr-42;control effectiveness unassessed") {
		t.Fatal("insignificant punctuation spacing rejected a valid answer")
	}
	if answersEqual("sr-42", "sr-42;control effectiveness unassessed") {
		t.Fatal("missing fact was accepted")
	}
}

func TestOldToolNeedsExactlyOneFollowUpAndModernDoesNot(t *testing.T) {
	item := scenarios()[0]
	if old := executeTool(item, false, 0); old == item.OldComplete {
		t.Fatal("old first page unexpectedly contains the complete answer")
	}
	if old := executeTool(item, false, 1); old != item.OldComplete {
		t.Fatalf("old follow-up = %s", old)
	}
	if modern := executeTool(item, true, 0); !strings.Contains(modern, item.Expected) {
		t.Fatalf("modern answer missing fact: %s", modern)
	}
}

func TestRoundReductionRequiresEveryAnswerToValidate(t *testing.T) {
	samples := []sample{
		{Scenario: "a", Variant: "old", Validated: true},
		{Scenario: "b", Variant: "new", Validated: false},
	}
	if allValidated(samples) {
		t.Fatal("an unvalidated answer was allowed into a passing report")
	}
	samples[1].Validated = true
	if !allValidated(samples) {
		t.Fatal("fully validated samples were rejected")
	}
}
