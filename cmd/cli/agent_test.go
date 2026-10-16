package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// cliAgentAnswer builds the structured answer the scripted agent replays. The
// security goal is the task's own: the facts builder derives it from the path's
// objectives, so the test reads the path it is about to run instead of guessing a
// vocabulary that belongs to the graph layer.
func cliAgentAnswer(securityGoal string) string {
	return fmt.Sprintf(`{
  "schema_version": %d,
  "security_goal": %q,
  "hypothesis": {
    "statement": "the request name reaches the query without parameterisation",
    "status": "candidate",
    "confidence": "medium"
  },
  "supporting_evidence": [
    {"kind": "source", "ref": "ev-1", "file": "main.go", "line": 46, "summary": "the query concatenates the request value"}
  ],
  "contradicting_evidence": [],
  "next_action": "request a deeper dataflow slice",
  "finding_candidate": true,
  "severity_hint": "high"
}`, agent.SchemaVersion, securityGoal)
}

// cliAuditAndGoal creates an audit over a CLI-built snapshot and returns its id
// and the security goal of its first path.
func cliAuditAndGoal(t *testing.T, workspace, db, snapID string) (string, string) {
	t.Helper()
	out, err := captureStdout(t, func() error {
		return runAudit(context.Background(), auditCreateArgs(snapID, workspace, db, "--json"))
	})
	if err != nil {
		t.Fatalf("audit create: %v\n%s", err, out)
	}
	var created auditResult
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("create output is not JSON: %v\n%s", err, out)
	}
	if created.Audit.ID == "" {
		t.Fatalf("audit create queued nothing: %s", out)
	}
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{
			"paths", created.Audit.ID, "--limit", "1", "--json", "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("audit paths: %v\n%s", err, out)
	}
	var page struct {
		Paths []path.Path `json:"paths"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("paths output is not JSON: %v\n%s", err, out)
	}
	if len(page.Paths) == 0 {
		t.Fatalf("the audit queued no path: %s", out)
	}
	objectives := page.Paths[0].Objectives
	if len(objectives) == 0 {
		t.Skip("the fixture path carries no objective, so there is no security goal to answer")
	}
	return created.Audit.ID, strings.Join(objectives, "; ")
}

// TestAgentCLIRunAndReads pins the whole P5 command surface on a CLI-built
// workspace: the run starts from the CLI's own runtime configuration (no API),
// and every read is reachable afterwards.
func TestAgentCLIRunAndReads(t *testing.T) {
	// Not parallel: the CLI writes to stdout, which is process-wide.
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)
	auditID, goal := cliAuditAndGoal(t, workspace, db, snapID)

	answer := cliAgentAnswer(goal)
	runArgs := func(extra ...string) []string {
		args := []string{
			"run", auditID, "--runtime", "scripted", "--agent-scripted-answer", answer,
			"--owner", "cli-worker", "--max-tool-calls", "10", "--max-hops", "2",
			"--workspace", workspace, "--db", db,
		}
		return append(args, extra...)
	}
	// --json mirrors the API's run batch. It is the first invocation so the run
	// that the later reads examine is the one this test started.
	out, err := captureStdout(t, func() error {
		return runAgent(context.Background(), runArgs("--json"))
	})
	if err != nil {
		t.Fatalf("run --json: %v\n%s", err, out)
	}
	var batch struct {
		Runs       []agent.Run `json:"runs"`
		Count      int         `json:"count"`
		StopReason string      `json:"stop_reason"`
	}
	if err := json.Unmarshal([]byte(out), &batch); err != nil {
		t.Fatalf("run --json output is not JSON: %v\n%s", err, out)
	}
	if batch.Count != 1 || len(batch.Runs) != 1 {
		t.Fatalf("run --json = %s", out)
	}
	first := batch.Runs[0]
	if first.Status != agent.RunSucceeded || first.StopReason == "" {
		t.Errorf("first run = %+v", first)
	}
	if first.Task.SecurityGoal == "" || len(first.Task.EvidenceRefs) == 0 {
		t.Errorf("the run lost its task: %+v", first.Task)
	}
	if first.Answer == nil || first.Answer.Hypothesis.Statement == "" {
		t.Errorf("the run lost its answer: %+v", first.Answer)
	}

	// The human-readable form carries what an operator reviews a run for: how it
	// ended, what it cost, and the claims it produced.
	out, err = captureStdout(t, func() error {
		return runAgent(context.Background(), runArgs())
	})
	if err != nil {
		t.Fatalf("run: %v\n%s", err, out)
	}
	for _, want := range []string{"SUCCEEDED", "completed", "tool call", "expansion", "token", "hypotheses", "candidate", "medium", "true"} {
		if !strings.Contains(out, want) {
			t.Errorf("run output is missing %q:\n%s", want, out)
		}
	}

	// The path ends HYPOTHESIS_FORMED without a lease, which is what makes the
	// loop terminate instead of re-running the same path.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{
			"path", first.PathID, "--json", "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("audit path: %v\n%s", err, out)
	}
	var detail struct {
		Path path.Path `json:"path"`
	}
	if err := json.Unmarshal([]byte(out), &detail); err != nil {
		t.Fatalf("path output is not JSON: %v\n%s", err, out)
	}
	if detail.Path.Status != path.StatusHypothesisFormed {
		t.Errorf("path status = %s, want HYPOTHESIS_FORMED", detail.Path.Status)
	}
	if detail.Path.LeaseOwner != "" {
		t.Errorf("the finished path still holds a lease for %q", detail.Path.LeaseOwner)
	}

	// runs list
	out, err = captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"runs", "list", "--audit", auditID, "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("runs list: %v\n%s", err, out)
	}
	if !strings.Contains(out, first.ID) || !strings.Contains(out, "SUCCEEDED") || !strings.Contains(out, "STATUS") {
		t.Errorf("runs list does not show the run:\n%s", out)
	}

	// runs show prints the whole run, including the hypotheses it produced.
	out, err = captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"runs", "show", first.ID, "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("runs show: %v\n%s", err, out)
	}
	for _, want := range []string{first.ID, first.PathID, "SUCCEEDED", "completed", "STATEMENT", "candidate"} {
		if !strings.Contains(out, want) {
			t.Errorf("runs show is missing %q:\n%s", want, out)
		}
	}

	// runs events honours --type and --after.
	out, err = captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"runs", "events", first.ID, "--json", "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("runs events: %v\n%s", err, out)
	}
	var events struct {
		Events []agent.Event `json:"events"`
	}
	if err := json.Unmarshal([]byte(out), &events); err != nil {
		t.Fatalf("events output is not JSON: %v\n%s", err, out)
	}
	if len(events.Events) == 0 {
		t.Fatalf("runs events returned nothing: %s", out)
	}
	sawFinished := false
	for _, event := range events.Events {
		if event.Type == agent.EventRunFinished {
			sawFinished = true
		}
	}
	if !sawFinished {
		t.Errorf("the event log has no run_finished event: %s", out)
	}

	filtered, err := captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"runs", "events", first.ID, "--type", agent.EventRunCreated, "--json",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("runs events --type: %v\n%s", err, filtered)
	}
	var typed struct {
		Events []agent.Event `json:"events"`
		Total  int           `json:"total"`
	}
	if err := json.Unmarshal([]byte(filtered), &typed); err != nil {
		t.Fatalf("filtered events are not JSON: %v\n%s", err, filtered)
	}
	if typed.Total != 1 || typed.Events[0].Type != agent.EventRunCreated {
		t.Errorf("--type filter = %s", filtered)
	}
	after, err := captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"runs", "events", first.ID, "--after", fmt.Sprint(events.Events[0].Seq), "--json",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("runs events --after: %v\n%s", err, after)
	}
	var resumed struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(after), &resumed); err != nil {
		t.Fatalf("resumed events are not JSON: %v\n%s", err, after)
	}
	if resumed.Total != len(events.Events)-1 {
		t.Errorf("--after returned %d events, want %d", resumed.Total, len(events.Events)-1)
	}

	// hypotheses list and show
	out, err = captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"hypotheses", "list", "--audit", auditID, "--finding-candidates",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("hypotheses list: %v\n%s", err, out)
	}
	for _, want := range []string{"HYPOTHESIS", "candidate", "true", "parameterisation"} {
		if !strings.Contains(out, want) {
			t.Errorf("hypotheses list is missing %q:\n%s", want, out)
		}
	}
	out, err = captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"hypotheses", "list", "--audit", auditID, "--path", first.PathID, "--json",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("hypotheses list --json: %v\n%s", err, out)
	}
	var listed struct {
		Hypotheses []agent.Hypothesis `json:"hypotheses"`
		Total      int                `json:"total"`
	}
	if err := json.Unmarshal([]byte(out), &listed); err != nil {
		t.Fatalf("hypotheses output is not JSON: %v\n%s", err, out)
	}
	// The very first run of this test is the one being read, so exactly its claim
	// is in scope. A later run is a different path and a different hypothesis.
	if listed.Total != 1 || len(listed.Hypotheses) != 1 {
		t.Fatalf("hypotheses = %s", out)
	}
	hypothesis := listed.Hypotheses[0]
	if !hypothesis.FindingCandidate || len(hypothesis.Supporting) == 0 {
		t.Errorf("hypothesis = %+v", hypothesis)
	}
	if hypothesis.RunID != first.ID || hypothesis.PathID != first.PathID {
		t.Errorf("hypothesis belongs to %s/%s, want %s/%s",
			hypothesis.RunID, hypothesis.PathID, first.ID, first.PathID)
	}

	out, err = captureStdout(t, func() error {
		return runAgent(context.Background(), []string{
			"hypotheses", "show", hypothesis.ID, "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("hypotheses show: %v\n%s", err, out)
	}
	for _, want := range []string{hypothesis.ID, "supporting", "ev-1", "candidate"} {
		if !strings.Contains(out, want) {
			t.Errorf("hypotheses show is missing %q:\n%s", want, out)
		}
	}
}

// TestAgentCLIRequiresConfiguration pins the actionable message: a run in a
// workspace with no agent configuration must say which flags configure one,
// because "nothing ran" is otherwise indistinguishable from an empty queue. The
// reads deliberately do not need an agent: a run recorded through the API is
// readable here against the same database.
func TestAgentCLIRequiresConfiguration(t *testing.T) {
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)
	auditID, _ := cliAuditAndGoal(t, workspace, db, snapID)

	out, err := captureStdout(t, func() error {
		return runAgent(context.Background(), []string{"run", auditID, "--workspace", workspace, "--db", db})
	})
	if err == nil {
		t.Fatalf("run unexpectedly succeeded:\n%s", out)
	}
	for _, want := range []string{"--agent-runtime", "--agent-command", "--runtime"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %q", err, want)
		}
	}

	// The reads answer an empty workspace rather than refusing to look.
	for _, args := range [][]string{
		{"runs", "list", "--workspace", workspace, "--db", db},
		{"hypotheses", "list", "--workspace", workspace, "--db", db},
	} {
		readOut, err := captureStdout(t, func() error { return runAgent(context.Background(), args) })
		if err != nil {
			t.Errorf("%v: %v\n%s", args, err, readOut)
		}
	}
}

func TestAgentCLIErrors(t *testing.T) {
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)
	auditID, _ := cliAuditAndGoal(t, workspace, db, snapID)

	cases := []struct {
		name     string
		args     []string
		mustHave string
	}{
		{"no subcommand", nil, "usage: codexploit"},
		{"unknown subcommand", []string{"nope"}, "unknown agent subcommand"},
		{"run without id", []string{"run", "--workspace", workspace, "--db", db}, "an audit id or a path id is required"},
		{"run too many", []string{"run", auditID, "--max-runs", "11", "--runtime", "scripted",
			"--agent-scripted-answer", `{}`, "--workspace", workspace, "--db", db}, "exceeds the 10"},
		{"unknown runtime", []string{"run", auditID, "--runtime", "gpt", "--workspace", workspace, "--db", db},
			"not an agent runtime"},
		{"cli without command", []string{"run", auditID, "--runtime", "cli", "--workspace", workspace, "--db", db},
			"--agent-command"},
		{"scripted without answer", []string{"run", auditID, "--runtime", "scripted", "--workspace", workspace, "--db", db},
			"--agent-scripted-answer"},
		{"bad scripted answer", []string{"run", auditID, "--runtime", "scripted",
			"--agent-scripted-answer", `{"security_goal": "x", "nope": 1}`, "--workspace", workspace, "--db", db},
			"not a valid agent answer"},
		{"unknown run", []string{"runs", "show", "run-00000000000000000000000000000000",
			"--runtime", "scripted", "--agent-scripted-answer", `{}`, "--workspace", workspace, "--db", db},
			"codexploit runs list"},
		{"unknown hypothesis", []string{"hypotheses", "show", "hyp-00000000000000000000000000000000",
			"--runtime", "scripted", "--agent-scripted-answer", `{}`, "--workspace", workspace, "--db", db},
			"codexploit runs list"},
		{"bad run status", []string{"runs", "list", "--status", "NOPE", "--runtime", "scripted",
			"--agent-scripted-answer", `{}`, "--workspace", workspace, "--db", db}, "unknown status"},
		{"bad hypothesis status", []string{"hypotheses", "list", "--status", "nope", "--runtime", "scripted",
			"--agent-scripted-answer", `{}`, "--workspace", workspace, "--db", db}, "unknown hypothesis status"},
		{"unknown runs subcommand", []string{"runs", "nope", "--workspace", workspace, "--db", db}, "unknown runs subcommand"},
		{"unknown hypotheses subcommand", []string{"hypotheses", "nope", "--workspace", workspace, "--db", db}, "unknown hypotheses subcommand"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureStdout(t, func() error { return runAgent(context.Background(), tc.args) })
			if err == nil {
				t.Fatalf("%v unexpectedly succeeded:\n%s", tc.args, out)
			}
			if !strings.Contains(err.Error(), tc.mustHave) {
				t.Errorf("error = %q, want it to contain %q", err, tc.mustHave)
			}
		})
	}
}
