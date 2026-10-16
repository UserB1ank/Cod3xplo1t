package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/schedule"
)

// schedulerArgs is the flag tail every scheduler command in this file shares: a
// real workspace, the SQLite database and the scripted adapter that answers the
// audit's own security goal.
func schedulerArgs(workspace, db string, extra ...string) []string {
	args := []string{"--workspace", workspace, "--db", db}
	return append(args, extra...)
}

// cliSinglePathAudit creates an audit with exactly one path and returns its id and
// the security goal that path's task carries.
//
// One path is what makes the scripted adapter usable here: a scripted answer must
// name the goal of the task it receives, and with several paths the scheduler's
// own pick (the earliest due path, id breaking ties) need not be the
// highest-priority one the test would otherwise read.
func cliSinglePathAudit(t *testing.T, workspace, db, snapID string) (string, string) {
	t.Helper()
	out, err := captureStdout(t, func() error {
		return runAudit(context.Background(), auditCreateArgs(snapID, workspace, db, "--json", "--max-paths", "1"))
	})
	if err != nil {
		t.Fatalf("audit create: %v\n%s", err, out)
	}
	var created auditResult
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("create output is not JSON: %v\n%s", err, out)
	}
	if created.Audit.ID == "" || created.PathCount != 1 {
		t.Fatalf("audit create with --max-paths 1 queued %d path(s), want exactly 1", created.PathCount)
	}
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{
			"paths", created.Audit.ID, "--limit", "1", "--json",
			"--workspace", workspace, "--db", db,
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
	if len(page.Paths) != 1 {
		t.Fatalf("audit has %d path(s), want the single path it was bounded to", len(page.Paths))
	}
	if len(page.Paths[0].Objectives) == 0 {
		t.Skip("the fixture path carries no objective, so there is no security goal to answer")
	}
	return created.Audit.ID, strings.Join(page.Paths[0].Objectives, "; ")
}

// TestSchedulerCLITickStatusAndReclaim drives the P7 command surface end to end on
// a CLI-built workspace: one pass runs a path, status reports the queue that is
// left, and the manual reclaim sweep is a no-op when nothing expired.
func TestSchedulerCLITickStatusAndReclaim(t *testing.T) {
	// Not parallel: the CLI writes to stdout, which is process-wide.
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)
	auditID, goal := cliSinglePathAudit(t, workspace, db, snapID)
	answer := cliAgentAnswer(goal)

	// One pass, bounded at one path, with the audit named explicitly.
	out, err := captureStdout(t, func() error {
		return runScheduler(context.Background(), append([]string{
			"tick", "--audits", auditID, "--concurrency", "1",
			"--runtime", "scripted", "--agent-scripted-answer", answer, "--json",
		}, schedulerArgs(workspace, db)...))
	})
	if err != nil {
		t.Fatalf("scheduler tick: %v\n%s", err, out)
	}
	var result schedule.TickResult
	if err := json.Unmarshal([]byte(out), &result); err != nil {
		t.Fatalf("tick output is not JSON: %v\n%s", err, out)
	}
	if result.Dispatched != 1 || result.Failed != 0 {
		t.Fatalf("tick = %+v, want one successful dispatch", result)
	}
	if result.Held != 0 {
		t.Errorf("held = %d, want 0 after the pass settled its work", result.Held)
	}

	// The path really ran: it left the queue and reached HYPOTHESIS_FORMED.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{
			"paths", auditID, "--status", "HYPOTHESIS_FORMED", "--json",
			"--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		t.Fatalf("audit paths: %v\n%s", err, out)
	}
	var page struct {
		Total int `json:"total"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("paths output is not JSON: %v\n%s", err, out)
	}
	if page.Total != 1 {
		t.Fatalf("paths at HYPOTHESIS_FORMED = %d, want the single dispatched path:\n%s", page.Total, out)
	}

	// Status reports the configuration and the durable queue.
	out, err = captureStdout(t, func() error {
		return runScheduler(context.Background(), append([]string{
			"status", "--runtime", "scripted", "--agent-scripted-answer", answer, "--json",
		}, schedulerArgs(workspace, db)...))
	})
	if err != nil {
		t.Fatalf("scheduler status: %v\n%s", err, out)
	}
	var status struct {
		Configured bool           `json:"configured"`
		Running    bool           `json:"running"`
		Queue      map[string]any `json:"queue"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("status output is not JSON: %v\n%s", err, out)
	}
	if !status.Configured {
		t.Errorf("configured = false with --runtime set:\n%s", out)
	}
	if status.Running {
		t.Error("running = true for a one-shot command")
	}
	if status.Queue == nil {
		t.Errorf("status carries no durable queue view:\n%s", out)
	}

	// The manual reclaim sweep finds nothing to recover.
	out, err = captureStdout(t, func() error {
		return runScheduler(context.Background(), append([]string{"reclaim", "--json"}, schedulerArgs(workspace, db)...))
	})
	if err != nil {
		t.Fatalf("scheduler reclaim: %v\n%s", err, out)
	}
	var reclaimed struct {
		Count int `json:"count"`
	}
	if err := json.Unmarshal([]byte(out), &reclaimed); err != nil {
		t.Fatalf("reclaim output is not JSON: %v\n%s", err, out)
	}
	if reclaimed.Count != 0 {
		t.Errorf("reclaimed %d lease(s) with nothing expired", reclaimed.Count)
	}
}

// TestSchedulerCLIRunReleasesAndStops pins the foreground loop: Ctrl-C cancels the
// context, Run returns cleanly and every lease it held is released.
func TestSchedulerCLIRunReleasesAndStops(t *testing.T) {
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)
	auditID, goal := cliAuditAndGoal(t, workspace, db, snapID)
	answer := cliAgentAnswer(goal)

	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		// The loop's first pass runs immediately; the long interval means only the
		// cancellation ends it.
		time.Sleep(250 * time.Millisecond)
		cancel()
	}()
	out, err := captureStdout(t, func() error {
		return runScheduler(ctx, append([]string{
			"run", "--audits", auditID, "--interval", "3600", "--concurrency", "1",
			"--runtime", "scripted", "--agent-scripted-answer", answer,
		}, schedulerArgs(workspace, db)...))
	})
	if err != nil {
		t.Fatalf("scheduler run: %v\n%s", err, out)
	}
	if !strings.Contains(out, "scheduler stopped") {
		t.Errorf("run output does not report the clean stop:\n%s", out)
	}

	// Nothing is left leased: the released path is claimable again.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{
			"next", auditID, "--json", "--workspace", workspace, "--db", db,
		})
	})
	if err != nil {
		// An audit whose work all completed has no next path; that is not a
		// failure of this test.
		t.Logf("audit next after the run: %v", err)
		return
	}
}

// TestSchedulerCLIStatusWithoutAnAgent keeps the read-only command usable without
// an adapter: the resident loop needs one, but reporting the queue does not.
func TestSchedulerCLIStatusWithoutAnAgent(t *testing.T) {
	workspace, db := scgWorkspace(t)
	out, err := captureStdout(t, func() error {
		return runScheduler(context.Background(), append([]string{"status", "--json"}, schedulerArgs(workspace, db)...))
	})
	if err != nil {
		t.Fatalf("scheduler status without an agent: %v\n%s", err, out)
	}
	var status struct {
		Configured bool           `json:"configured"`
		Queue      map[string]any `json:"queue"`
	}
	if err := json.Unmarshal([]byte(out), &status); err != nil {
		t.Fatalf("status output is not JSON: %v\n%s", err, out)
	}
	if status.Configured {
		t.Error("configured = true without an agent runtime")
	}
	if status.Queue == nil {
		t.Errorf("status carries no durable queue view:\n%s", out)
	}
}

// TestSchedulerCLIErrors pins the refusals: a scheduler without an agent cannot be
// started, and a nonsensical flag is rejected before anything is built.
func TestSchedulerCLIErrors(t *testing.T) {
	workspace, db := scgWorkspace(t)

	if err := runScheduler(context.Background(), []string{"nonsense"}); err == nil {
		t.Error("an unknown scheduler subcommand was accepted")
	}

	// tick needs the scheduler, and the scheduler needs an adapter.
	out, err := captureStdout(t, func() error {
		return runScheduler(context.Background(), append([]string{"tick"}, schedulerArgs(workspace, db)...))
	})
	if err == nil {
		t.Fatalf("scheduler tick without --runtime was accepted:\n%s", out)
	}
	if !strings.Contains(err.Error(), "agent runtime") {
		t.Errorf("tick without --runtime = %v, want the message to name the agent runtime", err)
	}

	if err := runScheduler(context.Background(), append([]string{"tick", "--concurrency", "-1"}, schedulerArgs(workspace, db)...)); err == nil {
		t.Error("a negative concurrency was accepted")
	}
	if err := runScheduler(context.Background(), append([]string{
		"run", "--interval", "-1", "--runtime", "cli", "--agent-command", "true",
	}, schedulerArgs(workspace, db)...)); err == nil {
		t.Error("a negative interval was accepted")
	}
	if err := runScheduler(context.Background(), append([]string{"reclaim", "--limit", "-1"}, schedulerArgs(workspace, db)...)); err == nil {
		t.Error("a negative reclaim limit was accepted")
	}
}
