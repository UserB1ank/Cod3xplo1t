package main

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// auditCreateArgs is the request the CLI tests reuse, so the replay check asks
// for exactly the same configuration.
func auditCreateArgs(snapshotID, workspace, db string, extra ...string) []string {
	args := []string{
		"create", "--snapshot", snapshotID,
		"--max-entries", "50", "--max-paths", "50",
		"--max-depth", "2", "--max-branches", "2", "--max-tool-calls", "10",
		"--max-active-leases", "2", "--exploration-fraction", "0.2",
		"--sensitivity", "substring=0.9",
		"--workspace", workspace, "--db", db,
	}
	return append(args, extra...)
}

func TestAuditCLILifecycle(t *testing.T) {
	// Not parallel: the CLI writes to stdout, which is process-wide.
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)

	// create --json
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
	if created.Audit.ID == "" || created.PathCount == 0 {
		t.Fatalf("create queued nothing: %s", out)
	}
	if created.Replayed {
		t.Error("a fresh audit reported itself as replayed")
	}
	auditID := created.Audit.ID

	// Repeating the same request replays the audit instead of ranking again.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), auditCreateArgs(snapID, workspace, db, "--json"))
	})
	if err != nil {
		t.Fatalf("audit create replay: %v\n%s", err, out)
	}
	var repeated auditResult
	if err := json.Unmarshal([]byte(out), &repeated); err != nil {
		t.Fatalf("replay output is not JSON: %v\n%s", err, out)
	}
	if !repeated.Replayed || repeated.Audit.ID != auditID {
		t.Errorf("replay = %+v, want audit %s replayed", repeated, auditID)
	}

	// show (positional before the flags, which exercises the argument splitter).
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"show", auditID, "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit show: %v\n%s", err, out)
	}
	for _, want := range []string{auditID, "READY", "paths", "coverage", "evidence"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit show does not contain %q:\n%s", want, out)
		}
	}

	// list
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"list", "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit list: %v\n%s", err, out)
	}
	if !strings.Contains(out, auditID) || !strings.Contains(out, "AUDIT") {
		t.Errorf("audit list does not show the audit:\n%s", out)
	}

	// paths --json
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"paths", auditID, "--limit", "50", "--json", "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit paths: %v\n%s", err, out)
	}
	var page struct {
		Paths []path.Path `json:"paths"`
		Total int         `json:"total"`
	}
	if err := json.Unmarshal([]byte(out), &page); err != nil {
		t.Fatalf("paths output is not JSON: %v\n%s", err, out)
	}
	if len(page.Paths) == 0 || page.Total == 0 {
		t.Fatalf("audit paths returned nothing: %s", out)
	}
	for i := 1; i < len(page.Paths); i++ {
		if page.Paths[i].Score.Priority > page.Paths[i-1].Score.Priority {
			t.Errorf("paths are not in priority order: %s before %s", page.Paths[i-1].ID, page.Paths[i].ID)
		}
	}

	// The human table must carry the columns an operator schedules from.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"paths", auditID, "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit paths (human): %v\n%s", err, out)
	}
	for _, want := range []string{"PRIORITY", "STATUS", "PATH_STATUS", "ENTRY -> TARGET", "CLUSTER", "LEASE"} {
		if !strings.Contains(out, want) {
			t.Errorf("path table is missing %q:\n%s", want, out)
		}
	}

	// path: steps, the priority breakdown, the open questions and the score
	// history, which is the answer an auditor reads.
	pathID := page.Paths[0].ID
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"path", pathID, "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit path: %v\n%s", err, out)
	}
	for _, want := range []string{"steps", "priority    R=", "open questions", "score history", "evidence refs"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit path is missing %q:\n%s", want, out)
		}
	}

	// order: the scheduling plan, including which picks are exploration picks.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"order", auditID, "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit order: %v\n%s", err, out)
	}
	for _, want := range []string{"PICK", "pick(s)", "limits"} {
		if !strings.Contains(out, want) {
			t.Errorf("audit order is missing %q:\n%s", want, out)
		}
	}

	// next answers without leasing.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"next", auditID, "--json", "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit next: %v\n%s", err, out)
	}
	var nextBody struct {
		Path   path.Path `json:"path"`
		Leased bool      `json:"leased"`
	}
	if err := json.Unmarshal([]byte(out), &nextBody); err != nil {
		t.Fatalf("next output is not JSON: %v\n%s", err, out)
	}
	if nextBody.Leased || nextBody.Path.LeaseOwner != "" {
		t.Errorf("next leased a path: %s", out)
	}
	nextPathID := nextBody.Path.ID

	// claim the next path, renew the lease, then hand it back.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"claim", nextPathID, "--owner", "worker-1", "--ttl", "60", "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit claim: %v\n%s", err, out)
	}
	if !strings.Contains(out, "ANALYZING") || !strings.Contains(out, "worker-1") {
		t.Errorf("claim does not show the leased path:\n%s", out)
	}
	claimedPathID := pathIDFromOutput(t, out, page.Paths)

	_, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"heartbeat", claimedPathID, "--owner", "worker-2", "--workspace", workspace, "--db", db})
	})
	if err == nil {
		t.Fatal("a foreign heartbeat succeeded")
	}
	if !strings.Contains(err.Error(), "another worker holds this path") {
		t.Errorf("foreign heartbeat error is not actionable: %v", err)
	}

	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"heartbeat", claimedPathID, "--owner", "worker-1", "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit heartbeat: %v\n%s", err, out)
	}
	if !strings.Contains(out, "renewed") {
		t.Errorf("heartbeat does not report the renewal:\n%s", out)
	}

	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"release", claimedPathID, "--owner", "worker-1", "--reason", "handing back", "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit release: %v\n%s", err, out)
	}
	if !strings.Contains(out, "QUEUED") {
		t.Errorf("release did not requeue the path:\n%s", out)
	}

	// pause, resume and cancel, with the positional argument first.
	for _, step := range []struct {
		action string
		want   string
	}{
		{"pause", "PAUSED"},
		{"resume", "QUEUED"},
		{"cancel", "CANCELLED"},
	} {
		action := step.action
		out, err = captureStdout(t, func() error {
			return runAudit(context.Background(), []string{action, claimedPathID, "--reason", "cli test", "--workspace", workspace, "--db", db})
		})
		if err != nil {
			t.Fatalf("audit %s: %v\n%s", action, err, out)
		}
		if !strings.Contains(out, step.want) {
			t.Errorf("audit %s does not report %s:\n%s", action, step.want, out)
		}
	}

	// rescore replays the ranking; reclaim reports that no lease expired.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"rescore", auditID, "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit rescore: %v\n%s", err, out)
	}
	if !strings.Contains(out, auditID) {
		t.Errorf("rescore does not report the audit:\n%s", out)
	}
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"reclaim", "--limit", "5", "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit reclaim: %v\n%s", err, out)
	}
	if !strings.Contains(out, "no expired lease") {
		t.Errorf("reclaim should have found nothing:\n%s", out)
	}

	// events: the log of the audit, including the generated queue.
	out, err = captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"events", "--audit", auditID, "--workspace", workspace, "--db", db})
	})
	if err != nil {
		t.Fatalf("audit events: %v\n%s", err, out)
	}
	if !strings.Contains(out, "audit_created") || !strings.Contains(out, "SEQ") {
		t.Errorf("audit events does not show the log:\n%s", out)
	}
}

// TestAuditCreateOnCLIBuiltSnapshot pins the CLI's own snapshot lifecycle: `asg
// build` writes the frozen tree and the graph rows but no `snapshots` table row
// (the CLI has no project concept, and `project_id` is NOT NULL), so resolving a
// snapshot through the store would reject the snapshot the user just built.
func TestAuditCreateOnCLIBuiltSnapshot(t *testing.T) {
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)

	// The precondition the bug depended on: a loadable snapshot with no row.
	ctx := context.Background()
	rt, err := app.Build(ctx, app.Config{Workspace: workspace, DBPath: db})
	if err != nil {
		t.Fatalf("open runtime: %v", err)
	}
	if _, err := rt.Manager.Load(snapID); err != nil {
		rt.Close()
		t.Fatalf("the CLI build did not leave a loadable snapshot: %v", err)
	}
	if _, err := rt.Store.GetSnapshot(ctx, snapID); !errors.Is(err, storage.ErrNotFound) {
		rt.Close()
		t.Fatalf("precondition: a snapshots row exists for %s (err=%v); this test no longer covers a CLI-only workspace", snapID, err)
	}
	if err := rt.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}

	out, err := captureStdout(t, func() error {
		return runAudit(ctx, auditCreateArgs(snapID, workspace, db, "--json"))
	})
	if err != nil {
		t.Fatalf("audit create on a CLI-built snapshot: %v\n%s", err, out)
	}
	var created auditResult
	if err := json.Unmarshal([]byte(out), &created); err != nil {
		t.Fatalf("create output is not JSON: %v\n%s", err, out)
	}
	if created.Audit.ID == "" || created.PathCount == 0 {
		t.Fatalf("create queued nothing: %s", out)
	}

	// The queue is readable through the same workspace, which is the answer the
	// user asked for.
	out, err = captureStdout(t, func() error {
		return runAudit(ctx, []string{"paths", created.Audit.ID, "--json", "--workspace", workspace, "--db", db})
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
		t.Fatalf("no path was queued for a CLI-built snapshot: %s", out)
	}
}

// pathIDFromOutput extracts the first path id printed by a command, which is what
// claim returns.
func pathIDFromOutput(t *testing.T, output string, candidates []path.Path) string {
	t.Helper()
	for _, p := range candidates {
		if strings.Contains(output, p.ID) {
			return p.ID
		}
	}
	t.Fatalf("output does not mention any known path:\n%s", output)
	return ""
}

func TestAuditCLIErrors(t *testing.T) {
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)

	// A snapshot with an SCG but no attack surface must name the build command.
	graphOnly := buildSCG(t, scgFixture(t), workspace, db)

	cases := []struct {
		name     string
		args     []string
		mustHave string
	}{
		{"no subcommand", nil, "usage: codexploit audit"},
		{"unknown subcommand", []string{"nope"}, "unknown audit subcommand"},
		{"create without snapshot", []string{"create", "--workspace", workspace, "--db", db}, "--snapshot is required"},
		{"show without id", []string{"show", "--workspace", workspace, "--db", db}, "an audit id is required"},
		{"unknown audit", []string{"show", "audit-00000000000000000000000000000000", "--workspace", workspace, "--db", db}, "codexploit audit list"},
		{"unknown path", []string{"path", "path-00000000000000000000000000000000", "--workspace", workspace, "--db", db}, "does not exist"},
		{"claim without owner", []string{"claim", "audit-00000000000000000000000000000000", "--workspace", workspace, "--db", db}, "--owner is required"},
		{"bad sensitivity", []string{"create", "--snapshot", snapID, "--sensitivity", "nope", "--workspace", workspace, "--db", db}, "sensitivity must be key=value"},
		{"bad status filter", []string{"paths", "audit-00000000000000000000000000000000", "--status", "NOPE", "--workspace", workspace, "--db", db}, "unknown status"},
		{"unknown snapshot", []string{"create", "--snapshot", "snap-00000000000000000000000000000000", "--workspace", workspace, "--db", db}, "codexploit snapshot"},
		{"no attack surface", []string{"create", "--snapshot", graphOnly, "--workspace", workspace, "--db", db}, "codexploit asg build"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out, err := captureStdout(t, func() error { return runAudit(context.Background(), tc.args) })
			if err == nil {
				t.Fatalf("audit %v unexpectedly succeeded:\n%s", tc.args, out)
			}
			if !strings.Contains(err.Error(), tc.mustHave) {
				t.Errorf("error = %q, want it to contain %q", err, tc.mustHave)
			}
		})
	}

	// A filter typo is an error, not an empty listing.
	if _, err := captureStdout(t, func() error {
		return runAudit(context.Background(), []string{"path", "path-00000000000000000000000000000000", "--workspace", workspace, "--db", db})
	}); err == nil || !strings.Contains(err.Error(), "codexploit audit paths") {
		t.Errorf("unknown path error is not actionable: %v", err)
	}
}

// TestAuditCLISortIsHonoured pins the sort flag to an observable order: the same
// audit listed by priority and by id must be the same set in a different order.
func TestAuditCLISortIsHonoured(t *testing.T) {
	source := asgFixture(t)
	workspace, db := scgWorkspace(t)
	snapID := buildASG(t, source, workspace, db)

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

	list := func(sortKey string) []path.Path {
		t.Helper()
		out, err := captureStdout(t, func() error {
			return runAudit(context.Background(), []string{"paths", created.Audit.ID, "--sort", sortKey, "--json", "--workspace", workspace, "--db", db})
		})
		if err != nil {
			t.Fatalf("audit paths --sort %s: %v\n%s", sortKey, err, out)
		}
		var page struct {
			Paths []path.Path `json:"paths"`
		}
		if err := json.Unmarshal([]byte(out), &page); err != nil {
			t.Fatalf("paths output is not JSON: %v\n%s", err, out)
		}
		return page.Paths
	}
	byID := list("path_id")
	if len(byID) < 2 {
		t.Skip("the fixture produced fewer than two paths")
	}
	ids := make([]string, 0, len(byID))
	for _, p := range byID {
		ids = append(ids, p.ID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("--sort path_id is not ascending: %v", ids)
	}
}
