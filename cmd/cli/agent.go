package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// agentFlags are the flags shared by the agent subcommands. They mirror the HTTP
// parameters one for one, so a run started through the API can be reproduced on
// the command line and the other way round.
type agentFlags struct {
	workspace string
	dbPath    string
	jsonOut   bool

	runtime        string
	command        repeatedArgs
	env            repeatedArgs
	workingDir     string
	timeout        int
	maxHops        int
	maxBranches    int
	maxToolCalls   int
	maxExpansions  int
	tokenBudget    int
	tools          string
	owner          string
	heartbeat      int
	scriptedAnswer string

	maxRuns    int
	pathID     string
	auditID    string
	snapshotID string
	status     string
	eventType  string
	after      int64
	limit      int
	offset     int

	findingCandidates bool
}

// repeatedArgs collects a flag that may be given more than once, keeping the
// order the operator wrote: an argv is order-significant.
type repeatedArgs []string

func (r *repeatedArgs) String() string { return strings.Join(*r, " ") }

func (r *repeatedArgs) Set(value string) error {
	*r = append(*r, value)
	return nil
}

// parseAgent builds the flag set of one subcommand and separates the positional
// arguments from the flags, exactly like the audit subcommands.
func parseAgent(name string, args []string, extra func(*flag.FlagSet, *agentFlags)) (*agentFlags, []string, error) {
	fs := flag.NewFlagSet("agent "+name, flag.ContinueOnError)
	c := &agentFlags{limit: 50}
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.StringVar(&c.dbPath, "db", "", "SQLite database file (default <workspace>/codexploit.db)")
	fs.BoolVar(&c.jsonOut, "json", false, "print JSON")
	if extra != nil {
		extra(fs, c)
	}
	positionals, flags := splitArgs(fs, args)
	if err := fs.Parse(flags); err != nil {
		return nil, nil, err
	}
	if abs, err := filepath.Abs(c.workspace); err == nil {
		c.workspace = abs
	}
	if c.dbPath == "" {
		c.dbPath = filepath.Join(c.workspace, "codexploit.db")
	}
	return c, positionals, nil
}

// addAgentRuntimeFlags registers the flags that configure an agent runtime. They
// are named after the server's flags so one configuration works in both places.
func addAgentRuntimeFlags(fs *flag.FlagSet, c *agentFlags) {
	fs.StringVar(&c.runtime, "runtime", "", "agent adapter: scripted or cli (default: the configured one)")
	fs.Var(&c.command, "agent-command", "agent command argv, repeatable; the binary plus its arguments")
	fs.Var(&c.env, "agent-env", "environment entry for the agent process as KEY=VALUE, repeatable")
	fs.StringVar(&c.workingDir, "agent-working-dir", "", "working directory of the agent process")
	fs.IntVar(&c.timeout, "agent-timeout", 0, "agent run timeout in seconds")
	fs.IntVar(&c.maxHops, "max-hops", 0, "maximum hops one run may explore")
	fs.IntVar(&c.maxBranches, "max-branches", 0, "maximum active branches one run may hold")
	fs.IntVar(&c.maxToolCalls, "max-tool-calls", 0, "maximum tool calls one run may make")
	fs.IntVar(&c.maxExpansions, "max-expansions", 0, "maximum expansions one run may request")
	fs.IntVar(&c.tokenBudget, "token-budget", 0, "reported token budget of one run (0 is not enforced)")
	fs.StringVar(&c.tools, "agent-tools", "", "comma-separated tool allowlist (default all graph agent tools)")
	fs.StringVar(&c.owner, "owner", "", "lease owner recorded on the runs")
	fs.IntVar(&c.heartbeat, "heartbeat", 0, "lease heartbeat interval in seconds")
	fs.StringVar(&c.scriptedAnswer, "agent-scripted-answer", "", "raw JSON answer for the scripted runtime")
}

// runAgent dispatches the P5 subcommands.
func runAgent(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit <run|runs|hypotheses> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "run":
		return runAgentRun(ctx, rest)
	case "runs":
		return runAgentRuns(ctx, rest)
	case "hypotheses", "hypothesis":
		return runAgentHypotheses(ctx, rest)
	default:
		return fmt.Errorf("unknown agent subcommand %q", sub)
	}
}

// runAgentRun answers `codexploit run <audit-id|path-id>`: run the loop once or
// up to --max-runs times and print what each run produced.
func runAgentRun(ctx context.Context, args []string) error {
	c, rest, err := parseAgent("run", args, func(fs *flag.FlagSet, c *agentFlags) {
		fs.IntVar(&c.maxRuns, "max-runs", 1, "maximum paths to run in this call (at most 10)")
		addAgentRuntimeFlags(fs, c)
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "an audit id or a path id is required")
	if err != nil {
		return err
	}
	if c.maxRuns <= 0 {
		c.maxRuns = 1
	}
	if c.maxRuns > 10 {
		return fmt.Errorf("--max-runs %d exceeds the 10 run(s) one call may start", c.maxRuns)
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Agent == nil {
		return agentNotConfiguredError()
	}
	auditID, err := resolveRunAudit(ctx, rt, id)
	if err != nil {
		return err
	}
	runs, err := rt.Agent.RunAudit(ctx, auditID, c.maxRuns)
	if err != nil {
		return asAgentError(err, auditID)
	}
	if c.jsonOut {
		// The answer mirrors the API's run batch, so `--json` output can be piped
		// into the same parser as the HTTP response.
		stop := ""
		if len(runs) > 0 {
			stop = runs[len(runs)-1].StopReason
		}
		if runs == nil {
			runs = []agent.Run{}
		}
		return printJSON(map[string]any{"runs": runs, "count": len(runs), "stop_reason": stop})
	}
	if len(runs) == 0 {
		fmt.Printf("audit %s has no queued path to run; inspect it with `codexploit audit paths %s`\n", auditID, auditID)
		return nil
	}
	for i := range runs {
		printRun(&runs[i], rt)
	}
	return nil
}

// resolveRunAudit accepts either an audit id or a path id, so the id printed by
// `audit paths` can be handed straight to `run`.
func resolveRunAudit(ctx context.Context, rt *app.Runtime, id string) (string, error) {
	if strings.HasPrefix(id, "path-") {
		p, _, err := rt.Audit.Path(id)
		if err != nil {
			return "", asAuditError(err, id)
		}
		return p.AuditID, nil
	}
	if _, err := requireAudit(ctx, rt, id); err != nil {
		return "", err
	}
	return id, nil
}

// printRun renders one run the way an operator reviews it: what it was, how it
// ended, what it cost, and what it claims.
func printRun(run *agent.Run, rt *app.Runtime) {
	fmt.Printf("run        %s\n", run.ID)
	fmt.Printf("path       %s\n", run.PathID)
	fmt.Printf("status     %s\n", run.Status)
	fmt.Printf("stop       %s\n", orNone(run.StopReason))
	fmt.Printf("runtime    %s %s\n", run.Runtime, run.RuntimeVersion)
	if run.Answer != nil {
		fmt.Printf("goal       %s\n", run.Answer.SecurityGoal)
	}
	fmt.Printf("usage      %d tool call(s), %d expansion(s), %d in / %d out token(s), %d ms\n",
		run.ToolCalls, run.Expansions, run.InputTokens, run.OutputTokens, run.ElapsedMS)
	if run.Error != "" {
		fmt.Printf("error      %s\n", run.Error)
	}
	hypotheses, total, err := rt.Store.ListHypotheses(agent.HypothesisQuery{RunID: run.ID, Limit: 100})
	if err != nil {
		fmt.Printf("hypotheses (unreadable: %v)\n", err)
		return
	}
	if total == 0 {
		fmt.Printf("hypotheses (none recorded)\n\n")
		return
	}
	fmt.Printf("hypotheses %d\n", total)
	rows := make([][]string, 0, len(hypotheses))
	for _, h := range hypotheses {
		rows = append(rows, []string{
			h.Status, h.Confidence, strconv.FormatBool(h.FindingCandidate),
			strconv.Itoa(len(h.Supporting)), strconv.Itoa(len(h.Contradicting)), h.Statement,
		})
	}
	writeTable([]string{"STATUS", "CONFIDENCE", "FINDING", "SUPPORT", "CONTRADICT", "STATEMENT"}, rows)
	fmt.Println()
}

// runAgentRuns dispatches `runs list|show|events`.
func runAgentRuns(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit runs <list|show|events> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runRunsList(ctx, rest)
	case "show":
		return runRunsShow(ctx, rest)
	case "events":
		return runRunsEvents(ctx, rest)
	default:
		return fmt.Errorf("unknown runs subcommand %q", sub)
	}
}

func runRunsList(ctx context.Context, args []string) error {
	c, _, err := parseAgent("runs list", args, func(fs *flag.FlagSet, c *agentFlags) {
		fs.StringVar(&c.pathID, "path", "", "only runs of this path")
		fs.StringVar(&c.auditID, "audit", "", "only runs of this audit")
		fs.StringVar(&c.snapshotID, "snapshot", "", "only runs of this snapshot")
		fs.StringVar(&c.status, "status", "", "comma-separated run statuses")
		fs.IntVar(&c.limit, "limit", 50, "maximum runs to return")
		fs.IntVar(&c.offset, "offset", 0, "runs to skip")
		// The runtime flags are accepted so a caller can read a workspace in the
		// same invocation shape as `run`; the reads themselves never start an agent.
		addAgentRuntimeFlags(fs, c)
	})
	if err != nil {
		return err
	}
	statuses, err := agentRunStatuses(c.status)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	runs, total, err := rt.Store.ListRuns(agent.RunQuery{
		PathID: c.pathID, AuditID: c.auditID, SnapshotID: c.snapshotID,
		Status: statuses, Limit: c.limit, Offset: c.offset,
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"runs": runs, "total": total})
	}
	if len(runs) == 0 {
		fmt.Println("no run matches; list every run with `codexploit runs list`")
		return nil
	}
	rows := make([][]string, 0, len(runs))
	for _, run := range runs {
		rows = append(rows, []string{
			run.ID, shortID(run.PathID), string(run.Status), orNone(run.StopReason), run.Runtime,
			strconv.Itoa(run.ToolCalls), strconv.Itoa(run.Expansions),
			strconv.Itoa(run.InputTokens + run.OutputTokens), run.CreatedAt,
		})
	}
	writeTable([]string{"RUN", "PATH", "STATUS", "STOP", "RUNTIME", "TOOLS", "EXPAND", "TOKENS", "CREATED"}, rows)
	fmt.Printf("%d of %d run(s)\n", len(runs), total)
	return nil
}

func runRunsShow(ctx context.Context, args []string) error {
	c, rest, err := parseAgent("runs show", args, func(fs *flag.FlagSet, c *agentFlags) {
		addAgentRuntimeFlags(fs, c)
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a run id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	run, err := rt.Store.GetRun(id)
	if err != nil {
		return asAgentError(err, id)
	}
	if c.jsonOut {
		return printJSON(run)
	}
	printRun(run, rt)
	return nil
}

func runRunsEvents(ctx context.Context, args []string) error {
	c, rest, err := parseAgent("runs events", args, func(fs *flag.FlagSet, c *agentFlags) {
		fs.StringVar(&c.eventType, "type", "", "comma-separated event types")
		fs.Int64Var(&c.after, "after", 0, "only events after this sequence number")
		fs.IntVar(&c.limit, "limit", 100, "maximum events to return")
		addAgentRuntimeFlags(fs, c)
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a run id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if _, err := rt.Store.GetRun(id); err != nil {
		return asAgentError(err, id)
	}
	events, err := rt.Store.ListRunEvents(agent.EventQuery{
		RunID: id, Types: splitList(c.eventType), AfterSeq: c.after, Limit: c.limit,
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"run_id": id, "events": events, "total": len(events)})
	}
	if len(events) == 0 {
		fmt.Println("no event matches; list every event with `codexploit runs events <run-id>`")
		return nil
	}
	rows := make([][]string, 0, len(events))
	for _, event := range events {
		rows = append(rows, []string{
			strconv.FormatInt(event.Seq, 10), event.Type, event.Actor, orNone(event.Tool),
			event.Summary, event.CreatedAt,
		})
	}
	writeTable([]string{"SEQ", "TYPE", "ACTOR", "TOOL", "SUMMARY", "AT"}, rows)
	fmt.Printf("%d event(s)\n", len(events))
	return nil
}

// runAgentHypotheses dispatches `hypotheses list|show`.
func runAgentHypotheses(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit hypotheses <list|show> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runHypothesesList(ctx, rest)
	case "show":
		return runHypothesesShow(ctx, rest)
	default:
		return fmt.Errorf("unknown hypotheses subcommand %q", sub)
	}
}

func runHypothesesList(ctx context.Context, args []string) error {
	c, _, err := parseAgent("hypotheses list", args, func(fs *flag.FlagSet, c *agentFlags) {
		fs.StringVar(&c.auditID, "audit", "", "only hypotheses of this audit")
		fs.StringVar(&c.pathID, "path", "", "only hypotheses of this path")
		fs.StringVar(&c.status, "status", "", "comma-separated hypothesis statuses")
		fs.BoolVar(&c.findingCandidates, "finding-candidates", false, "only claims a verification phase should look at")
		fs.IntVar(&c.limit, "limit", 50, "maximum hypotheses to return")
		fs.IntVar(&c.offset, "offset", 0, "hypotheses to skip")
		addAgentRuntimeFlags(fs, c)
	})
	if err != nil {
		return err
	}
	statuses, err := agentHypothesisStatuses(c.status)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	hypotheses, total, err := rt.Store.ListHypotheses(agent.HypothesisQuery{
		AuditID: c.auditID, PathID: c.pathID, Status: statuses,
		FindingCandidatesOnly: c.findingCandidates, Limit: c.limit, Offset: c.offset,
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"hypotheses": hypotheses, "total": total})
	}
	if len(hypotheses) == 0 {
		fmt.Println("no hypothesis matches; run an audit first with `codexploit run <audit-id>`")
		return nil
	}
	printHypothesisTable(hypotheses)
	fmt.Printf("%d of %d hypothesis(es)\n", len(hypotheses), total)
	return nil
}

func runHypothesesShow(ctx context.Context, args []string) error {
	c, rest, err := parseAgent("hypotheses show", args, func(fs *flag.FlagSet, c *agentFlags) {
		addAgentRuntimeFlags(fs, c)
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a hypothesis id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	hypothesis, err := rt.Store.GetHypothesis(id)
	if err != nil {
		return asAgentError(err, id)
	}
	if c.jsonOut {
		return printJSON(hypothesis)
	}
	printHypothesis(*hypothesis)
	return nil
}

// printHypothesisTable prints the claims of a run or an audit in one table.
func printHypothesisTable(hypotheses []agent.Hypothesis) {
	rows := make([][]string, 0, len(hypotheses))
	for _, h := range hypotheses {
		rows = append(rows, []string{
			h.ID, shortID(h.PathID), h.Status, h.Confidence,
			strconv.FormatBool(h.FindingCandidate), h.Statement,
		})
	}
	writeTable([]string{"HYPOTHESIS", "PATH", "STATUS", "CONFIDENCE", "FINDING", "STATEMENT"}, rows)
}

// printHypothesis renders one claim with the evidence that supports or contradicts
// it, because a claim without its citations is not reviewable.
func printHypothesis(h agent.Hypothesis) {
	fmt.Printf("hypothesis %s\n", h.ID)
	fmt.Printf("path       %s\n", h.PathID)
	fmt.Printf("run        %s\n", h.RunID)
	fmt.Printf("status     %s\n", h.Status)
	fmt.Printf("confidence %s\n", h.Confidence)
	fmt.Printf("finding    %t\n", h.FindingCandidate)
	if h.SeverityHint != "" {
		fmt.Printf("severity   %s\n", h.SeverityHint)
	}
	fmt.Printf("statement  %s\n", h.Statement)
	if h.NextAction != "" {
		fmt.Printf("next       %s\n", h.NextAction)
	}
	printEvidence("supporting", h.Supporting)
	printEvidence("contradicting", h.Contradicting)
}

func printEvidence(label string, refs []agent.EvidenceRef) {
	if len(refs) == 0 {
		return
	}
	fmt.Printf("%s\n", label)
	for _, ref := range refs {
		where := ref.File
		if ref.Line > 0 {
			where = fmt.Sprintf("%s:%d", ref.File, ref.Line)
		}
		switch {
		case where != "" && ref.ID != "":
			where = where + " (" + ref.ID + ")"
		case where == "":
			where = ref.ID
		}
		fmt.Printf("  - %s %s %s\n", ref.Kind, where, ref.Summary)
	}
}

// --- runtime configuration --------------------------------------------------

// build builds the runtime and, when a --runtime was given, the agent over the
// CLI's own workspace. The runtime overrides the same flags the server takes, so
// an operator can reproduce a run without starting a server.
func (c *agentFlags) build(ctx context.Context) (*app.Runtime, error) {
	cfg := app.Config{Workspace: c.workspace, DBPath: c.dbPath}
	if mode := strings.TrimSpace(c.runtime); mode != "" {
		switch mode {
		case app.AgentRuntimeScripted, app.AgentRuntimeCLI:
		default:
			return nil, fmt.Errorf("--runtime %q is not an agent runtime (want %s or %s)",
				mode, app.AgentRuntimeScripted, app.AgentRuntimeCLI)
		}
		cfg.Agent = app.AgentConfig{
			Enabled:            true,
			Runtime:            mode,
			Command:            c.command,
			Env:                c.env,
			WorkingDir:         c.workingDir,
			TimeoutSeconds:     c.timeout,
			MaxHops:            c.maxHops,
			MaxBranches:        c.maxBranches,
			MaxToolCalls:       c.maxToolCalls,
			MaxExpansions:      c.maxExpansions,
			TokenBudget:        c.tokenBudget,
			AllowedTools:       splitList(c.tools),
			Owner:              c.owner,
			HeartbeatSeconds:   c.heartbeat,
			ScriptedAnswerJSON: c.scriptedAnswer,
		}
	}
	return app.Build(ctx, cfg)
}

// agentNotConfiguredError names the two ways to configure an agent. The message
// is the whole answer to "why did nothing run": without it, a user cannot tell a
// disabled agent from an empty queue.
func agentNotConfiguredError() error {
	return errors.New("the agent is not configured in this workspace; " +
		"start the server with --agent-runtime scripted --agent-scripted-answer <json> or --agent-runtime cli --agent-command <binary>, " +
		"or pass --runtime scripted|cli to this command")
}

// asAgentError makes the runtime's sentinels actionable on the command line.
func asAgentError(err error, id string) error {
	switch {
	case errors.Is(err, agent.ErrNotFound), errors.Is(err, agent.ErrRunNotFound):
		return fmt.Errorf("no run or hypothesis %s in this workspace; list runs with `codexploit runs list`: %w", id, err)
	case errors.Is(err, path.ErrBudgetExceeded):
		return fmt.Errorf("%w: the audit's active-lease ceiling is reached; release or reclaim a path first", err)
	case errors.Is(err, agent.ErrConflict):
		return fmt.Errorf("%w (nothing was changed)", err)
	default:
		return err
	}
}

func agentRunStatuses(value string) ([]agent.RunStatus, error) {
	parts := splitList(value)
	out := make([]agent.RunStatus, 0, len(parts))
	for _, part := range parts {
		status := agent.RunStatus(part)
		if !agent.ValidRunStatus(status) {
			return nil, fmt.Errorf("unknown status %q; valid statuses are %s", part, strings.Join(runStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

func agentHypothesisStatuses(value string) ([]string, error) {
	parts := splitList(value)
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		switch part {
		case agent.HypothesisCandidate, agent.HypothesisConfirmed,
			agent.HypothesisRefuted, agent.HypothesisInconclusive:
			out = append(out, part)
		default:
			return nil, fmt.Errorf("unknown hypothesis status %q; valid statuses are %s", part, strings.Join(hypothesisStatusNames(), ", "))
		}
	}
	return out, nil
}

func runStatusNames() []string {
	statuses := agent.AllRunStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func hypothesisStatusNames() []string {
	return []string{agent.HypothesisCandidate, agent.HypothesisConfirmed,
		agent.HypothesisRefuted, agent.HypothesisInconclusive}
}
