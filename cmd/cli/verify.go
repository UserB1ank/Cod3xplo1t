package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// verifyFlags are the flags shared by the P6 subcommands. They mirror the HTTP
// parameters one for one, so a verification requested through the API can be
// reproduced on the command line and the other way round.
type verifyFlags struct {
	workspace string
	dbPath    string
	jsonOut   bool

	// Executor configuration.
	executor      string
	command       repeatedArgs
	env           repeatedArgs
	workingDir    string
	maxOutput     int64
	maxSteps      int
	scriptedSteps string

	// The scope and the environment of one verification.
	approved   bool
	approvedBy string
	allowNet   bool
	repository string
	targets    string
	profile    string
	timeout    int
	owner      string

	// Read filters.
	findingID    string
	pathID       string
	auditID      string
	snapshotID   string
	hypothesisID string
	status       string
	outcome      string
	kind         string
	conclusive   bool
	candidates   bool
	limit        int
	offset       int

	// Report options.
	format string
	out    string
}

// parseVerify builds the flag set of one subcommand and separates the positional
// arguments from the flags, exactly like the audit and agent subcommands.
func parseVerify(name string, args []string, extra func(*flag.FlagSet, *verifyFlags)) (*verifyFlags, []string, error) {
	fs := flag.NewFlagSet("verify "+name, flag.ContinueOnError)
	c := &verifyFlags{limit: 50}
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

// addExecutorFlags registers the flags that configure a verification executor.
// They are named after the server's flags so one configuration works in both
// places.
func addExecutorFlags(fs *flag.FlagSet, c *verifyFlags) {
	fs.StringVar(&c.executor, "executor", "", "verification executor: scripted, cli or unsupported (default: the configured one)")
	fs.Var(&c.command, "command", "verification command argv, repeatable; the binary plus its arguments")
	fs.Var(&c.env, "env", "environment entry for a verification step as KEY=VALUE, repeatable")
	fs.StringVar(&c.workingDir, "working-dir", "", "working directory of a cli verification step")
	fs.Int64Var(&c.maxOutput, "max-output", 0, "maximum bytes one cli verification step may return")
	fs.IntVar(&c.maxSteps, "max-steps", 0, "maximum steps a generated plan may carry")
	fs.StringVar(&c.scriptedSteps, "scripted-steps", "",
		"scripted executor steps as a raw JSON array, or @file to read one; without it a scripted run blocks every step")
}

// runVerify dispatches the P6 subcommands.
func runVerify(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit <verify|verifications|findings|report> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "verify":
		return runVerifyHypothesis(ctx, rest)
	case "verifications", "verification":
		return runVerifications(ctx, rest)
	case "findings", "finding":
		return runFindings(ctx, rest)
	case "report":
		return runReport(ctx, rest)
	default:
		return fmt.Errorf("unknown verification subcommand %q", sub)
	}
}

// runVerifyHypothesis answers `codexploit verify <hypothesis-id>`: create the
// finding, build the plan, run it, and print what it established.
func runVerifyHypothesis(ctx context.Context, args []string) error {
	c, rest, err := parseVerify("verify", args, func(fs *flag.FlagSet, c *verifyFlags) {
		addExecutorFlags(fs, c)
		fs.BoolVar(&c.approved, "approved", false, "record that a human approved this plan")
		fs.StringVar(&c.approvedBy, "approved-by", "", "name of the human who approved the plan (required when the plan needs approval)")
		fs.BoolVar(&c.allowNet, "allow-network", false, "authorize network access for this verification")
		fs.StringVar(&c.repository, "repository", "", "authorized repository identifier (required by the plan)")
		fs.StringVar(&c.targets, "targets", "", "comma-separated targets the scope authorizes")
		fs.StringVar(&c.profile, "profile", "", "environment profile (container image or VM template)")
		fs.IntVar(&c.timeout, "timeout", 0, "environment timeout in seconds")
		fs.StringVar(&c.owner, "owner", "", "owner recorded on the verification run")
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
	if rt.Verifier == nil || rt.VerifyPlanner == nil {
		return verificationNotConfiguredError()
	}
	// A scripted executor with no script would block every step. That is honest, but
	// a bare BLOCKED result is exactly what an operator might read as a finding, so
	// the missing configuration is reported instead.
	if err := scriptedStepsRequiredError(rt); err != nil {
		return err
	}
	// The hypothesis must exist before anything is written: `verify` on a typo must
	// not create a finding for a claim nobody recorded.
	if _, err := rt.Store.GetHypothesis(id); err != nil {
		return asVerifyError(err, id)
	}
	finding, err := rt.VerifyPlanner.EnsureFinding(ctx, id)
	if err != nil {
		return asVerifyError(err, id)
	}
	prepared, err := rt.VerifyPlanner.BuildPlan(ctx, id, c.scope(), c.environment())
	if err != nil {
		return asVerifyError(err, id)
	}
	if err := verify.Authorize(prepared, c.approved, c.approvedBy); err != nil {
		return asVerifyError(err, id)
	}
	run, err := rt.Verifier.Verify(ctx, verify.VerifyRequest{
		Plan:       prepared.Plan,
		Approved:   c.approved,
		ApprovedBy: strings.TrimSpace(c.approvedBy),
		Owner:      c.owner,
	})
	if err != nil {
		return asVerifyError(err, id)
	}
	if c.jsonOut {
		return printJSON(map[string]any{"finding": finding, "verification": run})
	}
	printVerification(run)
	return nil
}

// scope builds the authorization the CLI verification runs under. The network
// policy follows --allow-network, so a scope can never authorize more than the
// operator asked for.
func (c *verifyFlags) scope() verify.Scope {
	return verify.Scope{
		Repository:            strings.TrimSpace(c.repository),
		AllowedTargets:        splitList(c.targets),
		AllowNetwork:          c.allowNet,
		RequiresHumanApproval: c.allowNet,
	}
}

// environment builds the least-privilege environment. SourceReadOnly is always
// true: the planner and verify.Prepare both refuse a writable snapshot root.
func (c *verifyFlags) environment() verify.Environment {
	network := verify.NetworkNone
	hosts := splitList(c.targets)
	if c.allowNet {
		network = verify.NetworkTargetOnly
	}
	return verify.Environment{
		Profile:        strings.TrimSpace(c.profile),
		SourceReadOnly: true,
		Network:        network,
		AllowedHosts:   hosts,
		TimeoutSeconds: c.timeout,
	}
}

// build builds the runtime, with the verification layer when an --executor was
// given. The flags mirror the server's, so an operator can reproduce a
// verification without starting a server.
func (c *verifyFlags) build(ctx context.Context) (*app.Runtime, error) {
	cfg := app.Config{Workspace: c.workspace, DBPath: c.dbPath}
	mode := strings.TrimSpace(c.executor)
	if mode != "" {
		switch mode {
		case app.VerifyExecutorScripted, app.VerifyExecutorCLI, app.VerifyExecutorUnsupported:
		default:
			return nil, fmt.Errorf("--executor %q is not a verification executor (want %s, %s or %s)",
				mode, app.VerifyExecutorScripted, app.VerifyExecutorCLI, app.VerifyExecutorUnsupported)
		}
		cfg.Verification = app.VerificationConfig{
			Enabled:           true,
			Executor:          mode,
			Command:           c.command,
			Env:               c.env,
			WorkingDir:        c.workingDir,
			MaxOutputBytes:    c.maxOutput,
			AllowNetwork:      c.allowNet,
			MaxSteps:          c.maxSteps,
			ScriptedStepsJSON: c.scriptedSteps,
		}
	}
	return app.Build(ctx, cfg)
}

// verificationNotConfiguredError names the ways to configure verification. The
// message is the whole answer to "why did nothing run".
func verificationNotConfiguredError() error {
	return errors.New("the verification layer is not configured in this workspace; " +
		"pass --executor scripted|cli|unsupported to this command, " +
		"or start the server with --verify-executor scripted, --verify-executor cli --verify-command <binary>, or --verify-executor unsupported")
}

// scriptedStepsRequiredError refuses a scripted dry run that has nothing to replay.
// Without it the run would end BLOCKED, and a blocked verification is not a
// refutation — reporting the missing flag is the honest answer.
func scriptedStepsRequiredError(rt *app.Runtime) error {
	if rt == nil || strings.ToLower(strings.TrimSpace(rt.VerificationConfig.Executor)) != app.VerifyExecutorScripted {
		return nil
	}
	if len(rt.VerificationConfig.ScriptedSteps) > 0 {
		return nil
	}
	return errors.New("the scripted executor has no steps, so it would block every plan step; " +
		"pass --scripted-steps '<json array>' (or --scripted-steps @file) to replay a dry run, " +
		"or --executor unsupported if a blocked run is what you want")
}

// asVerifyError makes the verification sentinels actionable on the command line,
// always naming the next command.
func asVerifyError(err error, id string) error {
	switch {
	case errors.Is(err, verify.ErrNotFound), errors.Is(err, agent.ErrNotFound):
		return fmt.Errorf("no hypothesis, finding or verification %s in this workspace; "+
			"create an audit with `codexploit audit create --snapshot <id>` and run it with `codexploit run <audit-id>`: %w", id, err)
	case errors.Is(err, verify.ErrApprovalRequired):
		return fmt.Errorf("%w: re-run with --approved --approved-by <name> once a human has approved this plan", err)
	case errors.Is(err, verify.ErrScopeDenied):
		return fmt.Errorf("%w: check --allow-network, --repository and --targets", err)
	case errors.Is(err, verify.ErrUnsupportedStep):
		return fmt.Errorf("%w: this executor cannot run the step; use --executor scripted for a dry run", err)
	case errors.Is(err, verify.ErrInvalidPlan), errors.Is(err, verify.ErrInvalidArgument):
		return fmt.Errorf("%w: check --repository, --allow-network and --profile", err)
	default:
		return err
	}
}

// printVerification renders one run the way an operator reviews it: what was
// claimed, how it ended, and what the derivation said.
func printVerification(run *verify.Run) {
	fmt.Printf("verification %s\n", run.ID)
	fmt.Printf("hypothesis   %s\n", run.HypothesisID)
	fmt.Printf("finding      %s\n", run.FindingID)
	fmt.Printf("status       %s\n", run.Status)
	fmt.Printf("outcome      %s\n", orNone(string(run.Outcome)))
	fmt.Printf("executor     %s %s\n", run.Executor, run.ExecutorVersion)
	fmt.Printf("plan         %s (%d step(s))\n", run.PlanHash, len(run.Plan.Steps))
	fmt.Printf("environment  %s\n", run.EnvironmentDigest)
	if run.Approved {
		fmt.Printf("approved     by %s at %s\n", orNone(run.ApprovedBy), orNone(run.ApprovedAt))
	}
	fmt.Printf("reason       %s\n", orNone(run.StopReason))
	if run.Error != "" {
		fmt.Printf("error        %s\n", run.Error)
	}
	if run.Reproduction != "" {
		fmt.Printf("reproduction %s\n", run.Reproduction)
	}
	fmt.Printf("evidence     %d object(s)\n", len(run.EvidenceIDs))
}

// --- verifications ----------------------------------------------------------

// runVerifications dispatches `verifications list|show|evidence`.
func runVerifications(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit verifications <list|show|evidence> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runVerificationsList(ctx, rest)
	case "show":
		return runVerificationsShow(ctx, rest)
	case "evidence":
		return runVerificationsEvidence(ctx, rest)
	default:
		return fmt.Errorf("unknown verifications subcommand %q", sub)
	}
}

func runVerificationsList(ctx context.Context, args []string) error {
	c, _, err := parseVerify("verifications list", args, func(fs *flag.FlagSet, c *verifyFlags) {
		fs.StringVar(&c.hypothesisID, "hypothesis", "", "only verifications of this hypothesis")
		fs.StringVar(&c.findingID, "finding", "", "only verifications of this finding")
		fs.StringVar(&c.pathID, "path", "", "only verifications of this path")
		fs.StringVar(&c.auditID, "audit", "", "only verifications of this audit")
		fs.StringVar(&c.snapshotID, "snapshot", "", "only verifications of this snapshot")
		fs.StringVar(&c.status, "status", "", "comma-separated verification statuses")
		fs.StringVar(&c.outcome, "outcome", "", "comma-separated outcomes")
		fs.IntVar(&c.limit, "limit", 50, "maximum verifications to return")
		fs.IntVar(&c.offset, "offset", 0, "verifications to skip")
		addExecutorFlags(fs, c)
	})
	if err != nil {
		return err
	}
	statuses, err := verificationStatuses(c.status)
	if err != nil {
		return err
	}
	outcomes, err := outcomes(c.outcome)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Verifier == nil {
		return verificationNotConfiguredError()
	}
	runs, total, err := rt.Verifier.ListRuns(verify.RunQuery{
		HypothesisID: c.hypothesisID, FindingID: c.findingID, PathID: c.pathID,
		AuditID: c.auditID, SnapshotID: c.snapshotID,
		Status: statuses, Outcome: outcomes, Limit: c.limit, Offset: c.offset,
	})
	if err != nil {
		return asVerifyError(err, c.hypothesisID)
	}
	if c.jsonOut {
		return printJSON(map[string]any{"verifications": runs, "total": total})
	}
	if len(runs) == 0 {
		fmt.Println("no verification matches; start one with `codexploit verify <hypothesis-id> --executor scripted`")
		return nil
	}
	rows := make([][]string, 0, len(runs))
	for _, run := range runs {
		rows = append(rows, []string{
			run.ID, shortID(run.HypothesisID), string(run.Status), orNone(string(run.Outcome)),
			run.Executor, strconv.Itoa(len(run.EvidenceIDs)), orNone(run.StopReason), run.CreatedAt,
		})
	}
	writeTable([]string{"VERIFICATION", "HYPOTHESIS", "STATUS", "OUTCOME", "EXECUTOR", "EVIDENCE", "STOP", "CREATED"}, rows)
	fmt.Printf("%d of %d verification(s)\n", len(runs), total)
	return nil
}

func runVerificationsShow(ctx context.Context, args []string) error {
	c, rest, err := parseVerify("verifications show", args, func(fs *flag.FlagSet, c *verifyFlags) {
		addExecutorFlags(fs, c)
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a verification id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Verifier == nil {
		return verificationNotConfiguredError()
	}
	run, err := rt.Verifier.GetRun(id)
	if err != nil {
		return asVerifyError(err, id)
	}
	if c.jsonOut {
		return printJSON(run)
	}
	printVerification(run)
	return nil
}

func runVerificationsEvidence(ctx context.Context, args []string) error {
	c, rest, err := parseVerify("verifications evidence", args, func(fs *flag.FlagSet, c *verifyFlags) {
		fs.StringVar(&c.kind, "kind", "", "comma-separated evidence kinds")
		fs.IntVar(&c.limit, "limit", 50, "maximum evidence objects to return")
		fs.IntVar(&c.offset, "offset", 0, "evidence objects to skip")
		addExecutorFlags(fs, c)
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a verification id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Verifier == nil {
		return verificationNotConfiguredError()
	}
	if _, err := rt.Verifier.GetRun(id); err != nil {
		return asVerifyError(err, id)
	}
	kinds, err := evidenceKinds(c.kind)
	if err != nil {
		return err
	}
	items, total, err := rt.Verifier.ListEvidence(verify.EvidenceQuery{
		VerificationRunID: id, Kinds: kinds, Limit: c.limit, Offset: c.offset,
	})
	if err != nil {
		return asVerifyError(err, id)
	}
	if c.jsonOut {
		return printJSON(map[string]any{"verification_id": id, "evidence": items, "total": total})
	}
	if len(items) == 0 {
		fmt.Println("no evidence object matches; this verification produced none")
		return nil
	}
	printEvidenceTable(items)
	fmt.Printf("%d of %d evidence object(s)\n", len(items), total)
	return nil
}

// --- findings ---------------------------------------------------------------

// runFindings dispatches `findings list|show`.
func runFindings(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit findings <list|show> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "list":
		return runFindingsList(ctx, rest)
	case "show":
		return runFindingsShow(ctx, rest)
	default:
		return fmt.Errorf("unknown findings subcommand %q", sub)
	}
}

func runFindingsList(ctx context.Context, args []string) error {
	c, _, err := parseVerify("findings list", args, func(fs *flag.FlagSet, c *verifyFlags) {
		fs.StringVar(&c.auditID, "audit", "", "only findings of this audit")
		fs.StringVar(&c.snapshotID, "snapshot", "", "only findings of this snapshot")
		fs.StringVar(&c.pathID, "path", "", "only findings of this path")
		fs.StringVar(&c.status, "status", "", "comma-separated finding statuses")
		fs.BoolVar(&c.conclusive, "conclusive", false, "only findings verification has settled")
		fs.BoolVar(&c.candidates, "candidates", false, "only findings waiting for verification")
		fs.IntVar(&c.limit, "limit", 50, "maximum findings to return")
		fs.IntVar(&c.offset, "offset", 0, "findings to skip")
		addExecutorFlags(fs, c)
	})
	if err != nil {
		return err
	}
	statuses, err := findingStatuses(c.status)
	if err != nil {
		return err
	}
	if c.conclusive && c.candidates {
		return errors.New("--conclusive and --candidates select disjoint sets; pass one of them")
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Verifier == nil {
		return verificationNotConfiguredError()
	}
	findings, total, err := rt.Verifier.ListFindings(verify.FindingQuery{
		AuditID: c.auditID, SnapshotID: c.snapshotID, PathID: c.pathID, Status: statuses,
		ConclusiveOnly: c.conclusive, CandidatesOnly: c.candidates,
		Limit: c.limit, Offset: c.offset,
	})
	if err != nil {
		return asVerifyError(err, c.auditID)
	}
	if c.jsonOut {
		return printJSON(map[string]any{"findings": findings, "total": total})
	}
	if len(findings) == 0 {
		fmt.Println("no finding matches; derive one with `codexploit verify <hypothesis-id>`")
		return nil
	}
	printFindingTable(findings)
	fmt.Printf("%d of %d finding(s)\n", len(findings), total)
	return nil
}

func runFindingsShow(ctx context.Context, args []string) error {
	c, rest, err := parseVerify("findings show", args, func(fs *flag.FlagSet, c *verifyFlags) {
		addExecutorFlags(fs, c)
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a finding id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Verifier == nil {
		return verificationNotConfiguredError()
	}
	finding, err := rt.Verifier.GetFinding(id)
	if err != nil {
		return asVerifyError(err, id)
	}
	runs, _, err := rt.Verifier.ListRuns(verify.RunQuery{FindingID: id, Limit: 200})
	if err != nil {
		return asVerifyError(err, id)
	}
	if c.jsonOut {
		return printJSON(map[string]any{"finding": finding, "verifications": runs})
	}
	printFinding(*finding)
	if len(runs) > 0 {
		fmt.Println("verifications")
		for _, run := range runs {
			fmt.Printf("  - %s %s %s\n", run.ID, run.Status, orNone(string(run.Outcome)))
		}
	}
	return nil
}

// --- report -----------------------------------------------------------------

func runReport(ctx context.Context, args []string) error {
	c, rest, err := parseVerify("report", args, func(fs *flag.FlagSet, c *verifyFlags) {
		fs.StringVar(&c.format, "format", "md", "report format: md, json or sarif")
		fs.StringVar(&c.out, "out", "", "write the report to this file instead of stdout")
		fs.BoolVar(&c.candidates, "include-candidates", false, "include candidate findings")
		addExecutorFlags(fs, c)
	})
	if err != nil {
		return err
	}
	auditID, err := requirePositional(rest, "an audit id is required")
	if err != nil {
		return err
	}
	format, _, err := reportFormat(c.format)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Verifier == nil {
		return verificationNotConfiguredError()
	}
	if _, err := requireAudit(ctx, rt, auditID); err != nil {
		return err
	}
	findings, _, err := rt.Verifier.ListFindings(verify.FindingQuery{AuditID: auditID, Limit: 500})
	if err != nil {
		return asVerifyError(err, auditID)
	}
	evidence := map[string][]verify.Evidence{}
	snapshotID := ""
	for _, finding := range findings {
		grouped, err := groupEvidence(rt, &finding)
		if err != nil {
			return asVerifyError(err, finding.ID)
		}
		evidence[finding.ID] = append(append(append(
			[]verify.Evidence{}, grouped.Supporting...), grouped.Contradicting...), grouped.Inconclusive...)
		if snapshotID == "" {
			snapshotID = finding.SnapshotID
		} else if finding.SnapshotID != snapshotID {
			snapshotID = ""
		}
	}
	body, err := verify.RenderReport(findings, evidence, verify.ReportOptions{
		Format: format, AuditID: auditID, SnapshotID: snapshotID,
		IncludeCandidates: c.candidates, MaxFindings: 500,
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.out) == "" {
		_, err = os.Stdout.Write(body)
		return err
	}
	if err := os.WriteFile(c.out, body, 0o644); err != nil {
		return err
	}
	fmt.Printf("wrote %s report for audit %s to %s\n", format, auditID, c.out)
	return nil
}

// reportFormat validates the CLI's --format. It mirrors the API's vocabulary so
// the two spellings cannot drift.
func reportFormat(raw string) (string, string, error) {
	format := strings.ToLower(strings.TrimSpace(raw))
	if format == "" {
		format = "md"
	}
	if format == "markdown" {
		format = "md"
	}
	switch format {
	case "md":
		return format, "text/markdown", nil
	case "json":
		return format, "application/json", nil
	case "sarif":
		return format, "application/sarif+json", nil
	default:
		return "", "", fmt.Errorf("unknown report format %q; valid formats are md, json, sarif", raw)
	}
}

// grouping is the three-way split of one finding's evidence.
type grouping struct {
	Supporting    []verify.Evidence
	Contradicting []verify.Evidence
	Inconclusive  []verify.Evidence
}

// groupEvidence resolves a finding's three id lists into objects. A referenced
// object that cannot be read is skipped rather than invented; the finding's own
// lists remain the authority.
func groupEvidence(rt *app.Runtime, finding *verify.Finding) (grouping, error) {
	resolve := func(ids []string) ([]verify.Evidence, error) {
		out := make([]verify.Evidence, 0, len(ids))
		for _, id := range ids {
			item, err := rt.Verifier.GetEvidence(id)
			if err != nil {
				if errors.Is(err, verify.ErrNotFound) {
					continue
				}
				return nil, err
			}
			out = append(out, *item)
		}
		return out, nil
	}
	supporting, err := resolve(finding.Supporting)
	if err != nil {
		return grouping{}, err
	}
	contradicting, err := resolve(finding.Contradicting)
	if err != nil {
		return grouping{}, err
	}
	inconclusive, err := resolve(finding.Inconclusive)
	if err != nil {
		return grouping{}, err
	}
	return grouping{Supporting: supporting, Contradicting: contradicting, Inconclusive: inconclusive}, nil
}

// --- tables -----------------------------------------------------------------

func printFindingTable(findings []verify.Finding) {
	rows := make([][]string, 0, len(findings))
	for _, finding := range findings {
		rows = append(rows, []string{
			finding.ID, shortID(finding.HypothesisID), string(finding.Status), orNone(finding.Severity),
			strconv.Itoa(len(finding.Supporting)), strconv.Itoa(len(finding.Contradicting)),
			strconv.Itoa(len(finding.Inconclusive)), finding.Title,
		})
	}
	writeTable([]string{"FINDING", "HYPOTHESIS", "STATUS", "SEVERITY", "SUPPORT", "CONTRADICT", "INCONCLUSIVE", "TITLE"}, rows)
}

// printFinding renders one verdict with its evidence ids, so the reviewer knows
// what the conclusion rests on before opening the objects.
func printFinding(finding verify.Finding) {
	fmt.Printf("finding    %s\n", finding.ID)
	fmt.Printf("hypothesis %s\n", finding.HypothesisID)
	fmt.Printf("path       %s\n", finding.PathID)
	fmt.Printf("status     %s\n", finding.Status)
	if finding.Severity != "" {
		fmt.Printf("severity   %s\n", finding.Severity)
	}
	if finding.Confidence != "" {
		fmt.Printf("confidence %s\n", finding.Confidence)
	}
	fmt.Printf("title      %s\n", finding.Title)
	if finding.ReproduceSteps != "" {
		fmt.Printf("reproduce  %s\n", finding.ReproduceSteps)
	}
	printEvidenceIDs("supporting", finding.Supporting)
	printEvidenceIDs("contradicting", finding.Contradicting)
	printEvidenceIDs("inconclusive", finding.Inconclusive)
	printLimitations("limitations", finding.Limitations)
}

func printEvidenceIDs(label string, ids []string) {
	if len(ids) == 0 {
		return
	}
	fmt.Printf("%s\n", label)
	for _, id := range ids {
		fmt.Printf("  - %s\n", id)
	}
}

func printEvidenceTable(items []verify.Evidence) {
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		where := item.File
		if item.Line > 0 {
			where = fmt.Sprintf("%s:%d", item.File, item.Line)
		}
		rows = append(rows, []string{
			item.ID, string(item.Kind), item.Tool, strconv.FormatBool(item.Redacted),
			orNone(where), item.CreatedAt,
		})
	}
	writeTable([]string{"EVIDENCE", "KIND", "TOOL", "REDACTED", "LOCATION", "CREATED"}, rows)
}

// --- filters ----------------------------------------------------------------

func verificationStatuses(value string) ([]verify.VerificationStatus, error) {
	parts := splitList(value)
	out := make([]verify.VerificationStatus, 0, len(parts))
	for _, part := range parts {
		status := verify.VerificationStatus(part)
		if !verify.ValidVerificationStatus(status) {
			return nil, fmt.Errorf("unknown status %q; valid statuses are %s",
				part, strings.Join(verificationStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

func outcomes(value string) ([]verify.Outcome, error) {
	parts := splitList(value)
	out := make([]verify.Outcome, 0, len(parts))
	for _, part := range parts {
		outcome := verify.Outcome(part)
		if !verify.ValidOutcome(outcome) {
			return nil, fmt.Errorf("unknown outcome %q; valid outcomes are CONFIRMED, REFUTED, INCONCLUSIVE, BLOCKED", part)
		}
		out = append(out, outcome)
	}
	return out, nil
}

func findingStatuses(value string) ([]verify.FindingStatus, error) {
	parts := splitList(value)
	out := make([]verify.FindingStatus, 0, len(parts))
	for _, part := range parts {
		status := verify.FindingStatus(part)
		if !verify.ValidFindingStatus(status) {
			return nil, fmt.Errorf("unknown status %q; valid statuses are %s",
				part, strings.Join(findingStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

// evidenceKinds validates the --kind filter, exactly as the API does: an unknown
// kind is refused rather than dropped, because a silently dropped filter would
// answer a broader question than the one asked.
func evidenceKinds(value string) ([]verify.EvidenceKind, error) {
	parts := splitList(value)
	out := make([]verify.EvidenceKind, 0, len(parts))
	for _, part := range parts {
		kind := verify.EvidenceKind(part)
		if !verify.ValidEvidenceKind(kind) {
			return nil, fmt.Errorf("unknown evidence kind %q; valid kinds are %s",
				part, strings.Join(evidenceKindNames(), ", "))
		}
		out = append(out, kind)
	}
	return out, nil
}

func evidenceKindNames() []string {
	kinds := verify.AllEvidenceKinds()
	out := make([]string, 0, len(kinds))
	for _, kind := range kinds {
		out = append(out, string(kind))
	}
	return out
}

func verificationStatusNames() []string {
	statuses := verify.AllVerificationStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func findingStatusNames() []string {
	statuses := verify.AllFindingStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}
