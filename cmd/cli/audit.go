package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// auditFlags are the flags shared by the audit subcommands. They mirror the HTTP
// parameters one for one, so a ranking seen in the API can be reproduced on the
// command line.
type auditFlags struct {
	workspace string
	dbPath    string
	jsonOut   bool

	snapshot    string
	status      string
	pathStatus  string
	entry       string
	target      string
	minPriority float64
	sortKey     string
	limit       int
	offset      int
	after       int64

	auditID string
	pathID  string
	owner   string
	ttl     int
	reason  string
	force   bool

	maxEntries          int
	maxPaths            int
	maxSinksPerEntry    int
	maxActiveLeases     int
	maxDepth            int
	maxBranches         int
	maxToolCalls        int
	explorationFraction float64
	sensitivity         sensitivityFlag
}

// sensitivityFlag collects repeated key=value overrides for the score model.
type sensitivityFlag map[string]float64

func (s sensitivityFlag) String() string {
	keys := make([]string, 0, len(s))
	for key := range s {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s=%g", key, s[key]))
	}
	return strings.Join(parts, ",")
}

func (s sensitivityFlag) Set(value string) error {
	key, raw, ok := strings.Cut(value, "=")
	if !ok {
		return fmt.Errorf("sensitivity must be key=value, got %q", value)
	}
	key = strings.TrimSpace(key)
	if key == "" {
		return errors.New("sensitivity key must not be empty")
	}
	parsed, err := strconv.ParseFloat(strings.TrimSpace(raw), 64)
	if err != nil {
		return fmt.Errorf("sensitivity %s: %v", key, err)
	}
	if parsed < 0 || parsed > 1 {
		return fmt.Errorf("sensitivity %s must be in [0,1], got %g", key, parsed)
	}
	s[key] = parsed
	return nil
}

// parseAudit builds the flag set of one subcommand and separates the positional
// arguments from the flags.
func parseAudit(name string, args []string, extra func(*flag.FlagSet, *auditFlags)) (*auditFlags, []string, error) {
	fs := flag.NewFlagSet("audit "+name, flag.ContinueOnError)
	c := &auditFlags{sensitivity: sensitivityFlag{}}
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

// splitArgs separates positional arguments from flags. The standard flag package
// stops at the first positional argument, which would silently drop flags written
// after an id (`audit pause <path-id> --reason ...`); this keeps the documented
// argument order working in both directions.
func splitArgs(fs *flag.FlagSet, args []string) (positionals, flags []string) {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			return append(positionals, args[i+1:]...), flags
		}
		if arg == "" || arg == "-" || arg[0] != '-' {
			positionals = append(positionals, arg)
			continue
		}
		flags = append(flags, arg)
		name := strings.TrimLeft(arg, "-")
		if strings.Contains(name, "=") {
			continue
		}
		definition := fs.Lookup(name)
		if definition == nil {
			// Unknown flag: leave it for Parse to report.
			continue
		}
		if boolean, ok := definition.Value.(interface{ IsBoolFlag() bool }); ok && boolean.IsBoolFlag() {
			continue
		}
		if i+1 < len(args) {
			flags = append(flags, args[i+1])
			i++
		}
	}
	return positionals, flags
}

func (c *auditFlags) build(ctx context.Context) (*app.Runtime, error) {
	return app.Build(ctx, app.Config{Workspace: c.workspace, DBPath: c.dbPath})
}

func (c *auditFlags) requireSnapshot() (string, error) {
	if strings.TrimSpace(c.snapshot) == "" {
		return "", errors.New("--snapshot is required; create an audit with `codexploit audit create --snapshot <id>`")
	}
	return strings.TrimSpace(c.snapshot), nil
}

// runAudit dispatches the path-engine subcommands.
func runAudit(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit audit <create|list|show|paths|path|events|next|order|claim|heartbeat|release|pause|resume|cancel|reclaim|rescore> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "create":
		return runAuditCreate(ctx, rest)
	case "list", "audits":
		return runAuditList(ctx, rest)
	case "show":
		return runAuditShow(ctx, rest)
	case "paths":
		return runAuditPaths(ctx, rest)
	case "path":
		return runAuditPath(ctx, rest)
	case "events":
		return runAuditEvents(ctx, rest)
	case "next":
		return runAuditNext(ctx, rest)
	case "order", "plan":
		return runAuditOrder(ctx, rest)
	case "claim":
		return runAuditClaim(ctx, rest)
	case "heartbeat":
		return runAuditHeartbeat(ctx, rest)
	case "release":
		return runAuditRelease(ctx, rest)
	case "pause", "resume", "cancel":
		return runAuditTransition(ctx, sub, rest)
	case "reclaim", "reclaim-expired":
		return runAuditReclaim(ctx, rest)
	case "rescore":
		return runAuditRescore(ctx, rest)
	default:
		return fmt.Errorf("unknown audit subcommand %q", sub)
	}
}

// auditResult mirrors the API's create response, so `--json` output can be piped
// into the same parser as the HTTP answer.
type auditResult struct {
	Audit     path.Audit `json:"audit"`
	PathCount int        `json:"path_count"`
	Replayed  bool       `json:"replayed"`
}

func runAuditCreate(ctx context.Context, args []string) error {
	c, _, err := parseAudit("create", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.snapshot, "snapshot", "", "snapshot id")
		fs.BoolVar(&c.force, "force", false, "regenerate and rescore even when the audit already exists")
		fs.IntVar(&c.maxEntries, "max-entries", 0, "maximum ASG entry points to expand")
		fs.IntVar(&c.maxPaths, "max-paths", 0, "maximum paths to emit")
		fs.IntVar(&c.maxSinksPerEntry, "max-sinks-per-entry", 0, "maximum sinks per entry point")
		fs.IntVar(&c.maxActiveLeases, "max-active-leases", 0, "maximum leases active at once")
		fs.Float64Var(&c.explorationFraction, "exploration-fraction", 0, "share of picks reserved for exploration (0.15-0.25)")
		fs.IntVar(&c.maxDepth, "max-depth", 0, "maximum call-chain depth per path")
		fs.IntVar(&c.maxBranches, "max-branches", 0, "maximum branches explored per path")
		fs.IntVar(&c.maxToolCalls, "max-tool-calls", 0, "maximum tool calls per path")
		fs.Var(&c.sensitivity, "sensitivity", "score sensitivity as key=value, repeatable")
	})
	if err != nil {
		return err
	}
	snapshotID, err := c.requireSnapshot()
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	if err := requireSnapshotExists(rt, snapshotID); err != nil {
		return err
	}
	result, err := rt.Audit.CreateAudit(ctx, path.CreateAuditRequest{
		SnapshotID: snapshotID,
		Force:      c.force,
		Budget: path.Budget{
			MaxDepth:     c.maxDepth,
			MaxBranches:  c.maxBranches,
			MaxToolCalls: c.maxToolCalls,
		},
		Limits: path.Limits{
			MaxEntries:          c.maxEntries,
			MaxPaths:            c.maxPaths,
			MaxSinksPerEntry:    c.maxSinksPerEntry,
			MaxActiveLeases:     c.maxActiveLeases,
			ExplorationFraction: c.explorationFraction,
		},
		Sensitivity: c.sensitivity,
	})
	if err != nil {
		return asAuditError(err, snapshotID)
	}
	out := auditResult{Audit: result.Audit, PathCount: result.Audit.PathCount, Replayed: result.Replayed}
	if c.jsonOut {
		return printJSON(out)
	}
	printAudit(&out.Audit)
	if out.Replayed {
		fmt.Printf("\nreplayed the existing audit; pass --force to regenerate it\n")
	} else {
		fmt.Printf("\n%d path(s) queued\n", out.PathCount)
	}
	fmt.Printf("next       codexploit audit paths %s   (then `codexploit audit claim %s --owner <name>`)\n",
		out.Audit.ID, out.Audit.ID)
	return nil
}

func runAuditList(ctx context.Context, args []string) error {
	c, _, err := parseAudit("list", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.snapshot, "snapshot", "", "only audits of this snapshot")
		fs.StringVar(&c.status, "status", "", "only audits in this status (GENERATING, READY, FAILED)")
		fs.IntVar(&c.limit, "limit", 50, "maximum audits to return")
		fs.IntVar(&c.offset, "offset", 0, "audits to skip")
	})
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	audits, total, err := rt.Audit.Audits(path.AuditQuery{
		SnapshotID: c.snapshot, Status: strings.TrimSpace(c.status), Limit: c.limit, Offset: c.offset,
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"audits": audits, "total": total})
	}
	if len(audits) == 0 {
		fmt.Println("no audits yet; create one with `codexploit audit create --snapshot <id>`")
		return nil
	}
	rows := make([][]string, 0, len(audits))
	for _, a := range audits {
		rows = append(rows, []string{
			a.ID, shortID(a.SnapshotID), a.Status, strconv.Itoa(a.PathCount),
			formatCounts(a.CountsByStatus), a.CreatedAt,
		})
	}
	writeTable([]string{"AUDIT", "SNAPSHOT", "STATUS", "PATHS", "BY STATUS", "CREATED"}, rows)
	fmt.Printf("%d of %d audit(s)\n", len(audits), total)
	return nil
}

func runAuditShow(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("show", args, nil)
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "an audit id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	audit, err := requireAudit(ctx, rt, id)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(audit)
	}
	printAudit(audit)
	return nil
}

func runAuditPaths(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("paths", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.status, "status", "", "comma-separated lifecycle statuses")
		fs.StringVar(&c.pathStatus, "path-status", "", "comma-separated evidence classes")
		fs.StringVar(&c.entry, "entry", "", "only paths from this ASG entry node")
		fs.StringVar(&c.target, "target", "", "only paths to this ASG target node")
		fs.Float64Var(&c.minPriority, "min-priority", 0, "only paths at or above this priority")
		fs.StringVar(&c.sortKey, "sort", "priority", "order: priority, created or path_id")
		fs.IntVar(&c.limit, "limit", 50, "maximum paths to return")
		fs.IntVar(&c.offset, "offset", 0, "paths to skip")
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "an audit id is required")
	if err != nil {
		return err
	}
	statuses, err := auditStatuses(c.status)
	if err != nil {
		return err
	}
	pathStatuses, err := auditPathStatuses(c.pathStatus)
	if err != nil {
		return err
	}
	sortKey, err := auditSort(c.sortKey)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if _, err := requireAudit(ctx, rt, id); err != nil {
		return err
	}
	paths, total, err := rt.Audit.Paths(path.PathQuery{
		AuditID:      id,
		Status:       statuses,
		PathStatus:   pathStatuses,
		EntryNodeID:  c.entry,
		TargetNodeID: c.target,
		MinPriority:  c.minPriority,
		Sort:         sortKey,
		Limit:        c.limit,
		Offset:       c.offset,
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"audit_id": id, "paths": paths, "total": total})
	}
	if len(paths) == 0 {
		fmt.Printf("no path matches; drop the filters or inspect the audit with `codexploit audit show %s`\n", id)
		return nil
	}
	printPathTable(paths)
	fmt.Printf("%d of %d path(s); objectives %s\n", len(paths), total, formatCounts(path.ObjectiveCounts(paths)))
	return nil
}

func runAuditPath(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("path", args, nil)
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a path id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	p, features, err := rt.Audit.Path(id)
	if err != nil {
		return asAuditError(err, id)
	}
	if c.jsonOut {
		return printJSON(map[string]any{"path": p, "features": features})
	}
	printPathDetail(p, features)
	return nil
}

func runAuditEvents(ctx context.Context, args []string) error {
	c, _, err := parseAudit("events", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.auditID, "audit", "", "audit id")
		fs.StringVar(&c.pathID, "path", "", "only events of this path")
		fs.Int64Var(&c.after, "after", 0, "only events after this sequence number")
		fs.IntVar(&c.limit, "limit", 100, "maximum events to return")
	})
	if err != nil {
		return err
	}
	if strings.TrimSpace(c.auditID) == "" && strings.TrimSpace(c.pathID) == "" {
		return errors.New("--audit or --path is required")
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	auditID := strings.TrimSpace(c.auditID)
	if auditID == "" {
		// A path alone identifies its audit, so the caller does not have to look it
		// up first.
		p, _, err := rt.Audit.Path(strings.TrimSpace(c.pathID))
		if err != nil {
			return asAuditError(err, c.pathID)
		}
		auditID = p.AuditID
	}
	if _, err := requireAudit(ctx, rt, auditID); err != nil {
		return err
	}
	events, err := rt.Audit.Events(path.EventQuery{
		AuditID: auditID, PathID: strings.TrimSpace(c.pathID), AfterSeq: c.after, Limit: c.limit,
	})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(map[string]any{"audit_id": auditID, "events": events, "total": len(events)})
	}
	if len(events) == 0 {
		fmt.Println("no event matches")
		return nil
	}
	rows := make([][]string, 0, len(events))
	for _, event := range events {
		transition := ""
		if event.From != "" || event.To != "" {
			transition = fmt.Sprintf("%s -> %s", orNone(string(event.From)), orNone(string(event.To)))
		}
		rows = append(rows, []string{
			strconv.FormatInt(event.Seq, 10), event.Type, shortID(event.PathID), transition,
			event.Actor, event.Reason, event.CreatedAt,
		})
	}
	writeTable([]string{"SEQ", "TYPE", "PATH", "TRANSITION", "ACTOR", "REASON", "AT"}, rows)
	fmt.Printf("%d event(s)\n", len(events))
	return nil
}

func runAuditNext(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("next", args, nil)
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "an audit id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if _, err := requireAudit(ctx, rt, id); err != nil {
		return err
	}
	next, err := rt.Audit.Next(id)
	if err != nil {
		if errors.Is(err, path.ErrNotFound) {
			return fmt.Errorf("audit %s has no queued path; inspect the queue with `codexploit audit paths %s`", id, id)
		}
		return asAuditError(err, id)
	}
	if c.jsonOut {
		return printJSON(map[string]any{"audit_id": id, "path": next, "leased": false})
	}
	printPathTable([]path.Path{*next})
	fmt.Printf("no lease taken; claim it with `codexploit audit claim %s --owner <name>`\n", next.ID)
	return nil
}

func runAuditOrder(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("order", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.IntVar(&c.limit, "limit", 0, "maximum queued paths to plan (0 uses the engine default)")
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "an audit id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	if _, err := requireAudit(ctx, rt, id); err != nil {
		return err
	}
	plan, err := rt.Audit.Order(id, c.limit)
	if err != nil {
		return asAuditError(err, id)
	}
	if c.jsonOut {
		return printJSON(plan)
	}
	if len(plan.Order) == 0 {
		fmt.Printf("nothing is queued in %s; rescore it with `codexploit audit rescore %s`\n", id, id)
		return nil
	}
	exploration := map[string]bool{}
	for _, pathID := range plan.ExplorationPicks {
		exploration[pathID] = true
	}
	rows := make([][]string, 0, len(plan.Order))
	for i, p := range plan.Order {
		pick := ""
		if exploration[p.ID] {
			pick = "explore"
		}
		rows = append(rows, []string{
			strconv.Itoa(i + 1), fmt.Sprintf("%.4f", p.Score.Priority), string(p.Status),
			shortSubject(p.EntrySubject, p.EntryNodeID) + " -> " + shortSubject(p.TargetSubject, p.TargetNodeID),
			fmt.Sprintf("%d", p.Cluster.Size), pick,
		})
	}
	writeTable([]string{"#", "PRIORITY", "STATUS", "ENTRY -> TARGET", "CLUSTER", "PICK"}, rows)
	fmt.Printf("%d pick(s), %d exploration pick(s), %d node(s) already covered\n",
		len(plan.Order), len(plan.ExplorationPicks), plan.CoveredNodes)
	fmt.Printf("limits     active leases %d, exploration %.2f\n", plan.Limits.MaxActiveLeases, plan.Limits.ExplorationFraction)
	return nil
}

func runAuditClaim(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("claim", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.owner, "owner", "", "lease owner name (required)")
		fs.IntVar(&c.ttl, "ttl", 0, "lease duration in seconds (0 uses the audit default)")
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "an audit or path id is required")
	if err != nil {
		return err
	}
	if err := requireOwner(c.owner); err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	auditID, err := resolveAuditID(ctx, rt, id)
	if err != nil {
		return err
	}
	leased, err := rt.Audit.Claim(ctx, auditID, strings.TrimSpace(c.owner), time.Duration(c.ttl)*time.Second)
	if err != nil {
		if errors.Is(err, path.ErrNotFound) {
			return fmt.Errorf("audit %s has no queued path to claim; inspect the queue with `codexploit audit paths %s`", auditID, auditID)
		}
		return asAuditError(err, auditID)
	}
	if c.jsonOut {
		return printJSON(leased)
	}
	printPathTable([]path.Path{*leased})
	fmt.Printf("leased to %s until %s; renew with `codexploit audit heartbeat %s --owner %s`\n",
		leased.LeaseOwner, orNone(leased.LeaseUntil), leased.ID, leased.LeaseOwner)
	return nil
}

func runAuditHeartbeat(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("heartbeat", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.owner, "owner", "", "lease owner name (required)")
		fs.IntVar(&c.ttl, "ttl", 0, "lease duration in seconds (0 uses the audit default)")
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a path id is required")
	if err != nil {
		return err
	}
	if err := requireOwner(c.owner); err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	updated, err := rt.Audit.Heartbeat(id, strings.TrimSpace(c.owner), time.Duration(c.ttl)*time.Second)
	if err != nil {
		return asAuditError(err, id)
	}
	if c.jsonOut {
		return printJSON(updated)
	}
	printPathTable([]path.Path{*updated})
	fmt.Printf("lease renewed until %s\n", orNone(updated.LeaseUntil))
	return nil
}

func runAuditRelease(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("release", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.owner, "owner", "", "lease owner name (required)")
		fs.StringVar(&c.reason, "reason", "", "why the path goes back to the queue")
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a path id is required")
	if err != nil {
		return err
	}
	if err := requireOwner(c.owner); err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	reason := strings.TrimSpace(c.reason)
	if reason == "" {
		reason = "released by " + strings.TrimSpace(c.owner)
	}
	updated, err := rt.Audit.Release(id, strings.TrimSpace(c.owner), reason)
	if err != nil {
		return asAuditError(err, id)
	}
	if c.jsonOut {
		return printJSON(updated)
	}
	printPathTable([]path.Path{*updated})
	return nil
}

func runAuditTransition(ctx context.Context, action string, args []string) error {
	c, rest, err := parseAudit(action, args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.reason, "reason", "", "why the path changes state")
	})
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "a path id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	// The CLI reads the path first so the actor is recorded and a missing id is
	// reported before any state change.
	current, _, err := rt.Audit.Path(id)
	if err != nil {
		return asAuditError(err, id)
	}
	reason := strings.TrimSpace(c.reason)
	if reason == "" {
		reason = action + " requested on the command line"
	}
	var updated *path.Path
	switch action {
	case "pause":
		updated, err = rt.Audit.Pause(id, "cli", reason)
	case "resume":
		updated, err = rt.Audit.Resume(id, "cli", reason)
	case "cancel":
		updated, err = rt.Audit.Cancel(id, "cli", reason)
	}
	if err != nil {
		return asAuditError(err, id)
	}
	if c.jsonOut {
		return printJSON(updated)
	}
	fmt.Printf("%s: %s -> %s (%s)\n", id, current.Status, updated.Status, reason)
	printPathTable([]path.Path{*updated})
	return nil
}

func runAuditReclaim(ctx context.Context, args []string) error {
	c, _, err := parseAudit("reclaim", args, func(fs *flag.FlagSet, c *auditFlags) {
		fs.StringVar(&c.auditID, "audit", "", "only report paths of this audit")
		fs.IntVar(&c.limit, "limit", 10, "maximum paths to reclaim")
	})
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	auditID := strings.TrimSpace(c.auditID)
	if auditID != "" {
		if _, err := requireAudit(ctx, rt, auditID); err != nil {
			return err
		}
	}
	recovered, err := rt.Audit.ReclaimExpired(c.limit)
	if err != nil {
		return err
	}
	owned := make([]path.Path, 0, len(recovered))
	for _, p := range recovered {
		if auditID == "" || p.AuditID == auditID {
			owned = append(owned, p)
		}
	}
	if c.jsonOut {
		return printJSON(map[string]any{"recovered": owned, "count": len(owned), "recovered_total": len(recovered)})
	}
	if len(owned) == 0 {
		fmt.Println("no expired lease; nothing was reclaimed")
		return nil
	}
	printPathTable(owned)
	fmt.Printf("%d path(s) returned to the queue", len(owned))
	if auditID != "" && len(recovered) != len(owned) {
		fmt.Printf(" (%d in this workspace)", len(recovered))
	}
	fmt.Println()
	return nil
}

func runAuditRescore(ctx context.Context, args []string) error {
	c, rest, err := parseAudit("rescore", args, nil)
	if err != nil {
		return err
	}
	id, err := requirePositional(rest, "an audit id is required")
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()
	audit, err := rt.Audit.Rescore(id)
	if err != nil {
		return asAuditError(err, id)
	}
	if c.jsonOut {
		return printJSON(audit)
	}
	printAudit(audit)
	return nil
}

// --- output -----------------------------------------------------------------

// printAudit is the human summary of one audit: what it covers, how it is
// bounded, and where generation stopped early.
func printAudit(a *path.Audit) {
	fmt.Printf("audit      %s\n", a.ID)
	fmt.Printf("snapshot   %s\n", a.SnapshotID)
	fmt.Printf("status     %s   score version %d   config %s\n", a.Status, a.ScoreVersion, shortID(a.ConfigHash))
	fmt.Printf("paths      %d\n", a.PathCount)
	fmt.Printf("by status  %s\n", formatCounts(a.CountsByStatus))
	fmt.Printf("evidence   %s\n", formatCounts(a.CountsByPathStatus))
	if a.SCGVersion != "" || a.ASGVersion != "" {
		fmt.Printf("versions   scg %s  asg %s\n", orNone(a.SCGVersion), orNone(a.ASGVersion))
	}
	fmt.Printf("budget     depth %d, branches %d, tool calls %d\n",
		a.Budget.MaxDepth, a.Budget.MaxBranches, a.Budget.MaxToolCalls)
	fmt.Printf("limits     paths %d, entries %d, active leases %d, chain budget %d, ttl %ds, exploration %.2f\n",
		a.Limits.MaxPaths, a.Limits.MaxEntries, a.Limits.MaxActiveLeases,
		a.Limits.ChainQueryBudget, a.Limits.LeaseTTLSeconds, a.Limits.ExplorationFraction)
	fmt.Printf("coverage   %d/%d entry point(s), %d/%d sink(s), %d chain(s) resolved, %d unresolved, %d path(s) emitted\n",
		a.Coverage.EntryPointsExamined, a.Coverage.EntryPointsExamined+a.Coverage.EntryPointsSkipped,
		a.Coverage.SinksExamined, a.Coverage.SinksExamined+a.Coverage.SinksSkipped,
		a.Coverage.ChainsResolved, a.Coverage.ChainsUnresolved, a.Coverage.PathsEmitted)
	if a.Coverage.Truncated {
		fmt.Println("truncated  generation stopped early")
	}
	printLimitations("limitations", a.Limitations)
	printLimitations("truncation", a.Coverage.TruncationReasons)
	fmt.Printf("updated    %s\n", a.UpdatedAt)
}

// printPathTable is the queue answer an auditor reads first: the ranking, the
// lifecycle position, the evidence class and who holds the path, if anyone.
func printPathTable(paths []path.Path) {
	headers := []string{"PRIORITY", "STATUS", "PATH_STATUS", "ENTRY -> TARGET", "OBJECTIVES", "CLUSTER", "LEASE"}
	rows := make([][]string, 0, len(paths))
	for _, p := range paths {
		rows = append(rows, []string{
			fmt.Sprintf("%.4f", p.Score.Priority),
			string(p.Status),
			string(p.PathStatus),
			shortSubject(p.EntrySubject, p.EntryNodeID) + " -> " + shortSubject(p.TargetSubject, p.TargetNodeID),
			orNone(strings.Join(p.Objectives, ",")),
			strconv.Itoa(p.Cluster.Size),
			orNone(p.LeaseOwner),
		})
	}
	writeTable(headers, rows)
}

// printPathDetail explains one path: how the priority was computed, what the
// chain is, which facts support it, what is still open, and how the score
// changed over time.
func printPathDetail(p *path.Path, records []path.FeatureRecord) {
	fmt.Printf("path        %s\n", p.ID)
	fmt.Printf("audit       %s\n", p.AuditID)
	fmt.Printf("snapshot    %s\n", p.SnapshotID)
	fmt.Printf("status      %s   evidence %s   kind %s\n", p.Status, p.PathStatus, orNone(p.PathKind))
	fmt.Printf("entry       %s (%s)\n", shortSubject(p.EntrySubject, p.EntryNodeID), orNone(p.EntryKind))
	fmt.Printf("target      %s (%s)\n", shortSubject(p.TargetSubject, p.TargetNodeID), orNone(p.TargetKind))
	fmt.Printf("depth       %d hop(s), %d branch(es), budget depth %d / branches %d / tool calls %d\n",
		p.Depth, p.BranchCount, p.Budget.MaxDepth, p.Budget.MaxBranches, p.Budget.MaxToolCalls)
	fmt.Printf("priority    %s\n", path.PriorityBreakdown(*p))
	fmt.Printf("features    %s\n", featureLine(p.Features))
	for _, reason := range path.SortedReasons(p.Features) {
		fmt.Printf("            %-18s %s\n", reason[0], reason[1])
	}
	fmt.Printf("cluster     %s size %d representative %t differences %s\n",
		shortID(p.Cluster.ID), p.Cluster.Size, p.Cluster.Representative, orNone(strings.Join(p.Cluster.Differences, ",")))
	fmt.Printf("objectives  %s\n", orNone(strings.Join(p.Objectives, ", ")))
	fmt.Printf("boundaries  %s\n", orNone(strings.Join(p.Boundaries, ", ")))
	fmt.Printf("controls    %s\n", orNone(strings.Join(p.Controls, ", ")))
	fmt.Printf("inputs      %s\n", orNone(strings.Join(p.Inputs, ", ")))
	fmt.Printf("assets      %s\n", orNone(strings.Join(p.Assets, ", ")))
	if p.LeaseOwner != "" {
		fmt.Printf("lease       %s until %s\n", p.LeaseOwner, orNone(p.LeaseUntil))
	}
	fmt.Printf("attempts    %d of %d%s\n", p.Attempts, p.MaxAttempts, lastErrorSuffix(p.LastError))

	fmt.Println("steps")
	if len(p.Steps) == 0 {
		fmt.Println("  (none recorded)")
	}
	for i, step := range p.Steps {
		location := ""
		if step.File != "" {
			location = fmt.Sprintf("  %s:%d", step.File, step.Line)
		}
		fmt.Printf("  %2d  %-4s %-14s %s -> %s  %s%s\n",
			i+1, step.Layer, step.Kind, shortID(step.From), shortID(step.To), orNone(step.Subject), location)
	}
	evidenceRefs := append(append([]string(nil), p.SCGRefs...), p.ASGRefs...)
	fmt.Printf("evidence refs %s\n", orNone(strings.Join(evidenceRefs, ", ")))
	printList("open questions", p.OpenQuestions)
	printLimitations("limitations", p.Limitations)

	fmt.Println("score history")
	if len(records) == 0 {
		fmt.Println("  (none stored)")
	}
	for _, record := range records {
		fmt.Printf("  seq %-3d v%d  P=%.4f  R=%.4f  C=%.4f  U=%.4f  computed %s\n",
			record.Seq, record.ScoreVersion, record.Priority, record.Risk, record.Support, record.Utility, record.ComputedAt)
	}
}

func featureLine(f path.Features) string {
	return fmt.Sprintf("E=%.4f I=%.4f S=%.4f T=%.4f B=%.4f F=%.4f D=%.4f V=%.4f Q=%.4f N=%.4f G=%.4f H=%.4f K=%.4f D_dup=%.4f",
		f.Exposure, f.Impact, f.Controllability, f.TrustBoundary, f.BusinessSensitivity,
		f.ReachabilityEvidence, f.DataflowEvidence, f.ControlSuspicion, f.AnalysisQuality,
		f.Novelty, f.InformationGain, f.ReuseValue, f.EstimatedCost, f.DedupDiscount)
}

func printList(label string, items []string) {
	if len(items) == 0 {
		fmt.Printf("%s (none)\n", label)
		return
	}
	fmt.Println(label)
	for _, item := range items {
		fmt.Printf("  - %s\n", item)
	}
}

func lastErrorSuffix(lastError string) string {
	if strings.TrimSpace(lastError) == "" {
		return ""
	}
	return "; last error: " + lastError
}

// shortSubject prefers the display subject and falls back to the node id, then
// trims it so a wide subject does not destroy the table layout.
func shortSubject(subject, id string) string {
	value := strings.TrimSpace(subject)
	if value == "" {
		value = id
	}
	return shorten(value, 44)
}

func shorten(value string, max int) string {
	if len(value) <= max {
		return value
	}
	return value[:max-1] + "…"
}

// --- errors and validation --------------------------------------------------

func requirePositional(rest []string, message string) (string, error) {
	if len(rest) == 0 || strings.TrimSpace(rest[0]) == "" {
		return "", errors.New(message)
	}
	if len(rest) > 1 {
		return "", fmt.Errorf("unexpected arguments: %s", strings.Join(rest[1:], " "))
	}
	return strings.TrimSpace(rest[0]), nil
}

func requireOwner(owner string) error {
	if strings.TrimSpace(owner) == "" {
		return errors.New("--owner is required")
	}
	return nil
}

// requireSnapshotExists turns "not found" into the command that creates the
// snapshot, because an audit request is usually the first thing a new user runs.
//
// The manager is asked, not the store: the CLI's own build commands write a
// snapshot tree without a database record, so a store lookup would call every
// fresh snapshot unknown.
func requireSnapshotExists(rt *app.Runtime, snapshotID string) error {
	if _, err := rt.Manager.Load(snapshotID); err != nil {
		if errors.Is(err, repository.ErrSnapshotNotFound) {
			return fmt.Errorf("snapshot %s is not in this workspace; freeze one first with `codexploit snapshot --source <path>`", snapshotID)
		}
		return err
	}
	return nil
}

// requireAudit reports an unknown audit with the command that lists them.
func requireAudit(ctx context.Context, rt *app.Runtime, auditID string) (*path.Audit, error) {
	audit, err := rt.Audit.Audit(auditID)
	if err != nil {
		if errors.Is(err, path.ErrNotFound) {
			return nil, fmt.Errorf("audit %s does not exist; list audits with `codexploit audit list`", auditID)
		}
		return nil, err
	}
	return audit, nil
}

// resolveAuditID accepts either an audit id or a path id, so the id printed by
// `audit next` can be handed straight to `audit claim`.
func resolveAuditID(ctx context.Context, rt *app.Runtime, id string) (string, error) {
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

// asAuditError makes the engine's sentinels actionable. The two cases that cost
// a user the most time are a snapshot that was never frozen and a snapshot whose
// attack surface was never built; both name the command that fixes them.
func asAuditError(err error, id string) error {
	switch {
	case errors.Is(err, path.ErrNoASG):
		return fmt.Errorf("snapshot %s has no attack surface yet; build it first with `codexploit asg build`: %w", id, err)
	case errors.Is(err, path.ErrNotFound), errors.Is(err, storage.ErrNotFound):
		if strings.HasPrefix(id, "path-") {
			return fmt.Errorf("path %s does not exist; list the queue with `codexploit audit paths <audit-id>`: %w", id, err)
		}
		return err
	case errors.Is(err, path.ErrInvalidTransition):
		return fmt.Errorf("%w (nothing was changed)", err)
	case errors.Is(err, path.ErrLeaseHeld):
		return fmt.Errorf("%w: another worker holds this path; wait for its lease or reclaim it with `codexploit audit reclaim`", err)
	case errors.Is(err, path.ErrLeaseExpired):
		return fmt.Errorf("%w: the lease is gone; claim the path again with `codexploit audit claim <id> --owner <name>`", err)
	case errors.Is(err, path.ErrBudgetExceeded):
		return fmt.Errorf("%w: the audit's active-lease ceiling is reached; release or reclaim a path first", err)
	default:
		return err
	}
}

func auditStatuses(value string) ([]path.Status, error) {
	parts := splitList(value)
	out := make([]path.Status, 0, len(parts))
	for _, part := range parts {
		status := path.Status(part)
		if !path.ValidStatus(status) {
			return nil, fmt.Errorf("unknown status %q; valid statuses are %s", part, strings.Join(statusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

func auditPathStatuses(value string) ([]path.PathStatus, error) {
	parts := splitList(value)
	out := make([]path.PathStatus, 0, len(parts))
	for _, part := range parts {
		status := path.PathStatus(part)
		if !path.ValidPathStatus(status) {
			return nil, fmt.Errorf("unknown path status %q; valid values are %s", part, strings.Join(pathStatusNames(), ", "))
		}
		out = append(out, status)
	}
	return out, nil
}

func auditSort(value string) (string, error) {
	switch strings.TrimSpace(value) {
	case "", "priority", "created", "path_id":
		return strings.TrimSpace(value), nil
	default:
		return "", fmt.Errorf("unknown sort %q; valid values are priority, created, path_id", value)
	}
}

func statusNames() []string {
	statuses := path.AllStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}

func pathStatusNames() []string {
	statuses := path.AllPathStatuses()
	out := make([]string, 0, len(statuses))
	for _, status := range statuses {
		out = append(out, string(status))
	}
	return out
}
