package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/schedule"
)

// The scheduler subcommands are the operator's view of P7: what the resident loop
// is configured to do, one pass by hand, a recovery sweep, and the foreground loop
// itself. They reuse the agent runtime flags, because a scheduler without an
// adapter could claim leases it can never run.
type scheduleFlags struct {
	agentFlags // workspace, db, json, --runtime and the agent adapter flags

	auditsCSV   string
	concurrency int
	interval    int
	leaseTTL    int
	limit       int

	backoffBase   int
	backoffFactor float64
	backoffMax    int
	backoffJitter float64
}

// parseSchedule builds the flag set of one subcommand and splits positionals from
// flags exactly like the audit and agent subcommands.
func parseSchedule(name string, args []string, extra func(*flag.FlagSet, *scheduleFlags)) (*scheduleFlags, []string, error) {
	fs := flag.NewFlagSet("scheduler "+name, flag.ContinueOnError)
	c := &scheduleFlags{}
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

// build constructs a runtime. withScheduler enables the resident scheduler, which
// requires a configured agent: a scheduler with no adapter would claim work it can
// never run, so app.Build refuses it and this returns that error unchanged.
func (c *scheduleFlags) build(ctx context.Context, withScheduler bool) (*app.Runtime, error) {
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
	if withScheduler {
		cfg.Scheduler = app.SchedulerConfig{
			Enabled:       true,
			Audits:        splitList(c.auditsCSV),
			Interval:      time.Duration(c.interval) * time.Second,
			MaxConcurrent: c.concurrency,
			LeaseTTL:      time.Duration(c.leaseTTL) * time.Second,
			Owner:         c.owner,
			Backoff: path.Backoff{
				Base:   time.Duration(c.backoffBase) * time.Second,
				Factor: c.backoffFactor,
				Max:    time.Duration(c.backoffMax) * time.Second,
				Jitter: c.backoffJitter,
			},
		}
	}
	return app.Build(ctx, cfg)
}

// runScheduler dispatches the P7 subcommands.
func runScheduler(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit scheduler <status|tick|reclaim|run> [flags]")
	}
	sub, rest := args[0], args[1:]
	switch sub {
	case "status":
		return runSchedulerStatus(ctx, rest)
	case "tick":
		return runSchedulerTick(ctx, rest)
	case "reclaim", "reclaim-expired":
		return runSchedulerReclaim(ctx, rest)
	case "run", "start":
		return runSchedulerRun(ctx, rest)
	default:
		return fmt.Errorf("unknown scheduler subcommand %q", sub)
	}
}

// runSchedulerStatus answers `scheduler status`: whether the scheduler is
// configured, how, and what the durable queue looks like right now.
//
// Metrics live in the process that runs the loop, so a one-shot CLI cannot read
// the server's counters; the durable queue view is what makes this command useful
// from a shell. `GET /api/scheduler` on the running server answers with the
// in-process metrics.
func runSchedulerStatus(ctx context.Context, args []string) error {
	c, _, err := parseSchedule("status", args, func(fs *flag.FlagSet, c *scheduleFlags) {
		fs.StringVar(&c.auditsCSV, "audits", "", "comma-separated audit ids to report on (default: every audit)")
		addAgentRuntimeFlags(fs, &c.agentFlags)
	})
	if err != nil {
		return err
	}
	rt, err := c.build(ctx, strings.TrimSpace(c.runtime) != "")
	if err != nil {
		return err
	}
	defer rt.Close()

	queue, err := schedulerQueue(rt)
	if err != nil {
		return err
	}
	doc := map[string]any{"running": false, "configured": rt.Scheduler != nil, "queue": queue}
	if rt.Scheduler != nil {
		doc = rt.Scheduler.Snapshot()
		doc["queue"] = queue
	}
	if c.jsonOut {
		return printJSON(doc)
	}
	printSchedulerStatus(doc)
	return nil
}

// runSchedulerTick answers `scheduler tick`: one pass, synchronously, with the
// pass's own summary.
func runSchedulerTick(ctx context.Context, args []string) error {
	c, _, err := parseSchedule("tick", args, func(fs *flag.FlagSet, c *scheduleFlags) {
		fs.StringVar(&c.auditsCSV, "audits", "", "comma-separated audit ids to serve (default: the configured set)")
		fs.IntVar(&c.concurrency, "concurrency", 0, "maximum paths this pass dispatches (0 uses the configured budget)")
		addAgentRuntimeFlags(fs, &c.agentFlags)
	})
	if err != nil {
		return err
	}
	if c.concurrency < 0 {
		return fmt.Errorf("--concurrency must not be negative (got %d)", c.concurrency)
	}
	rt, err := c.build(ctx, true)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Scheduler == nil {
		return errors.New("the scheduler is not configured; pass --runtime scripted or cli")
	}
	result, err := rt.Scheduler.TickScoped(ctx, splitList(c.auditsCSV), c.concurrency)
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(result)
	}
	printTickResult(result)
	return nil
}

// runSchedulerReclaim answers `scheduler reclaim`: one recovery sweep of expired
// leases, which is what an operator runs after killing a worker.
func runSchedulerReclaim(ctx context.Context, args []string) error {
	c, _, err := parseSchedule("reclaim", args, func(fs *flag.FlagSet, c *scheduleFlags) {
		fs.IntVar(&c.limit, "limit", 0, "maximum leases to recover (0 uses the default)")
	})
	if err != nil {
		return err
	}
	if c.limit < 0 {
		return fmt.Errorf("--limit must not be negative (got %d)", c.limit)
	}
	rt, err := c.build(ctx, false)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Audit == nil {
		return errors.New("the path engine is not configured in this workspace")
	}
	limit := c.limit
	if limit == 0 {
		limit = 100
	}
	recovered, err := rt.Audit.ReclaimExpired(limit)
	if err != nil {
		return err
	}
	if recovered == nil {
		recovered = []path.Path{}
	}
	if c.jsonOut {
		return printJSON(map[string]any{"recovered": recovered, "count": len(recovered)})
	}
	if len(recovered) == 0 {
		fmt.Println("no expired lease; nothing was reclaimed")
		return nil
	}
	printPathTable(recovered)
	fmt.Printf("%d expired lease(s) returned to the queue\n", len(recovered))
	return nil
}

// runSchedulerRun answers `scheduler run`: the foreground loop. Ctrl-C cancels the
// context, which makes Run release every lease it still holds before returning.
func runSchedulerRun(ctx context.Context, args []string) error {
	c, _, err := parseSchedule("run", args, func(fs *flag.FlagSet, c *scheduleFlags) {
		fs.StringVar(&c.auditsCSV, "audits", "", "comma-separated audit ids to serve (default: the configured set)")
		fs.IntVar(&c.interval, "interval", 0, "seconds between passes (0 uses the configured interval)")
		fs.IntVar(&c.concurrency, "concurrency", 0, "maximum paths to run at once (0 uses the configured budget)")
		fs.IntVar(&c.leaseTTL, "lease-ttl", 0, "lease duration in seconds (0 uses the audit's own)")
		fs.IntVar(&c.backoffBase, "backoff-base", 0, "seconds to wait after the first failed attempt (0 uses the default)")
		fs.Float64Var(&c.backoffFactor, "backoff-factor", 0, "multiplier applied per failed attempt (0 uses the default)")
		fs.IntVar(&c.backoffMax, "backoff-max", 0, "maximum seconds a path may be deferred (0 uses the default)")
		fs.Float64Var(&c.backoffJitter, "backoff-jitter", 0, "jitter fraction in [0,1) (0 uses the default)")
		addAgentRuntimeFlags(fs, &c.agentFlags)
	})
	if err != nil {
		return err
	}
	if c.interval < 0 {
		return fmt.Errorf("--interval must not be negative (got %d)", c.interval)
	}
	rt, err := c.build(ctx, true)
	if err != nil {
		return err
	}
	defer rt.Close()
	if rt.Scheduler == nil {
		return errors.New("the scheduler is not configured; pass --runtime scripted or cli")
	}
	if c.interval > 0 {
		rt.Scheduler.Interval = time.Duration(c.interval) * time.Second
	}
	if !c.jsonOut {
		effective := rt.Scheduler.Config()
		fmt.Printf("scheduler  %s (every %.0fs, at most %d at once, owner %s)\n",
			strings.Join(effective.Audits, ","), effective.IntervalSeconds, effective.MaxConcurrent, effective.Owner)
		fmt.Println("press Ctrl-C to stop and release the leases this process holds")
	}
	if err := rt.Scheduler.Run(ctx); err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(rt.Scheduler.Snapshot())
	}
	fmt.Println("scheduler stopped; every lease this process held was released")
	return nil
}

// schedulerQueue is the durable queue view a one-shot command can compute.
func schedulerQueue(rt *app.Runtime) (map[string]any, error) {
	if rt.Audit == nil {
		return map[string]any{}, nil
	}
	now := path.NowString(time.Now().UTC())
	queued, _, err := rt.Audit.Paths(path.PathQuery{
		Status: []path.Status{path.StatusQueued}, Sort: "created", Limit: 100000,
	})
	if err != nil {
		return nil, err
	}
	due := 0
	oldest := ""
	for i := range queued {
		if queued[i].NextAttemptAt == "" || queued[i].NextAttemptAt <= now {
			due++
		}
		if oldest == "" && queued[i].CreatedAt != "" {
			oldest = queued[i].CreatedAt
		}
	}
	_, active, err := rt.Audit.Paths(path.PathQuery{
		Status: []path.Status{path.StatusAnalyzing, path.StatusLocalExploring, path.StatusVerifying},
		Limit:  1,
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"queued": len(queued), "due": due, "active_leases": active, "oldest_queued_at": oldest,
	}, nil
}

func printSchedulerStatus(doc map[string]any) {
	configured, _ := doc["configured"].(bool)
	running, _ := doc["running"].(bool)
	fmt.Printf("scheduler  configured=%t running=%t\n", configured, running)
	if cfg, ok := doc["config"].(schedule.EffectiveConfig); ok {
		fmt.Printf("owner      %s\n", cfg.Owner)
		fmt.Printf("interval   %.0fs\n", cfg.IntervalSeconds)
		fmt.Printf("at once    %d\n", cfg.MaxConcurrent)
		fmt.Printf("audits     %s\n", orNone(strings.Join(cfg.Audits, ",")))
		fmt.Printf("backoff    base %s, factor %g, max %s, jitter %g\n",
			cfg.Backoff.Base, cfg.Backoff.Factor, cfg.Backoff.Max, cfg.Backoff.Jitter)
	}
	if metrics, ok := doc["metrics"].(map[string]any); ok && len(metrics) > 0 {
		fmt.Printf("metrics    dispatched=%v succeeded=%v failed=%v retried=%v reclaimed=%v\n",
			metrics["dispatched_total"], metrics["succeeded_total"], metrics["failed_total"],
			metrics["retried_total"], metrics["reclaimed_total"])
	}
	if queue, ok := doc["queue"].(map[string]any); ok {
		fmt.Printf("queue      %v queued (%v due), %v active lease(s), oldest %v\n",
			queue["queued"], queue["due"], queue["active_leases"], orNone(fmt.Sprint(queue["oldest_queued_at"])))
	}
}

func printTickResult(result schedule.TickResult) {
	fmt.Printf("dispatched %d, failed %d, reclaimed %d, skipped %d, due %d, held %d\n",
		result.Dispatched, result.Failed, result.Reclaimed, result.Skipped, result.Due, result.Held)
}
