// Package app wires the P1 components into a runnable runtime. Both binaries use
// it, so the SQLite driver, the migration set and the workspace layout are
// configured in exactly one place.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/migrations"

	_ "modernc.org/sqlite"
)

// SQLiteDriver is the database/sql driver name registered by modernc.org/sqlite.
// It is pure Go, so the same binary works on Linux, macOS and Windows without
// cgo.
const SQLiteDriver = "sqlite"

// Config describes a runtime.
type Config struct {
	// Workspace is the directory holding snapshots and clone caches.
	Workspace string
	// DBPath is a SQLite file, or "" / "memory" for an in-process store.
	DBPath string
	// AllowNetwork permits cloning remote git URLs.
	AllowNetwork bool
	// GitBin overrides the git executable.
	GitBin string
	// Freeze makes snapshot trees read-only (default true).
	Freeze *bool
	// Limits overrides the snapshot limits.
	Limits repository.Limits
	// Analysis configures the analyzer.
	Analysis analysis.Config
	// Frontends overrides the SCG language frontends. The Go frontend is used
	// when this is empty.
	Frontends []scg.Frontend
	// BuildLimits bounds SCG builds.
	BuildLimits scg.BuildLimits
	// Agent configures the P5 agent runtime. The zero value is a disabled agent,
	// which is the safe default: a server that cannot run anything must say so
	// instead of advertising runs it will never start.
	Agent AgentConfig
}

// AgentConfig describes the agent runtime of a deployment.
type AgentConfig struct {
	Enabled bool
	// Runtime is "cli" or "scripted".
	Runtime string
	// Command is the argv of the CLI adapter. It is executed directly, never
	// through a shell.
	Command []string
	// Env is the complete allowlist of extra environment entries in "KEY=VALUE"
	// form. Nothing else is inherited except PATH, HOME and TMPDIR (plus
	// SystemRoot on Windows).
	Env        []string
	WorkingDir string
	// TimeoutSeconds bounds each run in addition to the orchestrator's own
	// deadline. Zero means the policy's timeout alone bounds it.
	TimeoutSeconds int
	// Exploration bounds. Zero means the documented default, not "unbounded".
	MaxHops      int
	MaxBranches  int
	MaxToolCalls int
	// MaxExpansions and TokenBudget have no default: zero is a real ceiling here,
	// because an expansion is a privilege and a token budget of zero means "not
	// enforced". AllowedTools is the advertised and enforced allowlist; empty
	// means the registry's own names.
	MaxExpansions int
	TokenBudget   int
	AllowedTools  []string
	// Owner names the lease holder; empty means "orchestrator".
	Owner string
	// HeartbeatSeconds is the lease renewal cadence; zero means the orchestrator's
	// default.
	HeartbeatSeconds int
	// ScriptedAnswerJSON and ScriptedNote configure the scripted runtime, which is
	// how a dry run and the tests exercise the loop without an external process.
	ScriptedAnswerJSON string
	ScriptedNote       string
}

// Runtime bundles the wired components.
type Runtime struct {
	Store      storage.FullStore
	Manager    *repository.Manager
	Analyzer   *analysis.Analyzer
	Builder    *scg.Builder
	Graph      *graph.Service
	ASGBuilder *asg.Builder
	ASG        *graph.ASGService
	// Audit is the path engine: it generates candidate AuditPaths, ranks them and
	// serves the scheduling queue.
	Audit *path.Service
	// Agent is the P5 orchestrator. It is nil when the agent is disabled, which is
	// what makes every run route answer 501 instead of pretending a run vanished.
	Agent *agent.Runner
	// AgentRegistry is the tool registry the runner executes against. The API
	// checks a request's allowlist against the registry's own names, so the
	// advertised tools are exactly the enforced ones.
	AgentRegistry *agent.Registry
	// AgentConfig is the configuration the agent was wired from. It is kept so a
	// caller (and a test) can reproduce the policy a run was bounded by.
	AgentConfig AgentConfig
	Workspace   string
	closers     []func() error
}

// Build constructs a runtime, applying migrations when a SQL database is used.
func Build(ctx context.Context, cfg Config) (*Runtime, error) {
	if strings.TrimSpace(cfg.Workspace) == "" {
		return nil, errors.New("app: workspace must not be empty")
	}
	freeze := true
	if cfg.Freeze != nil {
		freeze = *cfg.Freeze
	}
	mgr, err := repository.NewManager(cfg.Workspace,
		repository.WithLimits(cfg.Limits),
		repository.WithAllowNetwork(cfg.AllowNetwork),
		repository.WithGitBin(cfg.GitBin),
		repository.WithFreeze(freeze),
	)
	if err != nil {
		return nil, err
	}
	frontends := cfg.Frontends
	if len(frontends) == 0 {
		frontends = []scg.Frontend{gofrontend.New()}
	}
	builder := scg.NewBuilder(frontends...)
	builder.Limits = cfg.BuildLimits

	rt := &Runtime{
		Manager:     mgr,
		Analyzer:    analysis.NewAnalyzer(nil, cfg.Analysis),
		Builder:     builder,
		AgentConfig: cfg.Agent,
		Workspace:   mgr.Root,
	}

	path := strings.TrimSpace(cfg.DBPath)
	if path == "" || path == "memory" {
		memory := storage.NewMemory()
		rt.Store = memory
		rt.wireGraphServices(memory)
		if err := rt.wireAgent(rt.AgentConfig); err != nil {
			return nil, err
		}
		return rt, nil
	}
	if dir := filepath.Dir(path); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return nil, fmt.Errorf("app: create database directory: %w", err)
		}
	}
	sqlStore, err := storage.OpenSQL(ctx, SQLiteDriver, path)
	if err != nil {
		return nil, err
	}
	if err := sqlStore.EnsureSchema(ctx, migrations.FS); err != nil {
		sqlStore.Close()
		return nil, err
	}
	rt.Store = sqlStore
	rt.wireGraphServices(sqlStore)
	if err := rt.wireAgent(rt.AgentConfig); err != nil {
		sqlStore.Close()
		return nil, err
	}
	rt.closers = append(rt.closers, sqlStore.Close)
	return rt, nil
}

// wireGraphServices builds the query layer over the chosen store. Both stores
// implement the same interfaces, so nothing here depends on which one it is.
func (r *Runtime) wireGraphServices(store storage.FullStore) {
	r.Graph = graph.NewService(store, r.Manager)
	// The ASG builder reads the SCG through *graph.Service, which satisfies
	// asg.SCGReader with its narrow read methods.
	r.ASGBuilder = asg.NewBuilder(r.Graph)
	r.ASG = graph.NewASGService(store, r.Graph)
	// The path engine reads the same two graphs through its own narrow readers, and
	// writes audits through the store.
	facts := graph.NewPathFacts(r.Graph, r.ASG, store)
	engine := path.NewEngine(facts, facts)
	r.Audit = path.NewService(store, engine)
}

// wireAgent builds the P5 orchestrator over the already-wired graph and path
// services. A misconfigured agent fails here rather than yielding a server that
// accepts a run request it can never honour; a disabled agent leaves both fields
// nil, which is what makes the run routes answer 501.
func (r *Runtime) wireAgent(cfg AgentConfig) error {
	if !cfg.Enabled {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Runtime))
	if mode == "" {
		mode = AgentRuntimeDisabled
	}
	// "disabled" is not "an agent with no adapter": a runner with a nil runtime
	// would claim a lease and then fail every attempt, so it is refused here.
	if mode == AgentRuntimeDisabled {
		return errors.New("app: agent: Enabled is set but Runtime is \"disabled\"; " +
			"pass --agent-runtime scripted or cli, or leave the agent off")
	}
	allowed := normaliseToolNames(cfg.AllowedTools)
	if len(allowed) == 0 {
		allowed = normaliseToolNames(graph.AgentToolNames())
	}
	if len(allowed) == 0 {
		return errors.New("app: agent: no tools are registered; the runtime would advertise a tool list it cannot enforce")
	}
	// The registry is built from the effective allowlist, so "advertised" and
	// "enforceable" cannot drift: the API compares a request against these names.
	registry := agent.NewRegistry()
	graph.RegisterAgentTools(registry, r.Graph, r.ASG, r.Audit, r.Store)
	registered := registry.Names()
	for _, name := range allowed {
		if _, ok := registry.Lookup(name); !ok {
			return fmt.Errorf("app: agent: tool %q is not registered (registered tools: %s)",
				name, strings.Join(registered, ", "))
		}
	}
	policy := agent.ExplorationPolicy{
		MaxHops:       cfg.MaxHops,
		MaxBranches:   cfg.MaxBranches,
		MaxToolCalls:  cfg.MaxToolCalls,
		MaxExpansions: cfg.MaxExpansions,
		TokenBudget:   cfg.TokenBudget,
		AllowedTools:  allowed,
	}.Normalize()
	// Normalize exists to make a wire request complete, and it fills an unset
	// expansion ceiling with the documented default. A configured zero is a
	// decision, not an omission — zero expansions and an unenforced token budget
	// are both meaningful — so the configured values are restored afterwards.
	policy.MaxExpansions = cfg.MaxExpansions
	policy.TokenBudget = cfg.TokenBudget
	policy.AllowedTools = allowed

	runtime, err := r.buildAgentRuntime(mode, cfg)
	if err != nil {
		return err
	}
	facts := graph.NewAgentFacts(r.Graph, r.ASG, agent.BuildOptions{AllowedTools: policy.AllowedTools})
	r.AgentRegistry = registry
	r.Agent = &agent.Runner{
		Store:    r.Store,
		Registry: registry,
		Runtime:  runtime,
		Tasks:    facts,
		Paths:    graph.NewAgentCoordinator(r.Audit, cfg.Owner),
		Policy:   policy,
		Owner:    cfg.Owner,
	}
	if cfg.HeartbeatSeconds > 0 {
		r.Agent.HeartbeatEvery = time.Duration(cfg.HeartbeatSeconds) * time.Second
	}
	return nil
}

// Agent runtimes accepted by --agent-runtime. "disabled" is spelled out rather
// than inferred so a typo is an error instead of a silently dead server.
const (
	AgentRuntimeDisabled = "disabled"
	AgentRuntimeScripted = "scripted"
	AgentRuntimeCLI      = "cli"
)

// buildAgentRuntime builds the adapter the configuration names. An unknown mode,
// a CLI without a command and a malformed scripted answer are all errors here:
// each of them would otherwise surface as a run that fails every time.
func (r *Runtime) buildAgentRuntime(mode string, cfg AgentConfig) (agent.Runtime, error) {
	switch mode {
	case AgentRuntimeDisabled:
		return nil, nil
	case AgentRuntimeScripted:
		steps := make([]agent.ScriptStep, 0, 2)
		if strings.TrimSpace(cfg.ScriptedNote) != "" {
			steps = append(steps, agent.ScriptNote(cfg.ScriptedNote))
		}
		raw := strings.TrimSpace(cfg.ScriptedAnswerJSON)
		if raw == "" {
			return nil, errors.New("app: agent: the scripted runtime needs --agent-scripted-answer <json>; " +
				"a script with no answer only records invalid output")
		}
		var answer agent.Answer
		decoder := json.NewDecoder(strings.NewReader(raw))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&answer); err != nil {
			return nil, fmt.Errorf("app: agent: --agent-scripted-answer is not a valid agent answer: %w", err)
		}
		steps = append(steps, agent.ScriptAnswer(answer))
		return agent.NewScriptedRuntime(AgentRuntimeScripted, "1", steps), nil
	case AgentRuntimeCLI:
		if len(cfg.Command) == 0 || strings.TrimSpace(cfg.Command[0]) == "" {
			return nil, errors.New("app: agent: the cli runtime needs --agent-command <binary> [args...]")
		}
		return agent.NewCLIRuntime(agent.CLIConfig{
			Name:              AgentRuntimeCLI,
			Version:           "1",
			Command:           cfg.Command,
			Env:               cfg.Env,
			WorkingDir:        cfg.WorkingDir,
			Timeout:           time.Duration(cfg.TimeoutSeconds) * time.Second,
			HeartbeatInterval: time.Duration(cfg.HeartbeatSeconds) * time.Second,
		})
	default:
		return nil, fmt.Errorf("app: agent: unknown runtime %q (want %s, %s or %s)",
			cfg.Runtime, AgentRuntimeDisabled, AgentRuntimeScripted, AgentRuntimeCLI)
	}
}

// normaliseToolNames trims, drops empties and sorts a tool list, so the value
// stored in a policy and the value compared against a request cannot disagree
// over spacing or order.
func normaliseToolNames(names []string) []string {
	out := make([]string, 0, len(names))
	seen := map[string]bool{}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Close releases every resource the runtime owns.
func (r *Runtime) Close() error {
	var errs []error
	for _, close := range r.closers {
		if err := close(); err != nil {
			errs = append(errs, err)
		}
	}
	return errors.Join(errs...)
}
