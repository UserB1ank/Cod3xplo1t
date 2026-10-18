// Package app wires the P1 components into a runnable runtime. Both binaries use
// it, so storage profiles, migration sets and the workspace layout are
// configured in exactly one place.
package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/builtinanalysis"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/lifecycle"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/processplugin"
	"github.com/open-mcp-ai/Codexploit/internal/reporting"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/scg/gofrontend"
	"github.com/open-mcp-ai/Codexploit/internal/schedule"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
	"github.com/open-mcp-ai/Codexploit/internal/workflowexec"
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
	// StorageDriver selects the complete sqlite mode (default) or the limited
	// postgres knowledge profile. PostgreSQL credentials are read from a file.
	StorageDriver   string
	PostgresDSNFile string
	// AllowNetwork permits cloning remote git URLs.
	AllowNetwork bool
	// GitBin overrides the git executable.
	GitBin             string
	GitCAFile          string
	GitCredentialFiles map[string]string
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
	// Verification configures the P6 verification layer. The zero value is a
	// disabled verifier, which is the safe default: a deployment with no executor
	// must answer "not configured" instead of pretending a verification is missing.
	Verification VerificationConfig
	// Scheduler configures the P7 resident scheduler. The zero value is a disabled
	// scheduler, which is the safe default: a server that is not asked to run work
	// must not start spending an audit's budget on its own.
	Scheduler SchedulerConfig
	// PluginPackages is a deployment-managed directory of verified process
	// plugin packages. It is empty when no external package is installed.
	PluginPackages string
}

// SchedulerConfig describes the resident scheduler of a deployment.
type SchedulerConfig struct {
	Enabled bool
	// Audits restricts the scheduler to a set of audit ids. An empty list serves
	// every audit with due queued work.
	Audits []string
	// Interval is the pause between passes. Zero means the documented default.
	Interval time.Duration
	// MaxConcurrent bounds how many paths run at once. Zero means the engine's
	// active-lease ceiling.
	MaxConcurrent int
	// LeaseTTL is the lease asked for on a claim. Zero means the audit's own TTL.
	LeaseTTL time.Duration
	// Owner names the lease holder. Empty means "scheduler".
	Owner string
	// Backoff is the durable retry policy of a failed dispatch.
	Backoff path.Backoff
}

// VerificationConfig describes the verification layer of a deployment.
type VerificationConfig struct {
	Enabled bool
	// Executor is "scripted", "cli" or "unsupported". It is spelled out rather than
	// inferred, so a typo is an error instead of a silently dead verifier.
	Executor string
	// Command is the argv of the cli executor. It is executed directly, never
	// through a shell.
	Command []string
	// Env is the complete allowlist of extra environment entries in "KEY=VALUE"
	// form for the cli executor.
	Env        []string
	WorkingDir string
	// MaxOutputBytes bounds the output one cli step may return before it is
	// truncated. Zero means the executor's own default.
	MaxOutputBytes int64
	// AllowNetwork declares that the configured cli command is deployed inside a
	// network-capable restricted container or VM. It does not create a sandbox and
	// it is not an approval: a plan that needs network access is still refused
	// unless the request also carries an approval.
	AllowNetwork bool
	// MaxSteps bounds a plan the planner generates. Zero means the planner's
	// default, which is well under verify.MaxSteps.
	MaxSteps int
	// MaxSliceLines bounds the optional source slice a generated plan may name.
	// Zero means the graph service's own default.
	MaxSliceLines int
	// ScriptedSteps is the deterministic script of the scripted executor: one entry
	// per plan step, in order. An empty script is valid; a step with no entry is
	// reported as BLOCKED, which is what "the script has nothing to say" should
	// look like.
	ScriptedSteps []verify.StepOutcome
	// ScriptedStepsJSON is the same script as a JSON document, for a flag or a
	// configuration file: either the raw array or "@file" to read one. Its
	// vocabulary is verify.StepOutcome's own JSON (case-insensitive field names:
	// kind, content, command, contradicts, err, file, line, exitCode). Malformed
	// JSON fails Build rather than surfacing as a run that fails later.
	ScriptedStepsJSON string
}

// AgentConfig describes the agent runtime of a deployment.
type AgentConfig struct {
	Enabled       bool
	ModelSettings *llm.Manager
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
	Workflows        *workflow.Catalog
	WorkflowRunner   *workflow.Runner
	WorkflowCompiler *workflow.Compiler
	PluginCatalog    *plugin.Catalog
	Plugins          *plugin.Host
	Snapshots        lifecycle.Snapshots
	Store            storage.FullStore
	Manager          *repository.Manager
	Analyzer         *analysis.Analyzer
	Builder          *scg.Builder
	Graph            *graph.Service
	ASGBuilder       *asg.Builder
	ASG              *graph.ASGService
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
	// Verifier is the P6 verification engine. It is nil when verification is
	// disabled, which is what makes every verification route answer 501 instead of
	// pretending a verification is missing.
	Verifier *verify.Verifier
	// VerifyPlanner turns a hypothesis into a finding and a plan. It is nil when
	// verification is disabled.
	VerifyPlanner *graph.VerifyPlanner
	// VerificationConfig is the configuration verification was wired from.
	VerificationConfig VerificationConfig
	// Findings groups plugin observations and owns the reason-bearing severity
	// audit. Verification keeps the verdict.
	Findings *findings.Service
	// Scheduler is the P7 resident scheduler. It is nil when the scheduler is
	// disabled, which is what makes the operator surfaces say "not configured"
	// instead of pretending a scheduler is idle.
	Scheduler *schedule.Scheduler
	// Metrics is the scheduling metrics the runtime's scheduler (and any operator
	// surface) reads. It is non-nil whenever a scheduler is wired.
	Metrics *schedule.Metrics
	// SchedulerConfig is the configuration the scheduler was wired from.
	SchedulerConfig SchedulerConfig
	Workspace       string
	closers         []func() error
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
		repository.WithGitCAFile(cfg.GitCAFile),
		repository.WithGitCredentialFiles(cfg.GitCredentialFiles),
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
		Manager:            mgr,
		Analyzer:           analysis.NewAnalyzer(nil, cfg.Analysis),
		Builder:            builder,
		AgentConfig:        cfg.Agent,
		VerificationConfig: cfg.Verification,
		SchedulerConfig:    cfg.Scheduler,
		Workspace:          mgr.Root,
	}
	if cfg.StorageDriver != "" && cfg.StorageDriver != "sqlite" && cfg.StorageDriver != "postgres" {
		return nil, errors.New("app: unsupported storage driver")
	}
	if cfg.StorageDriver == "postgres" {
		if cfg.DBPath != "" || cfg.PostgresDSNFile == "" {
			return nil, errors.New("app: postgres requires a DSN file and cannot be combined with a SQLite path")
		}
		raw, err := os.ReadFile(cfg.PostgresDSNFile)
		if err != nil || strings.TrimSpace(string(raw)) == "" || len(raw) > 16384 {
			return nil, errors.New("app: PostgreSQL credential file is unavailable or invalid")
		}
		store, err := storage.OpenSQL(ctx, "pgx", strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, errors.New("app: PostgreSQL connection failed")
		}
		if err := store.EnsureSchema(ctx, migrations.Postgres); err != nil {
			store.Close()
			return nil, errors.New("app: PostgreSQL catalog migration failed")
		}
		rt.Store = store
		rt.Snapshots = lifecycle.Snapshots{Store: store, Manager: mgr}
		rt.closers = append(rt.closers, store.Close)
		rt.PluginCatalog, err = plugin.NewCatalog(ctx, store)
		if err != nil {
			rt.Close()
			return nil, err
		}
		rt.wireGraphServices(store)
		rt.Audit = nil // Direct analysis indexes do not enable execution tasks.
		if err := rt.wirePlugins(builtinanalysis.Executors()); err != nil {
			rt.Close()
			return nil, err
		}
		return rt, nil
	}
	if cfg.PostgresDSNFile != "" {
		return nil, errors.New("app: PostgreSQL credential file requires postgres storage")
	}

	executors := builtinanalysis.Executors()
	executors = append(executors, reporting.Executor())
	if strings.TrimSpace(cfg.PluginPackages) != "" {
		processExecutors, err := processplugin.Executors(cfg.PluginPackages)
		if err != nil {
			return nil, fmt.Errorf("load process plugin packages: %w", err)
		}
		executors = append(executors, processExecutors...)
	}

	path := strings.TrimSpace(cfg.DBPath)
	if path == "" || path == "memory" {
		memory := storage.NewMemory()
		rt.Store = memory
		rt.Findings = findings.NewService(memory)
		rt.wireGraphServices(memory)
		rt.PluginCatalog, err = plugin.NewCatalog(ctx, memory)
		if err != nil {
			return nil, err
		}
		if err := rt.wirePlugins(executors); err != nil {
			return nil, err
		}
		if err := rt.wireAgent(rt.AgentConfig); err != nil {
			return nil, err
		}
		if err := rt.wireVerification(rt.VerificationConfig); err != nil {
			return nil, err
		}
		if err := rt.wireWorkflowRunner(); err != nil {
			return nil, err
		}
		if err := rt.wireScheduler(rt.SchedulerConfig); err != nil {
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
	rt.Findings = findings.NewService(sqlStore)
	rt.wireGraphServices(sqlStore)
	rt.PluginCatalog, err = plugin.NewCatalog(ctx, sqlStore)
	if err != nil {
		sqlStore.Close()
		return nil, err
	}
	if err := rt.wirePlugins(executors); err != nil {
		sqlStore.Close()
		return nil, err
	}
	if err := rt.wireAgent(rt.AgentConfig); err != nil {
		sqlStore.Close()
		return nil, err
	}
	if err := rt.wireVerification(rt.VerificationConfig); err != nil {
		sqlStore.Close()
		return nil, err
	}
	if err := rt.wireWorkflowRunner(); err != nil {
		return nil, err
	}
	if err := rt.wireScheduler(rt.SchedulerConfig); err != nil {
		sqlStore.Close()
		return nil, err
	}
	rt.closers = append(rt.closers, sqlStore.Close)
	return rt, nil
}

func (r *Runtime) wirePlugins(executors []plugin.Executor) error {
	repo, ok := r.Store.(plugin.Repository)
	if !ok {
		return plugin.ErrUnsupported
	}
	index, ok := r.Store.(artifact.Index)
	if !ok {
		return plugin.ErrUnsupported
	}
	objects, err := artifact.NewLocal(filepath.Join(r.Workspace, "artifacts"), index)
	if err != nil {
		return err
	}
	r.Plugins, err = plugin.NewHost(plugin.Deps{Catalog: r.PluginCatalog, Repository: repo, Artifacts: objects, Scopes: index, Executors: executors})
	if err != nil {
		return err
	}
	r.closers = append(r.closers, r.Plugins.Close)
	if storage.LimitedPostgres(r.Store) {
		return nil
	}
	workflowRepo, ok := r.Store.(workflow.Repository)
	if !ok {
		return workflow.ErrInvalid
	}
	r.Workflows = &workflow.Catalog{Repository: workflowRepo}
	planRepo, ok := r.Store.(workflow.PlanRepository)
	if !ok {
		return workflow.ErrInvalid
	}
	knowledge, ok := r.Store.(workflow.Knowledge)
	if !ok {
		return workflow.ErrInvalid
	}
	ports := map[string]workflow.AdapterInputs{plugin.BuiltinID + "@" + plugin.BuiltinVersion: {Schemas: []string{"codexploit/source-tar/v1"}}}
	for _, executor := range executors {
		var manifest plugin.Manifest
		if err := json.Unmarshal(executor.Manifest, &manifest); err != nil {
			return err
		}
		ports[manifest.ID+"@"+manifest.Version] = workflow.AdapterInputs{Schemas: executor.InputSchemas, Producers: executor.InputPlugins}
	}
	r.WorkflowCompiler = &workflow.Compiler{AdapterInputs: ports, Plugins: r.PluginCatalog, Workflows: r.Workflows, Plans: planRepo, Artifacts: objects, Scopes: index, Knowledge: knowledge}
	return nil
}

// wireGraphServices builds the query layer over the chosen store. Both stores
// implement the same interfaces, so nothing here depends on which one it is.
func (r *Runtime) wireGraphServices(store storage.FullStore) {
	r.Snapshots = lifecycle.Snapshots{Store: store, Manager: r.Manager}
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
	if model, ok := runtime.(*agent.ModelRuntime); ok {
		model.ToolDescriptions = registry.Descriptions()
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
	AgentRuntimeLLM      = "llm"
)

// buildAgentRuntime builds the adapter the configuration names. An unknown mode,
// a CLI without a command and a malformed scripted answer are all errors here:
// each of them would otherwise surface as a run that fails every time.
func (r *Runtime) buildAgentRuntime(mode string, cfg AgentConfig) (agent.Runtime, error) {
	switch mode {
	case AgentRuntimeLLM:
		if cfg.ModelSettings == nil {
			return nil, errors.New("app: llm runtime needs a settings manager")
		}
		return &agent.ModelRuntime{Settings: cfg.ModelSettings}, nil
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
		return nil, fmt.Errorf("app: agent: unknown runtime %q (want %s, %s, %s or %s)",
			cfg.Runtime, AgentRuntimeDisabled, AgentRuntimeScripted, AgentRuntimeCLI, AgentRuntimeLLM)
	}
}

// Verification executors accepted by --verify-executor. "disabled" is spelled out
// rather than inferred so a typo is an error instead of a silently absent verifier.
const (
	VerifyExecutorDisabled    = "disabled"
	VerifyExecutorScripted    = "scripted"
	VerifyExecutorCLI         = "cli"
	VerifyExecutorUnsupported = "unsupported"
)

// wireVerification builds the P6 engine over the already-wired store and graph
// services.
//
// A misconfigured verifier fails here rather than yielding a server that accepts a
// verification request it can never execute. A disabled verifier leaves both
// fields nil, which is what makes the verification routes answer 501.
func (r *Runtime) wireVerification(cfg VerificationConfig) error {
	if !cfg.Enabled {
		return nil
	}
	mode := strings.ToLower(strings.TrimSpace(cfg.Executor))
	switch mode {
	case VerifyExecutorScripted, VerifyExecutorCLI, VerifyExecutorUnsupported:
	case VerifyExecutorDisabled:
		return errors.New("app: verification: Enabled is set but Executor is \"disabled\"; " +
			"pass --verify-executor scripted, cli or unsupported, or leave verification off")
	case "":
		return errors.New("app: verification: Enabled is set but Executor is empty; " +
			"pass --verify-executor scripted, cli or unsupported")
	default:
		return fmt.Errorf("app: verification: unknown executor %q (want %s, %s or %s)",
			cfg.Executor, VerifyExecutorScripted, VerifyExecutorCLI, VerifyExecutorUnsupported)
	}
	steps, err := scriptedSteps(cfg)
	if err != nil {
		return err
	}
	cfg.ScriptedSteps = steps
	executor, err := r.buildVerifyExecutor(mode, cfg)
	if err != nil {
		return err
	}
	if mode == VerifyExecutorScripted && len(cfg.ScriptedSteps) == 0 {
		// A scripted executor with no script is a dry run with nothing to say: every
		// step is reported unsupported and every run is BLOCKED. That is honest, but a
		// silent BLOCKED is the one outcome an operator may misread as a finding, so
		// it is said out loud here.
		slog.Warn("verification: the scripted executor has no steps; every plan step will be reported as unsupported and every run will be BLOCKED, which is not a refutation",
			"flag", "--verify-scripted-steps (server) or --scripted-steps (CLI)")
	}
	planner := graph.NewVerifyPlanner(r.Store, r.Graph)
	planner.MaxSteps = cfg.MaxSteps
	planner.MaxSliceLines = cfg.MaxSliceLines
	r.Verifier = verify.NewVerifier(r.Store, executor)
	r.VerifyPlanner = planner
	r.VerificationConfig = cfg
	return nil
}

// scriptedSteps resolves the scripted executor's script: the parsed form a caller
// (or a test) passed directly, or the JSON document a configuration supplied.
//
// The JSON vocabulary is verify.StepOutcome's own (case-insensitive field names:
// kind, content, command, contradicts, err, file, line, exitCode), so anything the
// package marshals can be fed back in. A value starting with "@" reads the document
// from a file. Malformed JSON is a wiring error here rather than a run that fails
// later.
func scriptedSteps(cfg VerificationConfig) ([]verify.StepOutcome, error) {
	raw := strings.TrimSpace(cfg.ScriptedStepsJSON)
	if raw == "" {
		return cfg.ScriptedSteps, nil
	}
	if len(cfg.ScriptedSteps) > 0 {
		return nil, errors.New("app: verification: pass the scripted steps either as the parsed ScriptedSteps or as ScriptedStepsJSON, not both")
	}
	if path, ok := strings.CutPrefix(raw, "@"); ok {
		path = strings.TrimSpace(path)
		if path == "" {
			return nil, errors.New("app: verification: --verify-scripted-steps @file needs a file path")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("app: verification: read the scripted steps file: %w", err)
		}
		raw = string(data)
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	var steps []verify.StepOutcome
	if err := decoder.Decode(&steps); err != nil {
		return nil, fmt.Errorf("app: verification: the scripted steps JSON is not a JSON array of step outcomes "+
			"(each entry has kind, content, command, contradicts, err, file, line, exitCode); "+
			"it is passed as --verify-scripted-steps on the server and --scripted-steps on the CLI: %w", err)
	}
	return steps, nil
}

// buildVerifyExecutor builds the adapter the configuration names. An unknown mode,
// a cli executor without a command and an unsupported executor asked to do work
// are all errors here: each of them would otherwise surface as a verification that
// fails every time.
func (r *Runtime) buildVerifyExecutor(mode string, cfg VerificationConfig) (verify.Executor, error) {
	switch mode {
	case VerifyExecutorScripted:
		return verify.NewScriptedExecutor(cfg.ScriptedSteps), nil
	case VerifyExecutorCLI:
		if len(cfg.Command) == 0 || strings.TrimSpace(cfg.Command[0]) == "" {
			return nil, errors.New("app: verification: the cli executor needs a command; " +
				"pass --verify-command <binary> [args...] (repeatable)")
		}
		if strings.TrimSpace(cfg.WorkingDir) == "" {
			return nil, errors.New("app: verification: the cli executor needs a scratch working directory; " +
				"pass --verify-working-dir <dir> (it must exist)")
		}
		return verify.NewCLIExecutor(verify.CLIConfig{
			Name:           VerifyExecutorCLI,
			Version:        "1",
			Command:        cfg.Command,
			Env:            cfg.Env,
			WorkingDir:     cfg.WorkingDir,
			MaxOutputBytes: cfg.MaxOutputBytes,
			AllowNetwork:   cfg.AllowNetwork,
		})
	case VerifyExecutorUnsupported:
		return verify.NewUnsupportedExecutor(VerifyExecutorUnsupported, "1",
			"no verification executor is configured for this deployment"), nil
	default:
		return nil, fmt.Errorf("app: verification: unknown executor %q (want %s, %s or %s)",
			mode, VerifyExecutorScripted, VerifyExecutorCLI, VerifyExecutorUnsupported)
	}
}

// wireScheduler builds the P7 resident scheduler over the already-wired path
// engine and agent runner.
//
// A misconfigured scheduler fails here rather than yielding a server that claims
// to schedule work it can never run; a disabled scheduler leaves both fields nil,
// which is what makes the operator surfaces say "not configured" and what makes
// the server log an explicit disabled line.
func (r *Runtime) wireScheduler(cfg SchedulerConfig) error {
	if !cfg.Enabled {
		return nil
	}
	if r.Audit == nil || r.Store == nil {
		return errors.New("app: scheduler: the path engine is not wired")
	}
	if r.Agent == nil {
		return errors.New("app: scheduler: the scheduler needs an agent runtime; " +
			"pass --agent-runtime scripted or cli (and its adapter flags) or leave the scheduler off")
	}
	if cfg.Interval < 0 {
		return fmt.Errorf("app: scheduler: Interval must not be negative (got %s)", cfg.Interval)
	}
	if cfg.MaxConcurrent < 0 {
		return fmt.Errorf("app: scheduler: MaxConcurrent must not be negative (got %d)", cfg.MaxConcurrent)
	}
	if cfg.LeaseTTL < 0 {
		return fmt.Errorf("app: scheduler: LeaseTTL must not be negative (got %s)", cfg.LeaseTTL)
	}
	audits, err := normaliseAuditIDs(cfg.Audits)
	if err != nil {
		return err
	}
	if cfg.Backoff.Base < 0 || cfg.Backoff.Max < 0 || cfg.Backoff.Factor < 0 || cfg.Backoff.Jitter < 0 {
		return fmt.Errorf("app: scheduler: the backoff policy must not have negative values (got %+v)", cfg.Backoff)
	}
	owner := strings.TrimSpace(cfg.Owner)
	if owner == "" {
		owner = "scheduler"
	}
	metrics := schedule.NewMetrics()
	dispatcher := &agentPathDispatcher{
		Runner: r.Agent,
		Owner:  owner,
		TTL:    cfg.LeaseTTL,
		Policy: r.Agent.Policy,
	}
	r.Scheduler = schedule.New(r.Audit, dispatcher,
		schedule.WithOwner(owner),
		schedule.WithAudits(audits),
		schedule.WithInterval(cfg.Interval),
		schedule.WithMaxConcurrent(cfg.MaxConcurrent),
		schedule.WithLeaseTTL(cfg.LeaseTTL),
		schedule.WithBackoff(cfg.Backoff),
		schedule.WithLogger(slog.Default()),
	)
	r.Scheduler.Metrics = metrics
	r.Metrics = metrics
	return nil
}

// agentPathDispatcher is the bridge from the scheduler to the P5 orchestrator. It
// exists so the scheduler never imports the agent package, and so the lease owner
// the scheduler claims with is exactly the owner the runner renews and settles
// with: a mismatch would make every re-claim look like another worker's lease.
type agentPathDispatcher struct {
	Runner *agent.Runner
	Owner  string
	TTL    time.Duration
	Policy agent.ExplorationPolicy
}

func (d *agentPathDispatcher) Ready() error { return d.Runner.Ready() }

// DispatchPath runs one path the scheduler already chose and leased.
//
// A run that finished without success — the adapter failed, timed out, produced
// invalid output or hit its budget — is returned as an error even though the
// orchestrator recorded it as a run. The run's status is not an error to the
// runner, but it is a failed dispatch to the scheduler: only the scheduler owns
// the durable retry schedule, and a nil error would make it treat a failed run as
// a completed one and re-dispatch the path immediately, with no backoff.
func (d *agentPathDispatcher) DispatchPath(ctx context.Context, pathID string) error {
	if d == nil || d.Runner == nil {
		return errors.New("app: scheduler: no agent runner is wired")
	}
	run, err := d.Runner.RunPath(ctx, pathID, d.Owner, d.TTL, d.Policy)
	if err != nil {
		return err
	}
	if run == nil {
		return fmt.Errorf("app: scheduler: path %s produced no run record", pathID)
	}
	if run.Status != agent.RunSucceeded {
		return fmt.Errorf("app: scheduler: run %s of path %s ended %s (%s)",
			run.ID, pathID, run.Status, run.StopReason)
	}
	return nil
}

// normaliseAuditIDs trims the configured audit set and refuses a blank entry: a
// typo in an audit id must be an error, not a scheduler that silently serves
// nothing.
func normaliseAuditIDs(ids []string) ([]string, error) {
	out := make([]string, 0, len(ids))
	seen := map[string]bool{}
	for _, id := range ids {
		trimmed := strings.TrimSpace(id)
		if trimmed == "" {
			return nil, errors.New("app: scheduler: an audit id must not be empty")
		}
		if seen[trimmed] {
			continue
		}
		seen[trimmed] = true
		out = append(out, trimmed)
	}
	return out, nil
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

func (r *Runtime) wireWorkflowRunner() error {
	repo, ok := r.Store.(workflow.RunRepository)
	if !ok {
		return workflow.ErrInvalid
	}
	r.WorkflowRunner = workflow.NewRunner(r.WorkflowCompiler, repo, workflow.PluginExecutor{Host: r.Plugins, Catalog: r.PluginCatalog}, r.WorkflowCompiler.Artifacts)
	r.WorkflowRunner.Effects = &workflowexec.Effects{Store: r.Store, Host: r.Plugins, Artifacts: r.WorkflowCompiler.Artifacts, Manager: r.Manager, Agent: r.Agent, Findings: r.Findings}
	if resumed, err := r.WorkflowRunner.Recover(context.Background()); err != nil {
		slog.Warn("workflow recovery failed", "error", err)
	} else if len(resumed) > 0 {
		slog.Info("resumed interrupted workflow runs", "count", len(resumed))
	}
	r.closers = append([]func() error{r.WorkflowRunner.Close}, r.closers...)
	return nil
}
