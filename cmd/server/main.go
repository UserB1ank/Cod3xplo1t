// Command server runs the Codexploit REST API.
//
//	codexploit-server --addr :8080 --workspace .codexploit --db .codexploit/codexploit.db
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/access"
	"github.com/open-mcp-ai/Codexploit/internal/api"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	pathpkg "github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/webui"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

// repeatedFlag collects a flag that may be given more than once.
type repeatedFlag []string

func (r *repeatedFlag) String() string { return strings.Join(*r, ",") }

func (r *repeatedFlag) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func run() error {
	var apiTokens repeatedFlag
	var gitCredentials repeatedFlag
	var agentCommand, agentEnv repeatedFlag
	var verifyCommand, verifyEnv repeatedFlag
	var (
		addr            = flag.String("addr", ":8080", "listen address")
		workspace       = flag.String("workspace", ".codexploit", "workspace directory for snapshots")
		dbPath          = flag.String("db", "", "SQLite database file (default <workspace>/codexploit.db, \"memory\" for an in-process store)")
		storageDriver   = flag.String("storage", "sqlite", "storage profile: sqlite or postgres")
		postgresDSNFile = flag.String("postgres-dsn-file", "", "runtime PostgreSQL credential file; never put a DSN in arguments")
		settingsKeyFile = flag.String("settings-key-file", "", "independent installation key for encrypted PostgreSQL model settings")
		allowNetwork    = flag.Bool("allow-network", false, "permit cloning remote git URLs")
		gitBin          = flag.String("git", "git", "git executable")
		gitCAFile       = flag.String("git-ca-file", "", "deployment-owned HTTPS CA bundle for Git")
		logLevel        = flag.String("log-level", "info", "debug, info, warn or error")
		anonymous       = flag.Bool("insecure-anonymous", false, "serve without authentication (local development only)")
		webAuth         = flag.Bool("web-auth", false, "enable administrator account setup and password login in the WebUI")
		localSourceRoot = flag.String("local-source-root", "/repos", "physical mount exposed as the logical /repos namespace for explicit folder sources")
		pluginPackages  = flag.String("plugin-packages", "", "deployment-managed directory of verified process plugin packages")
		idemTTL         = flag.Duration("idempotency-ttl", 24*time.Hour, "how long a stored write response may be replayed")

		agentRuntime    = flag.String("agent-runtime", app.AgentRuntimeDisabled, "agent adapter: disabled, scripted, cli or llm (configured in WebUI)")
		agentWorkDir    = flag.String("agent-working-dir", "", "working directory of the agent process")
		agentTimeout    = flag.Int("agent-timeout", 0, "agent run timeout in seconds (0 uses the policy default)")
		agentMaxHops    = flag.Int("agent-max-hops", 0, "maximum hops one agent run may explore (0 uses the default)")
		agentMaxBranch  = flag.Int("agent-max-branches", 0, "maximum active branches one agent run may hold (0 uses the default)")
		agentMaxTools   = flag.Int("agent-max-tool-calls", 0, "maximum tool calls one agent run may make (0 uses the default)")
		agentMaxExpand  = flag.Int("agent-max-expansions", 0, "maximum expansions one agent run may request")
		agentTokenBudge = flag.Int("agent-token-budget", 0, "reported token budget of one agent run (0 is not enforced)")
		agentTools      = flag.String("agent-tools", strings.Join(graph.AgentToolNames(), ","),
			"comma-separated tool allowlist (the default is every graph agent tool)")
		agentOwner     = flag.String("agent-owner", "", "lease owner recorded on agent runs (default orchestrator)")
		agentHeartbeat = flag.Int("agent-heartbeat", 0, "lease heartbeat interval in seconds (0 uses the default)")
		agentAnswer    = flag.String("agent-scripted-answer", "", "raw JSON answer for the scripted runtime (dry run)")

		verifyExecutor  = flag.String("verify-executor", app.VerifyExecutorDisabled, "verification executor: disabled, scripted, cli or unsupported")
		verifySteps     = flag.String("verify-scripted-steps", "", "scripted executor steps as a raw JSON array, or @file to read one; an empty script blocks every step")
		verifyWorkDir   = flag.String("verify-working-dir", "", "scratch working directory of a cli verification step (must exist)")
		verifyMaxOutput = flag.Int64("verify-max-output", 0, "maximum bytes one cli verification step may return (0 uses the executor default)")
		verifyAllowNet  = flag.Bool("verify-allow-network", false, "declare that --verify-command runs inside a network-capable restricted container (still needs a per-request approval)")

		scheduler           = flag.Bool("scheduler", false, "run the resident P7 scheduler (needs --agent-runtime)")
		schedulerInterval   = flag.Int("scheduler-interval", 30, "seconds between scheduler passes")
		schedulerConcurrent = flag.Int("scheduler-concurrency", 0, "maximum paths the scheduler runs at once (0 uses the engine ceiling)")
		schedulerLeaseTTL   = flag.Int("scheduler-lease-ttl", 0, "lease duration in seconds asked for on a claim (0 uses the audit's own)")
		schedulerOwner      = flag.String("scheduler-owner", "", "lease owner recorded by the scheduler (default scheduler)")
		schedulerBackoffB   = flag.Int("scheduler-backoff-base", 1, "seconds to wait after the first failed attempt")
		schedulerBackoffF   = flag.Float64("scheduler-backoff-factor", 2, "multiplier applied per failed attempt")
		schedulerBackoffM   = flag.Int("scheduler-backoff-max", 300, "maximum seconds a path may be deferred")
		schedulerBackoffJ   = flag.Float64("scheduler-backoff-jitter", 0.2, "deterministic jitter fraction in [0,1) applied to the delay")
	)
	var schedulerAudits repeatedFlag
	flag.Var(&schedulerAudits, "scheduler-audit", "audit id the scheduler serves, repeatable; empty serves every audit with due work")
	flag.Var(&apiTokens, "api-token", "token as name:role:secret, repeatable; role is reader, writer or admin")
	flag.Var(&gitCredentials, "git-credential-file", "deployment-owned Git credential reference as id=absolute-file-path, repeatable")
	flag.Var(&agentCommand, "agent-command", "agent command argv, repeatable; the binary plus its arguments")
	flag.Var(&agentEnv, "agent-env", "environment entry for the agent process as KEY=VALUE, repeatable")
	flag.Var(&verifyCommand, "verify-command", "verification command argv, repeatable; the binary plus its arguments")
	flag.Var(&verifyEnv, "verify-env", "environment entry for a verification step as KEY=VALUE, repeatable")
	flag.Parse()
	credentialFiles := make(map[string]string, len(gitCredentials))
	for _, value := range gitCredentials {
		ref, file, ok := strings.Cut(value, "=")
		if !ok || ref == "" || !filepath.IsAbs(file) {
			return errors.New("--git-credential-file requires id=absolute-file-path")
		}
		if _, exists := credentialFiles[ref]; exists {
			return errors.New("duplicate Git credential reference")
		}
		credentialFiles[ref] = file
	}

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	absWorkspace, err := filepath.Abs(*workspace)
	if err != nil {
		return err
	}
	path := *dbPath
	if path == "" && *storageDriver == "sqlite" {
		path = filepath.Join(absWorkspace, "codexploit.db")
	}
	if *webAuth && *anonymous {
		return errors.New("--web-auth cannot be combined with --insecure-anonymous")
	}
	var auth *api.Authenticator
	if *webAuth && len(apiTokens) == 0 && strings.TrimSpace(os.Getenv("CODEXPLOIT_API_TOKENS")) == "" {
		auth, err = api.NewAuthenticator(nil)
	} else {
		auth, err = buildAuthenticator(apiTokens, *anonymous, logger)
	}
	if err != nil {
		return err
	}
	rt, err := app.Build(ctx, app.Config{
		Workspace:          absWorkspace,
		DBPath:             path,
		StorageDriver:      *storageDriver,
		PostgresDSNFile:    *postgresDSNFile,
		SettingsKeyFile:    *settingsKeyFile,
		AllowNetwork:       *allowNetwork,
		GitBin:             *gitBin,
		GitCAFile:          *gitCAFile,
		GitCredentialFiles: credentialFiles,
		PluginPackages:     *pluginPackages,
		Agent: app.AgentConfig{
			Enabled:            !strings.EqualFold(strings.TrimSpace(*agentRuntime), app.AgentRuntimeDisabled),
			Runtime:            *agentRuntime,
			Command:            agentCommand,
			Env:                agentEnv,
			WorkingDir:         *agentWorkDir,
			TimeoutSeconds:     *agentTimeout,
			MaxHops:            *agentMaxHops,
			MaxBranches:        *agentMaxBranch,
			MaxToolCalls:       *agentMaxTools,
			MaxExpansions:      *agentMaxExpand,
			TokenBudget:        *agentTokenBudge,
			AllowedTools:       commaSeparated(*agentTools),
			Owner:              *agentOwner,
			HeartbeatSeconds:   *agentHeartbeat,
			ScriptedAnswerJSON: *agentAnswer,
		},
		Verification: app.VerificationConfig{
			Enabled:           !strings.EqualFold(strings.TrimSpace(*verifyExecutor), app.VerifyExecutorDisabled),
			Executor:          *verifyExecutor,
			Command:           verifyCommand,
			Env:               verifyEnv,
			WorkingDir:        *verifyWorkDir,
			MaxOutputBytes:    *verifyMaxOutput,
			AllowNetwork:      *verifyAllowNet,
			ScriptedStepsJSON: *verifySteps,
		},
		Scheduler: app.SchedulerConfig{
			Enabled:       *scheduler,
			Audits:        schedulerAudits,
			Interval:      time.Duration(*schedulerInterval) * time.Second,
			MaxConcurrent: *schedulerConcurrent,
			LeaseTTL:      time.Duration(*schedulerLeaseTTL) * time.Second,
			Owner:         *schedulerOwner,
			Backoff: pathpkg.Backoff{
				Base:   time.Duration(*schedulerBackoffB) * time.Second,
				Factor: *schedulerBackoffF,
				Max:    time.Duration(*schedulerBackoffM) * time.Second,
				Jitter: *schedulerBackoffJ,
			},
		},
	})
	if err != nil {
		return err
	}
	defer rt.Close()

	var accounts *access.Manager
	if *webAuth {
		if repo, ok := storage.IdentityRepository(rt.Store); ok && storage.IsPostgres(rt.Store) {
			accounts, err = access.OpenRepository(repo)
			if err == nil {
				imported, importErr := access.ImportLegacyAccount(filepath.Join(absWorkspace, "auth"), repo)
				if importErr != nil {
					logger.Warn("could not import the workspace account into PostgreSQL", "error", importErr)
				} else if imported {
					logger.Info("imported the workspace administrator account into PostgreSQL")
				}
			}
		} else {
			accounts, err = access.Open(filepath.Join(absWorkspace, "auth"))
		}
		if err != nil {
			return fmt.Errorf("open account store: %w", err)
		}
	}
	if rt.LLMSettings != nil && rt.LLMSettings.Unavailable() != nil {
		logger.Warn("model settings are unavailable; model runs stay paused until the installation key is restored",
			"hint", "pass --settings-key-file with a deployment secret")
	}

	if rt.Agent == nil {
		logger.Info("agent disabled; run and hypothesis routes answer 501",
			"hint", "pass --agent-runtime scripted (with --agent-scripted-answer) or --agent-runtime cli --agent-command <binary>")
	}
	if rt.Verifier == nil {
		logger.Info("verification disabled; verification, finding and report routes answer 501",
			"hint", "pass --verify-executor scripted, --verify-executor cli --verify-command <binary>, or --verify-executor unsupported")
	}
	if rt.Scheduler == nil {
		logger.Info("scheduler disabled; the queue only advances on an explicit run, tick or claim",
			"hint", "pass --scheduler (with --agent-runtime) to serve the due queue in this process")
	} else {
		effective := rt.Scheduler.Config()
		logger.Info("scheduler enabled",
			"owner", effective.Owner,
			"interval_seconds", effective.IntervalSeconds,
			"max_concurrent", effective.MaxConcurrent,
			"audits", strings.Join(effective.Audits, ","))
	}

	srv := api.NewServer(rt.Store, rt.Manager, rt.Analyzer,
		api.WithWorkflows(rt.Workflows),
		api.WithWorkflowCompiler(rt.WorkflowCompiler),
		api.WithWorkflowRunner(rt.WorkflowRunner),
		api.WithPluginCatalog(rt.PluginCatalog),
		api.WithPlugins(rt.Plugins),
		api.WithLocalSourceRoot(*localSourceRoot),
		api.WithAllowNetwork(*allowNetwork),
		api.WithGraph(rt.Graph),
		api.WithBuilder(rt.Builder),
		api.WithASG(rt.ASG),
		api.WithASGBuilder(rt.ASGBuilder),
		api.WithAudit(rt.Audit),
		api.WithAgent(rt.Agent),
		api.WithLLMSettings(rt.LLMSettings),
		api.WithVerifier(rt.Verifier),
		api.WithVerifyPlanner(rt.VerifyPlanner),
		api.WithScheduler(rt.Scheduler),
		api.WithAuth(auth),
		api.WithAccounts(accounts),
		api.WithIdempotencyTTL(*idemTTL),
		api.WithLogger(logger),
	)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           webui.Handler(srv.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Minute, // snapshotting a large repository is slow
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", httpServer.Addr, "storage", *storageDriver)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	// The scheduler runs in this process and must be waited for: it releases the
	// leases it still holds, and returning before it does would close the store
	// under a live claim. Its own context lets a failed listener stop it too.
	schedulerCtx, stopSchedulerLoop := context.WithCancel(ctx)
	defer stopSchedulerLoop()
	schedulerErr := make(chan error, 1)
	if rt.Scheduler != nil {
		go func() { schedulerErr <- rt.Scheduler.Run(schedulerCtx) }()
	}
	stopScheduler := func() {
		stopSchedulerLoop()
		select {
		case err := <-schedulerErr:
			if err != nil {
				logger.Error("scheduler stopped with an error", "error", err)
			}
		case <-time.After(30 * time.Second):
			logger.Warn("the scheduler did not stop in time; its leases will expire on their own")
		}
	}

	select {
	case err := <-errCh:
		if rt.Scheduler != nil {
			stopScheduler()
		}
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := httpServer.Shutdown(shutdownCtx)
		if rt.Scheduler != nil {
			stopScheduler()
		}
		return err
	}
}

// commaSeparated parses a comma-separated flag value. An empty value returns nil
// rather than a list holding one empty name, because an empty entry would be a
// tool the registry does not know.
func commaSeparated(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}

// buildAuthenticator reads tokens from the flags or from CODEXPLOIT_API_TOKENS
// (semicolon separated, same name:role:secret form). Without tokens the server
// refuses to start unless --insecure-anonymous was given explicitly, because an
// unauthenticated audit API is worse than an unavailable one.
func buildAuthenticator(flags repeatedFlag, allowAnonymous bool, logger *slog.Logger) (*api.Authenticator, error) {
	specs := []string(flags)
	if len(specs) == 0 {
		if env := strings.TrimSpace(os.Getenv("CODEXPLOIT_API_TOKENS")); env != "" {
			specs = strings.Split(env, ";")
		}
	}
	if len(specs) > 0 {
		tokens, err := api.ParseTokenSpecs(specs)
		if err != nil {
			return nil, err
		}
		auth, err := api.NewAuthenticator(tokens)
		if err != nil {
			return nil, err
		}
		logger.Info("authentication enabled", "tokens", auth.Tokens())
		return auth, nil
	}
	if !allowAnonymous {
		return nil, errors.New("no API tokens configured: pass --api-token name:role:secret (repeatable) " +
			"or set CODEXPLOIT_API_TOKENS, or use --insecure-anonymous for local development only")
	}
	logger.Warn("authentication is DISABLED: reads and writes are anonymous, destructive operations still need a token",
		"flag", "--insecure-anonymous")
	return api.NewAuthenticatorWithOptions(nil, api.WithAnonymousAccess(api.CapWrite))
}

func parseLevel(name string) slog.Level {
	switch name {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}
