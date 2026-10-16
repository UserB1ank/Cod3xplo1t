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

	"github.com/open-mcp-ai/Codexploit/internal/api"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
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
	var agentCommand, agentEnv repeatedFlag
	var verifyCommand, verifyEnv repeatedFlag
	var (
		addr         = flag.String("addr", ":8080", "listen address")
		workspace    = flag.String("workspace", ".codexploit", "workspace directory for snapshots")
		dbPath       = flag.String("db", "", "SQLite database file (default <workspace>/codexploit.db, \"memory\" for an in-process store)")
		allowNetwork = flag.Bool("allow-network", false, "permit cloning remote git URLs")
		gitBin       = flag.String("git", "git", "git executable")
		logLevel     = flag.String("log-level", "info", "debug, info, warn or error")
		anonymous    = flag.Bool("insecure-anonymous", false, "serve without authentication (local development only)")
		idemTTL      = flag.Duration("idempotency-ttl", 24*time.Hour, "how long a stored write response may be replayed")

		agentRuntime    = flag.String("agent-runtime", app.AgentRuntimeDisabled, "agent adapter: disabled, scripted or cli")
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
	)
	flag.Var(&apiTokens, "api-token", "token as name:role:secret, repeatable; role is reader, writer or admin")
	flag.Var(&agentCommand, "agent-command", "agent command argv, repeatable; the binary plus its arguments")
	flag.Var(&agentEnv, "agent-env", "environment entry for the agent process as KEY=VALUE, repeatable")
	flag.Var(&verifyCommand, "verify-command", "verification command argv, repeatable; the binary plus its arguments")
	flag.Var(&verifyEnv, "verify-env", "environment entry for a verification step as KEY=VALUE, repeatable")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))
	slog.SetDefault(logger)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	absWorkspace, err := filepath.Abs(*workspace)
	if err != nil {
		return err
	}
	path := *dbPath
	if path == "" {
		path = filepath.Join(absWorkspace, "codexploit.db")
	}
	auth, err := buildAuthenticator(apiTokens, *anonymous, logger)
	if err != nil {
		return err
	}

	rt, err := app.Build(ctx, app.Config{
		Workspace:    absWorkspace,
		DBPath:       path,
		AllowNetwork: *allowNetwork,
		GitBin:       *gitBin,
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
	})
	if err != nil {
		return err
	}
	defer rt.Close()

	if rt.Agent == nil {
		logger.Info("agent disabled; run and hypothesis routes answer 501",
			"hint", "pass --agent-runtime scripted (with --agent-scripted-answer) or --agent-runtime cli --agent-command <binary>")
	}
	if rt.Verifier == nil {
		logger.Info("verification disabled; verification, finding and report routes answer 501",
			"hint", "pass --verify-executor scripted, --verify-executor cli --verify-command <binary>, or --verify-executor unsupported")
	}

	srv := api.NewServer(rt.Store, rt.Manager, rt.Analyzer,
		api.WithAllowNetwork(*allowNetwork),
		api.WithGraph(rt.Graph),
		api.WithBuilder(rt.Builder),
		api.WithASG(rt.ASG),
		api.WithASGBuilder(rt.ASGBuilder),
		api.WithAudit(rt.Audit),
		api.WithAgent(rt.Agent),
		api.WithVerifier(rt.Verifier),
		api.WithVerifyPlanner(rt.VerifyPlanner),
		api.WithAuth(auth),
		api.WithIdempotencyTTL(*idemTTL),
		api.WithLogger(logger),
	)
	httpServer := &http.Server{
		Addr:              *addr,
		Handler:           srv.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       60 * time.Second,
		WriteTimeout:      10 * time.Minute, // snapshotting a large repository is slow
		IdleTimeout:       120 * time.Second,
	}

	errCh := make(chan error, 1)
	go func() {
		logger.Info("listening", "addr", httpServer.Addr, "workspace", rt.Workspace, "db", path)
		if err := httpServer.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		logger.Info("shutting down")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		return httpServer.Shutdown(shutdownCtx)
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
