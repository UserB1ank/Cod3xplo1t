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
	var (
		addr         = flag.String("addr", ":8080", "listen address")
		workspace    = flag.String("workspace", ".codexploit", "workspace directory for snapshots")
		dbPath       = flag.String("db", "", "SQLite database file (default <workspace>/codexploit.db, \"memory\" for an in-process store)")
		allowNetwork = flag.Bool("allow-network", false, "permit cloning remote git URLs")
		gitBin       = flag.String("git", "git", "git executable")
		logLevel     = flag.String("log-level", "info", "debug, info, warn or error")
		anonymous    = flag.Bool("insecure-anonymous", false, "serve without authentication (local development only)")
		idemTTL      = flag.Duration("idempotency-ttl", 24*time.Hour, "how long a stored write response may be replayed")
	)
	flag.Var(&apiTokens, "api-token", "token as name:role:secret, repeatable; role is reader, writer or admin")
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
	})
	if err != nil {
		return err
	}
	defer rt.Close()

	srv := api.NewServer(rt.Store, rt.Manager, rt.Analyzer,
		api.WithAllowNetwork(*allowNetwork),
		api.WithGraph(rt.Graph),
		api.WithBuilder(rt.Builder),
		api.WithASG(rt.ASG),
		api.WithASGBuilder(rt.ASGBuilder),
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
