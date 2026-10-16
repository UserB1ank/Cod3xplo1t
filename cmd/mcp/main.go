// Command mcp serves the Codexploit graph service over the Model Context
// Protocol on stdio.
//
//	codexploit-mcp --workspace .codexploit --db .codexploit/codexploit.db
//
// The process speaks MCP on stdout, so every log line goes to stderr; a single
// stray write to stdout would corrupt the protocol stream.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	internalmcp "github.com/open-mcp-ai/Codexploit/internal/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		workspace = flag.String("workspace", ".codexploit", "workspace directory for snapshots")
		dbPath    = flag.String("db", "", "SQLite database file (default <workspace>/codexploit.db, \"memory\" for an in-process store)")
		transport = flag.String("transport", "stdio", "transport to serve on; stdio is the only supported value")
		logLevel  = flag.String("log-level", "info", "debug, info, warn or error")
	)
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: parseLevel(*logLevel)}))
	slog.SetDefault(logger)

	// Refuse anything but stdio before touching the workspace: this binary must
	// never open a listening socket.
	if *transport != "stdio" {
		return fmt.Errorf("unsupported transport %q: this binary only serves stdio", *transport)
	}

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
	// Network access stays off: the MCP surface only reads snapshots that are
	// already in the workspace.
	rt, err := app.Build(ctx, app.Config{Workspace: absWorkspace, DBPath: path})
	if err != nil {
		return err
	}
	defer rt.Close()

	store, ok := rt.Store.(storage.FullStore)
	if !ok {
		return fmt.Errorf("store %T cannot answer graph queries", rt.Store)
	}
	svc := graph.NewService(store, rt.Manager)
	srv := internalmcp.NewServer(svc, store, logger)

	logger.Info("serving MCP on stdio", "workspace", rt.Workspace, "db", path)
	if err := srv.Run(ctx, &mcp.StdioTransport{}); err != nil {
		// A cancelled context is the SIGINT/SIGTERM path, not a failure.
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return nil
		}
		return err
	}
	return nil
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
