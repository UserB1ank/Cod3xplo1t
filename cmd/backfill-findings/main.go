// Command backfill-findings materializes candidate Findings from hypotheses
// accepted by existing path-agent runs. It never changes a verification verdict.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	_ "modernc.org/sqlite"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		driver   = flag.String("storage", "postgres", "storage profile: postgres or sqlite")
		dbPath   = flag.String("db", "", "SQLite database file")
		dsnFile  = flag.String("postgres-dsn-file", "", "PostgreSQL DSN file")
		auditID  = flag.String("audit", "", "optional audit id to backfill")
		pageSize = flag.Int("page-size", 200, "hypotheses per page (1-500)")
		dryRun   = flag.Bool("dry-run", false, "count candidates without writing findings")
	)
	flag.Parse()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	store, err := openStore(ctx, *driver, *dbPath, *dsnFile)
	if err != nil {
		return err
	}
	defer store.Close()
	full, ok := any(store).(storage.FullStore)
	if !ok {
		return errors.New("storage does not implement the full catalog")
	}
	if *dryRun {
		query := agent.HypothesisQuery{AuditID: strings.TrimSpace(*auditID), FindingCandidatesOnly: true}
		hypotheses, total, err := full.ListHypotheses(query)
		if err != nil {
			return err
		}
		fmt.Printf("candidate hypotheses: %d (page returned %d)\n", total, len(hypotheses))
		return nil
	}
	ensured, err := graph.BackfillCandidateFindings(
		ctx, full, graph.NewVerifyPlanner(full, nil),
		agent.HypothesisQuery{AuditID: strings.TrimSpace(*auditID)}, *pageSize,
	)
	if err != nil {
		return err
	}
	fmt.Printf("candidate findings ensured: %d\n", ensured)
	return nil
}

func openStore(ctx context.Context, driver, dbPath, dsnFile string) (*storage.SQL, error) {
	switch strings.ToLower(strings.TrimSpace(driver)) {
	case "postgres":
		raw, err := os.ReadFile(dsnFile)
		if err != nil || strings.TrimSpace(string(raw)) == "" || len(raw) > 16<<10 {
			return nil, errors.New("PostgreSQL DSN file is unavailable or invalid")
		}
		store, err := storage.OpenSQL(ctx, "pgx", strings.TrimSpace(string(raw)))
		if err != nil {
			return nil, errors.New("PostgreSQL connection failed")
		}
		if err := store.EnsureSchema(ctx, migrations.Postgres); err != nil {
			store.Close()
			return nil, err
		}
		return store, nil
	case "sqlite":
		if strings.TrimSpace(dbPath) == "" {
			return nil, errors.New("--db is required for sqlite")
		}
		store, err := storage.OpenSQL(ctx, "sqlite", dbPath)
		if err != nil {
			return nil, err
		}
		if err := store.EnsureSchema(ctx, migrations.FS); err != nil {
			store.Close()
			return nil, err
		}
		return store, nil
	default:
		return nil, errors.New("storage must be postgres or sqlite")
	}
}
