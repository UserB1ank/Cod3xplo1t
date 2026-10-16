// Package app wires the P1 components into a runnable runtime. Both binaries use
// it, so the SQLite driver, the migration set and the workspace layout are
// configured in exactly one place.
package app

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

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
	Audit     *path.Service
	Workspace string
	closers   []func() error
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
		Manager:   mgr,
		Analyzer:  analysis.NewAnalyzer(nil, cfg.Analysis),
		Builder:   builder,
		Workspace: mgr.Root,
	}

	path := strings.TrimSpace(cfg.DBPath)
	if path == "" || path == "memory" {
		memory := storage.NewMemory()
		rt.Store = memory
		rt.wireGraphServices(memory)
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
