// Command cli is the Codexploit developer entry point for the P1 snapshot chain.
//
//	codexploit snapshot --source <git-url|path> [--ref <rev>]
//	codexploit manifest --source <git-url|path> [--ref <rev>]
//	codexploit version
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

// version is the CLI version, kept in step with the engine versions.
const version = "0.1.0"

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	var err error
	args := os.Args[1:]
	if len(args) == 0 {
		usage(os.Stderr)
		os.Exit(2)
	}
	switch args[0] {
	case "snapshot":
		err = runSnapshot(ctx, args[1:])
	case "manifest", "scan":
		err = runManifest(ctx, args[1:])
	case "snapshots":
		err = runSnapshots(ctx, args[1:])
	case "scg", "graph":
		err = runSCG(ctx, args[1:])
	case "asg":
		err = runASG(ctx, args[1:])
	case "audit":
		err = runAudit(ctx, args[1:])
	case "run", "runs", "hypotheses", "hypothesis":
		// The singular spelling is an alias, so dispatch is on the canonical name.
		if args[0] == "hypothesis" {
			args[0] = "hypotheses"
		}
		err = runAgent(ctx, args)
	case "version", "--version", "-v":
		fmt.Printf("codexploit %s (snapshot schema %d, manifest schema %d)\n", version, repository.SchemaVersion, analysis.SchemaVersion)
	case "help", "--help", "-h":
		usage(os.Stdout)
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q\n\n", args[0])
		usage(os.Stderr)
		os.Exit(2)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func usage(w *os.File) {
	fmt.Fprint(w, `codexploit - static-analysis-driven code security auditing

Usage:
  codexploit snapshot --source <git-url|path> [flags]   freeze an immutable snapshot
  codexploit manifest --source <git-url|path> [flags]   snapshot and write repository_manifest.json
  codexploit scg build --source <git-url|path> [flags]   snapshot, manifest and SCG in one step
  codexploit scg summary|modules|files|symbols --snapshot <id>
  codexploit scg callers|callees --snapshot <id> --symbol <id|name> [--depth N]
  codexploit scg paths --snapshot <id> --from <sym> --to <sym> [--max-paths N]
  codexploit scg slice --snapshot <id> --symbol <id|name> [--include callers|calls|neighbors]
  codexploit scg unresolved --snapshot <id> [--symbol <sym>]
  codexploit asg build --source <git-url|path> [flags]   snapshot, manifest, SCG and attack surface
  codexploit asg summary|nodes|node|entrypoints|edges --snapshot <id>
  codexploit audit create --snapshot <id> [--force] [--json]   generate and rank audit paths
  codexploit audit list|show|paths|path|events|next|order ...
  codexploit audit claim|heartbeat|release|pause|resume|cancel|reclaim|rescore ...
  codexploit run <audit-id|path-id> [--runtime scripted|cli] [--max-runs N] [--json]
  codexploit runs list|show|events [--path --audit --snapshot --status --type --after --limit --json]
  codexploit hypotheses list|show [--audit --path --status --finding-candidates --limit --offset --json]
  codexploit snapshots list [--workspace <dir>]          list snapshots in a workspace
  codexploit snapshots remove --id <snapshot-id>         delete a snapshot (unfreezes the tree first)
  codexploit version

A frozen snapshot tree is read-only, so deleting a workspace with rm -rf fails.
Use "snapshots remove" (or the DELETE API) instead.

Flags (snapshot, manifest):
  --source string      repository URL or local path (required)
  --ref string         revision to pin (default HEAD for git sources)
  --workspace string   workspace directory (default .codexploit)
  --allow-network      permit cloning remote git URLs
  --no-freeze          keep the snapshot tree writable (debugging only)
  --json               print the full document instead of a summary
`)
}

type commonFlags struct {
	source       string
	ref          string
	workspace    string
	allowNetwork bool
	noFreeze     bool
	jsonOut      bool
}

func parseCommon(name string, args []string) (*commonFlags, error) {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	c := &commonFlags{}
	fs.StringVar(&c.source, "source", "", "repository URL or local path")
	fs.StringVar(&c.ref, "ref", "", "revision to pin")
	fs.StringVar(&c.workspace, "workspace", ".codexploit", "workspace directory")
	fs.BoolVar(&c.allowNetwork, "allow-network", false, "permit cloning remote git URLs")
	fs.BoolVar(&c.noFreeze, "no-freeze", false, "keep the snapshot tree writable")
	fs.BoolVar(&c.jsonOut, "json", false, "print the full document")
	if err := fs.Parse(args); err != nil {
		return nil, err
	}
	if strings.TrimSpace(c.source) == "" {
		return nil, errors.New("--source is required")
	}
	if fs.NArg() > 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	return c, nil
}

func (c *commonFlags) build(ctx context.Context) (*app.Runtime, error) {
	freeze := !c.noFreeze
	workspace, err := filepath.Abs(c.workspace)
	if err != nil {
		return nil, err
	}
	return app.Build(ctx, app.Config{
		Workspace:    workspace,
		DBPath:       "memory", // the CLI is stateless; the server owns the database
		AllowNetwork: c.allowNetwork,
		Freeze:       &freeze,
	})
}

func runSnapshot(ctx context.Context, args []string) error {
	c, err := parseCommon("snapshot", args)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	snap, err := rt.Manager.Create(ctx, repository.Source{Raw: c.source, Ref: c.ref})
	if err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(snap)
	}
	printSnapshot(snap)
	return nil
}

func runManifest(ctx context.Context, args []string) error {
	c, err := parseCommon("manifest", args)
	if err != nil {
		return err
	}
	rt, err := c.build(ctx)
	if err != nil {
		return err
	}
	defer rt.Close()

	snap, err := rt.Manager.Create(ctx, repository.Source{Raw: c.source, Ref: c.ref})
	if err != nil {
		return err
	}
	manifest, err := rt.Analyzer.Analyze(ctx, snap)
	if err != nil {
		return err
	}
	if err := manifest.WriteTo(snap); err != nil {
		return err
	}
	if c.jsonOut {
		return printJSON(manifest)
	}
	printSnapshot(snap)
	printManifest(manifest)
	fmt.Printf("\nmanifest written to %s\n", snap.ManifestPath())
	return nil
}

// runSnapshots manages the local workspace. Deleting a snapshot through the
// manager is the only supported way: read-only trees cannot be removed with
// rm -rf on any supported platform.
func runSnapshots(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: codexploit snapshots <list|remove> [flags]")
	}
	sub := args[0]
	fs := flag.NewFlagSet("snapshots "+sub, flag.ContinueOnError)
	workspace := fs.String("workspace", ".codexploit", "workspace directory")
	id := fs.String("id", "", "snapshot id (remove)")
	jsonOut := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	absWorkspace, err := filepath.Abs(*workspace)
	if err != nil {
		return err
	}
	rt, err := app.Build(ctx, app.Config{Workspace: absWorkspace, DBPath: "memory"})
	if err != nil {
		return err
	}
	defer rt.Close()

	switch sub {
	case "list":
		ids, err := rt.Manager.List()
		if err != nil {
			return err
		}
		if *jsonOut {
			return printJSON(map[string]any{"workspace": rt.Workspace, "snapshots": ids})
		}
		if len(ids) == 0 {
			fmt.Printf("no snapshots in %s\n", rt.Workspace)
			return nil
		}
		for _, snapshotID := range ids {
			snap, err := rt.Manager.Load(snapshotID)
			if err != nil {
				fmt.Printf("%s  (unreadable: %v)\n", snapshotID, err)
				continue
			}
			fmt.Printf("%s  %s  %s  %d file(s)\n", snap.SnapshotID, snap.VCS, shortRev(snap.Commit), snap.Stats.Files)
		}
	case "remove":
		if strings.TrimSpace(*id) == "" {
			return errors.New("--id is required")
		}
		if err := rt.Manager.Remove(*id); err != nil {
			return err
		}
		fmt.Printf("removed %s\n", *id)
	default:
		return fmt.Errorf("unknown snapshots subcommand %q", sub)
	}
	return nil
}

func shortRev(rev string) string {
	if len(rev) > 12 {
		return rev[:12]
	}
	return rev
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printSnapshot(s *repository.Snapshot) {
	fmt.Printf("snapshot   %s\n", s.SnapshotID)
	fmt.Printf("repository %s (%s)\n", s.Identity.Name, s.Identity.Kind)
	fmt.Printf("revision   %s", s.Commit)
	if s.RequestedRef != "" && s.RequestedRef != s.Commit {
		fmt.Printf(" (requested %s)", s.RequestedRef)
	}
	fmt.Println()
	fmt.Printf("tree       %s\n", s.TreeDir())
	fmt.Printf("contents   %d file(s), %s accepted, %d skipped\n", s.Stats.Files, humanBytes(s.Stats.Bytes), s.Stats.SkippedTotal())
	if s.WorktreeDirty {
		fmt.Printf("worktree   dirty (%d path(s)); snapshot reflects the commit only\n", s.DirtyPathCount)
	}
	if len(s.SubmoduleState) > 0 {
		fmt.Printf("submodules %d pinned, content not expanded\n", len(s.SubmoduleState))
	}
	if s.LFS.Detected {
		fmt.Println("git lfs    pointers only; content not fetched")
	}
	if len(s.Symlinks) > 0 {
		fmt.Printf("symlinks   %d recorded, not materialised\n", len(s.Symlinks))
	}
	printLimitations("coverage", s.Limitations)
}

func printManifest(m *analysis.Manifest) {
	fmt.Printf("\nanalysis   %s (rules %s, config %s)\n", m.AnalysisID, m.RulesetHash, m.ConfigHash)
	fmt.Printf("primary    %s\n", orNone(m.PrimaryLanguage))
	if len(m.Languages) > 0 {
		var parts []string
		for _, l := range m.Languages {
			parts = append(parts, fmt.Sprintf("%s (%d files)", l.Name, l.Files))
		}
		fmt.Printf("languages  %s\n", strings.Join(parts, ", "))
	}
	if len(m.Frameworks) > 0 {
		var parts []string
		for _, f := range m.Frameworks {
			parts = append(parts, fmt.Sprintf("%s [%s]", f.Name, f.Confidence))
		}
		fmt.Printf("frameworks %s\n", strings.Join(parts, ", "))
	}
	if len(m.Entrypoints) > 0 {
		var parts []string
		for _, e := range m.Entrypoints {
			parts = append(parts, e.Path)
		}
		fmt.Printf("entrypoints %s\n", strings.Join(parts, ", "))
	}
	if len(m.BuildConfigs) > 0 {
		fmt.Printf("build/ci   %d descriptor(s)\n", len(m.BuildConfigs))
	}
	if len(m.Dependencies.Managers) > 0 {
		var parts []string
		for _, mgr := range m.Dependencies.Managers {
			parts = append(parts, fmt.Sprintf("%s: %s (%d)", mgr.Name, mgr.ParseStatus, mgr.Packages))
		}
		fmt.Printf("deps       %s\n", strings.Join(parts, ", "))
	}
	fmt.Printf("coverage   %d/%d file(s) read (%d read call(s)), %s, %d detector(s)\n",
		m.Coverage.FilesRead, m.Coverage.FilesInTree, m.Coverage.ReadCalls, humanBytes(m.Coverage.BytesRead), len(m.Coverage.Detectors))
	printLimitations("unknowns", m.Unknowns)
}

func printLimitations(label string, items []string) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("%s\n", label)
	for _, item := range items {
		fmt.Printf("  - %s\n", item)
	}
}

func orNone(s string) string {
	if s == "" {
		return "(none)"
	}
	return s
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	units := []string{"KiB", "MiB", "GiB", "TiB"}
	value := float64(n)
	for _, u := range units {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f %s", value, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", value/unit)
}
