package mcp

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// Project tools are private to an authenticated supervisor turn. The stdio
// server retains its existing surface. Neither model arguments nor source
// content can change the project/snapshot scope captured here.
func NewProjectClient(ctx context.Context, svc *graph.Service, store storage.FullStore, projectID, snapshotID string, catalogs ...*plugin.Catalog) (*sdk.ClientSession, error) {
	p := projectReader{store: store, graph: svc, project: projectID, snapshot: snapshotID}
	if len(catalogs) > 0 {
		p.catalog = catalogs[0]
	}
	if _, err := store.GetProject(ctx, projectID); err != nil {
		return nil, err
	}
	server := newServer(svc, store, slog.New(slog.NewTextHandler(io.Discard, nil)), p.check)
	reg := registry{server, p.check}
	register(reg, &sdk.Tool{Name: "inspect_project", Description: "Inspect real application state for this project. Start with source or analysis when graph queries fail; missing graph does not mean missing source."}, p.inspect)
	register(reg, &sdk.Tool{Name: "read_source_file", Description: "Read a bounded line window from frozen project source, even before graph publication. No build or execution."}, p.readSource)
	register(reg, &sdk.Tool{Name: "list_source_files", Description: "List frozen source paths independently of graph indexing, with bounded pagination and optional path substring."}, p.listFiles)
	return connectClient(ctx, server)
}

func connectClient(ctx context.Context, server *sdk.Server) (*sdk.ClientSession, error) {
	st, ct := sdk.NewInMemoryTransports()
	go func() { _, _ = server.Connect(ctx, st, nil) }()
	client := sdk.NewClient(&sdk.Implementation{Name: "codexploit-project-supervisor", Version: "1.1.0"}, nil)
	return client.Connect(ctx, ct, nil)
}

type projectReader struct {
	store             storage.FullStore
	graph             *graph.Service
	catalog           *plugin.Catalog
	project, snapshot string
}

func (p projectReader) check(ctx context.Context, snapshot string) error {
	if snapshot != p.snapshot {
		return coded(CodeNotFound, errors.New("object is outside the bound project input"))
	}
	if _, err := p.store.GetProject(ctx, p.project); err != nil {
		return coded(CodeNotFound, errors.New("project is unavailable"))
	}
	rows, err := p.store.ListSnapshots(ctx, p.project)
	if err != nil {
		return coded(CodeInternal, errors.New("snapshot catalog unavailable"))
	}
	for _, row := range rows {
		if row.SnapshotID == snapshot {
			return nil
		}
	}
	return coded("snapshot_missing", errors.New("bound snapshot metadata is absent from this project's catalog"))
}

type inspectInput struct {
	snapshotArg
	ID      string `json:"id,omitempty"`
	Limit   int    `json:"limit,omitempty"`
	Offset  int    `json:"offset,omitempty"`
	Cursor  string `json:"cursor,omitempty"`
	Section string `json:"section" jsonschema:"source, analysis, workflow, plugins, invocations, tasks, paths, agent_runs, findings, reports, artifacts or system"`
}

func (p projectReader) inspect(ctx context.Context, in inspectInput) (*map[string]any, error) {
	out := map[string]any{"project_id": p.project, "snapshot_id": p.snapshot, "section": in.Section}
	switch in.Section {
	case "source":
		snapshot, err := p.store.GetSnapshot(ctx, p.snapshot)
		if err != nil {
			return nil, err
		}
		out["snapshot_present"] = true
		out["files"] = snapshot.Stats.Files
		out["bytes"] = snapshot.Stats.Bytes
		input, err := p.store.GetProjectInput(ctx, p.project)
		if err != nil {
			return nil, err
		}
		out["input_state"] = storage.EffectiveProjectInput(input, p.graph.Now()).State
		if p.graph.Snapshots != nil {
			snap, e := p.graph.Snapshots.Load(p.snapshot)
			if e == nil {
				info, e := os.Stat(snap.TreeDir())
				out["tree_present"] = e == nil && info.IsDir()
			}
		}
		summary, err := p.graph.Summary(ctx, p.snapshot)
		if errors.Is(err, graph.ErrNoGraph) {
			out["graph_ready"] = false
			out["graph_state"] = "not_published"
		} else if err != nil {
			return nil, err
		} else {
			out["graph_ready"] = true
			out["graph"] = summary
		}
	case "analysis":
		limit := in.Limit
		if limit < 1 || limit > 10 {
			limit = 1
		}
		runs, err := p.store.ListAnalysisRuns(ctx, p.project, limit)
		if in.ID != "" {
			run, e := p.store.GetAnalysisRun(ctx, p.project, in.ID)
			err = e
			runs = []storage.AnalysisRun{run}
		}
		if err != nil {
			return nil, err
		}
		items := []map[string]any{}
		for _, run := range runs {
			if run.SnapshotID == p.snapshot {
				items = append(items, analysisSummary(run))
			}
		}
		out["runs"] = items
		out["limited"] = in.ID == "" && len(runs) == limit
	default:
		if err := p.operations(ctx, in, out); err != nil {
			return nil, err
		}
	}
	return &out, nil
}

type fileInput struct {
	snapshotArg
	File      string `json:"file"`
	StartLine int    `json:"start_line,omitempty"`
	MaxLines  int    `json:"max_lines,omitempty"`
}

func allowedSource(file string) bool {
	if file == "" || filepath.IsAbs(file) || strings.ContainsAny(file, "\\:\x00\r\n") || filepath.ToSlash(filepath.Clean(file)) != file || file == ".." || strings.HasPrefix(file, "../") {
		return false
	}
	for _, part := range strings.Split(strings.ToLower(file), "/") {
		if strings.HasPrefix(part, ".env") || part == ".ssh" || part == ".git" || strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".key") {
			return false
		}
	}
	return true
}
func (p projectReader) sourceRoot() (*os.Root, error) {
	if p.graph.Snapshots == nil {
		return nil, coded(CodeTreeUnavailable, errors.New("source resolver unavailable"))
	}
	snap, err := p.graph.Snapshots.Load(p.snapshot)
	if err != nil {
		return nil, coded(CodeTreeUnavailable, errors.New("source tree unavailable; snapshot metadata may still exist"))
	}
	root, err := os.OpenRoot(snap.TreeDir())
	if err != nil {
		return nil, coded(CodeTreeUnavailable, errors.New("frozen source tree unavailable"))
	}
	return root, nil
}
func (p projectReader) readSource(ctx context.Context, in fileInput) (*map[string]any, error) {
	if !allowedSource(in.File) || in.StartLine < 0 || in.MaxLines < 0 {
		return nil, coded(CodeInvalidArgument, errors.New("invalid source window or path"))
	}
	root, err := p.sourceRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	info, err := root.Lstat(in.File)
	if err != nil || !info.Mode().IsRegular() {
		return nil, coded("source_file_missing", errors.New("regular source file absent"))
	}
	if info.Size() > 4<<20 {
		return nil, coded(CodeBudgetExceeded, errors.New("source file exceeds 4 MiB"))
	}
	file, err := root.Open(in.File)
	if err != nil {
		return nil, coded(CodeTreeUnavailable, errors.New("source file unavailable"))
	}
	defer file.Close()
	start, limit := in.StartLine, in.MaxLines
	if start < 1 {
		start = 1
	}
	if limit == 0 || limit > 200 {
		limit = 200
	}
	scanner := bufio.NewScanner(io.LimitReader(file, 4<<20+1))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var content strings.Builder
	line, end := 0, start-1
	truncated := false
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		line++
		if line < start {
			continue
		}
		if line >= start+limit || content.Len()+len(scanner.Text())+1 > 16000 {
			truncated = true
			break
		}
		text := scanner.Text()
		if !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return nil, coded(CodeInvalidArgument, errors.New("source file is not UTF-8 text"))
		}
		content.WriteString(text)
		content.WriteByte('\n')
		end = line
	}
	if scanner.Err() != nil {
		return nil, coded(CodeBudgetExceeded, errors.New("source text window unavailable"))
	}
	out := map[string]any{"project_id": p.project, "snapshot_id": p.snapshot, "file": in.File, "start_line": start, "end_line": end, "content": content.String(), "truncated": truncated, "origin": "frozen_source"}
	return &out, nil
}

type filesInput struct {
	snapshotArg
	Contains string `json:"contains,omitempty"`
	Offset   int    `json:"offset,omitempty"`
	Limit    int    `json:"limit,omitempty"`
}

func (p projectReader) listFiles(ctx context.Context, in filesInput) (*map[string]any, error) {
	if in.Offset < 0 || in.Offset > 1000000 || len(in.Contains) > 256 {
		return nil, coded(CodeInvalidArgument, errors.New("invalid source page"))
	}
	limit := in.Limit
	if limit < 1 || limit > 100 {
		limit = 100
	}
	root, err := p.sourceRoot()
	if err != nil {
		return nil, err
	}
	defer root.Close()
	files := []string{}
	seen, visited := 0, 0
	truncated := false
	stop := errors.New("page complete")
	err = fs.WalkDir(root.FS(), ".", func(name string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		visited++
		if visited > 1000000 {
			truncated = true
			return stop
		}
		if name == "." {
			return nil
		}
		if !allowedSource(name) {
			if d.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 || d.IsDir() || !strings.Contains(name, in.Contains) {
			return nil
		}
		if seen < in.Offset {
			seen++
			return nil
		}
		if len(files) == limit {
			truncated = true
			return stop
		}
		files = append(files, name)
		return nil
	})
	if err != nil && !errors.Is(err, stop) {
		return nil, coded(CodeTreeUnavailable, fmt.Errorf("source directory unavailable"))
	}
	out := map[string]any{"snapshot_id": p.snapshot, "files": files, "offset": in.Offset, "truncated": truncated, "next_offset": in.Offset + len(files)}
	return &out, nil
}
