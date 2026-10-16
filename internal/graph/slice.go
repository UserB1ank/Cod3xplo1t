package graph

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// Slice limits. A slice is the unit of context an audit agent is given, so it is
// small by default and every cut is reported.
const (
	defaultSliceLines    = 60
	maxSliceLines        = 400
	defaultSliceSections = 20
	maxSliceSections     = 100
	defaultContextLines  = 2
	maxContextLines      = 20
	maxSliceFileBytes    = 4 << 20
)

// Slice section reasons.
const (
	SectionDeclaration = "declaration"
	SectionCaller      = "caller_call_site"
	SectionCall        = "call_site"
)

// SliceRequest describes a code slice.
type SliceRequest struct {
	// SymbolID selects a symbol; File is the fallback selector.
	SymbolID string
	File     string
	// StartLine/EndLine bound a file-only slice (1-based, inclusive). They are
	// ignored when SymbolID is set.
	StartLine int
	EndLine   int
	// Include selects extra sections: "declaration" (default), "callers",
	// "calls", or "neighbors" for both extra directions.
	Include string
	// MaxLines caps the lines of one section; MaxSections caps how many sections
	// are returned.
	MaxLines     int
	MaxSections  int
	ContextLines int
	Options      Options
}

// SliceSection is one contiguous excerpt with its reason for being included.
type SliceSection struct {
	Reason    string   `json:"reason"`
	SymbolID  string   `json:"symbol_id,omitempty"`
	Symbol    string   `json:"symbol,omitempty"`
	File      string   `json:"file"`
	StartLine int      `json:"start_line"`
	EndLine   int      `json:"end_line"`
	Lines     []string `json:"lines"`
	// Truncated reports that the section was cut by MaxLines.
	Truncated bool   `json:"truncated"`
	Note      string `json:"note,omitempty"`
}

// CodeSlice is the answer of a slice request.
type CodeSlice struct {
	Root        scg.Symbol     `json:"root,omitempty"`
	Sections    []SliceSection `json:"sections"`
	Limitations []string       `json:"limitations"`
	Meta        Meta           `json:"meta"`
}

// Slice reads the requested excerpts out of the snapshot's frozen tree.
func (s *Service) Slice(ctx context.Context, snapshotID string, req SliceRequest) (*CodeSlice, error) {
	opt := req.Options.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	// Input validation comes before any state lookup: a malformed request is a
	// malformed request whether or not the snapshot has a graph yet.
	if strings.TrimSpace(req.SymbolID) == "" && strings.TrimSpace(req.File) == "" {
		return nil, fmt.Errorf("%w: symbol_id or file is required", ErrInvalidArgument)
	}
	maxLines := req.MaxLines
	if maxLines <= 0 {
		maxLines = defaultSliceLines
	}
	if maxLines > maxSliceLines {
		maxLines = maxSliceLines
	}
	maxSections := req.MaxSections
	if maxSections <= 0 {
		maxSections = defaultSliceSections
	}
	if maxSections > maxSliceSections {
		maxSections = maxSliceSections
	}
	contextLines := req.ContextLines
	if contextLines < 0 {
		contextLines = 0
	}
	if contextLines == 0 {
		contextLines = defaultContextLines
	}
	if contextLines > maxContextLines {
		contextLines = maxContextLines
	}
	include := req.Include
	if include == "" {
		include = SectionDeclaration
	}

	treeDir, err := s.treeDir(snapshotID)
	if err != nil {
		return nil, err
	}
	summary, err := s.Store.GraphSummary(ctx, snapshotID)
	if err != nil {
		return nil, mapStoreError(err, snapshotID)
	}
	out := &CodeSlice{Sections: []SliceSection{}, Limitations: []string{}}

	var seen = map[string]bool{}
	addSection := func(reason string, sym *scg.Symbol, file string, start, end int, note string) error {
		if len(out.Sections) >= maxSections {
			out.Limitations = append(out.Limitations,
				fmt.Sprintf("section budget of %d reached; the slice is incomplete", maxSections))
			return nil
		}
		if start < 1 {
			start = 1
		}
		if end < start {
			end = start
		}
		lines, total, err := readLines(treeDir, file, start, end, maxLines)
		if err != nil {
			return err
		}
		key := fmt.Sprintf("%s:%d-%d:%s", file, start, end, reason)
		if seen[key] {
			return nil
		}
		seen[key] = true
		section := SliceSection{
			Reason:    reason,
			File:      file,
			StartLine: start,
			EndLine:   start + len(lines) - 1,
			Lines:     lines,
			Truncated: int64(len(lines)) < total,
			Note:      note,
		}
		if sym != nil {
			section.SymbolID = sym.ID
			section.Symbol = sym.QualifiedName
		}
		out.Sections = append(out.Sections, section)
		return nil
	}

	switch {
	case req.SymbolID != "":
		sym, serr := s.Store.GetSymbol(ctx, snapshotID, req.SymbolID)
		if serr != nil {
			return nil, mapStoreError(serr, snapshotID)
		}
		out.Root = sym
		if err := addSection(SectionDeclaration, &sym, sym.File, sym.StartLine, sym.EndLine,
			"declaration as recorded in the graph"); err != nil {
			return nil, err
		}
		if include == "callers" || include == "neighbors" {
			if err := s.addCallerSections(ctx, snapshotID, sym, maxLines, contextLines, addSection); err != nil {
				return nil, err
			}
		}
		if include == "calls" || include == "neighbors" {
			if err := s.addCallSections(ctx, snapshotID, sym, maxLines, contextLines, addSection); err != nil {
				return nil, err
			}
		}
	case req.File != "":
		file := filepath.ToSlash(req.File)
		start, end := req.StartLine, req.EndLine
		if start <= 0 {
			start = 1
		}
		if end <= 0 {
			end = start + maxLines - 1
		}
		if err := addSection(SectionDeclaration, nil, file, start, end, "requested file window"); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("%w: symbol_id or file is required", ErrInvalidArgument)
	}

	out.Meta = s.meta(ctx, snapshotID, "slice", map[string]string{
		"symbol_id": req.SymbolID,
		"file":      req.File,
		"include":   include,
		"max_lines": fmt.Sprint(maxLines),
	}, opt, started)
	out.Meta.GraphVersion = summary.GraphVersion
	out.Meta.Truncated = len(out.Limitations) > 0
	if out.Meta.Truncated {
		out.Meta.TruncationReason = out.Limitations[0]
	}
	out.Limitations = append(out.Limitations, "slices are excerpts: they show the recorded declaration and call sites, not the whole translation unit")
	sort.SliceStable(out.Sections, func(i, j int) bool {
		if out.Sections[i].File != out.Sections[j].File {
			return out.Sections[i].File < out.Sections[j].File
		}
		return out.Sections[i].StartLine < out.Sections[j].StartLine
	})
	return out, nil
}

// addCallerSections adds the call sites that reach a symbol.
func (s *Service) addCallerSections(ctx context.Context, snapshotID string, sym scg.Symbol, maxLines, contextLines int, add func(string, *scg.Symbol, string, int, int, string) error) error {
	edges, err := s.Store.EdgesTo(ctx, snapshotID, []string{sym.ID}, []scg.EdgeKind{scg.EdgeCalls})
	if err != nil {
		return mapStoreError(err, snapshotID)
	}
	for _, e := range edges {
		caller, cerr := s.Store.GetSymbol(ctx, snapshotID, e.From)
		if cerr != nil {
			if errors.Is(cerr, repository.ErrSnapshotNotFound) {
				continue
			}
			return mapStoreError(cerr, snapshotID)
		}
		start := e.SourceLocation.Line - contextLines
		end := e.SourceLocation.Line + contextLines
		if err := add(SectionCaller, &caller, e.SourceLocation.File, start, end,
			fmt.Sprintf("call to %s", sym.QualifiedName)); err != nil {
			return err
		}
	}
	return nil
}

// addCallSections adds the call sites inside a symbol, including the ones the
// graph could not resolve.
func (s *Service) addCallSections(ctx context.Context, snapshotID string, sym scg.Symbol, maxLines, contextLines int, add func(string, *scg.Symbol, string, int, int, string) error) error {
	sites, _, err := s.Store.ListCallSites(ctx, storage.CallSiteQuery{
		SnapshotID:     snapshotID,
		CallerSymbolID: sym.ID,
		Limit:          100,
	})
	if err != nil {
		return mapStoreError(err, snapshotID)
	}
	for _, cs := range sites {
		note := "call to " + cs.CalleeText
		if !cs.Resolution.IsResolved() {
			note = fmt.Sprintf("unresolved call to %s (%s)", cs.CalleeText, cs.Resolution)
		}
		start := cs.Line - contextLines
		end := cs.Line + contextLines
		if err := add(SectionCall, &sym, cs.File, start, end, note); err != nil {
			return err
		}
	}
	return nil
}

// treeDir resolves the frozen tree of a snapshot.
func (s *Service) treeDir(snapshotID string) (string, error) {
	if s.Snapshots == nil {
		return "", fmt.Errorf("%w: no snapshot resolver is configured", ErrTreeUnavailable)
	}
	snap, err := s.Snapshots.Load(snapshotID)
	if err != nil {
		if errors.Is(err, repository.ErrSnapshotNotFound) {
			return "", fmt.Errorf("%w: %s", ErrTreeUnavailable, snapshotID)
		}
		return "", err
	}
	tree := snap.TreeDir()
	if info, serr := os.Stat(tree); serr != nil || !info.IsDir() {
		return "", fmt.Errorf("%w: %s", ErrTreeUnavailable, tree)
	}
	return tree, nil
}

// readLines reads lines [start, end] (1-based, inclusive) from a tree file,
// returning at most maxLines lines and the number of lines the window covers.
func readLines(treeDir, file string, start, end, maxLines int) ([]string, int64, error) {
	clean := filepath.Clean(filepath.FromSlash(file))
	if strings.HasPrefix(clean, "..") || filepath.IsAbs(clean) {
		return nil, 0, fmt.Errorf("%w: %q escapes the snapshot", ErrInvalidArgument, file)
	}
	full := filepath.Join(treeDir, clean)
	info, err := os.Stat(full)
	if err != nil {
		return nil, 0, fmt.Errorf("%w: %s", ErrTreeUnavailable, file)
	}
	if info.Size() > maxSliceFileBytes {
		return nil, 0, fmt.Errorf("%w: %s is larger than the slice limit", ErrInvalidArgument, file)
	}
	data, err := os.ReadFile(full)
	if err != nil {
		return nil, 0, err
	}
	if bytes.IndexByte(data, 0) >= 0 {
		return nil, 0, fmt.Errorf("%w: %s is not a text file", ErrInvalidArgument, file)
	}
	var all []string
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		all = append(all, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		return nil, 0, err
	}
	total := int64(len(all))
	if start > len(all) {
		return []string{}, total, nil
	}
	if end > len(all) {
		end = len(all)
	}
	window := all[start-1 : end]
	truncated := int64(len(window))
	if len(window) > maxLines {
		window = window[:maxLines]
	}
	return window, truncated, nil
}
