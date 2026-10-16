package api

import (
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// graphUnavailable reports that the server was built without a graph service.
func (s *Server) graphUnavailable(w http.ResponseWriter) bool {
	if s.Graph == nil {
		writeError(w, http.StatusNotImplemented, "graph_unavailable",
			errors.New("this server was started without the graph service"))
		return true
	}
	return false
}

type buildGraphRequest struct {
	// Force rebuilds even when a graph for this snapshot already exists.
	Force bool `json:"force"`
}

// handleBuildGraph builds (or rebuilds) the SCG of a snapshot.
//
// The build is deterministic for a given frontend set, so an existing graph is
// returned as-is unless Force is set; the graph version says which frontends
// produced it.
func (s *Server) handleBuildGraph(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	if s.Builder == nil {
		writeError(w, http.StatusNotImplemented, "builder_unavailable",
			errors.New("this server was started without the SCG builder"))
		return
	}
	id := r.PathValue("id")
	var req buildGraphRequest
	if !s.decode(w, r, &req) {
		return
	}
	if !req.Force {
		if summary, err := s.Graph.Summary(r.Context(), id); err == nil {
			writeJSON(w, http.StatusOK, map[string]any{"graph": summary, "built": false})
			return
		} else if !errors.Is(err, graph.ErrNoGraph) && !errors.Is(err, storage.ErrNotFound) {
			writeStorageError(w, err)
			return
		}
	}
	snap, err := s.Manager.Load(id)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	g, err := s.Builder.Build(r.Context(), snap)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if err := s.persistGraphArtifact(snap, g); err != nil {
		writeStorageError(w, err)
		return
	}
	if err := s.Store.ReplaceGraph(r.Context(), id, g); err != nil {
		writeStorageError(w, err)
		return
	}
	summary, err := s.Graph.Summary(r.Context(), id)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"graph": summary, "built": true})
}

func (s *Server) handleGraphSummary(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	summary, err := s.Graph.Summary(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

func (s *Server) handleListModules(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	page, err := s.Graph.Modules(r.Context(), r.PathValue("id"), queryOptions(r))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleListSymbols(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	q := graph.SymbolQuery{
		ModuleID:      r.URL.Query().Get("module_id"),
		FileID:        r.URL.Query().Get("file_id"),
		NameContains:  r.URL.Query().Get("name"),
		QualifiedName: r.URL.Query().Get("qualified_name"),
		Kinds:         parseKinds(r.URL.Query().Get("kind")),
		Options:       queryOptions(r),
	}
	page, err := s.Graph.Symbols(r.Context(), r.PathValue("id"), q)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, page)
}

func (s *Server) handleGetSymbol(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	sym, meta, err := s.Graph.Symbol(r.Context(), r.PathValue("id"), r.PathValue("symbolID"), queryOptions(r))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"symbol": sym, "meta": meta})
}

func (s *Server) handleCallers(w http.ResponseWriter, r *http.Request) {
	s.neighborhood(w, r, true)
}

func (s *Server) handleCallees(w http.ResponseWriter, r *http.Request) {
	s.neighborhood(w, r, false)
}

func (s *Server) neighborhood(w http.ResponseWriter, r *http.Request, callers bool) {
	if s.graphUnavailable(w) {
		return
	}
	ctx := r.Context()
	id := r.PathValue("id")
	symbol := r.PathValue("symbolID")
	opt := queryOptions(r)
	var (
		out *graph.Neighborhood
		err error
	)
	if callers {
		out, err = s.Graph.Callers(ctx, id, symbol, opt)
	} else {
		out, err = s.Graph.Callees(ctx, id, symbol, opt)
	}
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleUnresolvedCalls(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	opt := queryOptions(r)
	sites, meta, err := s.Graph.UnresolvedCalls(r.Context(), r.PathValue("id"), r.URL.Query().Get("caller_symbol_id"), opt)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"call_sites": sites, "meta": meta})
}

type callPathsRequest struct {
	Source   string `json:"source"`
	Sink     string `json:"sink"`
	MaxPaths int    `json:"max_paths"`
}

func (s *Server) handleCallPaths(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	var req callPathsRequest
	if !s.decode(w, r, &req) {
		return
	}
	paths, err := s.Graph.CallPaths(r.Context(), r.PathValue("id"), graph.PathRequest{
		Source:   req.Source,
		Sink:     req.Sink,
		MaxPaths: req.MaxPaths,
		Options:  queryOptions(r),
	})
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, paths)
}

type sliceRequest struct {
	SymbolID     string `json:"symbol_id"`
	File         string `json:"file"`
	StartLine    int    `json:"start_line"`
	EndLine      int    `json:"end_line"`
	Include      string `json:"include"`
	MaxLines     int    `json:"max_lines"`
	MaxSections  int    `json:"max_sections"`
	ContextLines int    `json:"context_lines"`
}

func (s *Server) handleSlice(w http.ResponseWriter, r *http.Request) {
	if s.graphUnavailable(w) {
		return
	}
	var req sliceRequest
	if !s.decode(w, r, &req) {
		return
	}
	// Query parameters may override the body, which keeps small slices usable
	// with a plain GET-style URL.
	q := r.URL.Query()
	if v := q.Get("symbol_id"); v != "" {
		req.SymbolID = v
	}
	if v := q.Get("file"); v != "" {
		req.File = v
	}
	if v := q.Get("include"); v != "" {
		req.Include = v
	}
	if v := q.Get("max_lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			req.MaxLines = n
		}
	}
	slice, err := s.Graph.Slice(r.Context(), r.PathValue("id"), graph.SliceRequest{
		SymbolID:     req.SymbolID,
		File:         req.File,
		StartLine:    req.StartLine,
		EndLine:      req.EndLine,
		Include:      req.Include,
		MaxLines:     req.MaxLines,
		MaxSections:  req.MaxSections,
		ContextLines: req.ContextLines,
		Options:      queryOptions(r),
	})
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, slice)
}

// queryOptions reads the budget parameters from the query string. Missing values
// fall back to the service defaults, which are deliberately small.
func queryOptions(r *http.Request) graph.Options {
	q := r.URL.Query()
	opt := graph.Options{}
	opt.MaxDepth = queryInt(q.Get("max_depth"), 0)
	opt.MaxNodes = queryInt(q.Get("max_nodes"), 0)
	opt.MaxEdges = queryInt(q.Get("max_edges"), 0)
	opt.Limit = queryInt(q.Get("limit"), 0)
	opt.Offset = queryInt(q.Get("offset"), 0)
	if v := q.Get("timeout_ms"); v != "" {
		if ms, err := strconv.Atoi(v); err == nil && ms > 0 {
			opt.Timeout = time.Duration(ms) * time.Millisecond
		}
	}
	return opt.WithDefaults()
}

func queryInt(value string, fallback int) int {
	if value == "" {
		return fallback
	}
	n, err := strconv.Atoi(value)
	if err != nil {
		return fallback
	}
	return n
}

func parseKinds(value string) []scg.SymbolKind {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	parts := strings.Split(value, ",")
	out := make([]scg.SymbolKind, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		out = append(out, scg.SymbolKind(p))
	}
	return out
}
