// Package graph implements the P2 Graph Service: bounded, provenance-carrying
// queries over a stored Source Code Graph.
//
// Two properties matter more than speed here (design doc §8):
//
//   - every query is scoped to one snapshot id and returns the graph version,
//     the engine, the arguments and the budget that produced the answer;
//   - a query that runs out of budget returns partial results with an explicit
//     truncation reason instead of silently looking complete.
package graph

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// Errors returned by the service.
var (
	// ErrInvalidArgument reports a malformed request.
	ErrInvalidArgument = errors.New("graph: invalid argument")
	// ErrTreeUnavailable means the frozen tree of the snapshot is not on this
	// machine, so code slices cannot be produced from it.
	ErrTreeUnavailable = errors.New("graph: snapshot tree is not available")
	// ErrNoGraph means the snapshot has not been indexed yet.
	ErrNoGraph = errors.New("graph: snapshot has no graph")
)

// Default budgets. They are deliberately small: an audit agent that needs more
// must ask for more, which is what the expansion protocol in the design doc is
// about.
const (
	defaultMaxDepth = 1
	defaultMaxNodes = 200
	defaultMaxEdges = 1000
	defaultLimit    = 100
	maxLimit        = 1000
	defaultTimeout  = 5 * time.Second
	maxTimeout      = 60 * time.Second
	maxDepthCap     = 10
)

// Options bound one query.
type Options struct {
	// MaxDepth is the traversal depth. Depth 1 means direct neighbours.
	MaxDepth int `json:"max_depth"`
	// MaxNodes and MaxEdges cap the work a traversal may do.
	MaxNodes int `json:"max_nodes"`
	MaxEdges int `json:"max_edges"`
	// Limit and Offset page list results.
	Limit  int `json:"limit"`
	Offset int `json:"offset"`
	// Timeout bounds the whole query, including store round trips.
	Timeout time.Duration `json:"timeout"`
}

// WithDefaults fills zero fields and clamps values into their allowed range.
func (o Options) WithDefaults() Options {
	if o.MaxDepth <= 0 {
		o.MaxDepth = defaultMaxDepth
	}
	if o.MaxDepth > maxDepthCap {
		o.MaxDepth = maxDepthCap
	}
	if o.MaxNodes <= 0 {
		o.MaxNodes = defaultMaxNodes
	}
	if o.MaxEdges <= 0 {
		o.MaxEdges = defaultMaxEdges
	}
	if o.Limit <= 0 {
		o.Limit = defaultLimit
	}
	if o.Limit > maxLimit {
		o.Limit = maxLimit
	}
	if o.Offset < 0 {
		o.Offset = 0
	}
	if o.Timeout <= 0 {
		o.Timeout = defaultTimeout
	}
	if o.Timeout > maxTimeout {
		o.Timeout = maxTimeout
	}
	return o
}

// Meta is the provenance block every result carries.
type Meta struct {
	SnapshotID   string            `json:"snapshot_id"`
	GraphVersion string            `json:"graph_version,omitempty"`
	Engine       string            `json:"engine,omitempty"`
	Query        string            `json:"query"`
	Args         map[string]string `json:"args,omitempty"`
	Budget       Options           `json:"budget"`
	ElapsedMS    int64             `json:"elapsed_ms"`
	CacheHit     bool              `json:"cache_hit"`
	NodesVisited int               `json:"nodes_visited,omitempty"`
	EdgesVisited int               `json:"edges_visited,omitempty"`
	DepthReached int               `json:"depth_reached,omitempty"`
	// MoreBeyondDepth reports that neighbours exist beyond the requested depth.
	// That is not truncation: the caller asked for exactly this depth. It is
	// reported separately so "complete to depth N" and "cut short by a budget"
	// never look the same.
	MoreBeyondDepth bool `json:"more_beyond_depth,omitempty"`
	// Truncated reports that a budget cut the answer short. TruncationReason
	// says which budget.
	Truncated        bool   `json:"truncated"`
	TruncationReason string `json:"truncation_reason,omitempty"`
}

// SnapshotResolver loads a snapshot record, which is how code slices reach the
// frozen tree. repository.Manager satisfies it.
type SnapshotResolver interface {
	Load(id string) (*repository.Snapshot, error)
}

// Service answers graph queries.
type Service struct {
	Store     storage.GraphStore
	Snapshots SnapshotResolver
	Cache     *Cache
	Now       func() time.Time
}

// NewService builds a service with a default cache.
func NewService(store storage.GraphStore, snapshots SnapshotResolver) *Service {
	return &Service{
		Store:     store,
		Snapshots: snapshots,
		Cache:     NewCache(512, 5*time.Minute),
		Now:       func() time.Time { return time.Now().UTC() },
	}
}

func (s *Service) now() time.Time {
	if s.Now == nil {
		return time.Now().UTC()
	}
	return s.Now()
}

// Summary returns the stored graph summary of a snapshot.
func (s *Service) Summary(ctx context.Context, snapshotID string) (*scg.Summary, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out, err := s.Store.GraphSummary(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return nil, fmt.Errorf("%w: %s", ErrNoGraph, snapshotID)
		}
		return nil, err
	}
	return out, nil
}

// ModulePage is a list of modules.
type ModulePage struct {
	Modules []scg.Module `json:"modules"`
	Meta    Meta         `json:"meta"`
}

// Modules lists the modules of a snapshot.
func (s *Service) Modules(ctx context.Context, snapshotID string, opt Options) (*ModulePage, error) {
	opt = opt.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	mods, err := s.Store.ListModules(ctx, snapshotID)
	if err != nil {
		return nil, mapStoreError(err, snapshotID)
	}
	out := &ModulePage{Modules: mods, Meta: s.meta(ctx, snapshotID, "modules", nil, opt, started)}
	if out.Modules == nil {
		out.Modules = []scg.Module{}
	}
	return out, nil
}

// SymbolPage is a page of symbols.
type SymbolPage struct {
	Symbols []scg.Symbol `json:"symbols"`
	Total   int          `json:"total"`
	Meta    Meta         `json:"meta"`
}

// SymbolQuery describes a symbol search.
type SymbolQuery struct {
	ModuleID string
	FileID   string
	Kinds    []scg.SymbolKind
	// NameContains is a substring match; QualifiedName is an exact match. Both
	// are provided because qualified names contain slashes and cannot be a path
	// segment.
	NameContains  string
	QualifiedName string
	Options       Options
}

// Symbols lists symbols, optionally filtered by module, file, kind or name.
func (s *Service) Symbols(ctx context.Context, snapshotID string, q SymbolQuery) (*SymbolPage, error) {
	opt := q.Options.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()

	// The cache key carries every filter, so two different searches never share
	// an entry.
	args := map[string]string{
		"module_id":      q.ModuleID,
		"file_id":        q.FileID,
		"kinds":          joinKinds(q.Kinds),
		"name_contains":  q.NameContains,
		"qualified_name": q.QualifiedName,
		"limit":          fmt.Sprint(opt.Limit),
		"offset":         fmt.Sprint(opt.Offset),
	}
	key, version, err := s.cacheKey(ctx, snapshotID, "symbols", args)
	if err != nil {
		return nil, err
	}
	var out SymbolPage
	if s.cacheLoad(key, &out) {
		out.Meta.CacheHit = true
		out.Meta.GraphVersion = version
		out.Meta.ElapsedMS = s.now().Sub(started).Milliseconds()
		return &out, nil
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	syms, total, err := s.Store.ListSymbols(ctx, storage.SymbolQuery{
		SnapshotID:    snapshotID,
		ModuleID:      q.ModuleID,
		FileID:        q.FileID,
		Kinds:         q.Kinds,
		NameContains:  q.NameContains,
		QualifiedName: q.QualifiedName,
		Limit:         opt.Limit,
		Offset:        opt.Offset,
	})
	if err != nil {
		return nil, mapStoreError(err, snapshotID)
	}
	out = SymbolPage{Symbols: syms, Total: total, Meta: s.meta(ctx, snapshotID, "symbols", args, opt, started)}
	if out.Symbols == nil {
		out.Symbols = []scg.Symbol{}
	}
	out.Meta.GraphVersion = version
	out.Meta.Truncated = opt.Offset+len(out.Symbols) < total
	if out.Meta.Truncated {
		out.Meta.TruncationReason = fmt.Sprintf("page %d of %d symbols", len(out.Symbols), total)
	}
	s.cacheStore(key, out)
	return &out, nil
}

// Symbol returns one symbol by id or qualified name.
func (s *Service) Symbol(ctx context.Context, snapshotID, symbolID string, opt Options) (*scg.Symbol, Meta, error) {
	opt = opt.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if strings.TrimSpace(symbolID) == "" {
		return nil, Meta{}, fmt.Errorf("%w: symbol id is required", ErrInvalidArgument)
	}
	if err := ctx.Err(); err != nil {
		return nil, Meta{}, err
	}
	sym, err := s.Store.GetSymbol(ctx, snapshotID, symbolID)
	if err != nil {
		return nil, Meta{}, mapStoreError(err, snapshotID)
	}
	meta := s.meta(ctx, snapshotID, "symbol", map[string]string{"symbol_id": symbolID}, opt, started)
	return &sym, meta, nil
}

// Module returns one module by id or path.
func (s *Service) Module(ctx context.Context, snapshotID, moduleID string, opt Options) (*scg.Module, Meta, error) {
	opt = opt.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, Meta{}, err
	}
	mod, err := s.Store.GetModule(ctx, snapshotID, moduleID)
	if err != nil {
		return nil, Meta{}, mapStoreError(err, snapshotID)
	}
	meta := s.meta(ctx, snapshotID, "module", map[string]string{"module_id": moduleID}, opt, started)
	return &mod, meta, nil
}

// Files lists the files of a snapshot, optionally of one module.
func (s *Service) Files(ctx context.Context, snapshotID, moduleID string, opt Options) ([]scg.File, Meta, error) {
	opt = opt.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, Meta{}, err
	}
	files, err := s.Store.ListFiles(ctx, snapshotID, moduleID)
	if err != nil {
		return nil, Meta{}, mapStoreError(err, snapshotID)
	}
	if files == nil {
		files = []scg.File{}
	}
	meta := s.meta(ctx, snapshotID, "files", map[string]string{"module_id": moduleID}, opt, started)
	return files, meta, nil
}

// UnresolvedCalls lists call sites the graph could not resolve, which is how a
// consumer learns where the graph is blind rather than assuming it is complete.
func (s *Service) UnresolvedCalls(ctx context.Context, snapshotID, callerSymbolID string, opt Options) ([]scg.CallSite, Meta, error) {
	opt = opt.WithDefaults()
	started := s.now()
	ctx, cancel := context.WithTimeout(ctx, opt.Timeout)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return nil, Meta{}, err
	}
	sites, _, err := s.Store.ListCallSites(ctx, storage.CallSiteQuery{
		SnapshotID:     snapshotID,
		CallerSymbolID: callerSymbolID,
		Resolution: []scg.Resolution{
			scg.Ambiguous, scg.Dynamic, scg.External, scg.Unsupported,
		},
		Limit:  opt.Limit,
		Offset: opt.Offset,
	})
	if err != nil {
		return nil, Meta{}, mapStoreError(err, snapshotID)
	}
	if sites == nil {
		sites = []scg.CallSite{}
	}
	meta := s.meta(ctx, snapshotID, "unresolved_calls", map[string]string{"caller_symbol_id": callerSymbolID}, opt, started)
	return sites, meta, nil
}

// --- helpers ----------------------------------------------------------------

// meta builds the provenance block, including the graph version when available.
func (s *Service) meta(ctx context.Context, snapshotID, query string, args map[string]string, opt Options, started time.Time) Meta {
	m := Meta{
		SnapshotID: snapshotID,
		Query:      query,
		Args:       args,
		Budget:     opt,
		ElapsedMS:  s.now().Sub(started).Milliseconds(),
	}
	if summary, err := s.Store.GraphSummary(ctx, snapshotID); err == nil {
		m.GraphVersion = summary.GraphVersion
		m.Engine = summary.Engine.Name + "@" + summary.Engine.Version
	}
	return m
}

// mapStoreError translates store errors into service errors.
func mapStoreError(err error, snapshotID string) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, storage.ErrNotFound) {
		return err
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("graph: query on snapshot %s exceeded its time budget: %w", snapshotID, err)
	}
	return err
}

func joinKinds(kinds []scg.SymbolKind) string {
	if len(kinds) == 0 {
		return ""
	}
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// --- cache ------------------------------------------------------------------

// Cache is a small content-addressed result cache. The key follows design doc
// §9: snapshot, graph version, query type and canonical arguments.
type Cache struct {
	mu      sync.Mutex
	entries map[string]cacheEntry
	max     int
	ttl     time.Duration
	hits    int64
	misses  int64
	now     func() time.Time
}

type cacheEntry struct {
	payload []byte
	expires time.Time
}

// NewCache builds a cache with a maximum entry count and a TTL.
func NewCache(max int, ttl time.Duration) *Cache {
	if max <= 0 {
		max = 256
	}
	if ttl <= 0 {
		ttl = 5 * time.Minute
	}
	return &Cache{
		entries: map[string]cacheEntry{},
		max:     max,
		ttl:     ttl,
		now:     func() time.Time { return time.Now().UTC() },
	}
}

// Stats reports cache hits and misses.
func (c *Cache) Stats() (hits, misses int64) {
	if c == nil {
		return 0, 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.hits, c.misses
}

func (c *Cache) get(key string) ([]byte, bool) {
	if c == nil {
		return nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	entry, ok := c.entries[key]
	if !ok {
		c.misses++
		return nil, false
	}
	if c.now().After(entry.expires) {
		delete(c.entries, key)
		c.misses++
		return nil, false
	}
	c.hits++
	return entry.payload, true
}

func (c *Cache) put(key string, payload []byte) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if len(c.entries) >= c.max {
		now := c.now()
		for k, e := range c.entries {
			if now.After(e.expires) {
				delete(c.entries, k)
			}
		}
		for len(c.entries) >= c.max {
			for k := range c.entries {
				delete(c.entries, k)
				break
			}
		}
	}
	c.entries[key] = cacheEntry{payload: append([]byte(nil), payload...), expires: c.now().Add(c.ttl)}
}

// cacheKey derives the cache key of a query. It returns the graph version so a
// rebuilt graph never serves stale results.
func (s *Service) cacheKey(ctx context.Context, snapshotID, query string, args map[string]string) (string, string, error) {
	if s.Cache == nil {
		return "", "", nil
	}
	summary, err := s.Store.GraphSummary(ctx, snapshotID)
	if err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return "", "", fmt.Errorf("%w: %s", ErrNoGraph, snapshotID)
		}
		return "", "", mapStoreError(err, snapshotID)
	}
	keys := make([]string, 0, len(args))
	for k := range args {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	h := sha256.New()
	fmt.Fprintf(h, "codexploit/graph-cache/v1\n")
	for _, field := range append([]string{snapshotID, summary.GraphVersion, query}, keys...) {
		fmt.Fprintf(h, "%d:%s\n", len(field), field)
	}
	for _, k := range keys {
		fmt.Fprintf(h, "%d:%s\n", len(args[k]), args[k])
	}
	return hex.EncodeToString(h.Sum(nil)[:16]), summary.GraphVersion, nil
}

func (s *Service) cacheLoad(key string, dst any) bool {
	if s.Cache == nil || key == "" {
		return false
	}
	payload, ok := s.Cache.get(key)
	if !ok {
		return false
	}
	if err := json.Unmarshal(payload, dst); err != nil {
		return false
	}
	return true
}

func (s *Service) cacheStore(key string, src any) {
	if s.Cache == nil || key == "" {
		return
	}
	payload, err := json.Marshal(src)
	if err != nil {
		return
	}
	s.Cache.put(key, payload)
}
