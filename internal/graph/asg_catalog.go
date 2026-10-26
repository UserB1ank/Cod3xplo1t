package graph

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const (
	asgCatalogDefaultLimit = 100
	asgCatalogMaxLimit     = 500
	repoMapLimitBytes      = 2000
	repoMapCallSitePages   = 20
	repoMapCallSiteLimit   = 1000
)

// EntryPointKinds returns the fixed entry-point vocabulary used by the ASG.
func EntryPointKinds() []string {
	return []string{
		asg.EntryHTTPRoute, asg.EntryRPCHandler, asg.EntryGraphQLHandler,
		asg.EntryMessageConsumer, asg.EntryCLICommand,
	}
}

// EntryPointBoundaries returns the trust boundaries an entry point can cross.
func EntryPointBoundaries() []string {
	return []string{
		asg.BoundaryNetwork, asg.BoundaryMessage, asg.BoundaryProcess, asg.BoundaryFilesystem,
	}
}

// SinkCategories returns the fixed sink vocabulary used by the ASG.
func SinkCategories() []string {
	return []string{
		asg.SinkSQL, asg.SinkFileWrite, asg.SinkProcess, asg.SinkNetwork,
		asg.SinkDeserialization, asg.SinkSensitiveOutput, asg.SinkExpressionInjection,
		asg.SinkJNDI, asg.SinkXXE, asg.SinkFileRead, asg.SinkLDAP,
		asg.SinkTemplateInjection,
	}
}

// ASGEntryPointQuery selects a bounded entry-point catalogue page. Kind and
// boundary are orthogonal user-facing filters, though only some pairs coexist
// in the current rule set.
type ASGEntryPointQuery struct {
	Kind      string
	Boundary  string
	File      string
	Generator string
	Limit     int
	Offset    int
}

// ASGSinkQuery selects a bounded sensitive-operation catalogue page.
type ASGSinkQuery struct {
	Category     string
	Partition    ASGSinkPartition
	RuleID       string
	ReceiverType string
	HasFlow      *bool
	File         string
	Generator    string
	Limit        int
	Offset       int
}

type ASGSinkPartition string

const (
	ASGSinkPartitionHighRisk     ASGSinkPartition = "high_risk"
	ASGSinkPartitionUnclassified ASGSinkPartition = "unclassified"
)

type ASGSinkPartitionCounts struct {
	HighRisk     int `json:"high_risk"`
	Unclassified int `json:"unclassified"`
}

// ASGEntryPointListPage is a catalogue page, not the expanded route table. Each
// node retains its subject, location, evidence status and SCG references.
type ASGEntryPointListPage struct {
	EntryPoints []asg.Node `json:"entry_points"`
	Total       int        `json:"total"`
	Meta        ASGMeta    `json:"meta"`
}

// ASGSinkListPage is a bounded catalogue of sensitive operations.
type ASGSinkListPage struct {
	Sinks      []asg.Node             `json:"sinks"`
	Total      int                    `json:"total"`
	Partitions ASGSinkPartitionCounts `json:"partitions"`
	Meta       ASGMeta                `json:"meta"`
}

// ListEntryPoints lists entry points independently of whether a path was found
// for them. A filtered page always reports its complete match count.
func (s *ASGService) ListEntryPoints(ctx context.Context, snapshotID string, q ASGEntryPointQuery) (*ASGEntryPointListPage, error) {
	started := s.now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	if q.Kind != "" && !containsString(EntryPointKinds(), q.Kind) {
		return nil, fmt.Errorf("%w: unknown entry-point kind %q", ErrInvalidArgument, q.Kind)
	}
	if q.Boundary != "" && !containsString(EntryPointBoundaries(), q.Boundary) {
		return nil, fmt.Errorf("%w: unknown entry-point boundary %q", ErrInvalidArgument, q.Boundary)
	}
	prefixes, err := entryPointPrefixes(q.Kind, q.Boundary)
	if err != nil {
		return nil, err
	}
	if len(q.File) > 1024 || len(q.Generator) > 256 {
		return nil, fmt.Errorf("%w: entry-point filter is too long", ErrInvalidArgument)
	}
	limit, offset := asgCatalogWindow(q.Limit, q.Offset)
	nodes, total, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeEntryPoint},
		SubjectPrefixes: prefixes, File: q.File, Generator: q.Generator,
		Limit: limit, Offset: offset,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	out := &ASGEntryPointListPage{
		EntryPoints: nodes, Total: total,
		Meta: s.meta(ctx, snapshotID, "asg_entry_points_catalog", map[string]string{
			"kind": q.Kind, "boundary": q.Boundary, "file": q.File, "generator": q.Generator,
			"limit": fmt.Sprint(limit), "offset": fmt.Sprint(offset),
		}, started),
	}
	if out.EntryPoints == nil {
		out.EntryPoints = []asg.Node{}
	}
	out.Meta.Limit, out.Meta.Offset, out.Meta.Total = limit, offset, total
	if offset+len(out.EntryPoints) < total {
		out.Meta.Truncated = true
		out.Meta.TruncationReason = fmt.Sprintf("page %d of %d entry points", len(out.EntryPoints), total)
	}
	return out, nil
}

// ListSinks lists every matched sensitive operation, including sinks for which
// no data-flow path was found. Category maps to the subject's sink:<kind>.
func (s *ASGService) ListSinks(ctx context.Context, snapshotID string, q ASGSinkQuery) (*ASGSinkListPage, error) {
	started := s.now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	if q.Category != "" && !containsString(SinkCategories(), q.Category) {
		return nil, fmt.Errorf("%w: unknown sink category %q", ErrInvalidArgument, q.Category)
	}
	if q.Partition != "" && q.Partition != ASGSinkPartitionHighRisk && q.Partition != ASGSinkPartitionUnclassified {
		return nil, fmt.Errorf("%w: unknown sink partition %q", ErrInvalidArgument, q.Partition)
	}
	if len(q.File) > 1024 || len(q.Generator) > 256 || len(q.RuleID) > 256 || len(q.ReceiverType) > 512 {
		return nil, fmt.Errorf("%w: sink filter is too long", ErrInvalidArgument)
	}
	limit, offset := asgCatalogWindow(q.Limit, q.Offset)
	query := storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeSensitiveOperation},
		File: q.File, Generator: q.Generator, CatalogID: q.RuleID,
		ReceiverType: q.ReceiverType, HasFlow: q.HasFlow,
		OrderBySinkPriority: true, Limit: limit, Offset: offset,
	}
	if q.Category != "" {
		query.Subject = "sink:" + q.Category
	}
	switch q.Partition {
	case ASGSinkPartitionHighRisk:
		classified := true
		query.Classified = &classified
	case ASGSinkPartitionUnclassified:
		classified := false
		query.Classified = &classified
	}
	nodes, total, err := s.Store.ListASGNodes(ctx, query)
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	highRisk, unclassified := true, false
	_, highRiskTotal, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeSensitiveOperation},
		Classified: &highRisk, Limit: 1,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	_, unclassifiedTotal, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeSensitiveOperation},
		Classified: &unclassified, Limit: 1,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	out := &ASGSinkListPage{
		Sinks: nodes, Total: total,
		Partitions: ASGSinkPartitionCounts{
			HighRisk: highRiskTotal, Unclassified: unclassifiedTotal,
		},
		Meta: s.meta(ctx, snapshotID, "asg_sinks_catalog", map[string]string{
			"category": q.Category, "partition": string(q.Partition),
			"rule_id": q.RuleID, "receiver_type": q.ReceiverType,
			"has_flow": fmt.Sprint(q.HasFlow), "file": q.File, "generator": q.Generator,
			"limit": fmt.Sprint(limit), "offset": fmt.Sprint(offset),
		}, started),
	}
	if out.Sinks == nil {
		out.Sinks = []asg.Node{}
	}
	out.Meta.Limit, out.Meta.Offset, out.Meta.Total = limit, offset, total
	if offset+len(out.Sinks) < total {
		out.Meta.Truncated = true
		out.Meta.TruncationReason = fmt.Sprintf("page %d of %d sinks", len(out.Sinks), total)
	}
	return out, nil
}

func entryPointPrefixes(kind, boundary string) ([]string, error) {
	byBoundary := map[string][]string{
		asg.BoundaryNetwork: {asg.EntryHTTPRoute, asg.EntryRPCHandler, asg.EntryGraphQLHandler},
		asg.BoundaryMessage: {asg.EntryMessageConsumer},
		asg.BoundaryProcess: {asg.EntryCLICommand},
	}
	if kind != "" {
		if boundary != "" && !containsString(byBoundary[boundary], kind) {
			return nil, fmt.Errorf("%w: entry-point kind %q does not cross the %q boundary", ErrInvalidArgument, kind, boundary)
		}
		return []string{kind + ":"}, nil
	}
	if boundary == "" {
		return nil, nil
	}
	kinds := byBoundary[boundary]
	if len(kinds) == 0 {
		return []string{"__no_current_entry_point_for_boundary__:"}, nil
	}
	prefixes := make([]string, 0, len(kinds))
	for _, value := range kinds {
		prefixes = append(prefixes, value+":")
	}
	return prefixes, nil
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func asgCatalogWindow(limit, offset int) (int, int) {
	if limit <= 0 {
		limit = asgCatalogDefaultLimit
	}
	if limit > asgCatalogMaxLimit {
		limit = asgCatalogMaxLimit
	}
	if offset < 0 {
		offset = 0
	}
	return limit, offset
}

// RepoMapModule is the compact module distribution used by repo_map.
type RepoMapModule struct {
	Path    string `json:"path"`
	Symbols int    `json:"symbols"`
	Files   int    `json:"files"`
}

// RepoMapUnresolvedFile is one file with unresolved call sites.
type RepoMapUnresolvedFile struct {
	File       string  `json:"file"`
	Unresolved int     `json:"unresolved"`
	Total      int     `json:"total"`
	Rate       float64 `json:"rate"`
}

// RepoMapCoverage records the exact denominators behind a compact repository
// map. A lost or truncated denominator remains visible.
type RepoMapCoverage struct {
	FilesInSnapshot          int  `json:"files_in_snapshot"`
	FilesParsed              int  `json:"files_parsed"`
	FilesUnparsed            int  `json:"files_unparsed"`
	CallSitesSeen            int  `json:"call_sites_seen"`
	CallSitesTotal           int  `json:"call_sites_total"`
	EntryPointsCatalogued    int  `json:"entry_points_catalogued"`
	EntryPointsTotal         int  `json:"entry_points_total"`
	SinksCatalogued          int  `json:"sinks_catalogued"`
	SinksTotal               int  `json:"sinks_total"`
	EntryPointsTruncated     int  `json:"entry_points_truncated"`
	CallSiteScanTruncated    bool `json:"call_site_scan_truncated"`
	EntryCatalogueTruncated  bool `json:"entry_catalogue_truncated"`
	SinkCatalogueTruncated   bool `json:"sink_catalogue_truncated"`
	DistributionsCompactOnly bool `json:"distributions_compact_only"`
}

// RepoMap is a bounded orientation map. It is deliberately not a probability
// or severity score: distributions describe where to look next.
type RepoMap struct {
	SnapshotID            string                  `json:"snapshot_id"`
	GraphVersion          string                  `json:"graph_version,omitempty"`
	ASGVersion            string                  `json:"asg_version,omitempty"`
	Modules               []RepoMapModule         `json:"modules"`
	EntryPointTotal       int                     `json:"entry_points"`
	EntryPointsByBoundary map[string]int          `json:"entry_points_by_boundary"`
	SinkTotal             int                     `json:"sinks"`
	SinksByCategory       map[string]int          `json:"sinks_by_category"`
	UnresolvedTop         []RepoMapUnresolvedFile `json:"unresolved_top"`
	Coverage              RepoMapCoverage         `json:"coverage"`
	Limitations           []string                `json:"limitations"`
	Meta                  ASGMeta                 `json:"meta"`
}

// RepoMap builds a compact map from one pinned SCG and ASG. The full source and
// graph remain queryable; this answer only bounds what enters model context.
func (s *ASGService) RepoMap(ctx context.Context, snapshotID string) (*RepoMap, error) {
	started := s.now()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := s.requireASG(ctx, snapshotID); err != nil {
		return nil, err
	}
	surface, err := s.Store.ASGSummary(ctx, snapshotID)
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	entryNodes, entryTotal, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeEntryPoint}, Limit: 2000,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	sinkNodes, sinkTotal, err := s.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeSensitiveOperation}, Limit: 2000,
	})
	if err != nil {
		return nil, mapASGError(err, snapshotID)
	}
	out := &RepoMap{
		SnapshotID: snapshotID, ASGVersion: surface.ASGVersion,
		EntryPointTotal: entryTotal, SinkTotal: sinkTotal,
		EntryPointsByBoundary: map[string]int{}, SinksByCategory: map[string]int{},
	}
	for _, node := range entryNodes {
		boundary := node.Detail["boundary"]
		if boundary == "" {
			boundary = "unclassified"
		}
		out.EntryPointsByBoundary[boundary]++
	}
	for _, node := range sinkNodes {
		category := strings.TrimPrefix(node.Subject, "sink:")
		if category == node.Subject || category == "" {
			category = "unclassified"
		}
		out.SinksByCategory[category]++
	}
	out.Coverage.EntryPointsCatalogued = len(entryNodes)
	out.Coverage.EntryPointsTotal = entryTotal
	out.Coverage.SinksCatalogued = len(sinkNodes)
	out.Coverage.SinksTotal = sinkTotal
	out.Coverage.EntryCatalogueTruncated = entryTotal > len(entryNodes)
	out.Coverage.SinkCatalogueTruncated = sinkTotal > len(sinkNodes)
	out.Coverage.EntryPointsTruncated = surface.Coverage.EntryPointsTruncated

	if s.SCG != nil {
		graphSummary, err := s.SCG.Summary(ctx, snapshotID)
		if err != nil {
			return nil, err
		}
		out.GraphVersion = graphSummary.GraphVersion
		out.Coverage.FilesInSnapshot = graphSummary.Coverage.FilesInSnapshot
		out.Coverage.FilesParsed = graphSummary.Coverage.FilesParsed
		out.Coverage.FilesUnparsed = graphSummary.Coverage.FilesUnparsed
		modules, err := s.SCG.Modules(ctx, snapshotID, Options{})
		if err != nil {
			return nil, err
		}
		out.Modules = compactModules(modules.Modules)
		unresolved, scanned, total, truncated, err := s.unresolvedByFile(ctx, snapshotID)
		if err != nil {
			return nil, err
		}
		out.UnresolvedTop = unresolved
		out.Coverage.CallSitesSeen = scanned
		out.Coverage.CallSitesTotal = total
		out.Coverage.CallSiteScanTruncated = truncated
	}
	out.Limitations = compactStrings(surface.Limitations, 3)
	out.Meta = s.meta(ctx, snapshotID, "repo_map", nil, started)
	out.Meta.Limit, out.Meta.Total = 0, surface.Nodes
	fitRepoMap(out)
	return out, nil
}

func compactModules(modules []scg.Module) []RepoMapModule {
	sort.Slice(modules, func(i, j int) bool {
		if modules[i].Symbols != modules[j].Symbols {
			return modules[i].Symbols > modules[j].Symbols
		}
		return modules[i].Path < modules[j].Path
	})
	limit := min(len(modules), 6)
	out := make([]RepoMapModule, 0, limit)
	for _, module := range modules[:limit] {
		out = append(out, RepoMapModule{
			Path: capString(module.Path, 96), Symbols: module.Symbols, Files: module.Files,
		})
	}
	return out
}

func (s *ASGService) unresolvedByFile(ctx context.Context, snapshotID string) ([]RepoMapUnresolvedFile, int, int, bool, error) {
	type counts struct{ total, unresolved int }
	byFile := map[string]*counts{}
	seen, total := 0, 0
	for page := 0; page < repoMapCallSitePages; page++ {
		result, err := s.SCG.CallSites(ctx, snapshotID, CallSiteQuery{
			Options: Options{Limit: repoMapCallSiteLimit, Offset: seen},
		})
		if err != nil {
			return nil, seen, total, false, err
		}
		total = result.Total
		for _, site := range result.CallSites {
			row := byFile[site.File]
			if row == nil {
				row = &counts{}
				byFile[site.File] = row
			}
			row.total++
			switch site.Resolution {
			case scg.Ambiguous, scg.Dynamic, scg.External, scg.Unsupported:
				row.unresolved++
			}
		}
		seen += len(result.CallSites)
		if len(result.CallSites) == 0 || seen >= total {
			break
		}
	}
	rows := make([]RepoMapUnresolvedFile, 0, len(byFile))
	for file, count := range byFile {
		if count.unresolved == 0 {
			continue
		}
		rows = append(rows, RepoMapUnresolvedFile{
			File: capString(file, 120), Unresolved: count.unresolved, Total: count.total,
			Rate: float64(count.unresolved) / float64(count.total),
		})
	}
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Rate != rows[j].Rate {
			return rows[i].Rate > rows[j].Rate
		}
		if rows[i].Unresolved != rows[j].Unresolved {
			return rows[i].Unresolved > rows[j].Unresolved
		}
		return rows[i].File < rows[j].File
	})
	if len(rows) > 5 {
		rows = rows[:5]
	}
	return rows, seen, total, seen < total, nil
}

func fitRepoMap(value *RepoMap) {
	raw, _ := json.Marshal(value)
	if len(raw) <= repoMapLimitBytes {
		return
	}
	value.Coverage.DistributionsCompactOnly = true
	value.UnresolvedTop = nil
	raw, _ = json.Marshal(value)
	if len(raw) > repoMapLimitBytes {
		value.Limitations = nil
		value.Modules = nil
	}
}

func compactStrings(values []string, limit int) []string {
	if len(values) > limit {
		values = values[:limit]
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, capString(value, 200))
	}
	return out
}

func capString(value string, limit int) string {
	runes := []rune(value)
	if len(runes) <= limit {
		return value
	}
	return string(runes[:limit])
}
