package builtinanalysis

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// enhanceConfig is deliberately small and deterministic. It can only retain,
// order and filter paths that the upstream generator already produced; it
// cannot invent endpoints, evidence, dataflow or a verdict.
type enhanceConfig struct {
	MaxPaths        int     `json:"max_paths"`
	MinPriority     float64 `json:"min_priority"`
	KeepExploration *bool   `json:"keep_exploration"`
	MaxPerEntry     int     `json:"max_per_entry"`
}

func (c enhanceConfig) normalized() (enhanceConfig, error) {
	if c.MaxPaths == 0 {
		c.MaxPaths = 200
	}
	if c.MaxPaths < 1 || c.MaxPaths > 500 {
		return c, plugin.ErrInvalid
	}
	if c.MinPriority < 0 || c.MinPriority > 100 {
		return c, plugin.ErrInvalid
	}
	if c.MaxPerEntry < 0 || c.MaxPerEntry > 50 {
		return c, plugin.ErrInvalid
	}
	if c.KeepExploration == nil {
		keep := true
		c.KeepExploration = &keep
	}
	return c, nil
}

// enhancePaths is the deterministic core. It is separated from the plugin
// wrapper so the selection rules can be tested without starting a host.
func enhancePaths(ctx context.Context, inv plugin.Invocation, discovery plugin.DiscoveryDocument, report plugin.NativeReport) (plugin.NativeReport, error) {
	if discovery.APIVersion != "codexploit/v1" || discovery.Kind != "discovery.paths" || discovery.Scope != inv.Request.Scope ||
		report.Scope != inv.Request.Scope || report.Format != "codexploit/paths-native/v1" || report.Paths == nil ||
		report.Graph == nil || report.Surface == nil {
		return plugin.NativeReport{}, plugin.ErrInvalid
	}
	if report.Paths.SnapshotID != report.Scope.SnapshotID || report.Paths.SCGVersion != report.Graph.GraphVersion || report.Paths.ASGVersion != report.Surface.ASGVersion {
		return plugin.NativeReport{}, plugin.ErrInvalid
	}
	if len(inv.Request.Inputs) != 2 || inv.Request.Inputs[0].Producer.InvocationID != inv.Request.Inputs[1].Producer.InvocationID {
		return plugin.NativeReport{}, plugin.ErrInvalid
	}
	// The caller may reuse the report (for example a retry test). Never mutate
	// the shared GenerateResult through its pointer.
	copied := *report.Paths
	copied.Paths = append([]path.Path(nil), report.Paths.Paths...)
	report.Paths = &copied
	normalized := map[string]plugin.DiscoveryPath{}
	for _, p := range discovery.Paths {
		if p.ID == "" {
			return plugin.NativeReport{}, plugin.ErrInvalid
		}
		if _, exists := normalized[p.ID]; exists {
			return plugin.NativeReport{}, plugin.ErrInvalid
		}
		normalized[p.ID] = p
	}
	native := map[string]bool{}
	for _, p := range report.Paths.Paths {
		if p.ID == "" || p.SnapshotID != report.Scope.SnapshotID || native[p.ID] {
			return plugin.NativeReport{}, plugin.ErrInvalid
		}
		if _, ok := normalized[p.ID]; !ok {
			return plugin.NativeReport{}, plugin.ErrInvalid
		}
		native[p.ID] = true
	}
	if len(native) != len(normalized) {
		return plugin.NativeReport{}, plugin.ErrInvalid
	}
	var config enhanceConfig
	if len(inv.Request.Config) > 0 {
		if json.Unmarshal(inv.Request.Config, &config) != nil {
			return plugin.NativeReport{}, plugin.ErrInvalid
		}
	}
	config, err := config.normalized()
	if err != nil {
		return plugin.NativeReport{}, err
	}
	// Score in a stable input-ID order so coverage/novelty features do not
	// depend on map iteration or on which node the scheduler happened to run
	// first. The enhancement stage is the authoritative scoring pass for its
	// selected output; later application stages must not overwrite the reasons.
	ordered := append([]path.Path(nil), report.Paths.Paths...)
	sort.SliceStable(ordered, func(i, j int) bool { return ordered[i].ID < ordered[j].ID })
	covered := path.NewCoverageSet()
	paths := make([]path.Path, 0, len(ordered))
	for _, candidate := range ordered {
		candidate = path.ScorePath(candidate, path.ScoreInput{Covered: covered, ClusterSize: candidate.Cluster.Size, Now: inv.CreatedAt})
		covered.Observe(candidate)
		paths = append(paths, candidate)
	}
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Score.Priority != paths[j].Score.Priority {
			return paths[i].Score.Priority > paths[j].Score.Priority
		}
		return paths[i].ID < paths[j].ID
	})
	weightsDigest := selectionWeightsDigest(paths)
	summary := path.EnhancementSummary{
		SchemaVersion:    "codexploit/path-enhancement-summary/v1",
		ProducerID:       inv.Request.PluginID,
		ProducerVersion:  inv.Request.PluginVersion,
		InvocationID:     inv.ID,
		ConfigDigest:     inv.ConfigDigest,
		InputArtifactIDs: []string{inv.Request.Inputs[0].ID, inv.Request.Inputs[1].ID},
		WeightsDigest:    weightsDigest,
		Selected:         []path.EnhancementPath{},
		Filtered:         []path.EnhancementPath{},
		Limitations:      []string{"Path enhancement retains and ranks existing candidates; filtering is not proof that a path is safe.", "Selection priority is a scheduling heuristic, not a vulnerability severity."},
	}
	selected := make([]path.Path, 0, len(paths))
	perEntry := map[string]int{}
	for _, candidate := range paths {
		if err := ctx.Err(); err != nil {
			return plugin.NativeReport{}, err
		}
		selection := path.PathSelection{
			SchemaVersion: "codexploit/path-selection/v1", Selection: "selected",
			ScoreVersion: candidate.Score.ScoreVersion, WeightsDigest: weightsDigest,
			SourcePathID: candidate.ID, SourceArtifactID: inv.Request.Inputs[1].ID,
			ProducerID: inv.Request.PluginID, ProducerVersion: inv.Request.PluginVersion, InvocationID: inv.ID,
		}
		filterCode, reason := "", ""
		switch {
		case candidate.Score.ScoreVersion == 0:
			filterCode, reason = "missing_score", "filtered: the upstream path carries no deterministic score; evidence is incomplete."
		case candidate.Score.Priority < config.MinPriority:
			filterCode = "below_priority_threshold"
			reason = fmt.Sprintf("filtered: priority %.4f is below the configured threshold %.4f; filtering is not proof of safety.", candidate.Score.Priority, config.MinPriority)
		case !*config.KeepExploration && candidate.PathStatus != path.PathStaticallySupported:
			filterCode, reason = "exploration_disabled", "filtered: exploration candidates are disabled by configuration; call reachability is not taint flow."
		case config.MaxPerEntry > 0 && perEntry[candidate.EntryNodeID] >= config.MaxPerEntry:
			filterCode = "entry_budget"
			reason = fmt.Sprintf("filtered: entry %s already retained %d paths (max_per_entry=%d).", candidate.EntryNodeID, perEntry[candidate.EntryNodeID], config.MaxPerEntry)
		case len(selected) >= config.MaxPaths:
			filterCode = "path_budget"
			reason = fmt.Sprintf("filtered: the max_paths budget of %d was reached; the omitted path is not proven safe.", config.MaxPaths)
		}
		if filterCode != "" {
			selection.Selection, selection.Reason, selection.FilterCode = "filtered", reason, filterCode
			summary.Filtered = append(summary.Filtered, enhancementPath(candidate, selection, reason))
			continue
		}
		selection.Reason = fmt.Sprintf("retained: priority %.4f meets the configured threshold; this is a scheduling decision, not a severity or vulnerability verdict.", candidate.Score.Priority)
		candidate.Selection = &selection
		selected = append(selected, candidate)
		summary.Selected = append(summary.Selected, enhancementPath(candidate, selection, selection.Reason))
		perEntry[candidate.EntryNodeID]++
	}
	report.Paths.Paths = selected
	if len(report.Paths.Paths) == 0 {
		report.Paths.Paths = []path.Path{}
	}
	if len(summary.Selected) > 0 {
		summary.ScoreVersion = summary.Selected[0].ScoreVersion
	} else if len(summary.Filtered) > 0 {
		summary.ScoreVersion = summary.Filtered[0].ScoreVersion
	}
	if len(summary.Filtered) > 0 {
		for _, filtered := range summary.Filtered {
			if filtered.Selection.FilterCode == "path_budget" || filtered.Selection.FilterCode == "entry_budget" {
				if !report.Coverage.Truncated {
					report.Coverage.Truncated = true
					report.Limitations = append(report.Limitations, "Enhancement budget filtered at least one candidate path")
				}
				break
			}
		}
	}
	report.Limitations = append(report.Limitations, summary.Limitations...)
	report.Enhancement = &summary
	return report, nil
}

func enhancementPath(p path.Path, selection path.PathSelection, reason string) path.EnhancementPath {
	return path.EnhancementPath{
		PathID: p.ID, EntrySubject: p.EntrySubject, TargetSubject: p.TargetSubject,
		EntryNodeID: p.EntryNodeID, TargetNodeID: p.TargetNodeID, PathStatus: string(p.PathStatus),
		Priority: p.Score.Priority, Risk: p.Score.Risk, Support: p.Score.Support, Utility: p.Score.Utility,
		ScoreVersion: p.Score.ScoreVersion, Selection: selection, Limitations: append([]string(nil), p.Limitations...),
	}
}

func selectionWeightsDigest(paths []path.Path) string {
	for _, p := range paths {
		if len(p.Score.Weights) == 0 {
			continue
		}
		keys := make([]string, 0, len(p.Score.Weights))
		for key := range p.Score.Weights {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		document := make([][2]any, 0, len(keys))
		for _, key := range keys {
			document = append(document, [2]any{key, p.Score.Weights[key]})
		}
		raw, _ := json.Marshal(document)
		return fmt.Sprintf("%x", sha256.Sum256(raw))
	}
	return fmt.Sprintf("%x", sha256.Sum256([]byte("no-weights")))
}

func enhance(ctx context.Context, inv plugin.Invocation, inputs [][]byte) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var discovery plugin.DiscoveryDocument
	var report plugin.NativeReport
	if json.Unmarshal(inputs[0], &discovery) != nil || json.Unmarshal(inputs[1], &report) != nil {
		return nil, plugin.ErrInvalid
	}
	result, err := enhancePaths(ctx, inv, discovery, report)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
