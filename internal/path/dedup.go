package path

import (
	"fmt"
	"sort"
	"strings"
)

// Deduplicate removes exactly identical paths (implementation guide §8.2).
//
// The exact key is the path signature: snapshot + entry + target + canonical edge
// sequence. Paths that differ in any hop survive, even when they share both
// endpoints — that difference is usually the interesting part. Order is
// deterministic: candidates are sorted by (entry, target, signature, path id) and
// the first of each signature wins, so the same document always keeps the same
// representative.
func Deduplicate(paths []Path) ([]Path, int) {
	sorted := append([]Path(nil), paths...)
	sort.SliceStable(sorted, func(i, j int) bool {
		if sorted[i].EntryNodeID != sorted[j].EntryNodeID {
			return sorted[i].EntryNodeID < sorted[j].EntryNodeID
		}
		if sorted[i].TargetNodeID != sorted[j].TargetNodeID {
			return sorted[i].TargetNodeID < sorted[j].TargetNodeID
		}
		if sorted[i].Signature != sorted[j].Signature {
			return sorted[i].Signature < sorted[j].Signature
		}
		return sorted[i].ID < sorted[j].ID
	})
	seen := map[string]bool{}
	out := make([]Path, 0, len(sorted))
	duplicates := 0
	for _, p := range sorted {
		if seen[p.Signature] {
			duplicates++
			continue
		}
		seen[p.Signature] = true
		out = append(out, p)
	}
	return out, duplicates
}

// ClusterPaths groups similar paths and marks a representative (implementation guide
// §8.2). Paths cluster when they share the entry point, the target and the
// sequence of security boundaries they cross: those three define the same
// "question", while the differing intermediate nodes are the branches worth
// keeping apart.
//
// Cluster membership never deletes a path — the caller decides what to do with a
// cluster, and the size of a cluster is itself information (many branches into one
// sink suggests the sink is worth auditing once, thoroughly).
func ClusterPaths(paths []Path) []Path {
	type group struct {
		members []int
	}
	groups := map[string]*group{}
	order := []string{}
	for i, p := range paths {
		id := ClusterID(p.SnapshotID, p.EntryNodeID, p.TargetNodeID, p.Boundaries)
		g, ok := groups[id]
		if !ok {
			g = &group{}
			groups[id] = g
			order = append(order, id)
		}
		g.members = append(g.members, i)
	}
	out := append([]Path(nil), paths...)
	for _, id := range order {
		g := groups[id]
		sort.Slice(g.members, func(a, b int) bool {
			pa, pb := out[g.members[a]], out[g.members[b]]
			if pa.Score.Priority != pb.Score.Priority {
				return pa.Score.Priority > pb.Score.Priority
			}
			return pa.ID < pb.ID
		})
		// The differences of a member are the intermediate nodes it does not share
		// with the representative.
		representative := out[g.members[0]]
		repNodes := map[string]bool{}
		for _, node := range representative.AllNodes() {
			repNodes[node] = true
		}
		for rank, idx := range g.members {
			member := out[idx]
			var differences []string
			for _, node := range member.AllNodes() {
				if !repNodes[node] {
					differences = append(differences, node)
				}
			}
			sort.Strings(differences)
			member.Cluster = Cluster{
				ID:             id,
				Representative: rank == 0,
				Size:           len(g.members),
				Differences:    differences,
			}
			if len(g.members) == 1 {
				member.Cluster.Differences = []string{}
			}
			out[idx] = member
		}
	}
	return out
}

// CoverageSet is the marginal-coverage accounting the scheduler uses to avoid
// dispatching several agents into the same subgraph (implementation guide §8.2).
type CoverageSet struct {
	covered map[string]int
}

// NewCoverageSet builds an empty coverage set.
func NewCoverageSet() *CoverageSet {
	return &CoverageSet{covered: map[string]int{}}
}

// Observe marks the nodes of a path as covered, returning the number of nodes
// that were new. The count matters: scheduling the same subgraph twice buys less
// each time.
func (c *CoverageSet) Observe(p Path) int {
	newNodes := 0
	for _, node := range p.ASGNodes() {
		if c.covered[node] == 0 {
			newNodes++
		}
		c.covered[node]++
	}
	return newNodes
}

// Novelty is the share of a path's attack-surface nodes that is not covered yet.
func (c *CoverageSet) Novelty(p Path) float64 {
	nodes := p.ASGNodes()
	if len(nodes) == 0 {
		return 0
	}
	fresh := 0
	for _, node := range nodes {
		if c.covered[node] == 0 {
			fresh++
		}
	}
	return float64(fresh) / float64(len(nodes))
}

// Overlap is the share of a path's nodes that is already covered.
func (c *CoverageSet) Overlap(p Path) float64 { return 1 - c.Novelty(p) }

// Nodes returns every covered node id, sorted.
func (c *CoverageSet) Nodes() []string {
	out := make([]string, 0, len(c.covered))
	for node := range c.covered {
		out = append(out, node)
	}
	sort.Strings(out)
	return out
}

// Covered reports whether a node has been covered.
func (c *CoverageSet) Covered(nodeID string) bool { return c.covered[nodeID] > 0 }

// Size returns the number of distinct covered nodes.
func (c *CoverageSet) Size() int { return len(c.covered) }

// SortByPriority orders paths the way the queue serves them: priority first, then
// path id, so equal scores have a stable order and a listing is reproducible.
func SortByPriority(paths []Path) {
	sort.SliceStable(paths, func(i, j int) bool {
		if paths[i].Score.Priority != paths[j].Score.Priority {
			return paths[i].Score.Priority > paths[j].Score.Priority
		}
		return paths[i].ID < paths[j].ID
	})
}

// ClusterSummary describes the clusters of a path set for coverage reporting.
func ClusterSummary(paths []Path) (clusters int, largest int, ids []string) {
	sizes := map[string]int{}
	for _, p := range paths {
		if p.Cluster.ID == "" {
			continue
		}
		sizes[p.Cluster.ID]++
	}
	for id, size := range sizes {
		ids = append(ids, id)
		if size > largest {
			largest = size
		}
	}
	sort.Strings(ids)
	return len(sizes), largest, ids
}

// DescribeCoverage renders a one-line summary for listings and the CLI.
func DescribeCoverage(paths []Path) string {
	clusters, largest, _ := ClusterSummary(paths)
	return fmt.Sprintf("%d path(s), %d cluster(s), largest cluster %d", len(paths), clusters, largest)
}

// ObjectiveCounts counts paths per objective, which is how a reviewer sees at a
// glance which classes of weakness the ranking is aiming at.
func ObjectiveCounts(paths []Path) map[string]int {
	out := map[string]int{}
	for _, p := range paths {
		for _, objective := range p.Objectives {
			out[objective]++
		}
	}
	return out
}

// StatusCounts counts paths per lifecycle status.
func StatusCounts(paths []Path) map[string]int {
	out := map[string]int{}
	for _, p := range paths {
		out[string(p.Status)]++
	}
	return out
}

// PathStatusCounts counts paths per evidence class.
func PathStatusCounts(paths []Path) map[string]int {
	out := map[string]int{}
	for _, p := range paths {
		out[string(p.PathStatus)]++
	}
	return out
}

// ObjectivesOf returns the union of the objectives of a path set, sorted.
func ObjectivesOf(paths []Path) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range paths {
		for _, objective := range p.Objectives {
			if seen[objective] {
				continue
			}
			seen[objective] = true
			out = append(out, objective)
		}
	}
	sort.Strings(out)
	return out
}

// TrimReason shortens a reason for display without hiding that it was cut.
func TrimReason(reason string, max int) string {
	if len(reason) <= max {
		return reason
	}
	return strings.TrimSpace(reason[:max]) + "…"
}
