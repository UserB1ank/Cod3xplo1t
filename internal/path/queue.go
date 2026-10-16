package path

import (
	"sort"
)

// Picker chooses what to schedule next.
//
// Two rules from the design meet here. Marginal coverage: a path whose nodes are
// already covered by scheduled work is worth less than its raw priority suggests,
// so several agents do not grind the same subgraph (implementation guide §8.2).
// Exploration reserve: a share of the picks ignores priority and takes the least
// covered candidate, so a score model cannot permanently close off a region
// (implementation guide §8.3 — the reserve is 15%–25% of picks, default 20%).
//
// The picker is deterministic: same queue, same coverage, same pick sequence.
type Picker struct {
	Limits Limits
	// Coverage is what has already been scheduled in this audit.
	Coverage *CoverageSet
	// picks counts the picks already made, which drives the reserve cadence.
	picks int
}

// NewPicker builds a picker for one audit.
func NewPicker(limits Limits, coverage *CoverageSet) *Picker {
	if coverage == nil {
		coverage = NewCoverageSet()
	}
	return &Picker{Limits: limits.Normalize(), Coverage: coverage}
}

// Picks returns how many picks have been made.
func (p *Picker) Picks() int { return p.picks }

// EffectivePriority is the priority a scheduler actually compares: the stored
// priority discounted by how much of the path is already covered. The stored
// priority is never rewritten by this — it stays the reproducible score.
func (p *Picker) EffectivePriority(candidate Path) float64 {
	return candidate.Score.Priority * (0.5 + 0.5*p.Coverage.Novelty(candidate))
}

// Explore reports whether the next pick is reserved for exploration.
func (p *Picker) Explore() bool {
	if p.Limits.ExplorationFraction <= 0 {
		return false
	}
	every := int(1 / p.Limits.ExplorationFraction)
	if every < 2 {
		every = 2
	}
	// The reserve is taken periodically rather than randomly, so a replay of the
	// same queue makes the same choices.
	return p.picks > 0 && p.picks%every == every-1
}

// Next picks the path to schedule. It returns false when there is nothing to pick.
//
// Exploration picks maximise novelty first and effective priority second;
// exploitation picks maximise effective priority. Both break ties by path id.
func (p *Picker) Next(candidates []Path) (Path, bool) {
	if len(candidates) == 0 {
		return Path{}, false
	}
	ordered := append([]Path(nil), candidates...)
	explore := p.Explore()
	sort.SliceStable(ordered, func(i, j int) bool {
		if explore {
			ni, nj := p.Coverage.Novelty(ordered[i]), p.Coverage.Novelty(ordered[j])
			if ni != nj {
				return ni > nj
			}
		}
		ei, ej := p.EffectivePriority(ordered[i]), p.EffectivePriority(ordered[j])
		if ei != ej {
			return ei > ej
		}
		return ordered[i].ID < ordered[j].ID
	})
	pick := ordered[0]
	p.picks++
	return pick, true
}

// Observe records a pick's coverage, so later picks see it as taken.
func (p *Picker) Observe(candidate Path) { p.Coverage.Observe(candidate) }

// ReserveOrder returns the pick order of a whole candidate list without mutating
// the picker, which makes the scheduling decision reviewable before it happens.
func ReserveOrder(limits Limits, coverage *CoverageSet, candidates []Path) []Path {
	picker := NewPicker(limits, coverage)
	remaining := append([]Path(nil), candidates...)
	out := make([]Path, 0, len(remaining))
	for len(remaining) > 0 {
		pick, ok := picker.Next(remaining)
		if !ok {
			break
		}
		out = append(out, pick)
		picker.Observe(pick)
		filtered := remaining[:0]
		for _, candidate := range remaining {
			if candidate.ID != pick.ID {
				filtered = append(filtered, candidate)
			}
		}
		remaining = filtered
	}
	return out
}

// SchedulePlan explains a scheduling decision: which paths would be served, in
// which order, and why the exploration reserve fired where it did.
type SchedulePlan struct {
	Order            []Path   `json:"order"`
	ExplorationPicks []string `json:"exploration_picks"`
	CoveredNodes     int      `json:"covered_nodes"`
	Limits           Limits   `json:"limits"`
}

// Plan computes the pick order for a queue snapshot.
func Plan(limits Limits, coverage *CoverageSet, candidates []Path) SchedulePlan {
	normalized := limits.Normalize()
	plan := SchedulePlan{Limits: normalized}
	work := NewPicker(normalized, coverage)
	remaining := append([]Path(nil), candidates...)
	for len(remaining) > 0 {
		explore := work.Explore()
		pick, ok := work.Next(remaining)
		if !ok {
			break
		}
		if explore {
			plan.ExplorationPicks = append(plan.ExplorationPicks, pick.ID)
		}
		plan.Order = append(plan.Order, pick)
		work.Observe(pick)
		filtered := remaining[:0]
		for _, candidate := range remaining {
			if candidate.ID != pick.ID {
				filtered = append(filtered, candidate)
			}
		}
		remaining = filtered
	}
	plan.CoveredNodes = coverage.Size()
	return plan
}

// Claimable filters paths a worker may lease.
func Claimable(paths []Path) []Path {
	out := make([]Path, 0, len(paths))
	for _, p := range paths {
		if p.Status.Claimable() && !leaseValid(p, "") {
			out = append(out, p)
		}
	}
	return out
}

// leaseValid reports whether a path currently holds a live lease (any owner, or a
// specific one when owner is not empty).
func leaseValid(p Path, owner string) bool {
	if p.LeaseOwner == "" || p.LeaseUntil == "" {
		return false
	}
	if owner != "" && p.LeaseOwner != owner {
		return false
	}
	return true
}

// ActiveLeases counts the paths currently held by a worker.
func ActiveLeases(paths []Path) int {
	count := 0
	for _, p := range paths {
		if p.Status.Active() {
			count++
		}
	}
	return count
}
