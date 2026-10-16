package scg

// edgeSet collects edges, drops duplicates and enforces the edge budget.
// Duplicates arise naturally: a module import is written once per file, and
// aggregated edges are rewritten as their count grows.
type edgeSet struct {
	edges   []Edge
	index   map[string]int
	max     int
	dropped int
}

func newEdgeSet(max int) *edgeSet {
	return &edgeSet{index: map[string]int{}, max: max}
}

// add inserts an edge if it is new, computing its id first.
func (s *edgeSet) add(e Edge) {
	if e.ID == "" {
		e.ID = EdgeID(e.From, e.To, e.Kind, e.SourceLocation, e.CallSiteID)
	}
	if _, ok := s.index[e.ID]; ok {
		return
	}
	if s.max > 0 && len(s.edges) >= s.max {
		s.dropped++
		return
	}
	s.index[e.ID] = len(s.edges)
	s.edges = append(s.edges, e)
}

// replace updates an already added edge (same id) in place.
func (s *edgeSet) replace(e Edge) {
	if e.ID == "" {
		e.ID = EdgeID(e.From, e.To, e.Kind, e.SourceLocation, e.CallSiteID)
	}
	i, ok := s.index[e.ID]
	if !ok {
		s.add(e)
		return
	}
	s.edges[i] = e
}

func (s *edgeSet) list() []Edge { return s.edges }
