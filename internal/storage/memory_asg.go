package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
)

// validateASG mirrors validateGraph: a document whose snapshot id disagrees with
// the one it is stored under would mix two snapshots and collide on derived ids,
// so it is rejected before anything is written.
func validateASG(snapshotID string, doc *asg.Document) error {
	if doc == nil || snapshotID == "" {
		return fmt.Errorf("%w: ASG document and snapshot id are required", ErrConflict)
	}
	if doc.SnapshotID != snapshotID {
		return fmt.Errorf("%w: ASG snapshot id %q does not match %q", ErrConflict, doc.SnapshotID, snapshotID)
	}
	return nil
}

// asgSummaryOf derives the cheap summary from a document without letting
// Document.Summarize rewrite the source it was handed: Summarize recomputes the
// histograms in place, and the source here is either a caller's document or one
// that concurrent readers share. The value copy absorbs that rewrite.
func asgSummaryOf(doc *asg.Document) *asg.Summary {
	c := *doc
	out := c.Summarize()
	// Summarize hands back the document's own slice, so a caller that mutates the
	// summary must not be able to reach into stored facts.
	out.Limitations = append([]string{}, doc.Limitations...)
	return out
}

// ReplaceASG implements ASGStore.
func (m *Memory) ReplaceASG(_ context.Context, snapshotID string, doc *asg.Document) error {
	if err := validateASG(snapshotID, doc); err != nil {
		return err
	}
	// Store a deep copy so a caller cannot mutate stored facts afterwards.
	data, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	var copyDoc asg.Document
	if err := json.Unmarshal(data, &copyDoc); err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(snapshotID); err != nil {
		return err
	}
	m.asgDocuments[snapshotID] = &copyDoc
	return nil
}

// DeleteASG implements ASGStore. Deleting an absent ASG is a no-op: the caller
// asked for the derived layer to be gone, and it is.
func (m *Memory) DeleteASG(_ context.Context, snapshotID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.asgDocuments, snapshotID)
	return nil
}

// ASGSummary implements ASGStore.
func (m *Memory) ASGSummary(_ context.Context, snapshotID string) (*asg.Summary, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.asgDocuments[snapshotID]
	if !ok {
		return nil, fmt.Errorf("%w: ASG for snapshot %s", ErrNotFound, snapshotID)
	}
	return asgSummaryOf(doc), nil
}

// ListASGNodes implements ASGStore.
func (m *Memory) ListASGNodes(_ context.Context, q ASGNodeQuery) ([]asg.Node, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.asgDocuments[q.SnapshotID]
	if !ok {
		return nil, 0, fmt.Errorf("%w: ASG for snapshot %s", ErrNotFound, q.SnapshotID)
	}
	kinds := map[asg.NodeKind]bool{}
	for _, k := range q.Kinds {
		kinds[k] = true
	}
	var all []asg.Node
	for _, n := range doc.Nodes {
		if len(kinds) > 0 && !kinds[n.Kind] {
			continue
		}
		if q.Subject != "" && n.Subject != q.Subject {
			continue
		}
		if q.Generator != "" && n.Generator != q.Generator {
			continue
		}
		if q.File != "" && n.File != q.File {
			continue
		}
		all = append(all, n)
	}
	sort.Slice(all, func(i, j int) bool {
		if all[i].Kind != all[j].Kind {
			return all[i].Kind < all[j].Kind
		}
		if all[i].Label != all[j].Label {
			return all[i].Label < all[j].Label
		}
		return all[i].ID < all[j].ID
	})
	total := len(all)
	return page(all, q.Offset, normaliseLimit(q.Limit, 200, 2000)), total, nil
}

// GetASGNode implements ASGStore.
func (m *Memory) GetASGNode(_ context.Context, snapshotID, nodeID string) (asg.Node, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.asgDocuments[snapshotID]
	if !ok {
		return asg.Node{}, fmt.Errorf("%w: ASG for snapshot %s", ErrNotFound, snapshotID)
	}
	for _, n := range doc.Nodes {
		if n.ID == nodeID {
			return n, nil
		}
	}
	return asg.Node{}, fmt.Errorf("%w: ASG node %s", ErrNotFound, nodeID)
}

// ListASGEdges implements ASGStore. The result is bounded rather than paged:
// callers ask for the edges of a small set of endpoints, not for a listing.
func (m *Memory) ListASGEdges(_ context.Context, q ASGEdgeQuery) ([]asg.Edge, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.asgDocuments[q.SnapshotID]
	if !ok {
		return nil, fmt.Errorf("%w: ASG for snapshot %s", ErrNotFound, q.SnapshotID)
	}
	from := map[string]bool{}
	for _, id := range q.From {
		from[id] = true
	}
	to := map[string]bool{}
	for _, id := range q.To {
		to[id] = true
	}
	kinds := map[asg.EdgeKind]bool{}
	for _, k := range q.Kinds {
		kinds[k] = true
	}
	var out []asg.Edge
	for _, e := range doc.Edges {
		if len(from) > 0 && !from[e.From] {
			continue
		}
		if len(to) > 0 && !to[e.To] {
			continue
		}
		if len(kinds) > 0 && !kinds[e.Kind] {
			continue
		}
		out = append(out, e)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return page(out, 0, normaliseLimit(q.Limit, 500, 5000)), nil
}
