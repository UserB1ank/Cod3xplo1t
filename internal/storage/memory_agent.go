package storage

import (
	"fmt"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// agentRunDocument is the in-memory aggregate of one agent run: the run itself,
// its append-only event log and the highest sequence number stored for it.
// Keeping them together is what makes DeleteRunsForSnapshot one delete per run,
// and it mirrors the audit document the path engine keeps.
//
// Every document handed to or returned from the store is deep-copied through a
// JSON round trip (cloneAgent), so the store never shares a slice or a map with a
// caller and a caller can never mutate stored facts.
type agentRunDocument struct {
	run    agent.Run
	events []agent.Event
	// maxSeq is the highest event sequence stored for the run. Events are
	// numbered per run, so this is the run's log position.
	maxSeq int64
}

// appendEventLocked records an event whose sequence was taken from the document
// itself, so it cannot collide. The caller must hold the write lock.
func (d *agentRunDocument) appendEventLocked(event agent.Event) {
	d.events = append(d.events, event)
	if event.Seq > d.maxSeq {
		d.maxSeq = event.Seq
	}
}

// docHasAgentEventID reports whether a run already stores an event with this id.
func docHasAgentEventID(doc *agentRunDocument, eventID string) bool {
	if eventID == "" {
		return false
	}
	for _, event := range doc.events {
		if event.ID == eventID {
			return true
		}
	}
	return false
}

// CreateRun implements agent.Store.
func (m *Memory) CreateRun(run agent.Run) error {
	if run.ID == "" {
		// A caller that forgot the id made a programming error, not a conflict with
		// stored state, and the API maps the two to different answers.
		return fmt.Errorf("%w: a run needs an id", agent.ErrInvalidArgument)
	}
	stored, err := cloneAgent(run)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(run.SnapshotID); err != nil {
		return err
	}
	if doc, ok := m.audits[run.AuditID]; ok && doc.audit.Archived {
		return path.ErrTaskArchived
	}
	if _, exists := m.agentRuns[run.ID]; exists {
		return fmt.Errorf("%w: run %s already exists", agent.ErrConflict, run.ID)
	}
	m.agentRuns[run.ID] = &agentRunDocument{run: stored}
	return nil
}

// GetRun implements agent.Store.
func (m *Memory) GetRun(runID string) (*agent.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.agentRuns[runID]
	if !ok {
		return nil, fmt.Errorf("%w: run %s", agent.ErrNotFound, runID)
	}
	stored, err := cloneAgent(doc.run)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// ListRuns implements agent.Store.
func (m *Memory) ListRuns(q agent.RunQuery) ([]agent.Run, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []agent.Run
	for _, doc := range m.agentRuns {
		if !matchesRunQuery(doc.run, q) {
			continue
		}
		stored, err := cloneAgent(doc.run)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, stored)
	}
	sortAgentRuns(out)
	total := len(out)
	// The runs of a snapshot are bounded by its paths and attempts and the
	// orchestrator pages with an explicit limit, so only a default applies and a
	// caller that asks for everything gets everything.
	return page(out, max(q.Offset, 0), normaliseLimit(q.Limit, 100, 0)), total, nil
}

// UpdateRun implements agent.Store.
func (m *Memory) UpdateRun(run agent.Run, expectedVersion int64) error {
	stored, err := cloneAgent(run)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, ok := m.agentRuns[run.ID]
	if !ok {
		return fmt.Errorf("%w: run %s", agent.ErrNotFound, run.ID)
	}
	if expectedVersion > 0 && doc.run.Version != expectedVersion {
		return fmt.Errorf("%w: run %s is at version %d, expected %d",
			agent.ErrConflict, run.ID, doc.run.Version, expectedVersion)
	}
	// A caller that did not advance the counter still gets a fresh version: a
	// stored run whose version never moves cannot be updated concurrently.
	if stored.Version <= doc.run.Version {
		stored.Version = doc.run.Version + 1
	}
	doc.run = stored
	return nil
}

// AppendRunEvents implements agent.Store. Sequence numbers are per run, so the
// whole batch is checked against the run's log position before anything is
// written: a rejected batch cannot leave half a log behind.
func (m *Memory) AppendRunEvents(events []agent.Event) error {
	now := agentNow()
	stored := make([]agent.Event, 0, len(events))
	for _, event := range events {
		copied, err := cloneAgent(event)
		if err != nil {
			return err
		}
		if copied.ID == "" {
			copied.ID = agent.EventID(copied.RunID, copied.Seq)
		}
		if copied.CreatedAt == "" {
			copied.CreatedAt = now
		}
		stored = append(stored, copied)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	type pending struct {
		doc   *agentRunDocument
		event agent.Event
	}
	plan := make([]pending, 0, len(stored))
	seenSeq := map[string]bool{}
	seenID := map[string]bool{}
	for _, event := range stored {
		doc, ok := m.agentRuns[event.RunID]
		if !ok {
			return fmt.Errorf("%w: run %s", agent.ErrNotFound, event.RunID)
		}
		// (run_id, seq) is unique in the schema; the memory store enforces the
		// same rule, including duplicates inside one batch.
		key := fmt.Sprintf("%s|%d", event.RunID, event.Seq)
		if seenSeq[key] || event.Seq <= doc.maxSeq {
			return fmt.Errorf("%w: event sequence %d is already used in run %s", agent.ErrConflict, event.Seq, event.RunID)
		}
		if seenID[event.ID] || docHasAgentEventID(doc, event.ID) {
			return fmt.Errorf("%w: event id %s is already stored", agent.ErrConflict, event.ID)
		}
		seenSeq[key] = true
		seenID[event.ID] = true
		plan = append(plan, pending{doc: doc, event: event})
	}
	for _, item := range plan {
		item.doc.appendEventLocked(item.event)
	}
	return nil
}

// ListRunEvents implements agent.Store.
func (m *Memory) ListRunEvents(q agent.EventQuery) ([]agent.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []agent.Event
	for _, doc := range m.agentRuns {
		for _, event := range doc.events {
			if !matchesEventQuery(event, q) {
				continue
			}
			copied, err := cloneAgent(event)
			if err != nil {
				return nil, err
			}
			out = append(out, copied)
		}
	}
	sortAgentEvents(out)
	// A run's log is append-only and unbounded (heartbeats alone make it long),
	// so the listing keeps a documented cap on top of the default.
	if n := normaliseLimit(q.Limit, 500, 5000); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// NextRunEventSeq implements agent.Store.
func (m *Memory) NextRunEventSeq(runID string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.agentRuns[runID]
	if !ok {
		return 0, fmt.Errorf("%w: run %s", agent.ErrNotFound, runID)
	}
	return doc.maxSeq + 1, nil
}

// SaveHypotheses implements agent.Store. Claims are upserted by
// (path_id, digest) — the same statement recorded twice is one hypothesis — and
// the event that records the save is written in the same critical section, so a
// claim never exists without its place in the run log.
func (m *Memory) SaveHypotheses(hypotheses []agent.Hypothesis) error {
	now := agentNow()
	m.mu.Lock()
	defer m.mu.Unlock()

	type plan struct {
		value  agent.Hypothesis
		events []agent.Event
	}
	plans := make([]plan, 0, len(hypotheses))
	// stagedByKey and stagedByID simulate the effect of the batch itself, so a
	// claim saved twice in one call behaves like two sequential saves instead of
	// writing twice from the pre-batch state.
	stagedByKey := map[string]agent.Hypothesis{}
	stagedByID := map[string]agent.Hypothesis{}
	nextSeq := map[string]int64{}

	for _, incoming := range hypotheses {
		if err := m.snapshotWritableLocked(incoming.SnapshotID); err != nil {
			return err
		}
		h := prepareHypothesis(incoming, now)
		key := hypothesisKey(h.PathID, h.Digest)

		stored, exists := stagedByKey[key]
		if !exists {
			if doc, ok := m.findHypothesisByKeyLocked(h.PathID, h.Digest); ok {
				stored, exists = doc, true
			}
		}
		row := h
		if exists {
			merged, err := mergeHypothesis(stored.ID, stored.CreatedAt, h, now)
			if err != nil {
				return err
			}
			row = merged
		} else {
			// The hypothesis id is a primary key, so two claims cannot share one.
			if other, ok := stagedByID[h.ID]; ok && hypothesisKey(other.PathID, other.Digest) != key {
				return fmt.Errorf("%w: hypothesis id %s is already used by another claim", agent.ErrConflict, h.ID)
			}
			if other, ok := m.agentHypotheses[h.ID]; ok && hypothesisKey(other.PathID, other.Digest) != key {
				return fmt.Errorf("%w: hypothesis id %s is already used by another claim", agent.ErrConflict, h.ID)
			}
		}
		stagedByKey[key] = row
		stagedByID[row.ID] = row

		item := plan{value: row}
		if row.RunID != "" {
			doc, ok := m.agentRuns[row.RunID]
			if !ok {
				return fmt.Errorf("%w: run %s", agent.ErrNotFound, row.RunID)
			}
			seq := nextSeq[row.RunID]
			if seq == 0 {
				seq = doc.maxSeq + 1
			}
			nextSeq[row.RunID] = seq + 1
			item.events = append(item.events, newHypothesisEvent(row, seq, now))
		}
		plans = append(plans, item)
	}

	for _, item := range plans {
		m.agentHypotheses[item.value.ID] = item.value
		for _, event := range item.events {
			m.agentRuns[event.RunID].appendEventLocked(event)
		}
	}
	return nil
}

// findHypothesisByKeyLocked returns the claim stored for (path_id, digest). The
// caller must hold at least the read lock.
func (m *Memory) findHypothesisByKeyLocked(pathID, digest string) (agent.Hypothesis, bool) {
	for _, h := range m.agentHypotheses {
		if h.PathID == pathID && h.Digest == digest {
			return h, true
		}
	}
	return agent.Hypothesis{}, false
}

// ListHypotheses implements agent.Store.
func (m *Memory) ListHypotheses(q agent.HypothesisQuery) ([]agent.Hypothesis, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []agent.Hypothesis
	for _, h := range m.agentHypotheses {
		if !matchesHypothesisQuery(h, q) {
			continue
		}
		stored, err := cloneAgent(h)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, stored)
	}
	sortAgentHypotheses(out)
	total := len(out)
	// A path produces a bounded number of distinct claims and the verification
	// phase pages explicitly, so only a default applies here.
	return page(out, max(q.Offset, 0), normaliseLimit(q.Limit, 100, 0)), total, nil
}

// GetHypothesis implements agent.Store.
func (m *Memory) GetHypothesis(hypothesisID string) (*agent.Hypothesis, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	h, ok := m.agentHypotheses[hypothesisID]
	if !ok {
		return nil, fmt.Errorf("%w: hypothesis %s", agent.ErrNotFound, hypothesisID)
	}
	stored, err := cloneAgent(h)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// DeleteRunsForSnapshot implements agent.Store.
func (m *Memory) DeleteRunsForSnapshot(snapshotID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteAgentRunsForSnapshotLocked(snapshotID), nil
}

// deleteAgentRunsForSnapshotLocked removes every run of a snapshot with its
// event log and the claims it produced. The caller must hold the write lock;
// DeleteSnapshot calls it so a deleted snapshot cannot keep answering agent
// queries. A claim is removed when it belongs to the snapshot or to one of the
// removed runs, so a mis-tagged claim cannot outlive the run that made it.
func (m *Memory) deleteAgentRunsForSnapshotLocked(snapshotID string) int {
	removedRuns := map[string]bool{}
	removed := 0
	for id, doc := range m.agentRuns {
		if doc.run.SnapshotID != snapshotID {
			continue
		}
		delete(m.agentRuns, id)
		removedRuns[id] = true
		removed++
	}
	for id, h := range m.agentHypotheses {
		if h.SnapshotID == snapshotID || removedRuns[h.RunID] {
			delete(m.agentHypotheses, id)
		}
	}
	return removed
}
