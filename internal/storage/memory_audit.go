package storage

import (
	"encoding/json"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

// auditDocument is the in-memory aggregate of one audit: the audit row, its path
// generation, the append-only feature snapshots and the event log. Keeping them
// together is what lets ReplacePaths swap a whole generation under a single lock,
// and what makes DeleteAuditsForSnapshot one delete.
//
// Every document handed to or returned from the store is deep-copied through a
// JSON round trip, so the store never shares a slice, a map or a string with a
// caller and a caller can never mutate stored facts.
type auditDocument struct {
	audit    path.Audit
	paths    map[string]path.Path
	features map[string][]path.FeatureRecord
	events   []path.Event
	// maxSeq is the highest event sequence stored for the audit. Events are
	// numbered per audit, so this is the audit's log position.
	maxSeq int64
}

func newAuditDocument(audit path.Audit) *auditDocument {
	return &auditDocument{
		audit:    audit,
		paths:    map[string]path.Path{},
		features: map[string][]path.FeatureRecord{},
	}
}

// cloneDocument deep-copies an audit document value. json is the copy discipline
// of this package: it is what keeps a stored document from aliasing a caller's.
func cloneDocument[T any](value T) (T, error) {
	var out T
	data, err := json.Marshal(value)
	if err != nil {
		return out, fmt.Errorf("storage: encode audit document: %w", err)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("storage: decode audit document: %w", err)
	}
	return out, nil
}

// findPathDocLocked returns the audit document that holds a path. The caller must
// hold at least the read lock.
func (m *Memory) findPathDocLocked(pathID string) (*auditDocument, path.Path, bool) {
	for _, doc := range m.audits {
		if p, ok := doc.paths[pathID]; ok {
			return doc, p, true
		}
	}
	return nil, path.Path{}, false
}

// appendEventLocked records an event whose sequence was taken from the document
// itself, so it cannot collide. The caller must hold the write lock.
func (d *auditDocument) appendEventLocked(event path.Event) {
	d.events = append(d.events, event)
	if event.Seq > d.maxSeq {
		d.maxSeq = event.Seq
	}
}

// CreateAudit implements path.Store.
func (m *Memory) CreateAudit(audit path.Audit) error {
	if audit.ID == "" {
		return fmt.Errorf("%w: an audit needs an id", path.ErrInvalidArgument)
	}
	stored, err := cloneDocument(audit)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(audit.SnapshotID); err != nil {
		return err
	}
	if _, exists := m.audits[audit.ID]; exists {
		return fmt.Errorf("%w: audit %s already exists", path.ErrConflict, audit.ID)
	}
	m.audits[audit.ID] = newAuditDocument(stored)
	return nil
}

// GetAudit implements path.Store.
func (m *Memory) GetAudit(auditID string) (*path.Audit, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.audits[auditID]
	if !ok {
		return nil, fmt.Errorf("%w: audit %s", path.ErrNotFound, auditID)
	}
	stored, err := cloneDocument(doc.audit)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// ListAudits implements path.Store.
func (m *Memory) ListAudits(q path.AuditQuery) ([]path.Audit, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]path.Audit, 0, len(m.audits))
	for _, doc := range m.audits {
		if q.Archived != nil && doc.audit.Archived != *q.Archived {
			continue
		}
		if q.CategorySet && doc.audit.Category != q.Category {
			continue
		}
		if q.TaskState != "" {
			live := doc.audit
			activity := m.taskActivityLocked(doc.audit.ID)
			live.CountsByStatus = activity.Counts
			state := path.TaskState(live)
			if activity.WorkflowRunID != "" && !live.Archived {
				state = workflowTaskState(activity.WorkflowStatus)
			}
			if state != q.TaskState {
				continue
			}
		}
		if q.Search != "" && !strings.Contains(strings.ToLower(doc.audit.Name+" "+doc.audit.Objective+" "+doc.audit.ID), strings.ToLower(q.Search)) {
			continue
		}
		if q.ProjectID != "" && m.snapshots[doc.audit.SnapshotID].projectID != q.ProjectID {
			continue
		}
		if q.SnapshotID != "" && doc.audit.SnapshotID != q.SnapshotID {
			continue
		}
		if q.Status != "" && doc.audit.Status != q.Status {
			continue
		}
		stored, err := cloneDocument(doc.audit)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, stored)
	}
	sort.Slice(out, func(i, j int) bool {
		if q.Organized {
			if out[i].Pinned != out[j].Pinned {
				return out[i].Pinned
			}
			if out[i].CreatedAt != out[j].CreatedAt {
				return out[i].CreatedAt > out[j].CreatedAt
			}
		}
		return out[i].ID < out[j].ID
	})
	total := len(out)
	return page(out, max(q.Offset, 0), normaliseLimit(q.Limit, 100, 1000)), total, nil
}

// UpdateAudit implements path.Store.
func (m *Memory) UpdateAudit(audit path.Audit, expectedVersion int64) error {
	stored, err := cloneDocument(audit)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(audit.SnapshotID); err != nil {
		return err
	}
	doc, ok := m.audits[audit.ID]
	if !ok {
		return fmt.Errorf("%w: audit %s", path.ErrNotFound, audit.ID)
	}
	if expectedVersion > 0 && doc.audit.Version != expectedVersion {
		return fmt.Errorf("%w: audit %s is at version %d, expected %d",
			path.ErrConflict, audit.ID, doc.audit.Version, expectedVersion)
	}
	if expectedVersion == 0 {
		stored.Pinned, stored.Archived = doc.audit.Pinned, doc.audit.Archived
		stored.Category = doc.audit.Category
	}
	if stored.Category != "" && !slices.Contains(m.categoriesLocked(m.snapshots[audit.SnapshotID].projectID).Categories, stored.Category) {
		return invalidTaskCategory()
	}
	if stored.Archived && !stored.Paused {
		if doc.audit.Archived {
			return path.ErrTaskArchived
		}
		return path.ErrTaskActive
	}
	if stored.Archived && !doc.audit.Archived {
		if m.taskActivityLocked(audit.ID).ActiveRuns {
			return path.ErrTaskActive
		}
		for _, p := range doc.paths {
			if p.Status.Active() {
				return path.ErrTaskActive
			}
		}
	}
	// A caller that did not advance the counter still gets a fresh version: a
	// stored document whose version never moves cannot be updated concurrently.
	if stored.Version <= doc.audit.Version {
		stored.Version = doc.audit.Version + 1
	}
	doc.audit = stored
	return nil
}

// ReplacePaths implements path.Store. Generation is a whole-document operation:
// the previous generation's paths are dropped and the new ones are installed
// under one lock, so a reader never sees half of an audit.
func (m *Memory) ReplacePaths(auditID string, paths []path.Path) error {
	replacement := make(map[string]path.Path, len(paths))
	signatures := make(map[string]bool, len(paths))
	for _, p := range paths {
		if p.AuditID != auditID {
			return fmt.Errorf("%w: path %s belongs to audit %q, not %q", path.ErrInvalidArgument, p.ID, p.AuditID, auditID)
		}
		// Exact dedup inside one audit is a database invariant; the memory store
		// enforces the same rule instead of letting a signature silently win.
		if signatures[p.Signature] {
			return fmt.Errorf("%w: duplicate path signature %s in audit %s", path.ErrConflict, p.Signature, auditID)
		}
		signatures[p.Signature] = true
		if _, duplicate := replacement[p.ID]; duplicate {
			return fmt.Errorf("%w: duplicate path id %s in audit %s", path.ErrConflict, p.ID, auditID)
		}
		stored, err := cloneDocument(p)
		if err != nil {
			return err
		}
		replacement[p.ID] = stored
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, ok := m.audits[auditID]
	if !ok {
		return fmt.Errorf("%w: audit %s", path.ErrNotFound, auditID)
	}
	// A path that leaves the generation takes its feature snapshots with it: score
	// sequences are derived from the stored generation, so a stale row would
	// collide when the path comes back. Snapshots of surviving paths are kept,
	// which is what makes a ranking append-only across a rerun.
	for id := range doc.paths {
		if _, kept := replacement[id]; !kept {
			delete(doc.features, id)
		}
	}
	doc.paths = replacement
	return nil
}

// GetPath implements path.Store.
func (m *Memory) GetPath(pathID string) (*path.Path, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	_, stored, ok := m.findPathDocLocked(pathID)
	if !ok {
		return nil, fmt.Errorf("%w: path %s", path.ErrNotFound, pathID)
	}
	out, err := cloneDocument(stored)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// ListPaths implements path.Store.
func (m *Memory) ListPaths(q path.PathQuery) ([]path.Path, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []path.Path
	for _, doc := range m.audits {
		for _, p := range doc.paths {
			if !matchesPathQuery(p, q) {
				continue
			}
			stored, err := cloneDocument(p)
			if err != nil {
				return nil, 0, err
			}
			out = append(out, stored)
		}
	}
	sortPathDocuments(out, q.Sort)
	total := len(out)
	// Paths are bounded per audit by Limits.MaxPaths, and the engine pages with an
	// explicit limit, so only a default applies and nothing is silently truncated.
	return page(out, max(q.Offset, 0), normaliseLimit(q.Limit, 500, 0)), total, nil
}

// ListDuePaths implements path.Store: the queued paths of one audit whose backoff
// has elapsed, oldest due time first so the queue cannot starve a path.
func (m *Memory) ListDuePaths(auditID, now string, limit int) ([]path.Path, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	for _, raw := range m.workflowRuns {
		var run workflow.Run
		if json.Unmarshal(raw, &run) == nil && run.TaskID == auditID {
			return []path.Path{}, nil
		}
	}
	var out []path.Path
	for _, doc := range m.audits {
		for _, p := range doc.paths {
			if p.AuditID != auditID || p.Status != path.StatusQueued {
				continue
			}
			if !retryDue(p.NextAttemptAt, now) {
				continue
			}
			stored, err := cloneDocument(p)
			if err != nil {
				return nil, err
			}
			out = append(out, stored)
		}
	}
	// Timestamps are RFC3339, so this is a time order; the path id breaks ties so
	// paging and retries are stable. An empty NextAttemptAt is due immediately and
	// therefore sorts first.
	sort.Slice(out, func(i, j int) bool {
		if out[i].NextAttemptAt != out[j].NextAttemptAt {
			return out[i].NextAttemptAt < out[j].NextAttemptAt
		}
		return out[i].ID < out[j].ID
	})
	return page(out, 0, normaliseLimit(limit, 100, 1000)), nil
}

// UpdatePath implements path.Store.
func (m *Memory) UpdatePath(p path.Path, expectedVersion int64) error {
	stored, err := cloneDocument(p)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(p.SnapshotID); err != nil {
		return err
	}
	doc, current, ok := m.findPathDocLocked(p.ID)
	if !ok {
		return fmt.Errorf("%w: path %s", path.ErrNotFound, p.ID)
	}
	if expectedVersion > 0 && current.Version != expectedVersion {
		return fmt.Errorf("%w: path %s is at version %d, expected %d",
			path.ErrConflict, p.ID, current.Version, expectedVersion)
	}
	if stored.Version <= current.Version {
		stored.Version = current.Version + 1
	}
	doc.paths[p.ID] = stored
	return nil
}

// AppendFeatures implements path.Store. The batch is validated before anything is
// written, so a rejected record cannot leave half a score history behind.
func (m *Memory) AppendFeatures(records []path.FeatureRecord) error {
	stored := make([]path.FeatureRecord, 0, len(records))
	for _, record := range records {
		copied, err := cloneDocument(record)
		if err != nil {
			return err
		}
		stored = append(stored, copied)
	}
	m.mu.Lock()
	defer m.mu.Unlock()

	type pending struct {
		doc    *auditDocument
		record path.FeatureRecord
	}
	plan := make([]pending, 0, len(stored))
	seen := map[string]bool{}
	for _, record := range stored {
		doc, _, ok := m.findPathDocLocked(record.PathID)
		if !ok {
			return fmt.Errorf("%w: path %s", path.ErrNotFound, record.PathID)
		}
		key := fmt.Sprintf("%s|%d", record.PathID, record.Seq)
		if seen[key] {
			return fmt.Errorf("%w: feature sequence %d is already in this batch for path %s", path.ErrConflict, record.Seq, record.PathID)
		}
		for _, existing := range doc.features[record.PathID] {
			if existing.Seq == record.Seq {
				return fmt.Errorf("%w: feature sequence %d is already stored for path %s", path.ErrConflict, record.Seq, record.PathID)
			}
		}
		seen[key] = true
		plan = append(plan, pending{doc: doc, record: record})
	}
	for _, item := range plan {
		item.doc.features[item.record.PathID] = append(item.doc.features[item.record.PathID], item.record)
	}
	return nil
}

// ListFeatures implements path.Store. Snapshots come back oldest first; a limit
// selects the most recent ones, which is the history a caller wants to compare.
func (m *Memory) ListFeatures(pathID string, limit int) ([]path.FeatureRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, _, ok := m.findPathDocLocked(pathID)
	if !ok {
		return []path.FeatureRecord{}, nil
	}
	var out []path.FeatureRecord
	for _, record := range doc.features[pathID] {
		copied, err := cloneDocument(record)
		if err != nil {
			return nil, err
		}
		out = append(out, copied)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if n := normaliseLimit(limit, 50, 1000); len(out) > n {
		out = out[len(out)-n:]
	}
	return out, nil
}

// AppendEvents implements path.Store. Sequence numbers are audit-scoped, so the
// batch is checked against the audit's log position: appending after a rerun
// continues the log instead of colliding with it.
func (m *Memory) AppendEvents(events []path.Event) error {
	stored := make([]path.Event, 0, len(events))
	for _, event := range events {
		copied, err := cloneDocument(event)
		if err != nil {
			return err
		}
		if copied.ID == "" {
			copied.ID = path.EventID(copied.AuditID, copied.PathID, copied.Seq)
		}
		stored = append(stored, copied)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	type pending struct {
		doc   *auditDocument
		event path.Event
	}
	plan := make([]pending, 0, len(stored))
	seenSeq := map[string]bool{}
	seenID := map[string]bool{}
	for _, event := range stored {
		doc, ok := m.audits[event.AuditID]
		if !ok {
			return fmt.Errorf("%w: audit %s", path.ErrNotFound, event.AuditID)
		}
		key := fmt.Sprintf("%s|%d", event.AuditID, event.Seq)
		if seenSeq[key] || event.Seq <= doc.maxSeq {
			return fmt.Errorf("%w: event sequence %d is already used in audit %s", path.ErrConflict, event.Seq, event.AuditID)
		}
		if seenID[event.ID] || docHasEventID(doc, event.ID) {
			return fmt.Errorf("%w: event id %s is already stored", path.ErrConflict, event.ID)
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

// docHasEventID reports whether an audit already stores an event with this id.
func docHasEventID(doc *auditDocument, eventID string) bool {
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

// ListEvents implements path.Store.
func (m *Memory) ListEvents(q path.EventQuery) ([]path.Event, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []path.Event
	for _, doc := range m.audits {
		for _, event := range doc.events {
			if q.AuditID != "" && event.AuditID != q.AuditID {
				continue
			}
			if q.PathID != "" && event.PathID != q.PathID {
				continue
			}
			if event.Seq <= q.AfterSeq {
				continue
			}
			copied, err := cloneDocument(event)
			if err != nil {
				return nil, err
			}
			out = append(out, copied)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AuditID != out[j].AuditID {
			return out[i].AuditID < out[j].AuditID
		}
		return out[i].Seq < out[j].Seq
	})
	if n := normaliseLimit(q.Limit, 500, 5000); len(out) > n {
		out = out[:n]
	}
	return out, nil
}

// NextEventSeq implements path.Store.
func (m *Memory) NextEventSeq(auditID string) (int64, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	doc, ok := m.audits[auditID]
	if !ok {
		return 0, fmt.Errorf("%w: audit %s", path.ErrNotFound, auditID)
	}
	return doc.maxSeq + 1, nil
}

// Transition implements path.Store: the status change and its event are applied
// together, under one lock.
func (m *Memory) Transition(req path.TransitionRequest) (*path.Path, error) {
	now := auditNow()
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, current, ok := m.findPathDocLocked(req.PathID)
	if !ok {
		return nil, fmt.Errorf("%w: path %s", path.ErrNotFound, req.PathID)
	}
	if err := m.snapshotWritableLocked(current.SnapshotID); err != nil {
		return nil, err
	}
	updated, event, err := planPathTransition(current, req, now)
	if err != nil {
		return nil, err
	}
	stored, err := cloneDocument(updated)
	if err != nil {
		return nil, err
	}
	event.Seq = doc.maxSeq + 1
	event.ID = path.EventID(event.AuditID, event.PathID, event.Seq)
	doc.paths[req.PathID] = stored
	doc.appendEventLocked(event)
	return &stored, nil
}

// ClaimPath implements path.Store.
func (m *Memory) ClaimPath(pathID, owner, until string, from []path.Status, actor string) (*path.Path, error) {
	now := auditNow()
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, current, ok := m.findPathDocLocked(pathID)
	if !ok {
		return nil, fmt.Errorf("%w: path %s", path.ErrNotFound, pathID)
	}
	if doc.audit.Paused {
		return nil, fmt.Errorf("%w: task is paused", path.ErrNotClaimable)
	}
	if err := m.snapshotWritableLocked(current.SnapshotID); err != nil {
		return nil, err
	}
	updated, event, err := planClaim(current, owner, until, from, actor, now)
	if err != nil {
		return nil, err
	}
	active := 0
	for _, p := range doc.paths {
		if p.Status.Active() {
			active++
		}
	}
	if active >= doc.audit.Limits.Normalize().MaxActiveLeases {
		return nil, fmt.Errorf("%w: audit %s has no free active lease", path.ErrBudgetExceeded, current.AuditID)
	}
	stored, err := cloneDocument(updated)
	if err != nil {
		return nil, err
	}
	event.Seq = doc.maxSeq + 1
	event.ID = path.EventID(event.AuditID, event.PathID, event.Seq)
	doc.paths[pathID] = stored
	doc.appendEventLocked(event)
	return &stored, nil
}

// RenewLease implements path.Store.
func (m *Memory) RenewLease(pathID, owner, until, actor string) (*path.Path, error) {
	now := auditNow()
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, current, ok := m.findPathDocLocked(pathID)
	if !ok {
		return nil, fmt.Errorf("%w: path %s", path.ErrNotFound, pathID)
	}
	updated, event, err := planLeaseRenewal(current, owner, until, actor, now)
	if err != nil {
		return nil, err
	}
	stored, err := cloneDocument(updated)
	if err != nil {
		return nil, err
	}
	event.Seq = doc.maxSeq + 1
	event.ID = path.EventID(event.AuditID, event.PathID, event.Seq)
	doc.paths[pathID] = stored
	doc.appendEventLocked(event)
	return &stored, nil
}

// ReleaseLease implements path.Store.
func (m *Memory) ReleaseLease(pathID, owner, actor, reason string) (*path.Path, error) {
	now := auditNow()
	m.mu.Lock()
	defer m.mu.Unlock()
	doc, current, ok := m.findPathDocLocked(pathID)
	if !ok {
		return nil, fmt.Errorf("%w: path %s", path.ErrNotFound, pathID)
	}
	updated, event, err := planRelease(current, owner, actor, reason, now)
	if err != nil {
		return nil, err
	}
	stored, err := cloneDocument(updated)
	if err != nil {
		return nil, err
	}
	event.Seq = doc.maxSeq + 1
	event.ID = path.EventID(event.AuditID, event.PathID, event.Seq)
	doc.paths[pathID] = stored
	doc.appendEventLocked(event)
	return &stored, nil
}

// ReclaimExpired implements path.Store. Every recovered path and its event are
// prepared before anything is written, so a failed plan cannot recover a subset.
func (m *Memory) ReclaimExpired(now string, limit int, actor string) ([]path.Path, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	type candidate struct {
		doc   *auditDocument
		path  path.Path
		event path.Event
	}
	var candidates []candidate
	for _, doc := range m.audits {
		for _, p := range doc.paths {
			if !leaseExpired(p, now) {
				continue
			}
			candidates = append(candidates, candidate{doc: doc, path: p})
		}
	}
	sort.Slice(candidates, func(i, j int) bool { return candidates[i].path.ID < candidates[j].path.ID })
	if n := normaliseLimit(limit, 100, 1000); len(candidates) > n {
		candidates = candidates[:n]
	}
	for i := range candidates {
		updated, event, err := planReclaim(candidates[i].path, actor, now)
		if err != nil {
			return nil, err
		}
		stored, err := cloneDocument(updated)
		if err != nil {
			return nil, err
		}
		event.Seq = candidates[i].doc.maxSeq + 1
		event.ID = path.EventID(event.AuditID, event.PathID, event.Seq)
		candidates[i].path = stored
		candidates[i].event = event
	}
	out := make([]path.Path, 0, len(candidates))
	for _, c := range candidates {
		c.doc.paths[c.path.ID] = c.path
		c.doc.appendEventLocked(c.event)
		out = append(out, c.path)
	}
	return out, nil
}

// DeleteAuditsForSnapshot implements path.Store.
func (m *Memory) DeleteAuditsForSnapshot(snapshotID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteAuditsForSnapshotLocked(snapshotID), nil
}

// deleteAuditsForSnapshotLocked removes every audit of a snapshot and everything
// derived from it. The caller must hold the write lock; DeleteSnapshot calls it
// so a deleted snapshot cannot keep answering audit queries.
func (m *Memory) deleteAuditsForSnapshotLocked(snapshotID string) int {
	removed := 0
	for id, doc := range m.audits {
		if doc.audit.SnapshotID != snapshotID {
			continue
		}
		delete(m.audits, id)
		removed++
	}
	return removed
}
