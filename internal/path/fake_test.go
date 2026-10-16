package path

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"
)

// fakeStore is an in-memory implementation of the persistence contract.
//
// It exists so the engine can be tested without a database, and it doubles as a
// check that the contract is implementable: every invariant the store
// implementations must hold — atomic transition with its event, lease ownership,
// optimistic concurrency, append-only scores — is enforced here as well.
type fakeStore struct {
	mu       sync.Mutex
	audits   map[string]Audit
	paths    map[string]Path
	features map[string][]FeatureRecord
	events   []Event
	seq      map[string]int64
	failNext error
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		audits:   map[string]Audit{},
		paths:    map[string]Path{},
		features: map[string][]FeatureRecord{},
		seq:      map[string]int64{},
	}
}

func (f *fakeStore) CreateAudit(audit Audit) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, exists := f.audits[audit.ID]; exists {
		return fmt.Errorf("%w: audit %s already exists", ErrConflict, audit.ID)
	}
	f.audits[audit.ID] = audit
	return nil
}

func (f *fakeStore) GetAudit(auditID string) (*Audit, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	audit, ok := f.audits[auditID]
	if !ok {
		return nil, fmt.Errorf("%w: audit %s", ErrNotFound, auditID)
	}
	return &audit, nil
}

func (f *fakeStore) ListAudits(q AuditQuery) ([]Audit, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Audit
	for _, audit := range f.audits {
		if q.SnapshotID != "" && audit.SnapshotID != q.SnapshotID {
			continue
		}
		if q.Status != "" && audit.Status != q.Status {
			continue
		}
		out = append(out, audit)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	total := len(out)
	out = pageAudits(out, q.Limit, q.Offset)
	return out, total, nil
}

func (f *fakeStore) UpdateAudit(audit Audit, expectedVersion int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, ok := f.audits[audit.ID]
	if !ok {
		return fmt.Errorf("%w: audit %s", ErrNotFound, audit.ID)
	}
	if expectedVersion > 0 && current.Version != expectedVersion {
		return fmt.Errorf("%w: audit %s at version %d, expected %d", ErrConflict, audit.ID, current.Version, expectedVersion)
	}
	if audit.Version <= current.Version {
		audit.Version = current.Version + 1
	}
	f.audits[audit.ID] = audit
	return nil
}

func (f *fakeStore) ReplacePaths(auditID string, paths []Path) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.audits[auditID]; !ok {
		return fmt.Errorf("%w: audit %s", ErrNotFound, auditID)
	}
	signatures := map[string]bool{}
	for _, p := range paths {
		if p.AuditID != auditID {
			return fmt.Errorf("%w: path %s belongs to audit %s", ErrInvalidArgument, p.ID, p.AuditID)
		}
		key := auditID + "|" + p.Signature
		if signatures[key] {
			return fmt.Errorf("%w: duplicate path signature %s in audit %s", ErrConflict, p.Signature, auditID)
		}
		signatures[key] = true
	}
	for id, p := range f.paths {
		if p.AuditID == auditID {
			delete(f.paths, id)
			delete(f.features, id)
		}
	}
	for _, p := range paths {
		f.paths[p.ID] = p
	}
	return nil
}

func (f *fakeStore) GetPath(pathID string) (*Path, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.paths[pathID]
	if !ok {
		return nil, fmt.Errorf("%w: path %s", ErrNotFound, pathID)
	}
	return &p, nil
}

func (f *fakeStore) ListPaths(q PathQuery) ([]Path, int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Path
	for _, p := range f.paths {
		if q.AuditID != "" && p.AuditID != q.AuditID {
			continue
		}
		if q.SnapshotID != "" && p.SnapshotID != q.SnapshotID {
			continue
		}
		if len(q.Status) > 0 && !containsStatus(q.Status, p.Status) {
			continue
		}
		if len(q.PathStatus) > 0 && !containsPathStatus(q.PathStatus, p.PathStatus) {
			continue
		}
		if q.EntryNodeID != "" && p.EntryNodeID != q.EntryNodeID {
			continue
		}
		if q.TargetNodeID != "" && p.TargetNodeID != q.TargetNodeID {
			continue
		}
		if q.MinPriority > 0 && p.Score.Priority < q.MinPriority {
			continue
		}
		if q.DueBefore != "" && !pathDue(p, q.DueBefore) {
			continue
		}
		out = append(out, p)
	}
	sortPaths(out, q.Sort)
	total := len(out)
	out = pagePaths(out, q.Limit, q.Offset)
	return out, total, nil
}

// ListDuePaths implements Store on the reference store: the queued paths of one
// audit whose backoff has elapsed, oldest due time first.
func (f *fakeStore) ListDuePaths(auditID, now string, limit int) ([]Path, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Path
	for _, p := range f.paths {
		if p.AuditID != auditID || p.Status != StatusQueued {
			continue
		}
		if !pathDue(p, now) {
			continue
		}
		out = append(out, p)
	}
	// Oldest due time first, path id breaking ties: the queue order a scheduler
	// must follow so a path that keeps losing the race is not starved. An empty
	// NextAttemptAt is due immediately and sorts before every timestamp.
	sort.Slice(out, func(i, j int) bool {
		if out[i].NextAttemptAt != out[j].NextAttemptAt {
			return out[i].NextAttemptAt < out[j].NextAttemptAt
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// pathDue reports whether a path's retry time has elapsed at `now`. Both values
// are RFC3339 strings, so a string comparison is a time comparison; an empty
// NextAttemptAt means the path was never deferred, which counts as due.
func pathDue(p Path, now string) bool {
	return p.NextAttemptAt == "" || p.NextAttemptAt <= now
}

func (f *fakeStore) UpdatePath(p Path, expectedVersion int64) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, ok := f.paths[p.ID]
	if !ok {
		return fmt.Errorf("%w: path %s", ErrNotFound, p.ID)
	}
	if expectedVersion > 0 && current.Version != expectedVersion {
		return fmt.Errorf("%w: path %s at version %d, expected %d", ErrConflict, p.ID, current.Version, expectedVersion)
	}
	if p.Version <= current.Version {
		p.Version = current.Version + 1
	}
	f.paths[p.ID] = p
	return nil
}

func (f *fakeStore) AppendFeatures(records []FeatureRecord) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, record := range records {
		if _, ok := f.paths[record.PathID]; !ok {
			return fmt.Errorf("%w: path %s", ErrNotFound, record.PathID)
		}
		for _, existing := range f.features[record.PathID] {
			if existing.Seq == record.Seq {
				return fmt.Errorf("%w: feature sequence %d already stored for %s", ErrConflict, record.Seq, record.PathID)
			}
		}
		f.features[record.PathID] = append(f.features[record.PathID], record)
	}
	return nil
}

func (f *fakeStore) ListFeatures(pathID string, limit int) ([]FeatureRecord, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := append([]FeatureRecord(nil), f.features[pathID]...)
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	if limit > 0 && len(out) > limit {
		out = out[len(out)-limit:]
	}
	return out, nil
}

func (f *fakeStore) AppendEvents(events []Event) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, event := range events {
		if _, ok := f.audits[event.AuditID]; !ok {
			return fmt.Errorf("%w: audit %s", ErrNotFound, event.AuditID)
		}
		if event.Seq <= f.seq[event.AuditID] && f.seq[event.AuditID] != 0 {
			return fmt.Errorf("%w: event sequence %d already used in audit %s", ErrConflict, event.Seq, event.AuditID)
		}
		f.seq[event.AuditID] = event.Seq
		f.events = append(f.events, event)
	}
	return nil
}

func (f *fakeStore) ListEvents(q EventQuery) ([]Event, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []Event
	for _, event := range f.events {
		if q.AuditID != "" && event.AuditID != q.AuditID {
			continue
		}
		if q.PathID != "" && event.PathID != q.PathID {
			continue
		}
		if event.Seq <= q.AfterSeq {
			continue
		}
		out = append(out, event)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].AuditID != out[j].AuditID {
			return out[i].AuditID < out[j].AuditID
		}
		return out[i].Seq < out[j].Seq
	})
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (f *fakeStore) NextEventSeq(auditID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.audits[auditID]; !ok {
		return 0, fmt.Errorf("%w: audit %s", ErrNotFound, auditID)
	}
	return f.seq[auditID] + 1, nil
}

func (f *fakeStore) Transition(req TransitionRequest) (*Path, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	current, ok := f.paths[req.PathID]
	if !ok {
		return nil, fmt.Errorf("%w: path %s", ErrNotFound, req.PathID)
	}
	if req.ExpectedVersion > 0 && current.Version != req.ExpectedVersion {
		return nil, fmt.Errorf("%w: path %s at version %d, expected %d", ErrConflict, req.PathID, current.Version, req.ExpectedVersion)
	}
	if err := ValidateTransition(current.Status, req.To); err != nil {
		return nil, err
	}
	if current.LeaseOwner != "" && req.Owner != "" && current.LeaseOwner != req.Owner {
		return nil, fmt.Errorf("%w: path %s is leased by %s", ErrLeaseHeld, req.PathID, current.LeaseOwner)
	}
	updated := current
	from := current.Status
	updated.Status = req.To
	switch {
	case req.ClearLease:
		updated.LeaseOwner = ""
		updated.LeaseUntil = ""
		updated.HeartbeatAt = ""
	case req.SetLeaseOwner != "":
		updated.LeaseOwner = req.SetLeaseOwner
		updated.LeaseUntil = req.SetLeaseUntil
		updated.HeartbeatAt = NowString(time.Now().UTC())
	}
	if req.Score != nil {
		updated.Score = *req.Score
	}
	if req.Features != nil {
		updated.Features = *req.Features
	}
	if req.IncrementAttempts {
		updated.Attempts++
	}
	if req.LastError != "" {
		updated.LastError = req.LastError
	}
	// The retry schedule travels with the transition: a non-empty value defers the
	// path, and an empty one clears the deferral (a settlement, a resume, a claim).
	updated.NextAttemptAt = req.NextAttemptAt
	updated.Version = current.Version + 1
	updated.UpdatedAt = NowString(time.Now().UTC())
	f.paths[req.PathID] = updated

	seq := f.seq[current.AuditID] + 1
	f.seq[current.AuditID] = seq
	eventType := req.EventType
	if eventType == "" {
		eventType = EventPathStatusChange
	}
	f.events = append(f.events, Event{
		ID: EventID(current.AuditID, req.PathID, seq), AuditID: current.AuditID, PathID: req.PathID,
		Seq: seq, Type: eventType, From: from, To: req.To, Actor: req.Actor,
		Reason: req.Reason, Detail: req.Detail, CreatedAt: updated.UpdatedAt,
	})
	return &updated, nil
}

func (f *fakeStore) ClaimPath(pathID, owner, until string, from []Status, actor string) (*Path, error) {
	current, err := f.GetPath(pathID)
	if err != nil {
		return nil, err
	}
	if !containsStatus(from, current.Status) {
		return nil, fmt.Errorf("%w: path %s is %s", ErrNotClaimable, pathID, current.Status)
	}
	if current.LeaseOwner != "" && current.LeaseOwner != owner {
		return nil, fmt.Errorf("%w: path %s is leased by %s", ErrLeaseHeld, pathID, current.LeaseOwner)
	}
	return f.Transition(TransitionRequest{
		PathID: pathID, To: StatusAnalyzing, Owner: owner, Actor: actor,
		SetLeaseOwner: owner, SetLeaseUntil: until, EventType: EventPathClaimed,
		Reason: "leased to " + owner, ExpectedVersion: current.Version,
	})
}

func (f *fakeStore) RenewLease(pathID, owner, until, actor string) (*Path, error) {
	current, err := f.GetPath(pathID)
	if err != nil {
		return nil, err
	}
	if current.LeaseOwner == "" {
		return nil, fmt.Errorf("%w: path %s holds no lease", ErrLeaseExpired, pathID)
	}
	if current.LeaseOwner != owner {
		return nil, fmt.Errorf("%w: path %s is leased by %s", ErrLeaseHeld, pathID, current.LeaseOwner)
	}
	if _, err := f.GetAudit(current.AuditID); err != nil {
		return nil, err
	}
	f.mu.Lock()
	updated := f.paths[pathID]
	updated.LeaseUntil = until
	updated.HeartbeatAt = NowString(time.Now().UTC())
	updated.Version++
	f.paths[pathID] = updated
	seq := f.seq[current.AuditID] + 1
	f.seq[current.AuditID] = seq
	f.events = append(f.events, Event{
		ID: EventID(current.AuditID, pathID, seq), AuditID: current.AuditID, PathID: pathID, Seq: seq,
		Type: EventPathHeartbeat, From: current.Status, To: current.Status, Actor: actor,
		Reason: "lease extended", CreatedAt: updated.HeartbeatAt,
	})
	f.mu.Unlock()
	return &updated, nil
}

func (f *fakeStore) ReleaseLease(pathID, owner, actor, reason string) (*Path, error) {
	current, err := f.GetPath(pathID)
	if err != nil {
		return nil, err
	}
	if current.LeaseOwner != "" && current.LeaseOwner != owner {
		return nil, fmt.Errorf("%w: path %s is leased by %s", ErrLeaseHeld, pathID, current.LeaseOwner)
	}
	return f.Transition(TransitionRequest{
		PathID: pathID, To: StatusQueued, Owner: owner, Actor: actor, ClearLease: true,
		EventType: EventPathReleased, Reason: reason, ExpectedVersion: current.Version,
	})
}

func (f *fakeStore) ReclaimExpired(now string, limit int, actor string) ([]Path, error) {
	f.mu.Lock()
	var expired []Path
	for _, p := range f.paths {
		if p.LeaseOwner == "" || p.LeaseUntil == "" {
			continue
		}
		// Timestamps are RFC3339, so a string comparison is a time comparison.
		if p.LeaseUntil < now {
			expired = append(expired, p)
		}
	}
	f.mu.Unlock()
	sort.Slice(expired, func(i, j int) bool { return expired[i].ID < expired[j].ID })
	if limit > 0 && len(expired) > limit {
		expired = expired[:limit]
	}
	out := make([]Path, 0, len(expired))
	for _, p := range expired {
		reclaimed, err := f.Transition(TransitionRequest{
			PathID: p.ID, To: StatusQueued, Actor: actor, ClearLease: true,
			EventType: EventPathLeaseExpired, Reason: "the lease expired and the path returned to the queue",
			ExpectedVersion: p.Version,
		})
		if err != nil {
			return nil, err
		}
		out = append(out, *reclaimed)
	}
	return out, nil
}

func (f *fakeStore) DeleteAuditsForSnapshot(snapshotID string) (int, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	removed := 0
	for id, audit := range f.audits {
		if audit.SnapshotID != snapshotID {
			continue
		}
		removed++
		delete(f.audits, id)
		delete(f.seq, id)
		for pathID, p := range f.paths {
			if p.AuditID == id {
				delete(f.paths, pathID)
				delete(f.features, pathID)
			}
		}
		filtered := f.events[:0]
		for _, event := range f.events {
			if event.AuditID != id {
				filtered = append(filtered, event)
			}
		}
		f.events = filtered
	}
	return removed, nil
}

func pageAudits(in []Audit, limit, offset int) []Audit {
	if offset >= len(in) {
		return nil
	}
	out := in[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func pagePaths(in []Path, limit, offset int) []Path {
	if offset >= len(in) {
		return nil
	}
	out := in[offset:]
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

func sortPaths(paths []Path, order string) {
	sort.SliceStable(paths, func(i, j int) bool {
		switch order {
		case "path_id":
			return paths[i].ID < paths[j].ID
		case "created":
			if paths[i].CreatedAt != paths[j].CreatedAt {
				return paths[i].CreatedAt < paths[j].CreatedAt
			}
			return paths[i].ID < paths[j].ID
		default: // priority
			if paths[i].Score.Priority != paths[j].Score.Priority {
				return paths[i].Score.Priority > paths[j].Score.Priority
			}
			return paths[i].ID < paths[j].ID
		}
	})
}

func containsStatus(list []Status, want Status) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

func containsPathStatus(list []PathStatus, want PathStatus) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// fakeReader supplies attack-surface facts and call chains for tests.
type fakeReader struct {
	facts   *ASGFacts
	chains  map[string][]CallChain
	caller  map[string]SymbolFact
	symbol  map[string]SymbolFact
	err     error
	queries int
}

func (r *fakeReader) ASGFacts(_ context.Context, snapshotID string) (*ASGFacts, error) {
	if r.err != nil {
		return nil, r.err
	}
	facts := *r.facts
	facts.SnapshotID = snapshotID
	return &facts, nil
}

func (r *fakeReader) Chains(_ context.Context, _, from, to string, _, _ int) ([]CallChain, error) {
	r.queries++
	return r.chains[from+"->"+to], nil
}

func (r *fakeReader) CallSiteCaller(_ context.Context, _, callSiteID string) (SymbolFact, bool, error) {
	symbol, ok := r.caller[callSiteID]
	return symbol, ok, nil
}

func (r *fakeReader) Symbol(_ context.Context, _, symbolID string) (SymbolFact, bool, error) {
	symbol, ok := r.symbol[symbolID]
	return symbol, ok, nil
}

func (r *fakeReader) Chain(from, to []string) {
	if r.chains == nil {
		r.chains = map[string][]CallChain{}
	}
	r.chains[from[0]+"->"+to[0]] = nil
}

// fixture builds an attack surface with two entry points, two sinks, two inputs,
// two controls, two assets and one trust boundary.
func fixture() *ASGFacts {
	nodes := map[string]ASGNode{
		"asgn-entry1": {ID: "asgn-entry1", Kind: "EntryPoint", Subject: "http_route:GET /orders/:id", Label: "GET /orders/:id",
			Detail: map[string]string{"entry_kind": "http_route", "handler_symbol_id": "sym-handler", "handler": "svc.getOrder", "boundary": "network", "framework": "gin"}, Evidence: "observed"},
		"asgn-entry2": {ID: "asgn-entry2", Kind: "EntryPoint", Subject: "cli_command:listen", Label: "cli_command listen",
			Detail: map[string]string{"entry_kind": "cli_command", "boundary": "process"}, Evidence: "observed"},
		"asgn-entry3": {ID: "asgn-entry3", Kind: "EntryPoint", Subject: "http_route:POST /orders", Label: "POST /orders",
			Detail: map[string]string{"entry_kind": "http_route", "boundary": "network", "handler": "unresolved"}, Evidence: "observed"},
		"asgn-boundary-net": {ID: "asgn-boundary-net", Kind: "TrustBoundary", Subject: "boundary:network",
			Detail: map[string]string{"boundary_kind": "network"}, Evidence: "observed"},
		"asgn-boundary-proc": {ID: "asgn-boundary-proc", Kind: "TrustBoundary", Subject: "boundary:process",
			Detail: map[string]string{"boundary_kind": "process"}, Evidence: "observed"},
		"asgn-input-param": {ID: "asgn-input-param", Kind: "AttackerControlledInput", Subject: "input:path_param:id",
			Detail: map[string]string{"source_kind": "path_param"}, Evidence: "observed", File: "web/server.go", Line: 36},
		"asgn-input-body": {ID: "asgn-input-body", Kind: "AttackerControlledInput", Subject: "input:body:",
			Detail: map[string]string{"source_kind": "body"}, Evidence: "observed", File: "web/server.go", Line: 40},
		"asgn-control-auth": {ID: "asgn-control-auth", Kind: "SecurityControl", Subject: "control:authentication:Use",
			Detail: map[string]string{"control_kind": "authentication"}, Evidence: "observed", File: "web/server.go", Line: 21},
		"asgn-control-param": {ID: "asgn-control-param", Kind: "SecurityControl", Subject: "control:parameterization:sql_placeholders",
			Detail: map[string]string{"control_kind": "parameterization"}, Evidence: "inferred", File: "web/server.go", Line: 47},
		"asgn-sink-sql": {ID: "asgn-sink-sql", Kind: "SensitiveOperation", Subject: "sink:sql_execution",
			Evidence: "observed", File: "web/server.go", Line: 47, SCGRefs: []string{"cs-sql"}},
		"asgn-sink-proc": {ID: "asgn-sink-proc", Kind: "SensitiveOperation", Subject: "sink:process_execution",
			Evidence: "observed", File: "web/server.go", Line: 52, SCGRefs: []string{"cs-proc"}},
		"asgn-asset-table": {ID: "asgn-asset-table", Kind: "Asset", Subject: "asset:database_table:orders", Evidence: "inferred"},
		"asgn-asset-cmd":   {ID: "asgn-asset-cmd", Kind: "Asset", Subject: "asset:command:sh", Evidence: "inferred"},
	}
	edges := []ASGEdge{
		{ID: "edge-cross-1", From: "asgn-entry1", To: "asgn-boundary-net", Kind: "CROSSES", Evidence: "observed"},
		{ID: "edge-cross-2", From: "asgn-entry2", To: "asgn-boundary-proc", Kind: "CROSSES", Evidence: "observed"},
		{ID: "edge-cross-3", From: "asgn-entry3", To: "asgn-boundary-net", Kind: "CROSSES", Evidence: "observed"},
		{ID: "edge-reach-param", From: "asgn-entry1", To: "asgn-input-param", Kind: "REACHES", Evidence: "inferred"},
		{ID: "edge-reach-body", From: "asgn-entry1", To: "asgn-input-body", Kind: "REACHES", Evidence: "inferred"},
		{ID: "edge-reach-sql", From: "asgn-entry1", To: "asgn-sink-sql", Kind: "REACHES", Evidence: "inferred"},
		{ID: "edge-reach-proc", From: "asgn-entry1", To: "asgn-sink-proc", Kind: "REACHES", Evidence: "inferred"},
		{ID: "edge-reach-sql-3", From: "asgn-entry3", To: "asgn-sink-sql", Kind: "REACHES", Evidence: "inferred"},
		{ID: "edge-protect-auth", From: "asgn-entry1", To: "asgn-control-auth", Kind: "PROTECTED_BY", Evidence: "observed"},
		{ID: "edge-protect-param", From: "asgn-entry1", To: "asgn-control-param", Kind: "PROTECTED_BY", Evidence: "inferred"},
		{ID: "edge-affect-table", From: "asgn-sink-sql", To: "asgn-asset-table", Kind: "MAY_AFFECT", Evidence: "inferred"},
		{ID: "edge-affect-cmd", From: "asgn-sink-proc", To: "asgn-asset-cmd", Kind: "MAY_AFFECT", Evidence: "inferred"},
	}
	return &ASGFacts{
		SnapshotID: "snap-0123456789abcdef0123456789abcdef",
		SCGVersion: "graph-abc", ASGVersion: "asg-abc",
		Nodes: nodes, Edges: edges,
		Limitations: []string{"fixture limitation"},
	}
}

func fixtureReader() *fakeReader {
	return &fakeReader{
		facts: fixture(),
		caller: map[string]SymbolFact{
			"cs-sql":  {ID: "sym-sqlcaller", QualifiedName: "svc.runQuery", File: "web/db.go", Line: 12},
			"cs-proc": {ID: "sym-proccaller", QualifiedName: "svc.runHook", File: "web/hook.go", Line: 8},
		},
		symbol: map[string]SymbolFact{
			"sym-handler":    {ID: "sym-handler", QualifiedName: "svc.getOrder", File: "web/server.go", Line: 30},
			"sym-sqlcaller":  {ID: "sym-sqlcaller", QualifiedName: "svc.runQuery", File: "web/db.go", Line: 12},
			"sym-proccaller": {ID: "sym-proccaller", QualifiedName: "svc.runHook", File: "web/hook.go", Line: 8},
		},
		chains: map[string][]CallChain{
			"sym-handler->sym-sqlcaller": {{
				Symbols: []SymbolFact{
					{ID: "sym-handler", QualifiedName: "svc.getOrder", File: "web/server.go", Line: 30},
					{ID: "sym-sqlcaller", QualifiedName: "svc.runQuery", File: "web/db.go", Line: 12},
				},
				Hops: []CallHop{{From: "sym-handler", To: "sym-sqlcaller", EdgeID: "scg-edge-1", Kind: "CALLS", Resolution: "resolved", File: "web/server.go", Line: 41, ToQualified: "svc.runQuery"}},
			}},
			"sym-handler->sym-proccaller": {{
				Symbols: []SymbolFact{
					{ID: "sym-handler", QualifiedName: "svc.getOrder", File: "web/server.go", Line: 30},
					{ID: "sym-proccaller", QualifiedName: "svc.runHook", File: "web/hook.go", Line: 8},
				},
				Hops: []CallHop{{From: "sym-handler", To: "sym-proccaller", EdgeID: "scg-edge-2", Kind: "CALLS", Resolution: "resolved_best_effort", File: "web/server.go", Line: 44, ToQualified: "svc.runHook"}},
			}},
		},
	}
}

func fixedEngine(reader *fakeReader) *Engine {
	stamp := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
	engine := NewEngine(reader, reader)
	engine.Now = func() time.Time { return stamp }
	return engine
}

func fixedService(store Store, reader *fakeReader) *Service {
	service := NewService(store, fixedEngine(reader))
	stamp := time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)
	service.Now = func() time.Time { return stamp }
	return service
}

func mustGenerate(t interface {
	Helper()
	Fatalf(string, ...any)
}, reader *fakeReader, opts GenerateOptions) *GenerateResult {
	result, err := fixedEngine(reader).Generate(context.Background(), "snap-0123456789abcdef0123456789abcdef", opts)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	return result
}

func pathByTarget(result *GenerateResult, targetID string) *Path {
	for i := range result.Paths {
		if result.Paths[i].TargetNodeID == targetID {
			return &result.Paths[i]
		}
	}
	return nil
}

func errIs(err error, target error) bool { return errors.Is(err, target) }

func containsString(list []string, want string) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

func joined(list []string) string { return strings.Join(list, ",") }
