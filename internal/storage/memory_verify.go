package storage

import (
	"fmt"
	"sort"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// The verification documents of the memory store live in three maps on Memory
// (see memory.go): runs keyed by run id, evidence keyed by evidence id, and
// findings keyed by finding id. The hypothesis is not a map key because the SQL
// schema enforces uniqueness on `findings(hypothesis_id)` rather than on a second
// index; the memory store enforces the same rule with a scan, which keeps one
// source of truth for the upsert identity.
//
// Every document handed to or returned from the store is deep-copied through a
// JSON round trip (cloneVerification), so the store never shares a slice with a
// caller and a caller can never mutate stored facts.

// CreateVerificationRun implements verify.Store.
func (m *Memory) CreateVerificationRun(run verify.Run) error {
	prepared, err := prepareVerificationRun(run, verifyNow())
	if err != nil {
		return err
	}
	stored, err := cloneVerification(prepared)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(run.SnapshotID); err != nil {
		return err
	}
	if _, exists := m.verificationRuns[prepared.ID]; exists {
		return fmt.Errorf("%w: verification run %s already exists", verify.ErrConflict, prepared.ID)
	}
	// (hypothesis_id, plan_hash) is unique in the schema; the memory store enforces
	// the same rule instead of letting a second attempt hide behind a new id.
	for _, existing := range m.verificationRuns {
		if runPlanKey(existing) == runPlanKey(prepared) {
			return fmt.Errorf("%w: the plan %s of hypothesis %s is already run %s",
				verify.ErrConflict, prepared.PlanHash, prepared.HypothesisID, existing.ID)
		}
	}
	m.verificationRuns[prepared.ID] = stored
	return nil
}

// GetVerificationRun implements verify.Store.
func (m *Memory) GetVerificationRun(runID string) (*verify.Run, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	run, ok := m.verificationRuns[runID]
	if !ok {
		return nil, fmt.Errorf("%w: verification run %s", verify.ErrNotFound, runID)
	}
	return m.copyRunLocked(run)
}

// ListVerificationRuns implements verify.Store.
func (m *Memory) ListVerificationRuns(q verify.RunQuery) ([]verify.Run, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []verify.Run
	for _, run := range m.verificationRuns {
		if !matchesVerificationRunQuery(run, q) {
			continue
		}
		stored, err := m.copyRunLocked(run)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, *stored)
	}
	sortVerificationRuns(out)
	total := len(out)
	// The runs of a snapshot are bounded by its hypotheses and plans and the
	// orchestrator pages with an explicit limit, so only a default applies and
	// nothing is silently truncated.
	return page(out, max(q.Offset, 0), normaliseLimit(q.Limit, 100, 0)), total, nil
}

// UpdateVerificationRun implements verify.Store.
func (m *Memory) UpdateVerificationRun(run verify.Run, expectedVersion int64) error {
	prepared, err := prepareVerificationRun(run, verifyNow())
	if err != nil {
		return err
	}
	stored, err := cloneVerification(prepared)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.verificationRuns[prepared.ID]
	if !ok {
		return fmt.Errorf("%w: verification run %s", verify.ErrNotFound, prepared.ID)
	}
	if expectedVersion > 0 && current.Version != expectedVersion {
		return fmt.Errorf("%w: verification run %s is at version %d, expected %d",
			verify.ErrConflict, prepared.ID, current.Version, expectedVersion)
	}
	// The plan of a run is its identity, so a write may not move it onto another
	// run's (hypothesis, plan_hash) key.
	for _, existing := range m.verificationRuns {
		if existing.ID != prepared.ID && runPlanKey(existing) == runPlanKey(stored) {
			return fmt.Errorf("%w: the plan %s of hypothesis %s is already run %s",
				verify.ErrConflict, stored.PlanHash, stored.HypothesisID, existing.ID)
		}
	}
	if stored.Version <= current.Version {
		stored.Version = current.Version + 1
	}
	m.verificationRuns[prepared.ID] = stored
	return nil
}

// copyRunLocked deep-copies a stored run and fills its derived evidence list. The
// caller must hold at least the read lock.
func (m *Memory) copyRunLocked(run verify.Run) (*verify.Run, error) {
	stored, err := cloneVerification(run)
	if err != nil {
		return nil, err
	}
	stored.EvidenceIDs = m.evidenceIDsForRunLocked(run.ID)
	return &stored, nil
}

// evidenceIDsForRunLocked returns the ids of the evidence that names a run,
// ordered by id — the order the verifier records when it closes a run.
func (m *Memory) evidenceIDsForRunLocked(runID string) []string {
	ids := []string{}
	for id, object := range m.evidence {
		if object.VerificationRunID == runID {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// AppendEvidence implements verify.Store. Evidence is append-only: the batch is
// checked before anything is written, so a rejected object cannot leave half a
// batch behind, and an object whose id is already stored is a no-op only when its
// identity — id, content hash and content — is the one already stored.
func (m *Memory) AppendEvidence(evidence []verify.Evidence) error {
	stored := make([]verify.Evidence, 0, len(evidence))
	for _, object := range evidence {
		if strings.TrimSpace(object.ID) == "" {
			return fmt.Errorf("%w: evidence needs an id", verify.ErrInvalidArgument)
		}
		copied, err := cloneVerification(object)
		if err != nil {
			return err
		}
		stored = append(stored, copied)
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	// pending holds the first occurrence of each id in the batch: a repeated object
	// is one append, and a repeat whose identity differs is a conflict rather than a
	// race the second write would win.
	pending := make([]verify.Evidence, 0, len(stored))
	seen := map[string]verify.Evidence{}
	for _, object := range stored {
		if err := m.snapshotWritableLocked(object.SnapshotID); err != nil {
			return err
		}
		if first, duplicate := seen[object.ID]; duplicate {
			if !sameEvidenceObject(first, object) {
				return fmt.Errorf("%w: evidence %s appears twice in the batch with different content", verify.ErrConflict, object.ID)
			}
			continue
		}
		seen[object.ID] = object
		existing, exists := m.evidence[object.ID]
		if exists {
			if !sameEvidenceObject(existing, object) {
				return fmt.Errorf("%w: evidence %s is already stored with different content", verify.ErrConflict, object.ID)
			}
			// The same evidence, re-derived: a no-op, so the stored object keeps its
			// original timestamp and the rest of its provenance.
			continue
		}
		pending = append(pending, object)
	}
	for _, object := range pending {
		m.evidence[object.ID] = object
	}
	return nil
}

// GetEvidence implements verify.Store.
func (m *Memory) GetEvidence(evidenceID string) (*verify.Evidence, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	object, ok := m.evidence[evidenceID]
	if !ok {
		return nil, fmt.Errorf("%w: evidence %s", verify.ErrNotFound, evidenceID)
	}
	stored, err := cloneVerification(object)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// ListEvidence implements verify.Store.
func (m *Memory) ListEvidence(q verify.EvidenceQuery) ([]verify.Evidence, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []verify.Evidence
	for _, object := range m.evidence {
		if !matchesEvidenceQuery(object, q) {
			continue
		}
		stored, err := cloneVerification(object)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, stored)
	}
	sortEvidence(out)
	total := len(out)
	// A snapshot's evidence grows with the runs that produced it; the listing
	// returns the total, so a caller pages explicitly and nothing is hidden.
	return page(out, max(q.Offset, 0), normaliseLimit(q.Limit, 200, 0)), total, nil
}

// UpsertFinding implements verify.Store. The verdict is keyed by hypothesis id,
// so a re-upsert updates the row already stored for that hypothesis instead of
// adding a second one.
func (m *Memory) UpsertFinding(finding verify.Finding) error {
	now := verifyNow()
	prepared, err := prepareFinding(finding, now)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(prepared.SnapshotID); err != nil {
		return err
	}
	row := prepared
	current, exists := m.findFindingByHypothesisLocked(prepared.HypothesisID)
	if exists {
		merged, err := mergeFinding(current, prepared, now)
		if err != nil {
			return err
		}
		row = merged
	} else if other, taken := m.findings[prepared.ID]; taken && other.HypothesisID != prepared.HypothesisID {
		// The finding id is a primary key, so two hypotheses cannot share one.
		return fmt.Errorf("%w: finding id %s is already used by the finding for hypothesis %s",
			verify.ErrConflict, prepared.ID, other.HypothesisID)
	}
	stored, err := cloneVerification(row)
	if err != nil {
		return err
	}
	m.findings[row.ID] = stored
	return nil
}

// findFindingByHypothesisLocked returns the verdict stored for a hypothesis. The
// caller must hold at least the read lock.
func (m *Memory) findFindingByHypothesisLocked(hypothesisID string) (verify.Finding, bool) {
	for _, finding := range m.findings {
		if finding.HypothesisID == hypothesisID {
			return finding, true
		}
	}
	return verify.Finding{}, false
}

// GetFinding implements verify.Store.
func (m *Memory) GetFinding(findingID string) (*verify.Finding, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	finding, ok := m.findings[findingID]
	if !ok {
		return nil, fmt.Errorf("%w: finding %s", verify.ErrNotFound, findingID)
	}
	stored, err := cloneVerification(finding)
	if err != nil {
		return nil, err
	}
	return &stored, nil
}

// ListFindings implements verify.Store.
func (m *Memory) ListFindings(q verify.FindingQuery) ([]verify.Finding, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	var out []verify.Finding
	for _, finding := range m.findings {
		if !matchesFindingQuery(finding, q) {
			continue
		}
		stored, err := cloneVerification(finding)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, stored)
	}
	sortFindings(out)
	total := len(out)
	// One finding per hypothesis bounds the table, and the report layer pages with
	// an explicit limit, so only a default applies here.
	return page(out, max(q.Offset, 0), normaliseLimit(q.Limit, 100, 0)), total, nil
}

// DeleteVerificationForSnapshot implements verify.Store.
func (m *Memory) DeleteVerificationForSnapshot(snapshotID string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.deleteVerificationForSnapshotLocked(snapshotID), nil
}

// deleteVerificationForSnapshotLocked removes every verification run of a
// snapshot with its evidence and the findings they produced. The caller must hold
// the write lock; DeleteSnapshot calls it so a deleted snapshot cannot keep
// answering verification queries.
//
// Evidence goes first: it can name a run by id, so a mis-tagged object must not
// outlive the run that produced it. Findings are removed by snapshot id, because a
// finding belongs to the hypothesis of one snapshot and only its run list mentions
// runs.
func (m *Memory) deleteVerificationForSnapshotLocked(snapshotID string) int {
	removedRuns := map[string]bool{}
	removed := 0
	for id, run := range m.verificationRuns {
		if run.SnapshotID != snapshotID {
			continue
		}
		removedRuns[id] = true
		removed++
	}
	for id, object := range m.evidence {
		if object.SnapshotID == snapshotID || removedRuns[object.VerificationRunID] {
			delete(m.evidence, id)
		}
	}
	for id, finding := range m.findings {
		if finding.SnapshotID == snapshotID {
			delete(m.findings, id)
		}
	}
	for id := range removedRuns {
		delete(m.verificationRuns, id)
	}
	return removed
}
