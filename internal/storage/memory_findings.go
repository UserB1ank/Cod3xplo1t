package storage

import (
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// validateFindingObservation is shared by both backends so an invalid claim
// cannot be accepted by one store and rejected by the other.
func validateFindingObservation(o findings.Observation) error {
	if o.ID == "" || len(o.ID) > 160 || o.FindingID == "" || len(o.FindingID) > 160 ||
		o.Scope.ProjectID == "" || o.Scope.SourceID == "" || o.Scope.SnapshotID == "" ||
		o.Producer.PluginID == "" || o.Producer.PluginVersion == "" || o.Producer.InvocationID == "" || o.Producer.ConfigDigest == "" ||
		o.RuleID == "" || o.RuleVersion == "" || o.RuleFamily == "" || o.Fingerprint == "" || o.FingerprintVersion == "" ||
		o.Title == "" || o.File == "" || o.Line < 1 || (o.EndLine != 0 && o.EndLine < o.Line) {
		return findings.ErrInvalid
	}
	if o.Status != verify.FindingCandidate {
		return fmt.Errorf("%w: an observation is a candidate, not a verdict", findings.ErrInvalid)
	}
	if o.SeverityHint != "" && o.SeverityHint != "high" && o.SeverityHint != "medium" && o.SeverityHint != "low" {
		return findings.ErrInvalid
	}
	return nil
}

func validateSeverityAudit(a findings.SeverityAudit) error {
	if a.ID == "" || a.FindingID == "" || a.Version < 2 || a.Severity == "" || a.Reason == "" || a.Actor == "" {
		return findings.ErrInvalid
	}
	if !validGrade(a.Severity) || (a.PreviousSeverity != "" && !validGrade(a.PreviousSeverity)) {
		return verify.ErrInvalidArgument
	}
	if len(a.Reason) > 2000 || len(a.Actor) > 200 {
		return findings.ErrInvalid
	}
	return nil
}

func cloneObservation(o findings.Observation) findings.Observation {
	raw, _ := json.Marshal(o)
	var clone findings.Observation
	_ = json.Unmarshal(raw, &clone)
	return clone
}

func sortObservations(items []findings.Observation) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].CreatedAt != items[j].CreatedAt {
			return items[i].CreatedAt < items[j].CreatedAt
		}
		return items[i].ID < items[j].ID
	})
}

func sortSeverityAudits(items []findings.SeverityAudit) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Version != items[j].Version {
			return items[i].Version < items[j].Version
		}
		return items[i].ID < items[j].ID
	})
}

// UpsertFindingObservation implements findings.ObservationStore.
func (m *Memory) UpsertFindingObservation(o findings.Observation) (bool, error) {
	if err := validateFindingObservation(o); err != nil {
		return false, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.snapshotWritableLocked(o.Scope.SnapshotID); err != nil {
		return false, err
	}
	finding, ok := m.findings[o.FindingID]
	if !ok {
		return false, findings.ErrNotFound
	}
	if finding.SnapshotID != o.Scope.SnapshotID {
		return false, findings.ErrConflict
	}
	if prior, ok := m.findingObservations[o.ID]; ok {
		if prior.Digest() != o.Digest() {
			return false, findings.ErrConflict
		}
		return false, nil
	}
	if o.CreatedAt == "" {
		o.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	m.findingObservations[o.ID] = cloneObservation(o)
	return true, nil
}

// GetFindingObservation implements findings.ObservationStore.
func (m *Memory) GetFindingObservation(id string) (*findings.Observation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	o, ok := m.findingObservations[id]
	if !ok {
		return nil, findings.ErrNotFound
	}
	clone := cloneObservation(o)
	return &clone, nil
}

// ListFindingObservations implements findings.ObservationStore.
func (m *Memory) ListFindingObservations(findingID string) ([]findings.Observation, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := []findings.Observation{}
	for _, o := range m.findingObservations {
		if o.FindingID == findingID {
			out = append(out, cloneObservation(o))
		}
	}
	sortObservations(out)
	return out, nil
}

// ListFindingObservationsByProject implements findings.ObservationStore.
func (m *Memory) ListFindingObservationsByProject(projectID string, limit, offset int) ([]findings.Observation, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := []findings.Observation{}
	for _, o := range m.findingObservations {
		if o.Scope.ProjectID == projectID {
			all = append(all, cloneObservation(o))
		}
	}
	return pageObservations(all, limit, offset)
}

// ListFindingObservationsByTask implements findings.ObservationStore.
func (m *Memory) ListFindingObservationsByTask(taskID string, limit, offset int) ([]findings.Observation, int, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	all := []findings.Observation{}
	for _, o := range m.findingObservations {
		if o.TaskID == taskID {
			all = append(all, cloneObservation(o))
		}
	}
	return pageObservations(all, limit, offset)
}

func pageObservations(all []findings.Observation, limit, offset int) ([]findings.Observation, int, error) {
	sortObservations(all)
	total := len(all)
	offset = max(offset, 0)
	limit = normaliseLimit(limit, 100, 0)
	if offset > total {
		offset = total
	}
	end := min(total, offset+limit)
	return all[offset:end], total, nil
}

// ListFindingSeverityAudits implements findings.ObservationStore.
func (m *Memory) ListFindingSeverityAudits(findingID string) ([]findings.SeverityAudit, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := append([]findings.SeverityAudit(nil), m.findingAudits[findingID]...)
	sortSeverityAudits(out)
	return out, nil
}

// SetFindingSeverityWithAudit implements findings.ObservationStore.
func (m *Memory) SetFindingSeverityWithAudit(findingID, severity string, expectedVersion int64, audit findings.SeverityAudit) error {
	if !validGrade(severity) {
		return fmt.Errorf("%w: severity must be high, medium or low", verify.ErrInvalidArgument)
	}
	if err := validateSeverityAudit(audit); err != nil {
		return err
	}
	if audit.FindingID != findingID || audit.Severity != severity || audit.Version != expectedVersion+1 {
		return findings.ErrConflict
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	finding, ok := m.findings[findingID]
	if !ok {
		return verify.ErrNotFound
	}
	if err := m.snapshotWritableLocked(finding.SnapshotID); err != nil {
		return err
	}
	if expectedVersion < 1 || finding.Version != expectedVersion {
		return verify.ErrConflict
	}
	for _, prior := range m.findingAudits[findingID] {
		if prior.ID == audit.ID || prior.Version == audit.Version {
			return findings.ErrConflict
		}
	}
	if audit.CreatedAt == "" {
		audit.CreatedAt = time.Now().UTC().Format(time.RFC3339Nano)
	}
	audit.PreviousSeverity = finding.Severity
	finding.Severity = severity
	finding.Version++
	finding.UpdatedAt = audit.CreatedAt
	m.findings[findingID] = finding
	m.findingAudits[findingID] = append(m.findingAudits[findingID], audit)
	return nil
}

// deleteFindingObservationsForSnapshotLocked is called by the snapshot cleanup
// under the same lock. Observations and audits are evidence about a finding, so
// they cannot outlive it.
func (m *Memory) deleteFindingObservationsForSnapshotLocked(snapshotID string, findingIDs map[string]bool) {
	for id, o := range m.findingObservations {
		if o.Scope.SnapshotID == snapshotID || findingIDs[o.FindingID] {
			delete(m.findingObservations, id)
		}
	}
	for id := range findingIDs {
		delete(m.findingAudits, id)
	}
}
