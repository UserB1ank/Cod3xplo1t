package storage

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

// CreateProject implements ProjectRepository.
func (m *Memory) CreateProject(_ context.Context, p Project) (Project, error) {
	if p.ID == "" {
		return Project{}, fmt.Errorf("%w: project id is required", ErrConflict)
	}
	if err := validateProjectDetails(p.Name, p.Description); err != nil {
		return Project{}, err
	}
	now := time.Now().UTC()
	if p.CreatedAt.IsZero() {
		p.CreatedAt = now
	}
	p.UpdatedAt = now
	p.Version = 1
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, deleted := m.projectDeletions[p.ID]; deleted {
		return Project{}, fmt.Errorf("%w: project %s is being deleted", ErrConflict, p.ID)
	}
	if _, exists := m.projects[p.ID]; exists {
		return Project{}, fmt.Errorf("%w: project %s already exists", ErrConflict, p.ID)
	}
	if m.projectInputs == nil {
		m.projectInputs = map[string]ProjectInput{}
	}
	m.projects[p.ID] = p
	m.projectInputs[p.ID] = ProjectInput{
		ProjectID: p.ID,
		State:     ProjectInputImporting,
		Version:   1,
		CreatedAt: now,
		UpdatedAt: now,
	}
	return p, nil
}

// GetProjectInput implements ProjectRepository.
func (m *Memory) GetProjectInput(_ context.Context, projectID string) (ProjectInput, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	input, ok := m.projectInputs[projectID]
	if !ok {
		return ProjectInput{}, fmt.Errorf("%w: project input for %s", ErrNotFound, projectID)
	}
	return input, nil
}

// ListProjectInputs implements ProjectRepository.
func (m *Memory) ListProjectInputs(_ context.Context) ([]ProjectInput, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]ProjectInput, 0, len(m.projectInputs))
	for _, input := range m.projectInputs {
		out = append(out, input)
	}
	return out, nil
}

// BeginProjectInput implements ProjectRepository.
func (m *Memory) BeginProjectInput(_ context.Context, projectID, sourceID, sourceKind, sourceName string) (ProjectInput, error) {
	if strings.TrimSpace(sourceID) == "" {
		return ProjectInput{}, fmt.Errorf("%w: source id is required", ErrConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.projectWritableLocked(projectID); err != nil {
		return ProjectInput{}, err
	}
	input, ok := m.projectInputs[projectID]
	if !ok {
		return ProjectInput{}, fmt.Errorf("%w: project input for %s", ErrNotFound, projectID)
	}
	now := time.Now().UTC()
	switch input.State {
	case ProjectInputReady:
		if !sameSource(input, sourceID) {
			return ProjectInput{}, ErrProjectInputFixed
		}
		// A replay of the completed import is not a new binding. Touch the
		// activity timestamp without advancing the binding version.
		input.UpdatedAt = now
		m.projectInputs[projectID] = input
		return input, nil
	case ProjectInputImporting:
		if sameSource(input, sourceID) {
			input.UpdatedAt = now
			m.projectInputs[projectID] = input
			return input, nil
		}
		if err := inputImportingLocked(input, sourceID, now); err != nil {
			return ProjectInput{}, err
		}
	case ProjectInputFailed:
		// Retrying an interrupted or failed import is a new binding attempt.
	default:
		return ProjectInput{}, fmt.Errorf("%w: unknown project input state %q", ErrConflict, input.State)
	}
	input.State = ProjectInputImporting
	input.SourceID, input.SourceKind, input.SourceName = sourceID, sourceKind, sourceName
	input.SnapshotID, input.Files, input.Bytes = "", 0, 0
	input.FailureCode, input.FailureMessage = "", ""
	input.Version++
	input.UpdatedAt = now
	m.projectInputs[projectID] = input
	return input, nil
}

// CompleteProjectInput implements ProjectRepository.
func (m *Memory) CompleteProjectInput(_ context.Context, projectID, sourceID, snapshotID string, files int, bytes int64) (ProjectInput, error) {
	if strings.TrimSpace(snapshotID) == "" {
		return ProjectInput{}, fmt.Errorf("%w: snapshot id is required", ErrConflict)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.projectWritableLocked(projectID); err != nil {
		return ProjectInput{}, err
	}
	input, ok := m.projectInputs[projectID]
	if !ok {
		return ProjectInput{}, fmt.Errorf("%w: project input for %s", ErrNotFound, projectID)
	}
	if input.State == ProjectInputReady {
		if sameSource(input, sourceID) && input.SnapshotID == snapshotID {
			return input, nil
		}
		return ProjectInput{}, ErrProjectInputFixed
	}
	if input.State != ProjectInputImporting {
		return ProjectInput{}, fmt.Errorf("%w: project input is %s, not importing", ErrConflict, input.State)
	}
	if !sameSource(input, sourceID) {
		return ProjectInput{}, fmt.Errorf("%w: input is bound to a different source", ErrConflict)
	}
	input.State = ProjectInputReady
	input.SnapshotID, input.Files, input.Bytes = snapshotID, files, bytes
	input.FailureCode, input.FailureMessage = "", ""
	input.Version++
	input.UpdatedAt = time.Now().UTC()
	m.projectInputs[projectID] = input
	return input, nil
}

// FailProjectInput implements ProjectRepository.
func (m *Memory) FailProjectInput(_ context.Context, projectID, sourceID, code, message string) (ProjectInput, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.projectWritableLocked(projectID); err != nil {
		return ProjectInput{}, err
	}
	input, ok := m.projectInputs[projectID]
	if !ok {
		return ProjectInput{}, fmt.Errorf("%w: project input for %s", ErrNotFound, projectID)
	}
	// A late failure from an older attempt must not overwrite a ready input or a
	// newer binding.
	if input.State != ProjectInputImporting || !sameSource(input, sourceID) {
		return input, nil
	}
	input.State = ProjectInputFailed
	input.FailureCode, input.FailureMessage = code, truncateMessage(message, 500)
	input.Version++
	input.UpdatedAt = time.Now().UTC()
	m.projectInputs[projectID] = input
	return input, nil
}

// UpdateProjectDetails implements ProjectRepository.
func (m *Memory) UpdateProjectDetails(_ context.Context, id, name, description string, expectedVersion int64) (Project, error) {
	if err := validateProjectDetails(name, description); err != nil {
		return Project{}, err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.projectWritableLocked(id); err != nil {
		return Project{}, err
	}
	p, ok := m.projects[id]
	if !ok {
		return Project{}, fmt.Errorf("%w: project %s", ErrNotFound, id)
	}
	if expectedVersion <= 0 || p.Version != expectedVersion {
		return Project{}, fmt.Errorf("%w: project %s was changed by another writer", ErrConflict, id)
	}
	p.Name, p.Description = name, description
	p.Version++
	p.UpdatedAt = time.Now().UTC()
	m.projects[id] = p
	return p, nil
}

// ProjectDeletion implements ProjectRepository.
func (m *Memory) ProjectDeletion(_ context.Context, id string) (ProjectDeletion, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	deletion, ok := m.projectDeletions[id]
	if !ok {
		return ProjectDeletion{}, fmt.Errorf("%w: project deletion for %s", ErrNotFound, id)
	}
	return deletion, nil
}

// BeginProjectDeletion implements ProjectRepository.
func (m *Memory) BeginProjectDeletion(_ context.Context, id string) (ProjectDeletion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if existing, ok := m.projectDeletions[id]; ok {
		return existing, nil
	}
	if _, ok := m.projects[id]; !ok {
		return ProjectDeletion{}, fmt.Errorf("%w: project %s", ErrNotFound, id)
	}
	input, hasInput := m.projectInputs[id]
	if hasInput {
		effective := EffectiveProjectInput(input, time.Now().UTC())
		if effective.State == ProjectInputImporting && effective.SourceID != "" {
			return ProjectDeletion{}, fmt.Errorf("%w: project %s is still importing its source", ErrConflict, id)
		}
	}
	snapshots := m.projectSnapshotIDsLocked(id)
	snapshotSet := make(map[string]bool, len(snapshots))
	for _, snapshotID := range snapshots {
		snapshotSet[snapshotID] = true
	}
	if err := m.projectHasActiveWorkLocked(id, snapshotSet); err != nil {
		return ProjectDeletion{}, err
	}
	now := time.Now().UTC()
	m.purgeProjectAuxiliaryLocked(id, snapshotSet)
	for _, snapshotID := range snapshots {
		m.deleting[snapshotID] = true
	}
	deletion := ProjectDeletion{ProjectID: id, State: ProjectDeletionPending, CreatedAt: now, UpdatedAt: now}
	m.projectDeletions[id] = deletion
	return deletion, nil
}

// FinishProjectDeletion implements ProjectRepository.
func (m *Memory) FinishProjectDeletion(_ context.Context, id string) (ProjectDeletion, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	deletion, ok := m.projectDeletions[id]
	if !ok {
		return ProjectDeletion{}, fmt.Errorf("%w: project deletion for %s", ErrNotFound, id)
	}
	if deletion.State == ProjectDeletionCompleted {
		return deletion, nil
	}
	if remaining := m.projectSnapshotIDsLocked(id); len(remaining) != 0 {
		return ProjectDeletion{}, fmt.Errorf("%w: project %s still has %d snapshot(s)", ErrConflict, id, len(remaining))
	}
	m.purgeProjectRowsLocked(id)
	delete(m.projects, id)
	delete(m.projectInputs, id)
	deletion.State = ProjectDeletionCompleted
	deletion.Failure = ""
	deletion.UpdatedAt = time.Now().UTC()
	m.projectDeletions[id] = deletion
	return deletion, nil
}

func (m *Memory) projectWritableLocked(id string) error {
	if _, deleted := m.projectDeletions[id]; deleted {
		return fmt.Errorf("%w: project %s is being deleted", ErrConflict, id)
	}
	return nil
}

func (m *Memory) projectSnapshotIDsLocked(projectID string) []string {
	out := make([]string, 0, 1)
	for snapshotID, stored := range m.snapshots {
		if stored.projectID == projectID {
			out = append(out, snapshotID)
		}
	}
	return out
}

func (m *Memory) projectHasActiveWorkLocked(projectID string, snapshots map[string]bool) error {
	for _, doc := range m.audits {
		if !snapshots[doc.audit.SnapshotID] {
			continue
		}
		if doc.audit.Status == "GENERATING" || doc.audit.Status == "PAUSING" || doc.audit.Status == "CANCELLING" {
			return fmt.Errorf("%w: project %s has an unfinished analysis", ErrConflict, projectID)
		}
		for _, p := range doc.paths {
			switch p.Status {
			case path.StatusQueued, path.StatusDiscovered, path.StatusAnalyzing,
				path.StatusLocalExploring, path.StatusHypothesisFormed, path.StatusVerifying:
				return fmt.Errorf("%w: project %s has queued or running paths", ErrConflict, projectID)
			}
		}
	}
	for _, doc := range m.agentRuns {
		if snapshots[doc.run.SnapshotID] && !doc.run.Status.Terminal() {
			return fmt.Errorf("%w: project %s has unfinished agent runs", ErrConflict, projectID)
		}
	}
	for _, run := range m.verificationRuns {
		if snapshots[run.SnapshotID] && !verificationTerminal(string(run.Status)) {
			return fmt.Errorf("%w: project %s has unfinished verification runs", ErrConflict, projectID)
		}
	}
	for _, raw := range m.workflowRuns {
		var run workflow.Run
		if json.Unmarshal(raw, &run) != nil {
			return fmt.Errorf("%w: unreadable workflow run", ErrConflict)
		}
		if snapshots[run.Scope.SnapshotID] && !workflow.RunTerminal(run.Status) {
			return fmt.Errorf("%w: project %s has unfinished workflow runs", ErrConflict, projectID)
		}
	}
	for _, raw := range m.pluginInvocations {
		var inv plugin.Invocation
		if json.Unmarshal(raw, &inv) != nil {
			return fmt.Errorf("%w: unreadable plugin invocation", ErrConflict)
		}
		if snapshots[inv.Request.Scope.SnapshotID] && !plugin.Terminal(inv.Status) {
			return fmt.Errorf("%w: project %s has unfinished plugin invocations", ErrConflict, projectID)
		}
	}
	for _, record := range m.plans {
		if record.Plan.ProjectID == projectID && (record.State == verify.PlanPending || record.State == verify.PlanApproved) {
			return fmt.Errorf("%w: project %s has a pending verification plan", ErrConflict, projectID)
		}
	}
	leases, err := m.environmentLeases.ListEnvironmentLeases(context.Background(), verify.EnvironmentLeaseQuery{})
	if err != nil {
		return err
	}
	for _, lease := range leases {
		if lease.ProjectID == projectID && (lease.State == verify.EnvironmentProvisioning || lease.State == verify.EnvironmentReady || lease.State == verify.EnvironmentRunning) {
			return fmt.Errorf("%w: project %s has an active verification environment", ErrConflict, projectID)
		}
	}
	return nil
}

// purgeProjectAuxiliaryLocked removes records that are not reached through a
// snapshot but would otherwise outlive the project. It runs only after the guard
// has proved no active work exists.
func (m *Memory) purgeProjectAuxiliaryLocked(projectID string, snapshots map[string]bool) {
	auditIDs := map[string]bool{}
	for auditID, doc := range m.audits {
		if snapshots[doc.audit.SnapshotID] {
			auditIDs[auditID] = true
		}
	}
	for checkpointID, checkpoint := range m.agentCheckpoints {
		if snapshots[checkpoint.SnapshotID] || auditIDs[checkpoint.AuditID] {
			delete(m.agentCheckpoints, checkpointID)
			delete(m.agentCheckpointResumes, checkpointID)
		}
	}
	for auditID := range auditIDs {
		delete(m.auditBudgets, auditID)
		delete(m.budgetGrants, auditID)
	}
	findingIDs := map[string]bool{}
	for observationID, observation := range m.findingObservations {
		if observation.Scope.ProjectID == projectID || snapshots[observation.Scope.SnapshotID] {
			findingIDs[observation.FindingID] = true
			delete(m.findingObservations, observationID)
		}
	}
	for findingID, finding := range m.findings {
		if snapshots[finding.SnapshotID] {
			findingIDs[findingID] = true
			delete(m.findings, findingID)
		}
	}
	for evidenceID, evidence := range m.evidence {
		if snapshots[evidence.SnapshotID] {
			delete(m.evidence, evidenceID)
		}
	}
	for findingID := range findingIDs {
		delete(m.findingAudits, findingID)
	}
	for planID, record := range m.plans {
		if record.Plan.ProjectID == projectID {
			delete(m.plans, planID)
		}
	}
	if m.environmentLeases != nil {
		m.environmentLeases.RemoveProjectLeases(projectID)
	}
}

// purgeProjectRowsLocked removes project-level rows after every snapshot is
// gone. Snapshot-scoped rows are already removed by DeleteSnapshot.
func (m *Memory) purgeProjectRowsLocked(projectID string) {
	for sourceID, source := range m.sources {
		if source.ProjectID == projectID {
			delete(m.sources, sourceID)
		}
	}
	for snapshotID, binding := range m.sourceSnapshots {
		if _, source := m.sources[binding.SourceID]; !source {
			delete(m.sourceSnapshots, snapshotID)
		}
	}
	for key, ref := range m.artifacts {
		if ref.Scope.ProjectID == projectID {
			delete(m.artifacts, key)
		}
	}
	for key := range m.knowledge {
		if strings.HasPrefix(key, projectID+"\x00") {
			delete(m.knowledge, key)
		}
	}
	for key, analysis := range m.knowledgeAnalyses {
		if analysis.Scope.ProjectID == projectID {
			delete(m.knowledgeAnalyses, key)
		}
	}
	for key := range m.workflows {
		if strings.HasPrefix(key, projectID+"/") {
			delete(m.workflows, key)
		}
	}
	for key := range m.workflowHeads {
		if strings.HasPrefix(key, projectID+"/") {
			delete(m.workflowHeads, key)
		}
	}
	for planID, raw := range m.workflowPlans {
		var plan workflow.Plan
		if json.Unmarshal(raw, &plan) == nil && plan.Scope.ProjectID == projectID {
			delete(m.workflowPlans, planID)
		}
	}
	for runID, raw := range m.workflowRuns {
		var run workflow.Run
		if json.Unmarshal(raw, &run) == nil && run.Scope.ProjectID == projectID {
			delete(m.workflowRuns, runID)
		}
	}
	for invocationID, raw := range m.pluginInvocations {
		var inv plugin.Invocation
		if json.Unmarshal(raw, &inv) == nil && inv.Request.Scope.ProjectID == projectID {
			delete(m.pluginInvocations, invocationID)
		}
	}
	for analysisRunID, run := range m.analysisRuns {
		if run.ProjectID == projectID {
			delete(m.analysisRuns, analysisRunID)
		}
	}
	for sessionID, session := range m.supervisorSessions {
		if session.ProjectID == projectID {
			delete(m.supervisorSessions, sessionID)
		}
	}
}

func verificationTerminal(status string) bool {
	switch status {
	case "SUCCEEDED", "FAILED", "BLOCKED", "CANCELLED", "TIMED_OUT":
		return true
	default:
		return false
	}
}

func truncateMessage(message string, limit int) string {
	if len([]rune(message)) <= limit {
		return message
	}
	return string([]rune(message)[:limit])
}
