package findings

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// Service records plugin observations into stable finding groups and exposes
// bounded grouped reads. It never changes a finding's status: only the
// verification layer can move a verdict past candidate.
type Service struct {
	Store Store
	Now   func() time.Time
}

func NewService(store Store) *Service {
	return &Service{Store: store, Now: func() time.Time { return time.Now().UTC() }}
}

func (s *Service) now() string {
	if s.Now == nil {
		return time.Now().UTC().Format(time.RFC3339Nano)
	}
	return s.Now().UTC().Format(time.RFC3339Nano)
}

// RecordInput is one observation claim. The candidate id makes the observation
// id idempotent for the invocation that produced it.
type RecordInput struct {
	Scope        artifact.Scope
	TaskID       string
	Producer     artifact.Producer
	CandidateID  string
	RuleID       string
	RuleVersion  string
	Title        string
	SeverityHint string
	File         string
	Line         int
	EndLine      int
	EvidenceRefs []string
	Limitations  []string
}

// Record stores one observation and its group. A replay of the same observation
// returns inserted=false and leaves the group untouched.
func (s *Service) Record(ctx context.Context, input RecordInput) (Observation, bool, error) {
	if err := ctx.Err(); err != nil {
		return Observation{}, false, err
	}
	if err := validateRecordInput(input); err != nil {
		return Observation{}, false, err
	}
	producer := input.Producer
	if producer.TaskID == "" {
		producer.TaskID = input.TaskID
	}
	family := RuleFamily(producer.PluginID, input.RuleID)
	fingerprint := Fingerprint(FingerprintVersion, FingerprintInput{
		Scope: input.Scope, RuleFamily: family, RuleVersion: input.RuleVersion,
		File: input.File, Line: input.Line, Status: verify.FindingCandidate,
	})
	findingID := "find-" + fingerprint
	created := s.now()
	observation := Observation{
		ID:                 observationID(producer, input),
		FindingID:          findingID,
		Scope:              input.Scope,
		TaskID:             input.TaskID,
		Producer:           producer,
		RuleID:             input.RuleID,
		RuleVersion:        input.RuleVersion,
		RuleFamily:         family,
		Title:              input.Title,
		SeverityHint:       input.SeverityHint,
		Status:             verify.FindingCandidate,
		File:               input.File,
		Line:               input.Line,
		EndLine:            input.EndLine,
		EvidenceRefs:       append([]string(nil), input.EvidenceRefs...),
		Limitations:        append([]string(nil), input.Limitations...),
		Fingerprint:        fingerprint,
		FingerprintVersion: FingerprintVersion,
		CreatedAt:          created,
	}
	finding, err := s.Store.GetFinding(findingID)
	if errors.Is(err, verify.ErrNotFound) {
		group := verify.Finding{
			ID: findingID, HypothesisID: "fp-" + FingerprintVersion + "-" + fingerprint,
			AuditID: input.TaskID, SnapshotID: input.Scope.SnapshotID, Title: input.Title,
			Status: verify.FindingCandidate, Confidence: "candidate",
			Supporting:  append([]string(nil), input.EvidenceRefs...),
			Limitations: append([]string(nil), input.Limitations...),
			CreatedAt:   created, UpdatedAt: created, Version: 1,
		}
		if err := s.Store.UpsertFinding(group); err != nil {
			return Observation{}, false, err
		}
		if finding, err = s.Store.GetFinding(findingID); err != nil {
			return Observation{}, false, err
		}
	} else if err != nil {
		return Observation{}, false, err
	}
	if finding.SnapshotID != input.Scope.SnapshotID {
		return Observation{}, false, ErrConflict
	}
	inserted, err := s.Store.UpsertFindingObservation(observation)
	if err != nil {
		return Observation{}, false, err
	}
	return observation, inserted, nil
}

// RecordCandidates records every candidate that names an explicit rule. A
// candidate without a rule id is deliberately left in its knowledge revision:
// without a rule-equivalence basis it must not become a cross-tool group.
func (s *Service) RecordCandidates(ctx context.Context, scope artifact.Scope, taskID string, producer artifact.Producer, candidates []plugin.Candidate) (int, error) {
	inserted := 0
	for _, candidate := range candidates {
		if err := ctx.Err(); err != nil {
			return inserted, err
		}
		if candidate.RuleID == "" {
			continue
		}
		if candidate.Status != "candidate" {
			return inserted, fmt.Errorf("%w: a plugin observation must be a candidate", ErrInvalid)
		}
		_, created, err := s.Record(ctx, RecordInput{
			Scope: scope, TaskID: taskID, Producer: producer, CandidateID: candidate.ID,
			RuleID: candidate.RuleID, RuleVersion: candidate.RuleVersion, Title: candidate.Title,
			SeverityHint: candidate.SeverityHint, File: candidate.File, Line: candidate.Line,
			EvidenceRefs: candidate.EvidenceRefs, Limitations: candidate.Limitations,
		})
		if err != nil {
			return inserted, err
		}
		if created {
			inserted++
		}
	}
	return inserted, nil
}

func validateRecordInput(input RecordInput) error {
	if input.Scope.ProjectID == "" || input.Scope.SourceID == "" || input.Scope.SnapshotID == "" ||
		input.Producer.PluginID == "" || input.Producer.PluginVersion == "" || input.Producer.InvocationID == "" || input.Producer.ConfigDigest == "" ||
		input.RuleID == "" || input.RuleVersion == "" || input.Title == "" || input.File == "" || input.Line < 1 ||
		(input.EndLine != 0 && input.EndLine < input.Line) {
		return ErrInvalid
	}
	if input.SeverityHint != "" && input.SeverityHint != "high" && input.SeverityHint != "medium" && input.SeverityHint != "low" {
		return ErrInvalid
	}
	if len(input.Title) > 2000 || len(input.EvidenceRefs) > 100 || len(input.Limitations) > 50 {
		return ErrInvalid
	}
	return nil
}

func observationID(producer artifact.Producer, input RecordInput) string {
	sum := sha256.Sum256([]byte("codexploit/finding-observation-id\n" +
		input.Scope.ProjectID + "\x00" + input.Scope.SnapshotID + "\x00" +
		producer.PluginID + "\x00" + producer.PluginVersion + "\x00" + producer.InvocationID + "\x00" +
		input.CandidateID + "\x00" + input.RuleID + "\x00" + input.File + "\x00" + fmt.Sprint(input.Line)))
	return "obs-" + hex.EncodeToString(sum[:])[:32]
}

// Get returns one group with every source and the severity history.
func (s *Service) Get(ctx context.Context, findingID string) (Group, error) {
	if err := ctx.Err(); err != nil {
		return Group{}, err
	}
	if findingID == "" {
		return Group{}, ErrInvalid
	}
	finding, err := s.Store.GetFinding(findingID)
	if err != nil {
		return Group{}, err
	}
	observations, err := s.Store.ListFindingObservations(findingID)
	if err != nil {
		return Group{}, err
	}
	audits, err := s.Store.ListFindingSeverityAudits(findingID)
	if err != nil {
		return Group{}, err
	}
	fingerprint, version := groupFingerprint(finding.SnapshotID, *finding, observations)
	return Group{Finding: *finding, Members: []verify.Finding{*finding}, Fingerprint: fingerprint, FingerprintVersion: version, Observations: observations, SeverityAudit: audits}, nil
}

// List returns bounded groups for a project or one task. The task filter matches
// any source observation, not only the group's first task.
func (s *Service) List(ctx context.Context, query ListQuery) (ListResult, error) {
	if err := ctx.Err(); err != nil {
		return ListResult{}, err
	}
	if query.ProjectID == "" {
		return ListResult{}, ErrInvalid
	}
	limit := query.Limit
	if limit <= 0 {
		limit = 50
	}
	if limit > 1000 {
		return ListResult{}, ErrInvalid
	}
	findings, truncated, err := s.collectFindings(ctx, query)
	if err != nil {
		return ListResult{}, err
	}
	groups := map[string]*Group{}
	for _, finding := range findings {
		observations, err := s.Store.ListFindingObservations(finding.ID)
		if err != nil {
			return ListResult{}, err
		}
		fingerprint, version := groupFingerprint(finding.SnapshotID, finding, observations)
		key := version + "\x00" + fingerprint
		group := groups[key]
		if group == nil {
			group = &Group{Finding: finding, Members: []verify.Finding{finding}, Fingerprint: fingerprint, FingerprintVersion: version}
			groups[key] = group
		} else {
			group.Members = append(group.Members, finding)
			if betterFinding(finding, group.Finding) {
				group.Finding = finding
			}
		}
		seen := map[string]bool{}
		for _, o := range group.Observations {
			seen[o.ID] = true
		}
		for _, o := range observations {
			if !seen[o.ID] {
				group.Observations = append(group.Observations, o)
				seen[o.ID] = true
			}
		}
	}
	counts := NewCounts()
	ordered := make([]Group, 0, len(groups))
	for _, group := range groups {
		counts.add(group.Finding.Status, verify.NormalizeSeverity(group.Finding.Severity))
		ordered = append(ordered, *group)
	}
	sort.Slice(ordered, func(i, j int) bool {
		if gradeRank(ordered[i].Finding.Severity) != gradeRank(ordered[j].Finding.Severity) {
			return gradeRank(ordered[i].Finding.Severity) < gradeRank(ordered[j].Finding.Severity)
		}
		return ordered[i].Fingerprint < ordered[j].Fingerprint
	})
	filtered := make([]Group, 0, len(ordered))
	for _, group := range ordered {
		if query.Severity != "" && verify.NormalizeSeverity(group.Finding.Severity) != query.Severity {
			continue
		}
		if query.Status != "" && group.Finding.Status != query.Status {
			continue
		}
		filtered = append(filtered, group)
	}
	total := len(filtered)
	offset := max(query.Offset, 0)
	if offset > total {
		offset = total
	}
	end := min(total, offset+limit)
	return ListResult{Groups: filtered[offset:end], Total: total, Counts: counts, Truncated: truncated}, nil
}

func (s *Service) collectFindings(ctx context.Context, query ListQuery) ([]verify.Finding, bool, error) {
	byID := map[string]verify.Finding{}
	const maxFindings = 10000
	if query.TaskID != "" {
		truncated := false
		for offset := 0; offset < maxFindings; offset += 500 {
			items, total, err := s.Store.ListFindings(verify.FindingQuery{ProjectID: query.ProjectID, AuditID: query.TaskID, Limit: 500, Offset: offset})
			if err != nil {
				return nil, false, err
			}
			for _, item := range items {
				byID[item.ID] = item
			}
			if total > maxFindings {
				truncated = true
			}
			if offset+len(items) >= total || len(items) == 0 {
				break
			}
		}
		// A group's canonical AuditID is its first task, but the same group may
		// have sources from this task. Those findings must still appear.
		for offset := 0; offset < maxFindings; offset += 500 {
			observations, total, err := s.Store.ListFindingObservationsByTask(query.TaskID, 500, offset)
			if err != nil {
				return nil, false, err
			}
			for _, o := range observations {
				if _, ok := byID[o.FindingID]; ok {
					continue
				}
				finding, err := s.Store.GetFinding(o.FindingID)
				if err != nil {
					return nil, false, err
				}
				byID[finding.ID] = *finding
			}
			if offset+len(observations) >= total || len(observations) == 0 {
				break
			}
			if offset+len(observations) >= maxFindings {
				truncated = true
				break
			}
		}
		return mapFindings(byID), truncated, nil
	} else {
		for offset := 0; offset < maxFindings; offset += 500 {
			items, total, err := s.Store.ListFindings(verify.FindingQuery{ProjectID: query.ProjectID, Limit: 500, Offset: offset})
			if err != nil {
				return nil, false, err
			}
			for _, item := range items {
				byID[item.ID] = item
			}
			if offset+len(items) >= total || len(items) == 0 {
				return mapFindings(byID), false, nil
			}
			if offset+len(items) >= maxFindings {
				return mapFindings(byID), true, nil
			}
		}
	}
	return mapFindings(byID), len(byID) >= maxFindings, nil
}

func mapFindings(byID map[string]verify.Finding) []verify.Finding {
	out := make([]verify.Finding, 0, len(byID))
	for _, finding := range byID {
		out = append(out, finding)
	}
	return out
}

func groupFingerprint(snapshotID string, finding verify.Finding, observations []Observation) (string, string) {
	if len(observations) > 0 {
		return observations[0].Fingerprint, observations[0].FingerprintVersion
	}
	return Fingerprint(FingerprintVersion, FingerprintInput{
		Scope:      artifact.Scope{SnapshotID: snapshotID},
		RuleFamily: "verification/" + firstNonEmpty(finding.PathID, finding.ID),
		Status:     finding.Status,
	}), FingerprintVersion
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func betterFinding(candidate, current verify.Finding) bool {
	if gradeRank(candidate.Severity) != gradeRank(current.Severity) {
		return gradeRank(candidate.Severity) < gradeRank(current.Severity)
	}
	return candidate.ID < current.ID
}

func gradeRank(severity string) int {
	switch verify.NormalizeSeverity(severity) {
	case "high":
		return 0
	case "medium":
		return 1
	case "low":
		return 2
	default:
		return 3
	}
}

// AssessSeverity is the only write that changes a grade. A reason and actor are
// mandatory, and the finding's verdict is never touched.
func (s *Service) AssessSeverity(ctx context.Context, findingID, severity, reason, actor string, expectedVersion int64) (Group, error) {
	if err := ctx.Err(); err != nil {
		return Group{}, err
	}
	if findingID == "" || (severity != "high" && severity != "medium" && severity != "low") ||
		strings.TrimSpace(reason) == "" || strings.TrimSpace(actor) == "" || expectedVersion < 1 ||
		len(reason) > 2000 || len(actor) > 200 {
		return Group{}, ErrInvalid
	}
	auditID := "audit-" + digest32(findingID+"\x00"+fmt.Sprint(expectedVersion+1))
	audit := SeverityAudit{
		ID: auditID, FindingID: findingID, Version: expectedVersion + 1,
		Severity: severity, Reason: strings.TrimSpace(reason), Actor: strings.TrimSpace(actor), CreatedAt: s.now(),
	}
	if err := s.Store.SetFindingSeverityWithAudit(findingID, severity, expectedVersion, audit); err != nil {
		return Group{}, err
	}
	return s.Get(ctx, findingID)
}

func digest32(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:32]
}
