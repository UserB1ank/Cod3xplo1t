package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"path"
	"strings"
	"sync"

	"github.com/google/jsonschema-go/jsonschema"
	contracts "github.com/open-mcp-ai/Codexploit/contracts/v1"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

var findingRuntimeSchema = sync.OnceValues(func() (*jsonschema.Resolved, error) {
	load := func(name string) (*jsonschema.Schema, error) {
		raw, err := contracts.Files.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var schema jsonschema.Schema
		if err := json.Unmarshal(raw, &schema); err != nil {
			return nil, err
		}
		return &schema, nil
	}
	schema, err := load("finding-runtime.schema.json")
	if err != nil {
		return nil, err
	}
	return schema.Resolve(&jsonschema.ResolveOptions{Loader: func(uri *url.URL) (*jsonschema.Schema, error) {
		if uri.Scheme != "https" || uri.Host != "codexploit.invalid" || path.Dir(uri.Path) != "/contracts/v1" {
			return nil, findings.ErrInvalid
		}
		return load(path.Base(uri.Path))
	}})
})

func WithFindings(service *findings.Service) Option { return func(s *Server) { s.Findings = service } }

func writeFindingRuntimeJSON(w http.ResponseWriter, status int, document any) {
	schema, err := findingRuntimeSchema()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "contract_unavailable", err)
		return
	}
	raw, err := json.Marshal(document)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "internal_error", err)
		return
	}
	var value any
	if json.Unmarshal(raw, &value) != nil || schema.Validate(value) != nil {
		writeError(w, http.StatusInternalServerError, "contract_violation", errors.New("findings response does not satisfy the public contract"))
		return
	}
	writeJSON(w, status, document)
}

type findingRuntimeSource struct {
	ObservationID string               `json:"observation_id,omitempty"`
	FindingID     string               `json:"finding_id"`
	Scope         *artifact.Scope      `json:"scope,omitempty"`
	TaskID        string               `json:"task_id,omitempty"`
	Producer      *artifact.Producer   `json:"producer,omitempty"`
	RuleID        string               `json:"rule_id,omitempty"`
	RuleVersion   string               `json:"rule_version,omitempty"`
	RuleFamily    string               `json:"rule_family,omitempty"`
	Title         string               `json:"title,omitempty"`
	SeverityHint  string               `json:"severity_hint,omitempty"`
	Status        verify.FindingStatus `json:"status"`
	File          string               `json:"file,omitempty"`
	Line          int                  `json:"line,omitempty"`
	EndLine       int                  `json:"end_line,omitempty"`
	EvidenceRefs  []string             `json:"evidence_refs,omitempty"`
	Limitations   []string             `json:"limitations,omitempty"`
	CreatedAt     string               `json:"created_at,omitempty"`
}

type findingRuntimeGroup struct {
	FindingID          string                   `json:"finding_id"`
	HypothesisID       string                   `json:"hypothesis_id"`
	PathID             string                   `json:"path_id"`
	AuditID            string                   `json:"audit_id"`
	SnapshotID         string                   `json:"snapshot_id"`
	Title              string                   `json:"title"`
	Severity           string                   `json:"severity,omitempty"`
	Status             verify.FindingStatus     `json:"status"`
	Confidence         string                   `json:"confidence"`
	Supporting         []string                 `json:"supporting_evidence"`
	Contradicting      []string                 `json:"contradicting_evidence"`
	Inconclusive       []string                 `json:"inconclusive_evidence"`
	Limitations        []string                 `json:"limitations"`
	ReproduceSteps     string                   `json:"reproduce_steps"`
	CreatedAt          string                   `json:"created_at"`
	UpdatedAt          string                   `json:"updated_at"`
	Version            int64                    `json:"version"`
	Fingerprint        string                   `json:"fingerprint"`
	FingerprintVersion string                   `json:"fingerprint_version"`
	Sources            []findingRuntimeSource   `json:"sources"`
	SeverityAudit      []findings.SeverityAudit `json:"severity_audit"`
}

func findingRuntimeFromGroup(group findings.Group) findingRuntimeGroup {
	finding := group.Finding
	item := findingRuntimeGroup{
		FindingID: finding.ID, HypothesisID: finding.HypothesisID, PathID: finding.PathID,
		AuditID: finding.AuditID, SnapshotID: finding.SnapshotID, Title: finding.Title,
		Severity: verify.NormalizeSeverity(finding.Severity), Status: finding.Status,
		Confidence: finding.Confidence, Supporting: nonNilStrings(finding.Supporting),
		Contradicting: nonNilStrings(finding.Contradicting), Inconclusive: nonNilStrings(finding.Inconclusive),
		Limitations: nonNilStrings(finding.Limitations), ReproduceSteps: finding.ReproduceSteps,
		CreatedAt: finding.CreatedAt, UpdatedAt: finding.UpdatedAt,
		Version: finding.Version, Fingerprint: group.Fingerprint, FingerprintVersion: group.FingerprintVersion,
		Sources: []findingRuntimeSource{}, SeverityAudit: group.SeverityAudit,
	}
	if item.SeverityAudit == nil {
		item.SeverityAudit = []findings.SeverityAudit{}
	}
	if len(group.Observations) == 0 {
		members := group.Members
		if len(members) == 0 {
			members = []verify.Finding{finding}
		}
		for _, member := range members {
			item.Sources = append(item.Sources, findingRuntimeSource{FindingID: member.ID, TaskID: member.AuditID, Status: member.Status})
		}
		return item
	}
	for _, observation := range group.Observations {
		scope, producer := observation.Scope, observation.Producer
		item.Sources = append(item.Sources, findingRuntimeSource{
			ObservationID: observation.ID, FindingID: observation.FindingID, Scope: &scope, TaskID: observation.TaskID,
			Producer: &producer, RuleID: observation.RuleID, RuleVersion: observation.RuleVersion, RuleFamily: observation.RuleFamily,
			Title: observation.Title, SeverityHint: observation.SeverityHint, Status: observation.Status,
			File: observation.File, Line: observation.Line, EndLine: observation.EndLine,
			EvidenceRefs: nonNilStrings(observation.EvidenceRefs), Limitations: nonNilStrings(observation.Limitations),
			CreatedAt: observation.CreatedAt,
		})
	}
	return item
}

func (s *Server) findingsUnavailable(w http.ResponseWriter) bool {
	if s.Findings == nil {
		writeError(w, http.StatusNotImplemented, "findings_unavailable", errors.New("the findings service is unavailable"))
		return true
	}
	return false
}

func (s *Server) findingProjectOwns(ctx context.Context, projectID, snapshotID string) bool {
	snapshots, err := s.Store.ListSnapshots(ctx, projectID)
	if err != nil {
		return false
	}
	for _, snapshot := range snapshots {
		if snapshot.SnapshotID == snapshotID {
			return true
		}
	}
	return false
}

func findingQuery(r *http.Request) (findings.ListQuery, error) {
	query := r.URL.Query()
	severity := strings.TrimSpace(query.Get("severity"))
	if severity != "" && severity != "high" && severity != "medium" && severity != "low" {
		return findings.ListQuery{}, errors.New("severity must be high, medium or low")
	}
	var status verify.FindingStatus
	if raw := strings.TrimSpace(query.Get("status")); raw != "" {
		status = verify.FindingStatus(raw)
		if !verify.ValidFindingStatus(status) {
			return findings.ListQuery{}, errors.New("unknown finding status")
		}
	}
	return findings.ListQuery{
		ProjectID: r.PathValue("projectID"),
		TaskID:    strings.TrimSpace(query.Get("task_id")),
		Severity:  severity,
		Status:    status,
		Limit:     min(pageLimit(query.Get("limit")), 200),
		Offset:    max(0, queryInt(query.Get("offset"), 0)),
	}, nil
}

func (s *Server) handleV1ProjectFindings(w http.ResponseWriter, r *http.Request) {
	if s.findingsUnavailable(w) {
		return
	}
	projectID := r.PathValue("projectID")
	if _, err := s.Store.GetProject(r.Context(), projectID); err != nil {
		writeStorageError(w, err)
		return
	}
	query, err := findingQuery(r)
	if err != nil {
		writeError(w, http.StatusBadRequest, "invalid_request", err)
		return
	}
	result, err := s.Findings.List(r.Context(), query)
	if err != nil {
		writeFindingsError(w, err)
		return
	}
	items := make([]findingRuntimeGroup, 0, len(result.Groups))
	for _, group := range result.Groups {
		items = append(items, findingRuntimeFromGroup(group))
	}
	writeFindingRuntimeJSON(w, http.StatusOK, map[string]any{
		"api_version":      "codexploit/v1",
		"findings":         items,
		"total":            result.Total,
		"counts":           result.Counts.Confirmed,
		"confirmed_counts": result.Counts.Confirmed,
		"candidate_counts": result.Counts.Candidate,
		"truncated":        result.Truncated,
	})
}

func (s *Server) handleV1Finding(w http.ResponseWriter, r *http.Request) {
	if s.findingsUnavailable(w) {
		return
	}
	group, err := s.Findings.Get(r.Context(), r.PathValue("findingID"))
	if err != nil {
		writeFindingsError(w, err)
		return
	}
	if !s.findingProjectOwns(r.Context(), r.PathValue("projectID"), group.Finding.SnapshotID) {
		writeFindingsError(w, findings.ErrNotFound)
		return
	}
	grouped, err := s.groupFindingEvidence(&group.Finding)
	if err != nil {
		writeVerifyError(w, err, group.Finding.ID)
		return
	}
	w.Header().Set("ETag", findingETag(&group.Finding))
	writeFindingRuntimeJSON(w, http.StatusOK, map[string]any{
		"api_version": "codexploit/v1",
		"finding":     findingRuntimeFromGroup(group),
		"evidence":    grouped,
	})
}

func (s *Server) handleV1GradeFinding(w http.ResponseWriter, r *http.Request) {
	if s.findingsUnavailable(w) {
		return
	}
	group, err := s.Findings.Get(r.Context(), r.PathValue("findingID"))
	if err != nil {
		writeFindingsError(w, err)
		return
	}
	if !s.findingProjectOwns(r.Context(), r.PathValue("projectID"), group.Finding.SnapshotID) {
		writeFindingsError(w, findings.ErrNotFound)
		return
	}
	if !requireEntityVersion(w, r, findingETag(&group.Finding)) {
		return
	}
	var request struct {
		Severity string `json:"severity"`
		Reason   string `json:"reason"`
	}
	if !s.decode(w, r, &request) {
		return
	}
	request.Reason = strings.TrimSpace(request.Reason)
	if request.Severity != "high" && request.Severity != "medium" && request.Severity != "low" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("severity must be high, medium or low"))
		return
	}
	if request.Reason == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("reason is required for a severity assessment"))
		return
	}
	updated, err := s.Findings.AssessSeverity(r.Context(), group.Finding.ID, request.Severity, request.Reason, principalName(r), group.Finding.Version)
	if err != nil {
		writeFindingsError(w, err)
		return
	}
	w.Header().Set("ETag", findingETag(&updated.Finding))
	writeFindingRuntimeJSON(w, http.StatusOK, map[string]any{
		"api_version": "codexploit/v1",
		"finding":     findingRuntimeFromGroup(updated),
	})
}
