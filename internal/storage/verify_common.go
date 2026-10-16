package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// This file holds the verification rules the two backends share.
//
// Keeping them in one place is what makes the memory and the SQL store behave
// identically: the implementations differ only in how a run, its immutable
// evidence and its findings are persisted, never in what an upsert changes or
// which listing a filter matches. The predicates here are the ones the SQL backend
// renders into its WHERE clauses, so the two cannot drift.

// verifyNow is the store-side clock of the verification layer. Run, evidence and
// finding timestamps are RFC3339 strings; the store fills a timestamp only when
// the caller left it empty, so a verifier that stamps its own changes keeps the
// exact values it wrote.
func verifyNow() string { return verify.NowString(time.Now().UTC()) }

// cloneVerification deep-copies a verification document through a JSON round trip.
// json is the copy discipline of this package: it keeps a stored document from
// aliasing a caller's slices and maps in both directions, so a caller may mutate
// whatever a getter handed it.
func cloneVerification[T any](value T) (T, error) {
	var out T
	data, err := json.Marshal(value)
	if err != nil {
		return out, fmt.Errorf("storage: encode verification document: %w", err)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("storage: decode verification document: %w", err)
	}
	return out, nil
}

// verificationJSON marshals a nested document for a TEXT column. A nil slice or
// map is stored as JSON null, so a document read back compares equal to the one
// written (nil stays nil, an empty collection stays empty).
func verificationJSON(value any) (string, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return "", fmt.Errorf("storage: encode verification document: %w", err)
	}
	return string(data), nil
}

// decodeVerificationJSON fills a nested document from a TEXT column. An empty
// column is left as the zero value.
func decodeVerificationJSON(raw string, target any) error {
	if raw == "" {
		return nil
	}
	if err := json.Unmarshal([]byte(raw), target); err != nil {
		return fmt.Errorf("storage: decode verification document: %w", err)
	}
	return nil
}

// sameEvidenceObject reports whether two evidence objects are the same stored
// object.
//
// The identity of evidence is its id, its content hash and its content: the id is
// derived from the content hash, and the hash is derived from the content, so those
// three are what a replay has to reproduce. Everything else — the timestamp, the
// provenance, the location — is metadata, which is why a verifier that rebuilds the
// same object with a fresh CreatedAt is re-appending evidence, not rewriting it.
//
// The direction that matters is the other one: the same id with a content hash or
// content that does not match is a conflict, because evidence that can be rewritten
// is not evidence. When the identity matches, the stored object stays authoritative,
// original timestamp included.
func sameEvidenceObject(a, b verify.Evidence) bool {
	return a.ID == b.ID && a.ContentHash == b.ContentHash && a.Content == b.Content
}

// prepareVerificationRun fills the derived identity and the timestamps a caller
// left empty. The plan and the environment are stored verbatim: the store derives
// only what the model says is derived.
//
// The caller's evidence list is deliberately dropped. `verification_runs` has no
// evidence column (migration 0008); the evidence table is the source of truth, so
// a run's evidence list is derived on read from the objects that name it. That is
// also what keeps a run from claiming evidence that was never stored.
func prepareVerificationRun(run verify.Run, now string) (verify.Run, error) {
	if strings.TrimSpace(run.ID) == "" {
		// A caller that forgot the id made a programming error, not a conflict with
		// stored state, and the API maps the two to different answers.
		return verify.Run{}, fmt.Errorf("%w: a verification run needs an id", verify.ErrInvalidArgument)
	}
	if run.PlanHash == "" {
		run.PlanHash = run.Plan.PlanHash
	}
	if run.PlanHash == "" {
		run.PlanHash = verify.PlanHashOf(run.Plan)
	}
	if run.EnvironmentDigest == "" {
		run.EnvironmentDigest = run.Environment.Digest()
	}
	if run.CreatedAt == "" {
		run.CreatedAt = now
	}
	if run.UpdatedAt == "" {
		run.UpdatedAt = run.CreatedAt
	}
	if run.Version < 1 {
		run.Version = 1
	}
	run.EvidenceIDs = nil
	return run, nil
}

// runPlanKey is the unique index of `verification_runs`: one plan for one
// hypothesis is one verification, so the pair identifies the attempt.
func runPlanKey(run verify.Run) string { return run.HypothesisID + "\x00" + run.PlanHash }

// prepareFinding fills the derived identity and the timestamps a caller left
// empty. A finding is the verdict about one hypothesis, so the hypothesis is the
// upsert key and the finding id is derived from it unless the caller supplied one.
func prepareFinding(finding verify.Finding, now string) (verify.Finding, error) {
	if strings.TrimSpace(finding.HypothesisID) == "" {
		return verify.Finding{}, fmt.Errorf("%w: a finding needs a hypothesis id; it is the key it is stored under", verify.ErrInvalidArgument)
	}
	if finding.ID == "" {
		finding.ID = verify.FindingID(finding.HypothesisID)
	}
	if finding.CreatedAt == "" {
		finding.CreatedAt = now
	}
	if finding.UpdatedAt == "" {
		finding.UpdatedAt = finding.CreatedAt
	}
	if finding.Version < 1 {
		finding.Version = 1
	}
	return finding, nil
}

// mergeFinding folds a re-upserted verdict into the row already stored for its
// hypothesis. The creation time of a finding is never rewritten by a later
// upsert, and the id must match: it is derived from the hypothesis, so a different
// id for the same hypothesis is a caller bug the store refuses instead of
// renaming a row that references already point at.
func mergeFinding(stored, incoming verify.Finding, now string) (verify.Finding, error) {
	if stored.ID != incoming.ID {
		return verify.Finding{}, fmt.Errorf("%w: the finding for hypothesis %s is already stored as %s",
			verify.ErrConflict, incoming.HypothesisID, stored.ID)
	}
	merged := incoming
	merged.CreatedAt = stored.CreatedAt
	if merged.UpdatedAt == "" {
		merged.UpdatedAt = now
	}
	// A caller that did not advance the counter still gets a fresh version: a
	// stored finding whose version never moves cannot be upserted concurrently.
	if merged.Version <= stored.Version {
		merged.Version = stored.Version + 1
	}
	return merged, nil
}

// mapVerifySQLError translates driver errors into the verification layer's
// vocabulary. The API answers with distinct codes for "no such run" and "lost the
// race", so the SQL backend may never leak storage.ErrNotFound for a run, an
// evidence object or a finding. The memory backend does not need it: it returns
// the verification sentinels directly.
func mapVerifySQLError(err error) error {
	mapped := mapSQLError(err)
	switch {
	case mapped == nil:
		return nil
	case errors.Is(mapped, ErrNotFound):
		return fmt.Errorf("%w: %v", verify.ErrNotFound, err)
	case errors.Is(mapped, ErrConflict):
		return fmt.Errorf("%w: %v", verify.ErrConflict, err)
	}
	return mapped
}

// containsVerificationStatus reports whether a status is one of the accepted values.
func containsVerificationStatus(list []verify.VerificationStatus, want verify.VerificationStatus) bool {
	for _, status := range list {
		if status == want {
			return true
		}
	}
	return false
}

// containsOutcome reports whether an outcome is one of the accepted values.
func containsOutcome(list []verify.Outcome, want verify.Outcome) bool {
	for _, outcome := range list {
		if outcome == want {
			return true
		}
	}
	return false
}

// containsEvidenceKind reports whether a kind is one of the accepted values.
func containsEvidenceKind(list []verify.EvidenceKind, want verify.EvidenceKind) bool {
	for _, kind := range list {
		if kind == want {
			return true
		}
	}
	return false
}

// containsFindingStatus reports whether a status is one of the accepted values.
func containsFindingStatus(list []verify.FindingStatus, want verify.FindingStatus) bool {
	for _, status := range list {
		if status == want {
			return true
		}
	}
	return false
}

// conclusiveFindingStatuses is the vocabulary of findings verification has
// settled. It is derived from FindingStatus.Conclusive, which stays the one place
// that decides what "settled" means, so the SQL filter cannot disagree with the
// memory predicate.
func conclusiveFindingStatuses() []verify.FindingStatus {
	out := []verify.FindingStatus{}
	for _, status := range verify.AllFindingStatuses() {
		if status.Conclusive() {
			out = append(out, status)
		}
	}
	return out
}

// matchesVerificationRunQuery applies the filters of a RunQuery to one run.
func matchesVerificationRunQuery(run verify.Run, q verify.RunQuery) bool {
	if q.HypothesisID != "" && run.HypothesisID != q.HypothesisID {
		return false
	}
	if q.FindingID != "" && run.FindingID != q.FindingID {
		return false
	}
	if q.PathID != "" && run.PathID != q.PathID {
		return false
	}
	if q.AuditID != "" && run.AuditID != q.AuditID {
		return false
	}
	if q.SnapshotID != "" && run.SnapshotID != q.SnapshotID {
		return false
	}
	if q.PlanHash != "" && run.PlanHash != q.PlanHash {
		return false
	}
	if len(q.Status) > 0 && !containsVerificationStatus(q.Status, run.Status) {
		return false
	}
	if len(q.Outcome) > 0 && !containsOutcome(q.Outcome, run.Outcome) {
		return false
	}
	return true
}

// matchesEvidenceQuery applies the filters of an EvidenceQuery to one object.
func matchesEvidenceQuery(object verify.Evidence, q verify.EvidenceQuery) bool {
	if q.SnapshotID != "" && object.SnapshotID != q.SnapshotID {
		return false
	}
	if q.HypothesisID != "" && object.HypothesisID != q.HypothesisID {
		return false
	}
	if q.FindingID != "" && object.FindingID != q.FindingID {
		return false
	}
	if q.PathID != "" && object.PathID != q.PathID {
		return false
	}
	if q.VerificationRunID != "" && object.VerificationRunID != q.VerificationRunID {
		return false
	}
	if len(q.Kinds) > 0 && !containsEvidenceKind(q.Kinds, object.Kind) {
		return false
	}
	return true
}

// matchesFindingQuery applies the filters of a FindingQuery to one verdict.
// ConclusiveOnly and CandidatesOnly are conjunctive, so asking for both answers
// with nothing: a candidate is by definition not settled.
func matchesFindingQuery(finding verify.Finding, q verify.FindingQuery) bool {
	if q.AuditID != "" && finding.AuditID != q.AuditID {
		return false
	}
	if q.SnapshotID != "" && finding.SnapshotID != q.SnapshotID {
		return false
	}
	if q.PathID != "" && finding.PathID != q.PathID {
		return false
	}
	if len(q.Status) > 0 && !containsFindingStatus(q.Status, finding.Status) {
		return false
	}
	if q.ConclusiveOnly && !finding.Status.Conclusive() {
		return false
	}
	if q.CandidatesOnly && finding.Status != verify.FindingCandidate {
		return false
	}
	return true
}

// sortVerificationRuns applies the documented listing order: creation time first,
// and the run id breaks ties so paging over an offset is stable. Timestamps are
// RFC3339 strings and are compared as strings, which is a time comparison for as
// long as every writer formats them the same way (verify.NowString).
func sortVerificationRuns(runs []verify.Run) {
	sort.SliceStable(runs, func(i, j int) bool {
		if runs[i].CreatedAt != runs[j].CreatedAt {
			return runs[i].CreatedAt < runs[j].CreatedAt
		}
		return runs[i].ID < runs[j].ID
	})
}

// sortEvidence orders a listing by creation time with the evidence id as the
// tie-breaker, matching the SQL ORDER BY.
func sortEvidence(evidence []verify.Evidence) {
	sort.SliceStable(evidence, func(i, j int) bool {
		if evidence[i].CreatedAt != evidence[j].CreatedAt {
			return evidence[i].CreatedAt < evidence[j].CreatedAt
		}
		return evidence[i].ID < evidence[j].ID
	})
}

// sortFindings orders a listing by creation time with the finding id as the
// tie-breaker, matching the SQL ORDER BY.
func sortFindings(findings []verify.Finding) {
	sort.SliceStable(findings, func(i, j int) bool {
		if findings[i].CreatedAt != findings[j].CreatedAt {
			return findings[i].CreatedAt < findings[j].CreatedAt
		}
		return findings[i].ID < findings[j].ID
	})
}
