package storage

import (
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

// This file holds the agent-runtime rules the two backends share.
//
// Keeping them in one place is what makes the memory and the SQL store behave
// identically: the implementations differ only in how the run, its event log and
// its hypotheses are persisted, never in which listing a filter matches or what
// an upsert changes. The predicates here are the ones the SQL backend renders
// into its WHERE clauses, so the two cannot drift.

// agentNow is the store-side clock of the agent runtime. Run and hypothesis
// timestamps are RFC3339 strings; the store fills a timestamp only when the
// caller left it empty, so an orchestrator that stamps its own changes keeps the
// exact values it wrote.
func agentNow() string { return agent.NowString(time.Now().UTC()) }

// cloneAgent deep-copies an agent document through a JSON round trip. json is
// the copy discipline of this package: it keeps a stored document from aliasing
// a caller's slices and maps in both directions, so GetRun can hand out a
// document a caller may mutate freely.
func cloneAgent[T any](value T) (T, error) {
	var out T
	data, err := json.Marshal(value)
	if err != nil {
		return out, fmt.Errorf("storage: encode agent document: %w", err)
	}
	if err := json.Unmarshal(data, &out); err != nil {
		return out, fmt.Errorf("storage: decode agent document: %w", err)
	}
	return out, nil
}

// mapAgentSQLError translates driver errors into the agent runtime's vocabulary.
// The API answers with distinct codes for "no such run" and "lost the race", so
// the SQL backend may never leak storage.ErrNotFound for a run, an event or a
// hypothesis. The memory backend does not need it: it returns the agent
// sentinels directly.
func mapAgentSQLError(err error) error {
	mapped := mapSQLError(err)
	switch {
	case mapped == nil:
		return nil
	case errors.Is(mapped, ErrNotFound):
		return fmt.Errorf("%w: %v", agent.ErrNotFound, err)
	case errors.Is(mapped, ErrConflict):
		return fmt.Errorf("%w: %v", agent.ErrConflict, err)
	}
	return mapped
}

// containsRunStatus reports whether a run status is one of the accepted values.
func containsRunStatus(list []agent.RunStatus, want agent.RunStatus) bool {
	for _, status := range list {
		if status == want {
			return true
		}
	}
	return false
}

// containsString reports whether a value is one of the accepted strings.
func containsString(list []string, want string) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

// matchesRunQuery applies the filters of a RunQuery to one run.
func matchesRunQuery(run agent.Run, q agent.RunQuery) bool {
	if q.PathID != "" && run.PathID != q.PathID {
		return false
	}
	if q.AuditID != "" && run.AuditID != q.AuditID {
		return false
	}
	if q.SnapshotID != "" && run.SnapshotID != q.SnapshotID {
		return false
	}
	if len(q.Status) > 0 && !containsRunStatus(q.Status, run.Status) {
		return false
	}
	return true
}

// matchesEventQuery applies the filters of an EventQuery to one event.
func matchesEventQuery(event agent.Event, q agent.EventQuery) bool {
	if q.RunID != "" && event.RunID != q.RunID {
		return false
	}
	if q.PathID != "" && event.PathID != q.PathID {
		return false
	}
	if len(q.Types) > 0 && !containsString(q.Types, event.Type) {
		return false
	}
	// AfterSeq is exclusive: a caller resuming a replay asks for the events that
	// follow the last sequence it saw.
	return event.Seq > q.AfterSeq
}

// matchesHypothesisQuery applies the filters of a HypothesisQuery to one claim.
func matchesHypothesisQuery(h agent.Hypothesis, q agent.HypothesisQuery) bool {
	if q.PathID != "" && h.PathID != q.PathID {
		return false
	}
	if q.AuditID != "" && h.AuditID != q.AuditID {
		return false
	}
	if q.SnapshotID != "" && h.SnapshotID != q.SnapshotID {
		return false
	}
	if q.RunID != "" && h.RunID != q.RunID {
		return false
	}
	if len(q.Status) > 0 && !containsString(q.Status, h.Status) {
		return false
	}
	// FindingCandidatesOnly is the verification phase's work list: a claim a run
	// flagged, whatever its status.
	if q.FindingCandidatesOnly && !h.FindingCandidate {
		return false
	}
	return true
}

// sortAgentRuns applies the documented listing order: creation time first, and
// the run id breaks ties so paging over an offset is stable. Timestamps are
// RFC3339 strings and are compared as strings, which is a time comparison for as
// long as every writer formats them the same way (agent.NowString).
func sortAgentRuns(runs []agent.Run) {
	sort.SliceStable(runs, func(i, j int) bool {
		if runs[i].CreatedAt != runs[j].CreatedAt {
			return runs[i].CreatedAt < runs[j].CreatedAt
		}
		return runs[i].ID < runs[j].ID
	})
}

// sortAgentEvents orders a listing by run and then by sequence, so a replay of
// one run is exactly its log order.
func sortAgentEvents(events []agent.Event) {
	sort.SliceStable(events, func(i, j int) bool {
		if events[i].RunID != events[j].RunID {
			return events[i].RunID < events[j].RunID
		}
		return events[i].Seq < events[j].Seq
	})
}

// sortAgentHypotheses orders a listing by creation time with the hypothesis id
// as the tie-breaker, matching the SQL ORDER BY.
func sortAgentHypotheses(hypotheses []agent.Hypothesis) {
	sort.SliceStable(hypotheses, func(i, j int) bool {
		if hypotheses[i].CreatedAt != hypotheses[j].CreatedAt {
			return hypotheses[i].CreatedAt < hypotheses[j].CreatedAt
		}
		return hypotheses[i].ID < hypotheses[j].ID
	})
}

// hypothesisKey is the upsert identity of a claim: inside one path a statement is
// one hypothesis, whatever else changed about it.
func hypothesisKey(pathID, digest string) string { return pathID + "\x00" + digest }

// prepareHypothesis fills the derived identity of a claim and the timestamps the
// caller left empty.
//
// The store does not re-validate the protocol: an answer is validated before a
// hypothesis exists (`agent.ValidateAnswer`), and the schema deliberately stores
// empty strings rather than rejecting them. What the store does derive is the
// identity, so a caller that only built the statement still upserts correctly.
func prepareHypothesis(h agent.Hypothesis, now string) agent.Hypothesis {
	if h.ID == "" {
		h.ID = agent.HypothesisID(h.PathID, h.Statement)
	}
	if h.Digest == "" {
		h.Digest = agent.Digest(h.Statement)
	}
	if h.CreatedAt == "" {
		h.CreatedAt = now
	}
	if h.UpdatedAt == "" {
		h.UpdatedAt = h.CreatedAt
	}
	return h
}

// mergeHypothesis folds a re-saved claim into the row already stored for its
// (path_id, digest). The creation time of a claim is never rewritten by a later
// save, and the id must match: both are derived from the claim, so a different id
// for the same claim is a caller bug the store refuses instead of renaming a row
// another run already points at.
func mergeHypothesis(storedID, storedCreatedAt string, incoming agent.Hypothesis, now string) (agent.Hypothesis, error) {
	if storedID != incoming.ID {
		return agent.Hypothesis{}, fmt.Errorf("%w: claim %s is already stored as %s", agent.ErrConflict, incoming.Digest, storedID)
	}
	merged := incoming
	merged.CreatedAt = storedCreatedAt
	if merged.UpdatedAt == "" {
		merged.UpdatedAt = now
	}
	return merged, nil
}

// newHypothesisEvent derives the run event that records a saved claim.
//
// SaveHypotheses takes hypotheses and no events, so the event log entry is
// derived here rather than supplied by the caller: a run's log has to show that
// the claim was recorded, and `agent.EventHypothesis` exists for exactly that.
func newHypothesisEvent(h agent.Hypothesis, seq int64, now string) agent.Event {
	createdAt := h.UpdatedAt
	if createdAt == "" {
		createdAt = now
	}
	return agent.Event{
		ID: agent.EventID(h.RunID, seq), RunID: h.RunID, PathID: h.PathID, Seq: seq,
		Type: agent.EventHypothesis, Actor: "agent", Summary: h.Statement,
		Detail: map[string]string{
			"hypothesis_id":     h.ID,
			"digest":            h.Digest,
			"status":            h.Status,
			"finding_candidate": strconv.FormatBool(h.FindingCandidate),
		},
		CreatedAt: createdAt,
	}
}
