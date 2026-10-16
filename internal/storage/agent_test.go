package storage

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
)

const (
	agentStoreSnapID       = "snap-0123456789abcdef0123456789abcdef"
	agentStoreOtherSnapID  = "snap-fedcba9876543210fedcba9876543210"
	agentStoreAbsentSnapID = "snap-00000000000000000000000000000000"
	agentStorePathID       = "path-00000000000000000000000000000001"
	agentStoreOtherPathID  = "path-00000000000000000000000000000002"
	agentStoreAuditID      = "audit-00000000000000000000000000000001"
	agentStoreOtherAuditID = "audit-00000000000000000000000000000002"
	agentStoreRunID        = "run-00000000000000000000000000000001"
	agentStoreOtherRunID   = "run-00000000000000000000000000000002"
	agentStoreAbsentRunID  = "run-000000000000000000000000000000ff"
)

// newAgentRunFixture builds a run whose task and answer carry every nested
// document the schema stores, so a codec that drops a column fails the
// comparison. Fixed timestamps and ids keep the fixture comparable across both
// backends.
func newAgentRunFixture(runID, pathID, auditID, snapshotID string) agent.Run {
	exit := 0
	task := agent.Task{
		SchemaVersion: agent.SchemaVersion,
		SnapshotID:    snapshotID, PathID: pathID, AuditID: auditID,
		SecurityGoal: "prevent SQL injection through the /search route",
		PathSummary:  "the handler copies the query parameter into a SQL string",
		SourceSinkRefs: agent.SourceSinkRefs{
			EntryNodeID: "asgn-entry-1", EntrySubject: "http_request",
			TargetNodeID: "asgn-sink-sql", TargetSubject: "sql_execution",
			Inputs: []string{"asgn-input-1"}, Controls: []string{"asgn-control-1"},
			Assets: []string{"asgn-asset-1"}, Boundaries: []string{"network"},
			SCGRefs: []string{"cs-1", "sym-1"}, ASGRefs: []string{"asgn-entry-1", "asgn-sink-sql"},
		},
		MinimalCodeSlice: []agent.SliceSection{
			{
				File: "internal/api/search.go", Symbol: "Search", StartLine: 10, EndLine: 24,
				Reason:  "the parameter reaches the query here",
				Content: "func Search(q string) { db.Query(\"SELECT * FROM t WHERE name = '\" + q + \"'\") }",
			},
			{
				File: "internal/db/query.go", Symbol: "Query", StartLine: 5, EndLine: 9,
				Reason: "the sink", Content: "func Query(sql string) { exec(sql) }",
			},
		},
		EvidenceRefs: []agent.EvidenceRef{
			{Kind: agent.EvidenceStatic, ID: "fact-1", Summary: "the route is public", File: "internal/api/router.go", Line: 42},
			{Kind: agent.EvidenceSource, ID: "fact-2", Summary: "the query is concatenated", File: "internal/api/search.go", Line: 17},
		},
		UnresolvedQuestions: []string{"is the parameter validated upstream?"},
		Exploration: agent.ExplorationPolicy{
			MaxHops: 3, MaxBranches: 2, MaxToolCalls: 12, MaxExpansions: 1,
			AllowedTools: []string{"read_file", "search_graph"}, TimeoutSeconds: 300,
			TokenBudget: 4096, MaxRepeatedOutputs: 3,
		},
		Budget:      agent.Budget{TimeoutSeconds: 300, TokenBudget: 4096},
		Limitations: []string{"dynamic dispatch is not resolved"},
		CreatedAt:   "2024-05-01T12:00:00Z",
	}
	return agent.Run{
		ID: runID, PathID: pathID, AuditID: auditID, SnapshotID: snapshotID,
		Runtime: "cli", RuntimeVersion: "1.2.3", Status: agent.RunSucceeded,
		Task: task, Exploration: task.Exploration, Budget: task.Budget,
		ToolCalls: 4, Expansions: 1, InputTokens: 1200, OutputTokens: 300, ElapsedMS: 12345,
		Owner: "worker-1", StartedAt: "2024-05-01T12:00:01Z", DeadlineAt: "2024-05-01T12:05:01Z",
		HeartbeatAt: "2024-05-01T12:04:00Z", FinishedAt: "2024-05-01T12:04:30Z",
		ExitCode: &exit, StopReason: agent.StopCompleted,
		Answer: &agent.Answer{
			SchemaVersion: agent.SchemaVersion,
			SecurityGoal:  task.SecurityGoal,
			Hypothesis: agent.HypothesisDraft{
				Statement: "the /search route is injectable through the q parameter",
				Status:    agent.HypothesisCandidate, Confidence: "medium",
			},
			SupportingEvidence: []agent.AnswerEvidence{
				{
					Kind: agent.EvidenceSource, Ref: "sym-search", File: "internal/api/search.go", Line: 17,
					Quote: "db.Query(\"SELECT * FROM t WHERE name = '\" + q + \"'\")", Summary: "the parameter is concatenated",
				},
			},
			ContradictingEvidence: []agent.AnswerEvidence{
				{Kind: agent.EvidenceRule, Ref: "rule-validate", Summary: "no upstream validation was found"},
			},
			NextAction: "verify with a request that contains a quote",
			RequestedExpansion: &agent.ExpansionAsk{
				TargetNodeID: "asgn-sink-exec", Purpose: "read the exec wrapper",
				ExpectedGain: "confirm the sink executes raw SQL", EstimatedCost: "one tool call",
				Hops: 1, ToolCalls: 1,
			},
			FindingCandidate: true, SeverityHint: "high",
			Notes: "the evidence is static only",
		},
		CreatedAt: "2024-05-01T12:00:00Z", UpdatedAt: "2024-05-01T12:04:30Z", Version: 3,
	}
}

// newAgentHypothesisFixture builds a claim with both evidence lists populated.
func newAgentHypothesisFixture(run agent.Run, statement, status, confidence string, findingCandidate bool) agent.Hypothesis {
	return agent.Hypothesis{
		ID:    agent.HypothesisID(run.PathID, statement),
		RunID: run.ID, PathID: run.PathID, AuditID: run.AuditID, SnapshotID: run.SnapshotID,
		SecurityGoal: run.Task.SecurityGoal,
		Statement:    statement, Status: status, Confidence: confidence,
		Supporting: []agent.EvidenceRef{
			{Kind: agent.EvidenceSource, ID: "sym-search", Summary: "the parameter is concatenated", File: "internal/api/search.go", Line: 17},
		},
		Contradicting: []agent.EvidenceRef{
			{Kind: agent.EvidenceRule, ID: "rule-1", Summary: "no sanitizer was found"},
		},
		NextAction: "verify with a quote in the parameter", FindingCandidate: findingCandidate, SeverityHint: "high",
		Digest: agent.Digest(statement), CreatedAt: "2024-05-01T12:00:00Z", UpdatedAt: "2024-05-01T12:00:00Z",
	}
}

func seedAgentRun(t *testing.T, store FullStore, run agent.Run) agent.Run {
	t.Helper()
	if err := store.CreateRun(run); err != nil {
		t.Fatalf("CreateRun(%s): %v", run.ID, err)
	}
	return run
}

func mustGetAgentRun(t *testing.T, store FullStore, runID string) agent.Run {
	t.Helper()
	run, err := store.GetRun(runID)
	if err != nil {
		t.Fatalf("GetRun(%s): %v", runID, err)
	}
	return *run
}

func mustGetHypothesis(t *testing.T, store FullStore, hypothesisID string) agent.Hypothesis {
	t.Helper()
	h, err := store.GetHypothesis(hypothesisID)
	if err != nil {
		t.Fatalf("GetHypothesis(%s): %v", hypothesisID, err)
	}
	return *h
}

func mustListRunEvents(t *testing.T, store FullStore, q agent.EventQuery) []agent.Event {
	t.Helper()
	events, err := store.ListRunEvents(q)
	if err != nil {
		t.Fatalf("ListRunEvents(%+v): %v", q, err)
	}
	return events
}

func mustListHypotheses(t *testing.T, store FullStore, q agent.HypothesisQuery) ([]agent.Hypothesis, int) {
	t.Helper()
	hypotheses, total, err := store.ListHypotheses(q)
	if err != nil {
		t.Fatalf("ListHypotheses(%+v): %v", q, err)
	}
	return hypotheses, total
}

func agentRunIDs(runs []agent.Run) []string {
	out := make([]string, 0, len(runs))
	for _, run := range runs {
		out = append(out, run.ID)
	}
	return out
}

func agentEventSeqs(events []agent.Event) []int64 {
	out := make([]int64, 0, len(events))
	for _, event := range events {
		out = append(out, event.Seq)
	}
	return out
}

func TestAgentRunRoundTrip(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			want := newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID)
			if err := store.CreateRun(want); err != nil {
				t.Fatalf("CreateRun: %v", err)
			}
			if err := store.CreateRun(want); !errors.Is(err, agent.ErrConflict) {
				t.Errorf("CreateRun twice = %v, want agent.ErrConflict", err)
			}
			if got := mustGetAgentRun(t, store, agentStoreRunID); !reflect.DeepEqual(got, want) {
				t.Errorf("GetRun = %+v, want %+v", got, want)
			}
			for _, absent := range []string{agentStoreAbsentRunID, ""} {
				if _, err := store.GetRun(absent); !errors.Is(err, agent.ErrNotFound) {
					t.Errorf("GetRun(%q) = %v, want agent.ErrNotFound", absent, err)
				}
			}
			// A returned document is a copy: mutating it cannot reach the store.
			mutated := mustGetAgentRun(t, store, agentStoreRunID)
			mutated.Task.MinimalCodeSlice[0].Content = "mutated"
			mutated.Answer.Notes = "mutated"
			mutated.Task.EvidenceRefs[0].Summary = "mutated"
			if got := mustGetAgentRun(t, store, agentStoreRunID); !reflect.DeepEqual(got, want) {
				t.Errorf("a caller mutated the stored run: %+v", got.Task.MinimalCodeSlice)
			}

			// UpdateRun without a version check still advances the counter, and
			// the stale expected version is refused.
			updated := want
			updated.Status = agent.RunFailed
			updated.StopReason = agent.StopAdapterFailed
			updated.Error = "the adapter exited"
			if err := store.UpdateRun(updated, 0); err != nil {
				t.Fatalf("UpdateRun without a version check: %v", err)
			}
			afterFirst := mustGetAgentRun(t, store, agentStoreRunID)
			if afterFirst.Version != want.Version+1 || afterFirst.Status != agent.RunFailed || afterFirst.Error != "the adapter exited" {
				t.Errorf("UpdateRun stored %+v", afterFirst)
			}
			if err := store.UpdateRun(updated, want.Version); !errors.Is(err, agent.ErrConflict) {
				t.Errorf("UpdateRun with a stale version = %v, want agent.ErrConflict", err)
			}
			if got := mustGetAgentRun(t, store, agentStoreRunID); !reflect.DeepEqual(got, afterFirst) {
				t.Errorf("a refused update altered the row: %+v", got)
			}
			if err := store.UpdateRun(updated, afterFirst.Version); err != nil {
				t.Fatalf("UpdateRun with the current version: %v", err)
			}
			if got := mustGetAgentRun(t, store, agentStoreRunID); got.Version != afterFirst.Version+1 {
				t.Errorf("UpdateRun version = %d, want %d", got.Version, afterFirst.Version+1)
			}
			absent := newAgentRunFixture(agentStoreAbsentRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID)
			if err := store.UpdateRun(absent, 0); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("UpdateRun(absent) = %v, want agent.ErrNotFound", err)
			}
		})
	}
}

func TestAgentRunListingFilters(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			first := newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID)
			first.CreatedAt = "2024-05-01T12:00:01Z"
			second := newAgentRunFixture(agentStoreOtherRunID, agentStoreOtherPathID, agentStoreAuditID, agentStoreSnapID)
			second.CreatedAt, second.Status = "2024-05-01T12:00:02Z", agent.RunRunning
			third := newAgentRunFixture("run-00000000000000000000000000000003", agentStorePathID, agentStoreOtherAuditID, agentStoreOtherSnapID)
			third.CreatedAt, third.Status = "2024-05-01T12:00:03Z", agent.RunFailed
			for _, run := range []agent.Run{first, second, third} {
				seedAgentRun(t, store, run)
			}

			all, total, err := store.ListRuns(agent.RunQuery{})
			if err != nil || total != 3 || len(all) != 3 {
				t.Fatalf("ListRuns = %d/%d, %v", len(all), total, err)
			}
			// Creation order, with the run id breaking ties.
			if ids := agentRunIDs(all); !reflect.DeepEqual(ids, []string{first.ID, second.ID, third.ID}) {
				t.Errorf("ListRuns order = %v", ids)
			}
			page, total, err := store.ListRuns(agent.RunQuery{Limit: 1, Offset: 1})
			if err != nil || total != 3 || len(page) != 1 || page[0].ID != second.ID {
				t.Errorf("ListRuns paged = %v/%d, %v", agentRunIDs(page), total, err)
			}

			for _, check := range []struct {
				name string
				q    agent.RunQuery
				want []string
			}{
				{"path", agent.RunQuery{PathID: agentStorePathID}, []string{first.ID, third.ID}},
				{"other path", agent.RunQuery{PathID: agentStoreOtherPathID}, []string{second.ID}},
				{"audit", agent.RunQuery{AuditID: agentStoreAuditID}, []string{first.ID, second.ID}},
				{"snapshot", agent.RunQuery{SnapshotID: agentStoreOtherSnapID}, []string{third.ID}},
				{"status", agent.RunQuery{Status: []agent.RunStatus{agent.RunFailed}}, []string{third.ID}},
				{"two statuses", agent.RunQuery{Status: []agent.RunStatus{agent.RunSucceeded, agent.RunRunning}}, []string{first.ID, second.ID}},
				{"absent snapshot", agent.RunQuery{SnapshotID: agentStoreAbsentSnapID}, []string{}},
				{"absent status", agent.RunQuery{Status: []agent.RunStatus{agent.RunTimedOut}}, []string{}},
				{"path and status", agent.RunQuery{PathID: agentStorePathID, Status: []agent.RunStatus{agent.RunFailed}}, []string{third.ID}},
			} {
				runs, total, err := store.ListRuns(check.q)
				if err != nil {
					t.Fatalf("ListRuns(%s): %v", check.name, err)
				}
				if total != len(check.want) || len(runs) != len(check.want) {
					t.Errorf("ListRuns(%s) = %d/%d, want %d", check.name, len(runs), total, len(check.want))
					continue
				}
				if ids := agentRunIDs(runs); !reflect.DeepEqual(ids, check.want) {
					t.Errorf("ListRuns(%s) = %v, want %v", check.name, ids, check.want)
				}
			}
		})
	}
}

func TestAgentRunDocumentSurvivesTheRoundTrip(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			want := newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID)
			seedAgentRun(t, store, want)
			got := mustGetAgentRun(t, store, agentStoreRunID)
			for _, check := range []struct {
				name      string
				got, want any
			}{
				{"task", got.Task, want.Task},
				{"exploration policy", got.Exploration, want.Exploration},
				{"budget", got.Budget, want.Budget},
			} {
				if !reflect.DeepEqual(check.got, check.want) {
					t.Errorf("%s did not survive the round trip:\ngot  %+v\nwant %+v", check.name, check.got, check.want)
				}
			}
			if got.Answer == nil {
				t.Fatal("the answer did not survive the round trip")
			}
			if !reflect.DeepEqual(*got.Answer, *want.Answer) {
				t.Errorf("answer = %+v, want %+v", *got.Answer, *want.Answer)
			}
			if got.Answer.RequestedExpansion == nil ||
				!reflect.DeepEqual(*got.Answer.RequestedExpansion, *want.Answer.RequestedExpansion) {
				t.Errorf("requested expansion = %+v", got.Answer.RequestedExpansion)
			}
			if got.Task.MinimalCodeSlice[1].Content != want.Task.MinimalCodeSlice[1].Content {
				t.Errorf("the slice sections lost their content")
			}
			if got.ExitCode == nil || *got.ExitCode != 0 {
				t.Errorf("exit code = %v", got.ExitCode)
			}

			// A run without an answer and without an exit code keeps both nil,
			// and a nil collection stays nil rather than becoming empty.
			bare := newAgentRunFixture(agentStoreOtherRunID, agentStoreOtherPathID, agentStoreAuditID, agentStoreSnapID)
			bare.Answer, bare.ExitCode = nil, nil
			bare.Task.MinimalCodeSlice, bare.Task.EvidenceRefs = nil, nil
			seedAgentRun(t, store, bare)
			gotBare := mustGetAgentRun(t, store, agentStoreOtherRunID)
			if gotBare.Answer != nil || gotBare.ExitCode != nil {
				t.Errorf("bare run = %+v", gotBare)
			}
			if gotBare.Task.MinimalCodeSlice != nil || gotBare.Task.EvidenceRefs != nil {
				t.Errorf("nil collections came back non-nil: %+v", gotBare.Task)
			}
			if !reflect.DeepEqual(gotBare, bare) {
				t.Errorf("bare run = %+v, want %+v", gotBare, bare)
			}
		})
	}
}

func TestAgentRunEventLog(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := seedAgentRun(t, store, newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID))
			if seq, err := store.NextRunEventSeq(run.ID); err != nil || seq != 1 {
				t.Fatalf("NextRunEventSeq on an empty log = %d, %v", seq, err)
			}
			appended := []agent.Event{
				{RunID: run.ID, PathID: run.PathID, Seq: 1, Type: agent.EventRunCreated, Actor: "orchestrator", Summary: "run created"},
				{
					RunID: run.ID, PathID: run.PathID, Seq: 2, Type: agent.EventToolRequested, Actor: "agent",
					CallID: "call-1", Tool: "read_file", Detail: map[string]string{"file": "internal/api/search.go"},
				},
				{
					RunID: run.ID, PathID: run.PathID, Seq: 3, Type: agent.EventToolResult, Actor: "orchestrator",
					CallID: "call-1", Tool: "read_file", Detail: map[string]string{"ok": "true", "result": "func Search(q string)"},
				},
			}
			if err := store.AppendRunEvents(appended); err != nil {
				t.Fatalf("AppendRunEvents: %v", err)
			}
			events := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID})
			if seqs := agentEventSeqs(events); !reflect.DeepEqual(seqs, []int64{1, 2, 3}) {
				t.Fatalf("ListRunEvents sequences = %v, want [1 2 3]", seqs)
			}
			if events[0].ID != agent.EventID(run.ID, 1) {
				t.Errorf("a missing event id was not derived: %q", events[0].ID)
			}
			if events[1].Detail["file"] != "internal/api/search.go" || events[2].Detail["ok"] != "true" {
				t.Errorf("event details did not survive: %+v", events)
			}
			if events[0].CreatedAt == "" {
				t.Error("a missing event timestamp was not stamped")
			}
			if _, err := store.NextRunEventSeq(run.ID); err != nil {
				t.Fatalf("NextRunEventSeq: %v", err)
			}
			if seq, err := store.NextRunEventSeq(run.ID); err != nil || seq != 4 {
				t.Errorf("NextRunEventSeq = %d, %v, want 4", seq, err)
			}
			if after := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID, AfterSeq: 1}); !reflect.DeepEqual(agentEventSeqs(after), []int64{2, 3}) {
				t.Errorf("AfterSeq = %v", agentEventSeqs(after))
			}
			if typed := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID, Types: []string{agent.EventToolResult}}); len(typed) != 1 || typed[0].Type != agent.EventToolResult {
				t.Errorf("Types filter = %+v", typed)
			}
			if both := mustListRunEvents(t, store, agent.EventQuery{
				RunID: run.ID, Types: []string{agent.EventToolRequested, agent.EventToolResult},
			}); len(both) != 2 {
				t.Errorf("Types filter with two values = %+v", both)
			}
			if byPath := mustListRunEvents(t, store, agent.EventQuery{PathID: run.PathID}); len(byPath) != 3 {
				t.Errorf("PathID filter = %+v", byPath)
			}
			if none := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID, AfterSeq: 99}); len(none) != 0 {
				t.Errorf("AfterSeq past the log = %+v", none)
			}
			if none := mustListRunEvents(t, store, agent.EventQuery{RunID: agentStoreAbsentRunID}); len(none) != 0 {
				t.Errorf("events of an absent run = %+v", none)
			}

			// A reused sequence is refused, alone and inside one batch, and the
			// refused batch leaves nothing behind.
			if err := store.AppendRunEvents([]agent.Event{
				{RunID: run.ID, PathID: run.PathID, Seq: 2, Type: agent.EventRunHeartbeat},
			}); !errors.Is(err, agent.ErrConflict) {
				t.Errorf("duplicate sequence = %v, want agent.ErrConflict", err)
			}
			if err := store.AppendRunEvents([]agent.Event{
				{RunID: run.ID, PathID: run.PathID, Seq: 4, Type: agent.EventRunHeartbeat},
				{RunID: run.ID, PathID: run.PathID, Seq: 4, Type: agent.EventRunHeartbeat},
			}); !errors.Is(err, agent.ErrConflict) {
				t.Errorf("duplicate sequence inside one batch = %v, want agent.ErrConflict", err)
			}
			if err := store.AppendRunEvents([]agent.Event{
				{RunID: run.ID, PathID: run.PathID, Seq: 1, Type: agent.EventRunHeartbeat},
			}); !errors.Is(err, agent.ErrConflict) {
				t.Errorf("a sequence that goes backwards = %v, want agent.ErrConflict", err)
			}
			if still := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID}); len(still) != 3 {
				t.Errorf("a refused batch wrote %d events", len(still))
			}
			if seq, err := store.NextRunEventSeq(run.ID); err != nil || seq != 4 {
				t.Errorf("NextRunEventSeq after refused batches = %d, %v, want 4", seq, err)
			}

			// An explicitly supplied event id is kept.
			if err := store.AppendRunEvents([]agent.Event{
				{ID: "aev-explicit", RunID: run.ID, PathID: run.PathID, Seq: 4, Type: agent.EventRunFinished},
			}); err != nil {
				t.Fatalf("AppendRunEvents with an explicit id: %v", err)
			}
			all := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID})
			if len(all) != 4 || all[3].ID != "aev-explicit" {
				t.Errorf("explicit event id = %+v", all)
			}
			if seq, err := store.NextRunEventSeq(run.ID); err != nil || seq != 5 {
				t.Errorf("NextRunEventSeq = %d, %v, want 5", seq, err)
			}

			// Events of another run are ordered after this run's, and a missing
			// run is refused rather than silently accepted.
			other := seedAgentRun(t, store, newAgentRunFixture(agentStoreOtherRunID, agentStoreOtherPathID, agentStoreAuditID, agentStoreSnapID))
			if err := store.AppendRunEvents([]agent.Event{
				{RunID: other.ID, PathID: other.PathID, Seq: 1, Type: agent.EventRunCreated, Actor: "orchestrator"},
			}); err != nil {
				t.Fatalf("AppendRunEvents on the second run: %v", err)
			}
			combined := mustListRunEvents(t, store, agent.EventQuery{})
			if len(combined) != 5 {
				t.Fatalf("ListRunEvents = %d events, want 5", len(combined))
			}
			for i := 1; i < len(combined); i++ {
				previous, current := combined[i-1], combined[i]
				if previous.RunID > current.RunID || (previous.RunID == current.RunID && previous.Seq >= current.Seq) {
					t.Fatalf("ListRunEvents is not ordered by run and sequence: %+v -> %+v", previous, current)
				}
			}
			if err := store.AppendRunEvents([]agent.Event{
				{RunID: agentStoreAbsentRunID, PathID: agentStorePathID, Seq: 1, Type: agent.EventRunCreated},
			}); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("AppendRunEvents for an absent run = %v, want agent.ErrNotFound", err)
			}
			if _, err := store.NextRunEventSeq(agentStoreAbsentRunID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("NextRunEventSeq(absent) = %v, want agent.ErrNotFound", err)
			}
		})
	}
}

func TestAgentHypothesesUpsert(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := seedAgentRun(t, store, newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID))
			otherRun := seedAgentRun(t, store, newAgentRunFixture(agentStoreOtherRunID, agentStoreOtherPathID, agentStoreOtherAuditID, agentStoreOtherSnapID))

			statement := "the q parameter reaches the SQL sink without parameterization"
			first := newAgentHypothesisFixture(run, statement, agent.HypothesisCandidate, "low", true)
			first.CreatedAt, first.UpdatedAt = "2024-05-01T12:00:01Z", "2024-05-01T12:00:01Z"
			if err := store.SaveHypotheses([]agent.Hypothesis{first}); err != nil {
				t.Fatalf("SaveHypotheses: %v", err)
			}
			if got := mustGetHypothesis(t, store, first.ID); !reflect.DeepEqual(got, first) {
				t.Errorf("GetHypothesis = %+v, want %+v", got, first)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{PathID: agentStorePathID}); total != 1 {
				t.Fatalf("ListHypotheses = %d, want 1", total)
			}

			// The same statement saved again updates the row instead of adding one,
			// and the creation time of the claim is not rewritten.
			updated := first
			updated.Confidence, updated.Status = "high", agent.HypothesisInconclusive
			updated.NextAction, updated.UpdatedAt = "verify with a quote in the parameter", "2024-05-01T13:00:00Z"
			if err := store.SaveHypotheses([]agent.Hypothesis{updated}); err != nil {
				t.Fatalf("SaveHypotheses (update): %v", err)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{PathID: agentStorePathID}); total != 1 {
				t.Fatalf("a re-saved statement duplicated the row: total %d", total)
			}
			got := mustGetHypothesis(t, store, first.ID)
			if got.Confidence != "high" || got.Status != agent.HypothesisInconclusive || got.NextAction != "verify with a quote in the parameter" {
				t.Errorf("the update was not applied: %+v", got)
			}
			if got.CreatedAt != first.CreatedAt || got.UpdatedAt != "2024-05-01T13:00:00Z" {
				t.Errorf("the update rewrote the timestamps: %+v", got)
			}
			if !reflect.DeepEqual(got.Supporting, first.Supporting) || !reflect.DeepEqual(got.Contradicting, first.Contradicting) {
				t.Errorf("the evidence lists did not survive: %+v", got)
			}

			// A different statement is a second row, and the store derives the
			// identity when the caller omits it.
			second := newAgentHypothesisFixture(run, "the sink executes raw SQL", agent.HypothesisCandidate, "medium", false)
			second.ID, second.Digest = "", ""
			second.CreatedAt, second.UpdatedAt = "2024-05-01T12:00:02Z", "2024-05-01T12:00:02Z"
			if err := store.SaveHypotheses([]agent.Hypothesis{second}); err != nil {
				t.Fatalf("SaveHypotheses (derived identity): %v", err)
			}
			derivedID := agent.HypothesisID(agentStorePathID, second.Statement)
			derived := mustGetHypothesis(t, store, derivedID)
			if derived.Digest != agent.Digest(second.Statement) {
				t.Errorf("derived digest = %q", derived.Digest)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{PathID: agentStorePathID}); total != 2 {
				t.Errorf("a different statement did not create a row")
			}

			third := newAgentHypothesisFixture(otherRun, "the exec wrapper is reachable", agent.HypothesisCandidate, "low", true)
			third.CreatedAt, third.UpdatedAt = "2024-05-01T12:00:03Z", "2024-05-01T12:00:03Z"
			if err := store.SaveHypotheses([]agent.Hypothesis{third}); err != nil {
				t.Fatalf("SaveHypotheses (second run): %v", err)
			}

			for _, check := range []struct {
				name string
				q    agent.HypothesisQuery
				want int
			}{
				{"all", agent.HypothesisQuery{}, 3},
				{"path", agent.HypothesisQuery{PathID: agentStorePathID}, 2},
				{"other path", agent.HypothesisQuery{PathID: agentStoreOtherPathID}, 1},
				{"audit", agent.HypothesisQuery{AuditID: agentStoreAuditID}, 2},
				{"snapshot", agent.HypothesisQuery{SnapshotID: agentStoreOtherSnapID}, 1},
				{"run", agent.HypothesisQuery{RunID: otherRun.ID}, 1},
				{"status candidate", agent.HypothesisQuery{Status: []string{agent.HypothesisCandidate}}, 2},
				{"status inconclusive", agent.HypothesisQuery{Status: []string{agent.HypothesisInconclusive}}, 1},
				{"finding candidates", agent.HypothesisQuery{FindingCandidatesOnly: true}, 2},
				{"candidate finding candidates", agent.HypothesisQuery{Status: []string{agent.HypothesisCandidate}, FindingCandidatesOnly: true}, 1},
				{"absent snapshot", agent.HypothesisQuery{SnapshotID: agentStoreAbsentSnapID}, 0},
				{"absent status", agent.HypothesisQuery{Status: []string{agent.HypothesisConfirmed}}, 0},
			} {
				hypotheses, total := mustListHypotheses(t, store, check.q)
				if total != check.want || len(hypotheses) != check.want {
					t.Errorf("ListHypotheses(%s) = %d/%d, want %d", check.name, len(hypotheses), total, check.want)
				}
			}
			// Creation order, with the hypothesis id breaking ties.
			all, total := mustListHypotheses(t, store, agent.HypothesisQuery{})
			if total != 3 {
				t.Fatalf("ListHypotheses total = %d, want 3", total)
			}
			if all[0].ID != first.ID || all[1].ID != derivedID || all[2].ID != third.ID {
				t.Errorf("ListHypotheses order = %q, %q, %q", all[0].ID, all[1].ID, all[2].ID)
			}
			if paged, total := mustListHypotheses(t, store, agent.HypothesisQuery{Limit: 1, Offset: 2}); total != 3 || len(paged) != 1 || paged[0].ID != third.ID {
				t.Errorf("ListHypotheses paged = %+v/%d", paged, total)
			}
			if _, err := store.GetHypothesis("hyp-absent"); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("GetHypothesis(absent) = %v, want agent.ErrNotFound", err)
			}

			// Renaming the row of an existing claim, or reusing its id for another
			// claim, is a conflict: the identity of a claim is derived from it.
			renamed := first
			renamed.ID = "hyp-hand-made"
			if err := store.SaveHypotheses([]agent.Hypothesis{renamed}); !errors.Is(err, agent.ErrConflict) {
				t.Errorf("renaming a stored claim = %v, want agent.ErrConflict", err)
			}
			reused := newAgentHypothesisFixture(run, "another claim entirely", agent.HypothesisCandidate, "low", false)
			reused.ID = derivedID
			if err := store.SaveHypotheses([]agent.Hypothesis{reused}); !errors.Is(err, agent.ErrConflict) {
				t.Errorf("reusing a stored hypothesis id = %v, want agent.ErrConflict", err)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{PathID: agentStorePathID}); total != 2 {
				t.Errorf("a refused save added a row: total %d", total)
			}
		})
	}
}

// TestSaveHypothesesAppendsTheHypothesisEvent pins the contract's "appends the
// hypothesis events in the same transaction": SaveHypotheses takes claims and no
// events, so the store derives the run event that records the save.
func TestSaveHypothesesAppendsTheHypothesisEvent(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := seedAgentRun(t, store, newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID))
			if err := store.AppendRunEvents([]agent.Event{
				{RunID: run.ID, PathID: run.PathID, Seq: 1, Type: agent.EventRunStarted, Actor: "orchestrator", Summary: "run started"},
			}); err != nil {
				t.Fatalf("AppendRunEvents: %v", err)
			}
			claim := newAgentHypothesisFixture(run, "the q parameter reaches the sink", agent.HypothesisCandidate, "medium", true)
			if err := store.SaveHypotheses([]agent.Hypothesis{claim}); err != nil {
				t.Fatalf("SaveHypotheses: %v", err)
			}
			events := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID, Types: []string{agent.EventHypothesis}})
			if len(events) != 1 {
				t.Fatalf("hypothesis events = %+v, want exactly one", events)
			}
			event := events[0]
			if event.Seq != 2 || event.PathID != run.PathID || event.Actor != "agent" {
				t.Errorf("hypothesis event = %+v", event)
			}
			if event.Summary != claim.Statement {
				t.Errorf("hypothesis event summary = %q", event.Summary)
			}
			if event.Detail["hypothesis_id"] != claim.ID || event.Detail["digest"] != claim.Digest || event.Detail["status"] != claim.Status {
				t.Errorf("hypothesis event detail = %+v", event.Detail)
			}
			if seq, err := store.NextRunEventSeq(run.ID); err != nil || seq != 3 {
				t.Errorf("NextRunEventSeq = %d, %v, want 3", seq, err)
			}

			// A claim that names no run has no log to write to; it is still stored.
			orphan := newAgentHypothesisFixture(run, "a claim without a run", agent.HypothesisCandidate, "low", false)
			orphan.RunID, orphan.ID, orphan.Digest = "", "", ""
			if err := store.SaveHypotheses([]agent.Hypothesis{orphan}); err != nil {
				t.Fatalf("SaveHypotheses (no run): %v", err)
			}
			if got := mustGetHypothesis(t, store, agent.HypothesisID(agentStorePathID, orphan.Statement)); got.RunID != "" {
				t.Errorf("orphan claim = %+v", got)
			}
			if events := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID}); len(events) != 2 {
				t.Errorf("an orphan claim added %d events", len(events)-2)
			}
			if seq, err := store.NextRunEventSeq(run.ID); err != nil || seq != 3 {
				t.Errorf("NextRunEventSeq after an orphan claim = %d, %v", seq, err)
			}

			// A batch that names a missing run writes neither the earlier claims
			// nor their events.
			valid := newAgentHypothesisFixture(run, "an atomic claim", agent.HypothesisCandidate, "low", false)
			valid.ID, valid.Digest = "", ""
			broken := newAgentHypothesisFixture(run, "a claim of a missing run", agent.HypothesisCandidate, "low", false)
			broken.ID, broken.Digest, broken.RunID = "", "", agentStoreAbsentRunID
			if err := store.SaveHypotheses([]agent.Hypothesis{valid, broken}); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("SaveHypotheses with a missing run = %v, want agent.ErrNotFound", err)
			}
			if _, err := store.GetHypothesis(agent.HypothesisID(agentStorePathID, valid.Statement)); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("a refused batch stored a claim: %v", err)
			}
			if events := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID}); len(events) != 2 {
				t.Errorf("a refused batch wrote events: %+v", events)
			}
		})
	}
}

func TestDeleteRunsForSnapshot(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			run := seedAgentRun(t, store, newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID))
			otherRun := seedAgentRun(t, store, newAgentRunFixture(agentStoreOtherRunID, agentStoreOtherPathID, agentStoreOtherAuditID, agentStoreOtherSnapID))
			for _, seed := range []agent.Run{run, otherRun} {
				if err := store.AppendRunEvents([]agent.Event{
					{RunID: seed.ID, PathID: seed.PathID, Seq: 1, Type: agent.EventRunCreated, Actor: "orchestrator"},
				}); err != nil {
					t.Fatalf("AppendRunEvents(%s): %v", seed.ID, err)
				}
			}
			claim := newAgentHypothesisFixture(run, "the q parameter reaches the sink", agent.HypothesisCandidate, "low", true)
			otherClaim := newAgentHypothesisFixture(otherRun, "the exec wrapper is reachable", agent.HypothesisCandidate, "low", true)
			if err := store.SaveHypotheses([]agent.Hypothesis{claim, otherClaim}); err != nil {
				t.Fatalf("SaveHypotheses: %v", err)
			}
			// A claim cannot outlive the run that made it, even if its snapshot id
			// was written wrong.
			misTagged := newAgentHypothesisFixture(run, "a claim tagged with the wrong snapshot", agent.HypothesisCandidate, "low", false)
			misTagged.SnapshotID = agentStoreOtherSnapID
			if err := store.SaveHypotheses([]agent.Hypothesis{misTagged}); err != nil {
				t.Fatalf("SaveHypotheses (mis-tagged): %v", err)
			}

			if removed, err := store.DeleteRunsForSnapshot(agentStoreAbsentSnapID); err != nil || removed != 0 {
				t.Errorf("DeleteRunsForSnapshot(absent) = %d, %v", removed, err)
			}
			removed, err := store.DeleteRunsForSnapshot(agentStoreSnapID)
			if err != nil || removed != 1 {
				t.Fatalf("DeleteRunsForSnapshot = %d, %v, want 1", removed, err)
			}
			if _, err := store.GetRun(run.ID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("the run survived: %v", err)
			}
			if events := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID}); len(events) != 0 {
				t.Errorf("the events survived: %+v", events)
			}
			if _, err := store.NextRunEventSeq(run.ID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("NextRunEventSeq after deletion = %v, want agent.ErrNotFound", err)
			}
			if _, err := store.GetHypothesis(claim.ID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("the claim survived: %v", err)
			}
			if _, err := store.GetHypothesis(misTagged.ID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("a claim of a deleted run survived: %v", err)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{SnapshotID: agentStoreSnapID}); total != 0 {
				t.Errorf("ListHypotheses after deletion = %d, want 0", total)
			}

			// The other snapshot is untouched.
			if got := mustGetAgentRun(t, store, otherRun.ID); got.ID != otherRun.ID {
				t.Errorf("the other run = %+v", got)
			}
			// The other run keeps its own creation event and the hypothesis event
			// SaveHypotheses derived from its claim.
			if events := mustListRunEvents(t, store, agent.EventQuery{RunID: otherRun.ID}); len(events) != 2 {
				t.Errorf("the other events = %+v", events)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{SnapshotID: agentStoreOtherSnapID}); total != 1 {
				t.Errorf("the other claims = %d, want 1", total)
			}
			if seq, err := store.NextRunEventSeq(otherRun.ID); err != nil || seq != 3 {
				t.Errorf("the other event sequence = %d, %v", seq, err)
			}
		})
	}
}

func TestDeleteSnapshotRemovesAgentRuns(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			ctx := context.Background()
			project := testProject("proj-agent")
			if err := store.PutProject(ctx, project); err != nil {
				t.Fatalf("PutProject: %v", err)
			}
			for _, snapshotID := range []string{agentStoreSnapID, agentStoreOtherSnapID} {
				if err := store.PutSnapshot(ctx, project.ID, testSnapshot(snapshotID)); err != nil {
					t.Fatalf("PutSnapshot(%s): %v", snapshotID, err)
				}
			}
			run := seedAgentRun(t, store, newAgentRunFixture(agentStoreRunID, agentStorePathID, agentStoreAuditID, agentStoreSnapID))
			otherRun := seedAgentRun(t, store, newAgentRunFixture(agentStoreOtherRunID, agentStoreOtherPathID, agentStoreOtherAuditID, agentStoreOtherSnapID))
			if err := store.AppendRunEvents([]agent.Event{
				{RunID: run.ID, PathID: run.PathID, Seq: 1, Type: agent.EventRunCreated, Actor: "orchestrator"},
				{RunID: otherRun.ID, PathID: otherRun.PathID, Seq: 1, Type: agent.EventRunCreated, Actor: "orchestrator"},
			}); err != nil {
				t.Fatalf("AppendRunEvents: %v", err)
			}
			claim := newAgentHypothesisFixture(run, "the q parameter reaches the sink", agent.HypothesisCandidate, "low", true)
			otherClaim := newAgentHypothesisFixture(otherRun, "the exec wrapper is reachable", agent.HypothesisCandidate, "low", true)
			if err := store.SaveHypotheses([]agent.Hypothesis{claim, otherClaim}); err != nil {
				t.Fatalf("SaveHypotheses: %v", err)
			}

			if err := store.DeleteSnapshot(ctx, agentStoreSnapID); err != nil {
				t.Fatalf("DeleteSnapshot: %v", err)
			}
			if _, err := store.GetRun(run.ID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("GetRun after DeleteSnapshot = %v, want agent.ErrNotFound", err)
			}
			if events := mustListRunEvents(t, store, agent.EventQuery{RunID: run.ID}); len(events) != 0 {
				t.Errorf("ListRunEvents after DeleteSnapshot = %+v", events)
			}
			if _, err := store.GetHypothesis(claim.ID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("GetHypothesis after DeleteSnapshot = %v, want agent.ErrNotFound", err)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{SnapshotID: agentStoreSnapID}); total != 0 {
				t.Errorf("ListHypotheses after DeleteSnapshot = %d, want 0", total)
			}
			if _, err := store.NextRunEventSeq(run.ID); !errors.Is(err, agent.ErrNotFound) {
				t.Errorf("NextRunEventSeq after DeleteSnapshot = %v, want agent.ErrNotFound", err)
			}

			if got := mustGetAgentRun(t, store, otherRun.ID); got.ID != otherRun.ID {
				t.Errorf("deleting one snapshot removed another run: %+v", got)
			}
			// The surviving run keeps its creation event and its hypothesis event.
			if events := mustListRunEvents(t, store, agent.EventQuery{RunID: otherRun.ID}); len(events) != 2 {
				t.Errorf("the surviving events = %+v", events)
			}
			if _, total := mustListHypotheses(t, store, agent.HypothesisQuery{SnapshotID: agentStoreOtherSnapID}); total != 1 {
				t.Errorf("the surviving claims = %d, want 1", total)
			}
		})
	}
}
