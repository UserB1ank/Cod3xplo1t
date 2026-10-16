package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// The orchestrator tests exercise the whole loop against in-memory fakes: the
// store, the path coordinator, the task builder and the tool registry are all
// seams precisely so this file can drive every stop condition without a database,
// a scheduler, a scheduler clock or a real adapter.
//
// ScriptedRuntime covers everything that is a matter of ordering. Two local fakes
// cover what it cannot: a run that must stay alive until the orchestrator stops it
// (cancellation, a lost lease, a heartbeat) and a store whose timestamps are
// injected. Identifier names are runner-test scoped so a parallel test file cannot
// collide with them.

const runnerTestGoal = "sql_injection"

var runnerTestClock = time.Date(2024, 5, 1, 12, 0, 0, 0, time.UTC)

// runnerTestNow is injected into the Runner so a replay of the same script
// produces the same timestamps and the same elapsed times.
func runnerTestNow() time.Time { return runnerTestClock }

func runnerTestPolicy() ExplorationPolicy {
	return ExplorationPolicy{
		MaxHops:            2,
		MaxBranches:        4,
		MaxToolCalls:       30,
		MaxExpansions:      3,
		AllowedTools:       []string{"graph.query"},
		TimeoutSeconds:     60,
		MaxRepeatedOutputs: 2,
	}
}

func runnerTestAnswer() Answer {
	return Answer{
		SchemaVersion: SchemaVersion,
		SecurityGoal:  runnerTestGoal,
		Hypothesis: HypothesisDraft{
			Statement:  "the upload name reaches the query without parameterisation",
			Status:     HypothesisCandidate,
			Confidence: "medium",
		},
		SupportingEvidence: []AnswerEvidence{
			{Kind: EvidenceSource, Ref: "ev-1", File: "handlers/upload.go", Line: 12, Summary: "the slice concatenates the name"},
		},
		NextAction:       "request a deeper dataflow slice",
		FindingCandidate: false,
	}
}

func runnerTestPath(auditID, pathID string) path.Path {
	return path.Path{
		ID: pathID, AuditID: auditID, SnapshotID: "snap-1",
		EntryNodeID: "entry-1", TargetNodeID: "sink-1", PathKind: "entry_to_sink",
		PathStatus: path.PathStaticallySupported, Status: path.StatusQueued,
		MaxAttempts: 3,
		CreatedAt:   path.NowString(runnerTestClock), UpdatedAt: path.NowString(runnerTestClock),
	}
}

// runnerTestStore is an in-memory Store. It enforces the two invariants the
// orchestrator relies on: a run event sequence strictly increases, and
// SaveHypotheses appends its hypothesis event in the same step as the upsert.
type runnerTestStore struct {
	mu       sync.Mutex
	runs     map[string]Run
	runOrder []string
	events   map[string][]Event
	seq      map[string]int64
	hyps     map[string]Hypothesis
	hypOrder []string
}

var _ Store = (*runnerTestStore)(nil)

func newRunnerTestStore() *runnerTestStore {
	return &runnerTestStore{
		runs:   map[string]Run{},
		events: map[string][]Event{},
		seq:    map[string]int64{},
		hyps:   map[string]Hypothesis{},
	}
}

func (s *runnerTestStore) CreateRun(run Run) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.runs[run.ID]; exists {
		return fmt.Errorf("%w: run %s already exists", ErrConflict, run.ID)
	}
	if run.Version == 0 {
		run.Version = 1
	}
	s.runs[run.ID] = run
	s.runOrder = append(s.runOrder, run.ID)
	return nil
}

func (s *runnerTestStore) GetRun(runID string) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[runID]
	if !ok {
		return nil, fmt.Errorf("%w: run %s", ErrRunNotFound, runID)
	}
	out := run
	return &out, nil
}

func (s *runnerTestStore) ListRuns(q RunQuery) ([]Run, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	matched := make([]Run, 0, len(s.runOrder))
	for _, id := range s.runOrder {
		run := s.runs[id]
		if q.PathID != "" && run.PathID != q.PathID {
			continue
		}
		if q.AuditID != "" && run.AuditID != q.AuditID {
			continue
		}
		if q.SnapshotID != "" && run.SnapshotID != q.SnapshotID {
			continue
		}
		if len(q.Status) > 0 && !runnerTestHasStatus(q.Status, run.Status) {
			continue
		}
		matched = append(matched, run)
	}
	total := len(matched)
	if q.Offset > 0 {
		if q.Offset >= len(matched) {
			return []Run{}, total, nil
		}
		matched = matched[q.Offset:]
	}
	if q.Limit > 0 && len(matched) > q.Limit {
		matched = matched[:q.Limit]
	}
	return matched, total, nil
}

func (s *runnerTestStore) UpdateRun(run Run, expectedVersion int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	stored, ok := s.runs[run.ID]
	if !ok {
		return fmt.Errorf("%w: run %s", ErrRunNotFound, run.ID)
	}
	if expectedVersion != 0 && stored.Version != expectedVersion {
		return fmt.Errorf("%w: run %s is at version %d, want %d", ErrConflict, run.ID, stored.Version, expectedVersion)
	}
	if run.Version == 0 {
		run.Version = stored.Version + 1
	}
	s.runs[run.ID] = run
	return nil
}

func (s *runnerTestStore) AppendRunEvents(events []Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, event := range events {
		if event.RunID == "" {
			return errors.New("runnerTestStore: an event without a run id")
		}
		next := s.nextSeqLocked(event.RunID)
		if event.Seq != 0 && event.Seq != next {
			return fmt.Errorf("runnerTestStore: event %s has seq %d, want %d", event.Type, event.Seq, next)
		}
		event.Seq = next
		if event.ID == "" {
			event.ID = EventID(event.RunID, event.Seq)
		}
		s.events[event.RunID] = append(s.events[event.RunID], event)
		s.seq[event.RunID] = event.Seq + 1
	}
	return nil
}

func (s *runnerTestStore) ListRunEvents(q EventQuery) ([]Event, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Event
	for _, runID := range s.runOrder {
		for _, event := range s.events[runID] {
			if q.RunID != "" && event.RunID != q.RunID {
				continue
			}
			if q.PathID != "" && event.PathID != q.PathID {
				continue
			}
			if len(q.Types) > 0 && !runnerTestHasString(q.Types, event.Type) {
				continue
			}
			if q.AfterSeq > 0 && event.Seq <= q.AfterSeq {
				continue
			}
			out = append(out, event)
		}
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, nil
}

func (s *runnerTestStore) NextRunEventSeq(runID string) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nextSeqLocked(runID), nil
}

func (s *runnerTestStore) nextSeqLocked(runID string) int64 {
	if s.seq[runID] <= 0 {
		return 1
	}
	return s.seq[runID]
}

func (s *runnerTestStore) SaveHypotheses(hypotheses []Hypothesis) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, hypothesis := range hypotheses {
		key := hypothesis.PathID + "/" + hypothesis.Digest
		if _, exists := s.hyps[key]; !exists {
			s.hypOrder = append(s.hypOrder, key)
		}
		s.hyps[key] = hypothesis
		// The Store contract puts the hypothesis event in the same transaction as
		// the upsert; the orchestrator relies on that and does not append one.
		seq := s.nextSeqLocked(hypothesis.RunID)
		s.events[hypothesis.RunID] = append(s.events[hypothesis.RunID], Event{
			ID: EventID(hypothesis.RunID, seq), RunID: hypothesis.RunID, PathID: hypothesis.PathID,
			Seq: seq, Type: EventHypothesis, Actor: runnerActorOrchestrator,
			Summary: "hypothesis recorded", CreatedAt: hypothesis.CreatedAt,
		})
		s.seq[hypothesis.RunID] = seq + 1
	}
	return nil
}

func (s *runnerTestStore) ListHypotheses(q HypothesisQuery) ([]Hypothesis, int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []Hypothesis
	for _, key := range s.hypOrder {
		hypothesis := s.hyps[key]
		if q.PathID != "" && hypothesis.PathID != q.PathID {
			continue
		}
		if q.AuditID != "" && hypothesis.AuditID != q.AuditID {
			continue
		}
		if q.SnapshotID != "" && hypothesis.SnapshotID != q.SnapshotID {
			continue
		}
		if q.RunID != "" && hypothesis.RunID != q.RunID {
			continue
		}
		if len(q.Status) > 0 && !runnerTestHasString(q.Status, hypothesis.Status) {
			continue
		}
		if q.FindingCandidatesOnly && !hypothesis.FindingCandidate {
			continue
		}
		out = append(out, hypothesis)
	}
	total := len(out)
	if q.Offset > 0 {
		if q.Offset >= len(out) {
			return []Hypothesis{}, total, nil
		}
		out = out[q.Offset:]
	}
	if q.Limit > 0 && len(out) > q.Limit {
		out = out[:q.Limit]
	}
	return out, total, nil
}

func (s *runnerTestStore) GetHypothesis(hypothesisID string) (*Hypothesis, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, key := range s.hypOrder {
		if s.hyps[key].ID == hypothesisID {
			out := s.hyps[key]
			return &out, nil
		}
	}
	return nil, fmt.Errorf("%w: hypothesis %s", ErrNotFound, hypothesisID)
}

func (s *runnerTestStore) DeleteRunsForSnapshot(snapshotID string) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	removed := 0
	kept := s.runOrder[:0]
	for _, id := range s.runOrder {
		if s.runs[id].SnapshotID == snapshotID {
			removed++
			delete(s.runs, id)
			delete(s.events, id)
			delete(s.seq, id)
			continue
		}
		kept = append(kept, id)
	}
	s.runOrder = kept
	return removed, nil
}

// eventTypes returns the run's logged event types in sequence order.
func (s *runnerTestStore) eventTypes(t *testing.T, runID string) []string {
	t.Helper()
	events, err := s.ListRunEvents(EventQuery{RunID: runID})
	if err != nil {
		t.Fatalf("ListRunEvents: %v", err)
	}
	types := make([]string, 0, len(events))
	for i, event := range events {
		if event.Seq != int64(i+1) {
			t.Fatalf("event %q has seq %d, want %d: the log is not strictly increasing", event.Type, event.Seq, i+1)
		}
		if want := EventID(runID, event.Seq); event.ID != want {
			t.Fatalf("event %q has id %q, want %q", event.Type, event.ID, want)
		}
		types = append(types, event.Type)
	}
	return types
}

func (s *runnerTestStore) runCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.runOrder)
}

func (s *runnerTestStore) hypothesisCount() int {
	_, total, _ := s.ListHypotheses(HypothesisQuery{})
	return total
}

func runnerTestHasStatus(list []RunStatus, want RunStatus) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

func runnerTestHasString(list []string, want string) bool {
	for _, value := range list {
		if value == want {
			return true
		}
	}
	return false
}

// runnerTestPaths is a PathCoordinator that keeps a queue and records every
// settle call, so a test can assert what happened to the lease.
type runnerTestPaths struct {
	mu        sync.Mutex
	order     []string
	docs      map[string]path.Path
	claimed   []string
	completed []string
	released  []string
	advanced  []path.Status
	beats     int

	claimErr     error
	heartbeatErr error
}

var _ PathCoordinator = (*runnerTestPaths)(nil)

func newRunnerTestPaths(paths ...path.Path) *runnerTestPaths {
	p := &runnerTestPaths{docs: map[string]path.Path{}}
	for _, item := range paths {
		p.order = append(p.order, item.ID)
		p.docs[item.ID] = item
	}
	return p
}

func (p *runnerTestPaths) ClaimPathForRun(_ context.Context, _, owner string, ttl time.Duration) (*path.Path, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.claimErr != nil {
		return nil, p.claimErr
	}
	if len(p.order) == 0 {
		return nil, path.ErrNotFound
	}
	id := p.order[0]
	p.order = p.order[1:]
	doc := p.docs[id]
	doc.Status = path.StatusAnalyzing
	doc.LeaseOwner = owner
	doc.LeaseUntil = path.NowString(time.Now().Add(ttl))
	p.docs[id] = doc
	p.claimed = append(p.claimed, id)
	out := doc
	return &out, nil
}

func (p *runnerTestPaths) HeartbeatPath(_ context.Context, _, _ string, _ time.Duration) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.beats++
	if p.heartbeatErr != nil {
		return p.heartbeatErr
	}
	return nil
}

func (p *runnerTestPaths) CompletePath(_ context.Context, pathID, _, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	doc := p.docs[pathID]
	doc.Status = path.StatusHypothesisFormed
	p.docs[pathID] = doc
	p.completed = append(p.completed, pathID)
	return nil
}

func (p *runnerTestPaths) ReleasePath(_ context.Context, pathID, _, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	doc := p.docs[pathID]
	doc.Status = path.StatusQueued
	doc.LeaseOwner = ""
	p.docs[pathID] = doc
	p.released = append(p.released, pathID)
	p.order = append(p.order, pathID)
	return nil
}

func (p *runnerTestPaths) AdvancePath(_ context.Context, pathID, _ string, to path.Status, _ string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	doc := p.docs[pathID]
	doc.Status = to
	p.docs[pathID] = doc
	p.advanced = append(p.advanced, to)
	return nil
}

func (p *runnerTestPaths) claimIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.claimed...)
}

func (p *runnerTestPaths) completedIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.completed...)
}

func (p *runnerTestPaths) releasedIDs() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]string(nil), p.released...)
}

func (p *runnerTestPaths) advancedTo() []path.Status {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]path.Status(nil), p.advanced...)
}

func (p *runnerTestPaths) heartbeatCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.beats
}

// runnerTestTasks builds the smallest task ValidateTask accepts, from the claimed
// path and the policy the runner handed over.
type runnerTestTasks struct {
	mu   sync.Mutex
	seen []ExplorationPolicy
	err  error
}

var _ TaskBuilder = (*runnerTestTasks)(nil)

func (b *runnerTestTasks) BuildTask(_ context.Context, p path.Path, policy ExplorationPolicy) (Task, error) {
	b.mu.Lock()
	b.seen = append(b.seen, policy)
	b.mu.Unlock()
	if b.err != nil {
		return Task{}, b.err
	}
	return Task{
		SchemaVersion: SchemaVersion,
		SnapshotID:    p.SnapshotID,
		PathID:        p.ID,
		AuditID:       p.AuditID,
		SecurityGoal:  runnerTestGoal,
		PathSummary:   "entry reaches the sink",
		SourceSinkRefs: SourceSinkRefs{
			EntryNodeID: p.EntryNodeID, TargetNodeID: p.TargetNodeID,
		},
		MinimalCodeSlice: []SliceSection{
			{File: "handlers/upload.go", Symbol: "Upload", StartLine: 10, EndLine: 12, Content: "db.Query(name)"},
		},
		EvidenceRefs: []EvidenceRef{
			{Kind: EvidenceSource, ID: "ev-1", Summary: "route registration", File: "main.go", Line: 9},
		},
		UnresolvedQuestions: []string{"is the name parameterised?"},
		Exploration:         policy,
		Budget:              Budget{TimeoutSeconds: policy.TimeoutSeconds, TokenBudget: policy.TokenBudget},
		CreatedAt:           NowString(runnerTestClock),
	}, nil
}

func (b *runnerTestTasks) policies() []ExplorationPolicy {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]ExplorationPolicy(nil), b.seen...)
}

// runnerTestTool is a read-only executor that records what it was asked.
type runnerTestTool struct {
	name   string
	result string
	err    error

	mu    sync.Mutex
	calls int
	args  []map[string]string
}

var _ ToolExecutor = (*runnerTestTool)(nil)

func (t *runnerTestTool) Name() string     { return t.name }
func (t *runnerTestTool) Describe() string { return "runner test tool" }

func (t *runnerTestTool) Call(_ context.Context, args map[string]string) (ToolResult, error) {
	t.mu.Lock()
	t.calls++
	copied := make(map[string]string, len(args))
	for key, value := range args {
		copied[key] = value
	}
	t.args = append(t.args, copied)
	t.mu.Unlock()
	if t.err != nil {
		return ToolResult{}, t.err
	}
	return ToolResult{CallID: args["call_id"], Tool: t.name, OK: true, Result: t.result}, nil
}

func (t *runnerTestTool) callCount() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.calls
}

// runnerTestBlockingRuntime never closes its event stream. The run can therefore
// only end because the orchestrator decided to stop it, which is exactly what a
// cancellation, a deadline and a lost lease test needs.
type runnerTestBlockingRuntime struct {
	caps     RuntimeCapabilities
	startErr error

	events     chan RuntimeEvent
	done       chan RuntimeResult
	started    chan struct{}
	cancelled  chan struct{}
	startOnce  sync.Once
	cancelOnce sync.Once

	mu      sync.Mutex
	cancels int
}

var _ Runtime = (*runnerTestBlockingRuntime)(nil)

func newRunnerTestBlockingRuntime(name string) *runnerTestBlockingRuntime {
	return &runnerTestBlockingRuntime{
		caps:      RuntimeCapabilities{Name: name, Version: "1.0", ToolCalls: true, Expansions: true, Streaming: true},
		events:    make(chan RuntimeEvent),
		done:      make(chan RuntimeResult, 1),
		started:   make(chan struct{}),
		cancelled: make(chan struct{}),
	}
}

func (rt *runnerTestBlockingRuntime) Capabilities() RuntimeCapabilities { return rt.caps }

func (rt *runnerTestBlockingRuntime) Start(_ context.Context, _ Task) (*Handle, error) {
	if rt.startErr != nil {
		return nil, rt.startErr
	}
	rt.startOnce.Do(func() { close(rt.started) })
	return &Handle{
		Events: rt.events,
		Done:   rt.done,
		Cancel: func() {
			rt.mu.Lock()
			rt.cancels++
			rt.mu.Unlock()
			rt.cancelOnce.Do(func() { close(rt.cancelled) })
		},
	}, nil
}

func (rt *runnerTestBlockingRuntime) cancelCount() int {
	rt.mu.Lock()
	defer rt.mu.Unlock()
	return rt.cancels
}

func runnerTestRunner(store Store, paths PathCoordinator, tasks TaskBuilder, runtime Runtime, registry *Registry, policy ExplorationPolicy) *Runner {
	return &Runner{
		Store: store, Registry: registry, Runtime: runtime, Tasks: tasks, Paths: paths,
		Policy: policy, Owner: "worker-1", Now: runnerTestNow,
	}
}

func TestRunnerHappyPath(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	tasks := &runnerTestTasks{}
	tool := &runnerTestTool{name: "graph.query", result: "edge-list"}
	registry := NewRegistry()
	registry.Register(tool)
	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{
		ScriptNote("inspecting the slice"),
		ScriptAnswer(runnerTestAnswer()),
	})
	r := runnerTestRunner(store, paths, tasks, runtime, registry, runnerTestPolicy())

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunSucceeded || run.StopReason != StopCompleted {
		t.Fatalf("run status = %s/%s, want %s/%s (error %q)", run.Status, run.StopReason, RunSucceeded, StopCompleted, run.Error)
	}
	if run.Answer == nil || run.Answer.Hypothesis.Statement != runnerTestAnswer().Hypothesis.Statement {
		t.Fatalf("run answer = %+v, want the accepted answer", run.Answer)
	}
	if run.Runtime != "scripted" || run.RuntimeVersion != "1.0" {
		t.Errorf("run runtime = %s/%s, want scripted/1.0", run.Runtime, run.RuntimeVersion)
	}
	if run.Owner != "worker-1" {
		t.Errorf("run owner = %q, want worker-1", run.Owner)
	}
	if run.DeadlineAt != NowString(runnerTestClock.Add(60*time.Second)) {
		t.Errorf("deadline = %q, want the policy timeout from the injected clock", run.DeadlineAt)
	}

	if got := paths.claimIDs(); len(got) != 1 || got[0] != "path-1" {
		t.Errorf("claimed = %v, want [path-1]", got)
	}
	if got := paths.completedIDs(); len(got) != 1 || got[0] != "path-1" {
		t.Errorf("completed = %v, want [path-1]", got)
	}
	if got := paths.releasedIDs(); len(got) != 0 {
		t.Errorf("released = %v, want none", got)
	}

	hypotheses, total, err := store.ListHypotheses(HypothesisQuery{PathID: "path-1"})
	if err != nil {
		t.Fatalf("ListHypotheses: %v", err)
	}
	if total != 1 || len(hypotheses) != 1 {
		t.Fatalf("hypotheses = %d, want 1", total)
	}
	hypothesis := hypotheses[0]
	want := runnerTestAnswer()
	if hypothesis.ID != HypothesisID("path-1", want.Hypothesis.Statement) {
		t.Errorf("hypothesis id = %q, want the derived id", hypothesis.ID)
	}
	if hypothesis.Digest != Digest(want.Hypothesis.Statement) {
		t.Errorf("hypothesis digest = %q, want %q", hypothesis.Digest, Digest(want.Hypothesis.Statement))
	}
	if hypothesis.Status != HypothesisCandidate || hypothesis.Confidence != "medium" {
		t.Errorf("hypothesis status/confidence = %s/%s, want candidate/medium", hypothesis.Status, hypothesis.Confidence)
	}
	if hypothesis.SecurityGoal != runnerTestGoal || hypothesis.RunID != run.ID || hypothesis.AuditID != "audit-1" {
		t.Errorf("hypothesis identity = %+v, want the run's own", hypothesis)
	}
	if len(hypothesis.Supporting) != 1 || hypothesis.Supporting[0].ID != "ev-1" {
		t.Errorf("supporting evidence = %+v, want the cited ref", hypothesis.Supporting)
	}
	if hypothesis.NextAction != want.NextAction {
		t.Errorf("next action = %q, want %q", hypothesis.NextAction, want.NextAction)
	}

	got := store.eventTypes(t, run.ID)
	wantTypes := []string{
		EventRunCreated, EventRunStarted, EventTaskDelivered, runnerEventNote,
		EventOutputReceived, EventHypothesis, EventRunFinished,
	}
	if strings.Join(got, ",") != strings.Join(wantTypes, ",") {
		t.Fatalf("event types = %v, want %v", got, wantTypes)
	}

	if policies := tasks.policies(); len(policies) != 1 || len(policies[0].AllowedTools) != 1 || policies[0].AllowedTools[0] != "graph.query" {
		t.Errorf("task builder policies = %+v, want the normalized run policy", policies)
	}
}

func TestRunnerToolRequests(t *testing.T) {
	newRunner := func(steps []ScriptStep, policy ExplorationPolicy) (*runnerTestStore, *runnerTestPaths, *runnerTestTool, *Runner) {
		store := newRunnerTestStore()
		paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
		tool := &runnerTestTool{name: "graph.query", result: "edge-list"}
		registry := NewRegistry()
		registry.Register(tool)
		runtime := NewScriptedRuntime("scripted", "1.0", steps)
		return store, paths, tool, runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, policy)
	}

	t.Run("an allowed tool is executed and its result shares the call id", func(t *testing.T) {
		policy := runnerTestPolicy()
		store, paths, tool, r := newRunner([]ScriptStep{
			ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query", Args: map[string]string{"symbol": "sink-1"}}),
			ScriptAnswer(runnerTestAnswer()),
		}, policy)
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if run.Status != RunSucceeded {
			t.Fatalf("run = %s/%s (%s), want success", run.Status, run.StopReason, run.Error)
		}
		if tool.callCount() != 1 {
			t.Fatalf("tool calls = %d, want 1", tool.callCount())
		}
		if run.ToolCalls != 1 {
			t.Errorf("run tool calls = %d, want 1", run.ToolCalls)
		}
		events, _ := store.ListRunEvents(EventQuery{RunID: run.ID})
		var resultSeen bool
		for _, event := range events {
			switch event.Type {
			case EventToolAllowed:
				if event.CallID != "call-1" || event.Tool != "graph.query" {
					t.Errorf("tool_allowed = %+v, want call-1/graph.query", event)
				}
			case EventToolResult:
				resultSeen = true
				if event.CallID != "call-1" {
					t.Errorf("tool_result call id = %q, want call-1", event.CallID)
				}
				if event.Detail["result"] != "edge-list" {
					t.Errorf("tool_result payload = %q, want edge-list", event.Detail["result"])
				}
				if _, ok := event.Detail["elapsed_ms"]; !ok {
					t.Errorf("tool_result has no elapsed_ms: %+v", event.Detail)
				}
			}
		}
		if !resultSeen {
			t.Errorf("no tool_result event in %v", store.eventTypes(t, run.ID))
		}
		if got := paths.completedIDs(); len(got) != 1 {
			t.Errorf("completed = %v, want the path advanced", got)
		}
	})

	t.Run("a tool outside the allowlist is denied and the run continues", func(t *testing.T) {
		policy := runnerTestPolicy()
		store, paths, tool, r := newRunner([]ScriptStep{
			ScriptTool(ToolRequest{CallID: "call-2", Tool: "shell.exec", Args: map[string]string{"cmd": "id"}}),
			ScriptAnswer(runnerTestAnswer()),
		}, policy)
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if run.Status != RunSucceeded {
			t.Fatalf("run = %s/%s, want success: a denial is not a run failure", run.Status, run.StopReason)
		}
		if tool.callCount() != 0 {
			t.Fatalf("tool calls = %d, want 0", tool.callCount())
		}
		if run.ToolCalls != 0 {
			t.Errorf("run tool calls = %d, want 0", run.ToolCalls)
		}
		events, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventToolDenied}})
		if len(events) != 1 {
			t.Fatalf("tool_denied events = %d, want 1", len(events))
		}
		if events[0].CallID != "call-2" {
			t.Errorf("denied call id = %q, want call-2", events[0].CallID)
		}
		if !strings.Contains(events[0].Summary, "graph.query") {
			t.Errorf("denial %q does not name the allowlist", events[0].Summary)
		}
		if got := paths.completedIDs(); len(got) != 1 {
			t.Errorf("completed = %v, want the path advanced", got)
		}
	})

	t.Run("exceeding the tool budget stops the run", func(t *testing.T) {
		policy := runnerTestPolicy()
		policy.MaxToolCalls = 2
		store, paths, tool, r := newRunner([]ScriptStep{
			ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query"}),
			ScriptTool(ToolRequest{CallID: "call-2", Tool: "graph.query"}),
			ScriptTool(ToolRequest{CallID: "call-3", Tool: "graph.query"}),
			ScriptAnswer(runnerTestAnswer()),
		}, policy)
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if run.Status != RunBudgetExceeded || run.StopReason != StopToolBudget {
			t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunBudgetExceeded, StopToolBudget)
		}
		if tool.callCount() != 2 || run.ToolCalls != 2 {
			t.Errorf("tool calls = %d/%d, want 2/2", tool.callCount(), run.ToolCalls)
		}
		if run.Answer != nil {
			t.Errorf("answer = %+v, want none: a stopped run has no hypothesis", run.Answer)
		}
		if store.hypothesisCount() != 0 {
			t.Errorf("hypotheses = %d, want 0", store.hypothesisCount())
		}
		denied, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventToolDenied}})
		if len(denied) != 1 || denied[0].CallID != "call-3" {
			t.Errorf("denied = %+v, want the third call refused", denied)
		}
		results, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventToolResult}})
		if len(results) != 2 {
			t.Errorf("tool_result events = %d, want 2", len(results))
		}
		if got := paths.releasedIDs(); len(got) != 1 {
			t.Errorf("released = %v, want the path requeued", got)
		}
	})
}

func TestRunnerExpansionDecisions(t *testing.T) {
	runScript := func(t *testing.T, policy ExplorationPolicy, expand ExpandPolicy, steps []ScriptStep) (*runnerTestStore, *runnerTestPaths, *Run) {
		t.Helper()
		store := newRunnerTestStore()
		paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
		runtime := NewScriptedRuntime("scripted", "1.0", steps)
		r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), policy)
		r.Expand = expand
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		return store, paths, run
	}

	t.Run("a shrunk grant moves only the granted amounts", func(t *testing.T) {
		policy := runnerTestPolicy()
		policy.MaxHops = 1
		policy.MaxToolCalls = 2
		// The expand policy advertises a wider allowlist on purpose: the run must
		// keep its own.
		expand := ExpandPolicy{
			MaxHopsPerExpansion:      1,
			MaxToolCallsPerExpansion: 2,
			MaxExpansionsPerRun:      3,
			AllowedTools:             []string{"graph.query", "shell.exec"},
		}
		store, _, run := runScript(t, policy, expand, []ScriptStep{
			ScriptExpansion(ExpansionAsk{TargetNodeID: "asgn-2", Purpose: "cross the boundary", ExpectedGain: "one edge", EstimatedCost: "cheap", Hops: 3, ToolCalls: 1}),
			ScriptExpansion(ExpansionAsk{TargetNodeID: "asgn-3", Purpose: "read another symbol", ExpectedGain: "one slice", EstimatedCost: "cheap", Hops: 1, ToolCalls: 5}),
			ScriptAnswer(runnerTestAnswer()),
		})
		if run.Status != RunSucceeded {
			t.Fatalf("run = %s/%s (%s), want success", run.Status, run.StopReason, run.Error)
		}
		if run.Expansions != 2 {
			t.Fatalf("expansions = %d, want 2", run.Expansions)
		}
		if run.Exploration.MaxHops != 3 {
			t.Errorf("max hops = %d, want 3 (1 start + 1 + 1 granted)", run.Exploration.MaxHops)
		}
		if run.Exploration.MaxToolCalls != 4 {
			t.Errorf("max tool calls = %d, want 4 (2 start + 2 granted)", run.Exploration.MaxToolCalls)
		}
		for _, allowed := range run.Exploration.AllowedTools {
			if allowed == "shell.exec" {
				t.Fatalf("allowlist = %v, want no widening", run.Exploration.AllowedTools)
			}
		}
		decisions, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventExpansionDecided}})
		if len(decisions) != 2 {
			t.Fatalf("expansion_decided events = %d, want 2", len(decisions))
		}
		for _, event := range decisions {
			if event.Detail["decision"] != ExpansionShrunk {
				t.Errorf("decision = %q, want %q", event.Detail["decision"], ExpansionShrunk)
			}
		}
		requested, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventExpansionAsked}})
		if len(requested) != 2 {
			t.Errorf("expansion_requested events = %d, want 2", len(requested))
		}
	})

	t.Run("approved within every limit", func(t *testing.T) {
		policy := runnerTestPolicy()
		policy.MaxHops = 1
		policy.MaxToolCalls = 2
		expand := ExpandPolicy{MaxHopsPerExpansion: 2, MaxToolCallsPerExpansion: 5, MaxExpansionsPerRun: 3}
		_, _, run := runScript(t, policy, expand, []ScriptStep{
			ScriptExpansion(ExpansionAsk{TargetNodeID: "asgn-2", Purpose: "cross the boundary", ExpectedGain: "one edge", Hops: 1, ToolCalls: 2}),
			ScriptAnswer(runnerTestAnswer()),
		})
		if run.Exploration.MaxHops != 2 || run.Exploration.MaxToolCalls != 4 {
			t.Errorf("policy = %+v, want +1 hop and +2 tool calls", run.Exploration)
		}
	})

	t.Run("deferred while the branch ceiling is reached", func(t *testing.T) {
		policy := runnerTestPolicy()
		policy.MaxBranches = 1
		expand := ExpandPolicy{MaxHopsPerExpansion: 1, MaxToolCallsPerExpansion: 1, MaxExpansionsPerRun: 3}
		store, _, run := runScript(t, policy, expand, []ScriptStep{
			ScriptExpansion(ExpansionAsk{TargetNodeID: "asgn-2", Purpose: "more room", ExpectedGain: "one edge", Hops: 1, ToolCalls: 1}),
			ScriptAnswer(runnerTestAnswer()),
		})
		decided, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventExpansionDecided}})
		if len(decided) != 1 || decided[0].Detail["decision"] != ExpansionDeferred {
			t.Fatalf("decision = %+v, want deferred", decided)
		}
		if run.Exploration.MaxHops != policy.MaxHops {
			t.Errorf("max hops = %d, want %d: a deferred request grants nothing", run.Exploration.MaxHops, policy.MaxHops)
		}
	})

	t.Run("rejected once the requests are spent", func(t *testing.T) {
		policy := runnerTestPolicy()
		policy.MaxExpansions = 5
		expand := ExpandPolicy{MaxHopsPerExpansion: 1, MaxToolCallsPerExpansion: 1, MaxExpansionsPerRun: 1}
		store, _, run := runScript(t, policy, expand, []ScriptStep{
			ScriptExpansion(ExpansionAsk{TargetNodeID: "asgn-2", Purpose: "first", ExpectedGain: "one edge", Hops: 1, ToolCalls: 1}),
			ScriptExpansion(ExpansionAsk{TargetNodeID: "asgn-3", Purpose: "second", ExpectedGain: "one edge", Hops: 1, ToolCalls: 1}),
			ScriptAnswer(runnerTestAnswer()),
		})
		decided, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventExpansionDecided}})
		if len(decided) != 2 {
			t.Fatalf("decisions = %d, want 2", len(decided))
		}
		if decided[0].Detail["decision"] != ExpansionApproved || decided[1].Detail["decision"] != ExpansionRejected {
			t.Fatalf("decisions = %q, %q; want approved, rejected", decided[0].Detail["decision"], decided[1].Detail["decision"])
		}
		if run.Exploration.MaxHops != policy.MaxHops+1 {
			t.Errorf("max hops = %d, want %d: only the approved request grants room", run.Exploration.MaxHops, policy.MaxHops+1)
		}
	})
}

func TestRunnerInvalidOutput(t *testing.T) {
	newRunner := func(steps []ScriptStep) (*runnerTestStore, *runnerTestPaths, *Runner) {
		store := newRunnerTestStore()
		paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
		runtime := NewScriptedRuntime("scripted", "1.0", steps)
		return store, paths, runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())
	}

	t.Run("malformed json from the adapter", func(t *testing.T) {
		store, paths, r := newRunner([]ScriptStep{ScriptRawAnswer([]byte("{not json"))})
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if run.Status != RunInvalidOutput || run.StopReason != StopInvalidOutput {
			t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunInvalidOutput, StopInvalidOutput)
		}
		if store.hypothesisCount() != 0 {
			t.Errorf("hypotheses = %d, want 0", store.hypothesisCount())
		}
		rejected, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventOutputRejected}})
		if len(rejected) == 0 {
			t.Fatalf("no output_rejected event in %v", store.eventTypes(t, run.ID))
		}
		if got := paths.releasedIDs(); len(got) != 1 {
			t.Errorf("released = %v, want the path requeued", got)
		}
		if got := paths.completedIDs(); len(got) != 0 {
			t.Errorf("completed = %v, want none", got)
		}
	})

	t.Run("an answer that claims confirmation", func(t *testing.T) {
		answer := runnerTestAnswer()
		answer.Hypothesis.Status = HypothesisConfirmed
		store, _, r := newRunner([]ScriptStep{ScriptAnswer(answer)})
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if run.Status != RunInvalidOutput || run.StopReason != StopInvalidOutput {
			t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunInvalidOutput, StopInvalidOutput)
		}
		if !strings.Contains(run.Error, HypothesisConfirmed) {
			t.Errorf("error = %q, want it to name the refused status", run.Error)
		}
		rejected, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventOutputRejected}})
		if len(rejected) != 1 || !strings.Contains(rejected[0].Summary, HypothesisConfirmed) {
			t.Errorf("output_rejected = %+v, want a clear reason naming %q", rejected, HypothesisConfirmed)
		}
		if store.hypothesisCount() != 0 {
			t.Errorf("hypotheses = %d, want 0", store.hypothesisCount())
		}
	})

	t.Run("raw output streamed in a detail field", func(t *testing.T) {
		store, _, r := newRunner([]ScriptStep{
			ScriptNoteDetail("raw output follows", map[string]string{runnerDetailAnswerJSON: "{"}),
		})
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		if run.Status != RunInvalidOutput || run.StopReason != StopInvalidOutput {
			t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunInvalidOutput, StopInvalidOutput)
		}
		if store.hypothesisCount() != 0 {
			t.Errorf("hypotheses = %d, want 0", store.hypothesisCount())
		}
	})
}

func TestRunnerRepeatedOutputStopsRun(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	policy := runnerTestPolicy()
	policy.MaxRepeatedOutputs = 2
	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{
		ScriptAnswer(runnerTestAnswer()),
		ScriptAnswer(runnerTestAnswer()),
		ScriptAnswer(runnerTestAnswer()),
	})
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), policy)

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.StopReason != StopRepeatedOutput {
		t.Fatalf("run = %s/%s, want %s", run.Status, run.StopReason, StopRepeatedOutput)
	}
	if run.Status != RunFailed {
		t.Errorf("status = %s, want %s", run.Status, RunFailed)
	}
	if store.hypothesisCount() != 0 {
		t.Errorf("hypotheses = %d, want 0: the repeated claim is not new evidence", store.hypothesisCount())
	}
}

func TestRunnerCancellationReleasesPath(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runtime := newRunnerTestBlockingRuntime("blocking")
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	type outcome struct {
		run *Run
		err error
	}
	finished := make(chan outcome, 1)
	go func() {
		run, err := r.RunOnce(ctx, "audit-1")
		finished <- outcome{run: run, err: err}
	}()

	select {
	case <-runtime.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the adapter was never started")
	}
	cancel()

	var result outcome
	select {
	case result = <-finished:
	case <-time.After(5 * time.Second):
		t.Fatal("RunOnce did not return after the cancellation")
	}
	if result.err != nil {
		t.Fatalf("RunOnce: %v", result.err)
	}
	if result.run.Status != RunCancelled || result.run.StopReason != StopCancelled {
		t.Fatalf("run = %s/%s, want %s/%s", result.run.Status, result.run.StopReason, RunCancelled, StopCancelled)
	}
	if got := paths.releasedIDs(); len(got) != 1 || got[0] != "path-1" {
		t.Errorf("released = %v, want [path-1]: a cancelled run leaves a visible path", got)
	}
	if got := paths.completedIDs(); len(got) != 0 {
		t.Errorf("completed = %v, want none", got)
	}
	if store.hypothesisCount() != 0 {
		t.Errorf("hypotheses = %d, want 0", store.hypothesisCount())
	}
	if runtime.cancelCount() != 1 {
		t.Errorf("adapter cancels = %d, want 1: a stopped run must cancel its adapter", runtime.cancelCount())
	}
}

func TestRunnerLostLeaseStopsRun(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	paths.heartbeatErr = path.ErrLeaseHeld
	runtime := newRunnerTestBlockingRuntime("blocking")
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())
	r.HeartbeatEvery = time.Millisecond

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunFailed || run.StopReason != StopLeaseLost {
		t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunFailed, StopLeaseLost)
	}
	if run.HeartbeatAt != "" {
		t.Errorf("heartbeat at = %q, want empty: the renewal failed", run.HeartbeatAt)
	}
	if got := paths.completedIDs(); len(got) != 0 {
		t.Errorf("completed = %v, want none: a lost lease must not complete the path", got)
	}
	if got := paths.releasedIDs(); len(got) != 0 {
		t.Errorf("released = %v, want none: the path is not ours to release", got)
	}
	if got := paths.advancedTo(); len(got) != 0 {
		t.Errorf("advanced = %v, want none", got)
	}
	if paths.heartbeatCount() == 0 {
		t.Error("no heartbeat was attempted")
	}
	if runtime.cancelCount() != 1 {
		t.Errorf("adapter cancels = %d, want 1", runtime.cancelCount())
	}
}

func TestRunnerRunOnceEmptyQueue(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths()
	runtime := NewScriptedRuntime("scripted", "1.0", nil)
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())

	run, err := r.RunOnce(context.Background(), "audit-1")
	if !errors.Is(err, ErrNotFound) {
		t.Fatalf("RunOnce error = %v, want ErrNotFound", err)
	}
	if run != nil {
		t.Errorf("run = %+v, want nil", run)
	}
	if store.runCount() != 0 {
		t.Errorf("runs = %d, want 0: an empty queue writes nothing", store.runCount())
	}
}

func TestRunnerRunAuditBounds(t *testing.T) {
	t.Run("maxRuns caps the call", func(t *testing.T) {
		store := newRunnerTestStore()
		paths := newRunnerTestPaths(
			runnerTestPath("audit-1", "path-1"),
			runnerTestPath("audit-1", "path-2"),
			runnerTestPath("audit-1", "path-3"),
		)
		runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{ScriptAnswer(runnerTestAnswer())})
		r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())

		runs, err := r.RunAudit(context.Background(), "audit-1", 2)
		if err != nil {
			t.Fatalf("RunAudit: %v", err)
		}
		if len(runs) != 2 {
			t.Fatalf("runs = %d, want 2", len(runs))
		}
		for _, run := range runs {
			if run.Status != RunSucceeded {
				t.Errorf("run %s = %s/%s, want success", run.ID, run.Status, run.StopReason)
			}
		}
		if got := paths.claimIDs(); len(got) != 2 {
			t.Errorf("claimed = %v, want exactly two paths", got)
		}
	})

	t.Run("a path is not retried past max attempts", func(t *testing.T) {
		store := newRunnerTestStore()
		paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
		// A script that ends without an answer is a run that produced nothing, so
		// RunAudit must stop retrying it after max_attempts.
		runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{ScriptNote("nothing usable")})
		r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())

		runs, err := r.RunAudit(context.Background(), "audit-1", 10)
		if err != nil {
			t.Fatalf("RunAudit: %v", err)
		}
		if len(runs) != 3 {
			t.Fatalf("runs = %d, want 3 (the path's max attempts)", len(runs))
		}
		seenIDs := map[string]bool{}
		for _, run := range runs {
			if run.Status == RunSucceeded {
				t.Errorf("run %s succeeded unexpectedly", run.ID)
			}
			if seenIDs[run.ID] {
				t.Errorf("run id %s repeated: attempts must be distinct", run.ID)
			}
			seenIDs[run.ID] = true
		}
		if got := paths.advancedTo(); len(got) != 1 || got[0] != path.StatusFailed {
			t.Errorf("advanced = %v, want the path failed once its attempts were spent", got)
		}
		if got := paths.releasedIDs(); len(got) != 2 {
			t.Errorf("released = %v, want the first two attempts requeued", got)
		}
	})
}

func TestRunnerEventSequenceIsDeterministic(t *testing.T) {
	replay := func() (Run, []string) {
		store := newRunnerTestStore()
		paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
		tool := &runnerTestTool{name: "graph.query", result: "edge-list"}
		registry := NewRegistry()
		registry.Register(tool)
		runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{
			ScriptNote("inspecting the slice"),
			ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query"}),
			ScriptExpansion(ExpansionAsk{TargetNodeID: "asgn-2", Purpose: "cross", ExpectedGain: "one edge", Hops: 1, ToolCalls: 1}),
			ScriptAnswer(runnerTestAnswer()),
		})
		r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, runnerTestPolicy())
		run, err := r.RunOnce(context.Background(), "audit-1")
		if err != nil {
			t.Fatalf("RunOnce: %v", err)
		}
		return *run, store.eventTypes(t, run.ID)
	}

	firstRun, firstEvents := replay()
	secondRun, secondEvents := replay()
	if strings.Join(firstEvents, ",") != strings.Join(secondEvents, ",") {
		t.Fatalf("event sequences differ:\n%v\n%v", firstEvents, secondEvents)
	}
	if firstRun.Status != secondRun.Status || firstRun.StopReason != secondRun.StopReason {
		t.Fatalf("terminal states differ: %s/%s vs %s/%s",
			firstRun.Status, firstRun.StopReason, secondRun.Status, secondRun.StopReason)
	}
	if firstRun.CreatedAt != secondRun.CreatedAt || firstRun.FinishedAt != secondRun.FinishedAt {
		t.Errorf("timestamps differ with an injected clock: %q/%q vs %q/%q",
			firstRun.CreatedAt, firstRun.FinishedAt, secondRun.CreatedAt, secondRun.FinishedAt)
	}
}

func TestRunnerToolResultTruncation(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	tool := &runnerTestTool{name: "graph.query", result: strings.Repeat("x", MaxToolResultChars+50)}
	registry := NewRegistry()
	registry.Register(tool)
	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{
		ScriptTool(ToolRequest{CallID: "call-1", Tool: "graph.query"}),
		ScriptAnswer(runnerTestAnswer()),
	})
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, registry, runnerTestPolicy())

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	events, _ := store.ListRunEvents(EventQuery{RunID: run.ID, Types: []string{EventToolResult}})
	if len(events) != 1 {
		t.Fatalf("tool_result events = %d, want 1", len(events))
	}
	if got := len(events[0].Detail["result"]); got != MaxToolResultChars {
		t.Errorf("result length = %d, want %d", got, MaxToolResultChars)
	}
	if events[0].Detail["truncated"] != "true" {
		t.Errorf("truncated = %q, want true", events[0].Detail["truncated"])
	}
}

func TestRunnerAdapterStartFailure(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runtime := newRunnerTestBlockingRuntime("blocking")
	runtime.startErr = errors.New("adapter could not start")
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunFailed || run.StopReason != StopAdapterFailed {
		t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunFailed, StopAdapterFailed)
	}
	if got := paths.releasedIDs(); len(got) != 1 {
		t.Errorf("released = %v, want the path requeued for another attempt", got)
	}
	types := store.eventTypes(t, run.ID)
	if !runnerTestHasString(types, EventRunError) || !runnerTestHasString(types, EventRunFinished) {
		t.Errorf("event types = %v, want a terminal error and finish", types)
	}
}

// TestRunnerRejectedOutputIsNotOverridden locks the interaction between the
// adapter's own rejection and its terminal error: the orchestrator records
// invalid output rather than blaming the adapter for reporting it.
func TestRunnerRejectedOutputIsNotOverridden(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{ScriptRawAnswer([]byte(`{"schema_version":1}`))})
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunInvalidOutput || run.StopReason != StopInvalidOutput {
		t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunInvalidOutput, StopInvalidOutput)
	}
	if run.Error == "" {
		t.Error("error = empty, want the protocol's reason")
	}
}

// TestRunnerAnswerFromTerminalResult covers an adapter that only reports its
// answer in Done, never in an event: the orchestrator still validates it through
// DecodeAnswer.
func TestRunnerAnswerFromTerminalResult(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	tasks := &runnerTestTasks{}
	// Build the task first so the answer can match its security goal, then hand the
	// same task to the adapter through a fixed answer.
	task, err := tasks.BuildTask(context.Background(), runnerTestPath("audit-1", "path-1"), runnerTestPolicy().Normalize())
	if err != nil {
		t.Fatalf("BuildTask: %v", err)
	}
	answer := runnerTestAnswer()
	raw, err := json.Marshal(answer)
	if err != nil {
		t.Fatalf("marshal answer: %v", err)
	}
	if _, err := DecodeAnswer(raw, task); err != nil {
		t.Fatalf("fixture answer does not validate: %v", err)
	}

	doneOnly := newRunnerTestDoneOnlyRuntime("done-only", &answer)
	r := runnerTestRunner(store, paths, tasks, doneOnly, NewRegistry(), runnerTestPolicy())
	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunSucceeded || run.StopReason != StopCompleted {
		t.Fatalf("run = %s/%s (%s), want success", run.Status, run.StopReason, run.Error)
	}
	if store.hypothesisCount() != 1 {
		t.Errorf("hypotheses = %d, want 1", store.hypothesisCount())
	}
}

// runnerTestDoneOnlyRuntime emits no event and reports its answer only in the
// terminal result.
type runnerTestDoneOnlyRuntime struct {
	name   string
	answer *Answer
}

var _ Runtime = (*runnerTestDoneOnlyRuntime)(nil)

func newRunnerTestDoneOnlyRuntime(name string, answer *Answer) *runnerTestDoneOnlyRuntime {
	return &runnerTestDoneOnlyRuntime{name: name, answer: answer}
}

func (rt *runnerTestDoneOnlyRuntime) Capabilities() RuntimeCapabilities {
	return RuntimeCapabilities{Name: rt.name}
}

func (rt *runnerTestDoneOnlyRuntime) Start(_ context.Context, _ Task) (*Handle, error) {
	events := make(chan RuntimeEvent)
	done := make(chan RuntimeResult, 1)
	close(events)
	done <- RuntimeResult{ExitCode: 0, Answer: rt.answer}
	close(done)
	return &Handle{Events: events, Done: done, Cancel: func() {}}, nil
}

// runnerTestEventRuntime replays a fixed event slice and a fixed terminal result.
// It exists for the accounting test that needs reported token usage, which
// ScriptedRuntime deliberately never reports.
type runnerTestEventRuntime struct {
	name   string
	events []RuntimeEvent
	result RuntimeResult
}

var _ Runtime = (*runnerTestEventRuntime)(nil)

func (rt *runnerTestEventRuntime) Capabilities() RuntimeCapabilities {
	return RuntimeCapabilities{Name: rt.name, TokenUsage: true}
}

func (rt *runnerTestEventRuntime) Start(_ context.Context, _ Task) (*Handle, error) {
	events := make(chan RuntimeEvent, len(rt.events))
	for _, event := range rt.events {
		events <- event
	}
	close(events)
	done := make(chan RuntimeResult, 1)
	done <- rt.result
	close(done)
	return &Handle{Events: events, Done: done, Cancel: func() {}}, nil
}

func TestRunnerHeartbeatRenewsLease(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	// The answer step sleeps before it runs, so the run stays alive long enough
	// for the lease renewal to happen at least once.
	runtime := NewScriptedRuntime("scripted", "1.0", []ScriptStep{ScriptAnswer(runnerTestAnswer())})
	runtime.StepDelay = 50 * time.Millisecond
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), runnerTestPolicy())
	r.HeartbeatEvery = time.Millisecond

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunSucceeded {
		t.Fatalf("run = %s/%s (%s), want success", run.Status, run.StopReason, run.Error)
	}
	if paths.heartbeatCount() == 0 {
		t.Fatal("no lease renewal happened")
	}
	if run.HeartbeatAt == "" {
		t.Error("heartbeat at = empty, want the last successful renewal")
	}
	if types := store.eventTypes(t, run.ID); !runnerTestHasString(types, EventRunHeartbeat) {
		t.Errorf("event types = %v, want a run_heartbeat", types)
	}
}

func TestRunnerDeadlineStopsRun(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runtime := newRunnerTestBlockingRuntime("blocking")
	policy := runnerTestPolicy()
	policy.TimeoutSeconds = 1
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), policy)

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunTimedOut || run.StopReason != StopDeadline {
		t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunTimedOut, StopDeadline)
	}
	if store.hypothesisCount() != 0 {
		t.Errorf("hypotheses = %d, want 0", store.hypothesisCount())
	}
	if got := paths.completedIDs(); len(got) != 0 {
		t.Errorf("completed = %v, want none", got)
	}
	if runtime.cancelCount() != 1 {
		t.Errorf("adapter cancels = %d, want 1", runtime.cancelCount())
	}
}

func TestRunnerTokenBudgetStopsRun(t *testing.T) {
	store := newRunnerTestStore()
	paths := newRunnerTestPaths(runnerTestPath("audit-1", "path-1"))
	runtime := &runnerTestEventRuntime{
		name: "token-reporting",
		events: []RuntimeEvent{{
			Type: runnerEventNote, Summary: "reported usage",
			InputTokens: 40, OutputTokens: 40,
		}},
	}
	policy := runnerTestPolicy()
	policy.TokenBudget = 10
	r := runnerTestRunner(store, paths, &runnerTestTasks{}, runtime, NewRegistry(), policy)

	run, err := r.RunOnce(context.Background(), "audit-1")
	if err != nil {
		t.Fatalf("RunOnce: %v", err)
	}
	if run.Status != RunBudgetExceeded || run.StopReason != StopTokenBudget {
		t.Fatalf("run = %s/%s, want %s/%s", run.Status, run.StopReason, RunBudgetExceeded, StopTokenBudget)
	}
	if run.InputTokens+run.OutputTokens != 80 {
		t.Errorf("tokens = %d+%d, want the reported usage recorded", run.InputTokens, run.OutputTokens)
	}
	if store.hypothesisCount() != 0 {
		t.Errorf("hypotheses = %d, want 0", store.hypothesisCount())
	}
}
