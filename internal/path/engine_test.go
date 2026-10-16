package path

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestGenerateProducesAuditablePaths(t *testing.T) {
	t.Parallel()
	reader := fixtureReader()
	result := mustGenerate(t, reader, GenerateOptions{AuditID: "audit-1", Budget: DefaultBudget(), Limits: DefaultLimits()})

	if len(result.Paths) != 3 {
		t.Fatalf("paths = %d, want 3 (two sinks of entry1 plus entry3's sink): %s", len(result.Paths), describePaths(result.Paths))
	}
	if result.ASGVersion != "asg-abc" || result.SCGVersion != "graph-abc" {
		t.Errorf("versions = %q/%q", result.ASGVersion, result.SCGVersion)
	}

	sql := pathByTarget(result, "asgn-sink-sql")
	if sql == nil {
		t.Fatalf("no path to the SQL sink: %s", describePaths(result.Paths))
	}
	if sql.PathStatus != PathStaticallySupported {
		t.Errorf("sql path status = %q, want statically_supported (observed chain and observed sink)", sql.PathStatus)
	}
	if sql.EntryKind != "http_route" || sql.TargetKind != "SensitiveOperation" {
		t.Errorf("kinds = %q/%q", sql.EntryKind, sql.TargetKind)
	}
	if sql.Depth != 1 {
		t.Errorf("depth = %d, want 1", sql.Depth)
	}
	if !containsString(sql.Boundaries, "network") {
		t.Errorf("boundaries = %v, want network", sql.Boundaries)
	}
	if !containsString(sql.Inputs, "input:path_param:id") || !containsString(sql.Inputs, "input:body:") {
		t.Errorf("inputs = %v", sql.Inputs)
	}
	if !containsString(sql.Assets, "asset:database_table:orders") {
		t.Errorf("assets = %v", sql.Assets)
	}
	if !containsString(sql.Objectives, "sql_injection") {
		t.Errorf("objectives = %v, want sql_injection", sql.Objectives)
	}
	if len(sql.OpenQuestions) < 3 {
		t.Errorf("open questions = %v, want questions about dataflow, inputs and controls", sql.OpenQuestions)
	}
	if len(sql.SCGRefs) < 3 || len(sql.ASGRefs) < 6 {
		t.Errorf("evidence refs too thin: scg=%v asg=%v", sql.SCGRefs, sql.ASGRefs)
	}
	for _, want := range []string{"sym-handler", "sym-sqlcaller", "scg-edge-1", "cs-sql"} {
		if !containsString(sql.SCGRefs, want) {
			t.Errorf("scg refs %v missing %s", sql.SCGRefs, want)
		}
	}
	for _, want := range []string{"asgn-entry1", "asgn-boundary-net", "asgn-input-param", "asgn-control-auth", "asgn-asset-table"} {
		if !containsString(sql.ASGRefs, want) {
			t.Errorf("asg refs %v missing %s", sql.ASGRefs, want)
		}
	}
	if len(sql.Limitations) < 3 {
		t.Errorf("limitations = %v, want the standard reachability and scoring caveats", sql.Limitations)
	}
	if sql.Status != StatusDiscovered {
		t.Errorf("generation status = %q, want DISCOVERED (the service queues it)", sql.Status)
	}
	if got := sql.ID; got != PathID("audit-1", "snap-0123456789abcdef0123456789abcdef", "asgn-entry1", "asgn-sink-sql", sql.CanonicalEdges(), PathKindCallGraph) {
		t.Errorf("path id = %q, want the content-derived id", got)
	}

	// The step order is what makes a path readable: boundary, inputs, call chain,
	// the sensitive operation, its controls, its assets.
	kinds := stepKinds(sql)
	want := []string{"asg:CROSSES", "asg:REACHES", "asg:REACHES", "scg:CALLS", "asg:REACHES", "asg:PROTECTED_BY", "asg:PROTECTED_BY", "asg:MAY_AFFECT"}
	if joined(kinds) != joined(want) {
		t.Errorf("steps = %v, want %v", kinds, want)
	}

	// A best-effort hop is not an observed call, so the path is a candidate.
	proc := pathByTarget(result, "asgn-sink-proc")
	if proc == nil {
		t.Fatalf("no path to the process sink")
	}
	if proc.PathStatus != PathCandidate {
		t.Errorf("process path status = %q, want candidate (one hop is best effort)", proc.PathStatus)
	}

	// An entry point without a resolved handler still yields an auditable item,
	// and says why the chain is missing.
	unresolved := pathByTarget(result, "asgn-sink-sql")
	for i := range result.Paths {
		if result.Paths[i].EntryNodeID == "asgn-entry3" && result.Paths[i].TargetNodeID == "asgn-sink-sql" {
			unresolved = &result.Paths[i]
		}
	}
	if unresolved == nil || unresolved.EntryNodeID != "asgn-entry3" {
		t.Fatalf("no path from the handler-less entry point: %s", describePaths(result.Paths))
	}
	if unresolved.PathStatus != PathUnresolved {
		t.Errorf("handler-less path status = %q, want unresolved", unresolved.PathStatus)
	}
	if !strings.Contains(joined(unresolved.OpenQuestions), "no resolved handler") {
		t.Errorf("open questions do not explain the missing chain: %v", unresolved.OpenQuestions)
	}
}

func TestGenerationRecordsItsBounds(t *testing.T) {
	t.Parallel()
	reader := fixtureReader()
	limits := DefaultLimits()
	limits.MaxEntries = 1
	limits.MaxSinksPerEntry = 2
	limits.MaxPaths = 1
	result := mustGenerate(t, reader, GenerateOptions{AuditID: "audit-1", Limits: limits})

	if !result.Coverage.Truncated {
		t.Fatal("coverage does not report truncation although every limit was hit")
	}
	if !strings.Contains(joined(result.Coverage.TruncationReasons), "entry point(s) beyond the limit") {
		t.Errorf("truncation reasons = %v", result.Coverage.TruncationReasons)
	}
	if !strings.Contains(joined(result.Coverage.TruncationReasons), "path(s) beyond the limit") {
		t.Errorf("truncation reasons = %v", result.Coverage.TruncationReasons)
	}
	if result.Coverage.EntryPointsSkipped != 2 || result.Coverage.SinksSkipped != 0 {
		t.Errorf("coverage = %+v", result.Coverage)
	}
	if result.Coverage.PathsSkipped == 0 {
		t.Errorf("no path was reported as dropped: %+v", result.Coverage)
	}
	if !strings.Contains(joined(result.Limitations), "generation was truncated") {
		t.Errorf("limitations do not restate the truncation: %v", result.Limitations)
	}
	if len(result.Paths) != 1 {
		t.Errorf("paths = %d, want the limit of 1", len(result.Paths))
	}
}

func TestGenerationIsDeterministic(t *testing.T) {
	t.Parallel()
	first := mustGenerate(t, fixtureReader(), GenerateOptions{AuditID: "audit-1"})
	second := mustGenerate(t, fixtureReader(), GenerateOptions{AuditID: "audit-1"})
	a, _ := json.Marshal(first)
	b, _ := json.Marshal(second)
	if string(a) != string(b) {
		t.Error("two generations of the same attack surface differ")
	}

	// The audit is part of the path id: two audits are two scheduling units.
	other := mustGenerate(t, fixtureReader(), GenerateOptions{AuditID: "audit-2"})
	if other.Paths[0].ID == first.Paths[0].ID {
		t.Error("path ids do not depend on the audit")
	}
	if other.Paths[0].Signature != first.Paths[0].Signature {
		t.Error("signatures must not depend on the audit: they are the cross-audit identity")
	}
}

func TestGenerationRefusesASnapshotWithoutAnAttackSurface(t *testing.T) {
	t.Parallel()
	reader := fixtureReader()
	reader.err = errors.New("asg: snapshot has no attack surface")
	_, err := fixedEngine(reader).Generate(context.Background(), "snap-0123456789abcdef0123456789abcdef", GenerateOptions{})
	if err == nil {
		t.Fatal("generation succeeded without an attack surface")
	}
	if !strings.Contains(err.Error(), "no attack surface") {
		t.Errorf("error = %v", err)
	}
}

func TestDeduplicateAndCluster(t *testing.T) {
	t.Parallel()
	result := mustGenerate(t, fixtureReader(), GenerateOptions{AuditID: "audit-1"})

	// Exact duplicates collapse; the count is reported instead of hidden.
	kept, duplicates := Deduplicate(append(append([]Path{}, result.Paths...), result.Paths...))
	if duplicates != len(result.Paths) {
		t.Errorf("duplicates = %d, want %d", duplicates, len(result.Paths))
	}
	if len(kept) != len(result.Paths) {
		t.Errorf("kept = %d, want %d", len(kept), len(result.Paths))
	}

	// Paths that differ in their chain survive, and cluster by entry, target and
	// boundary sequence.
	base := result.Paths[0]
	varied := base
	varied.Steps = append([]Step{}, base.Steps...)
	for i := range varied.Steps {
		if varied.Steps[i].Layer == "scg" {
			varied.Steps[i].To = "sym-other"
			varied.Steps[i].Subject = "svc.other"
		}
	}
	varied.Signature = Signature(varied.SnapshotID, varied.EntryNodeID, varied.TargetNodeID, varied.PathKind, varied.CanonicalEdges())
	varied.ID = PathID(varied.AuditID, varied.SnapshotID, varied.EntryNodeID, varied.TargetNodeID, varied.CanonicalEdges(), varied.PathKind)
	varied.Score.Priority = base.Score.Priority - 10
	clustered := ClusterPaths([]Path{base, varied})
	if len(clustered) != 2 || clustered[0].Cluster.ID == "" {
		t.Fatalf("clustering did not assign a cluster: %+v", clustered)
	}
	if clustered[0].Cluster.ID != clustered[1].Cluster.ID {
		t.Error("similar paths landed in different clusters")
	}
	if clustered[0].Cluster.Size != 2 {
		t.Errorf("cluster size = %d, want 2", clustered[0].Cluster.Size)
	}
	if clustered[0].Score.Priority < clustered[1].Score.Priority {
		t.Error("the cluster representative is not the higher-priority path")
	}
	if !clustered[0].Cluster.Representative || clustered[1].Cluster.Representative {
		t.Error("exactly one member must be the representative")
	}
	if len(clustered[1].Cluster.Differences) == 0 {
		t.Error("the non-representative member does not record what differs")
	}

	// Coverage accounting is what the scheduler uses to stop re-auditing a region.
	coverage := NewCoverageSet()
	first := coverage.Observe(result.Paths[0])
	if first == 0 {
		t.Error("observing a path covered nothing")
	}
	if again := coverage.Observe(result.Paths[0]); again != 0 {
		t.Errorf("re-observing a path reported %d new nodes, want 0", again)
	}
	if novelty := coverage.Novelty(result.Paths[0]); novelty != 0 {
		t.Errorf("novelty after full coverage = %v, want 0", novelty)
	}
}

func TestScoringFollowsTheDocumentedFormula(t *testing.T) {
	t.Parallel()
	result := mustGenerate(t, fixtureReader(), GenerateOptions{AuditID: "audit-1"})
	scored := make([]Path, 0, len(result.Paths))
	for _, p := range result.Paths {
		scored = append(scored, ScorePath(p, ScoreInput{Covered: NewCoverageSet(), Now: "2024-05-01T12:00:00Z"}))
	}

	for _, p := range scored {
		f := p.Features
		for name, value := range map[string]float64{
			"exposure": f.Exposure, "impact": f.Impact, "controllability": f.Controllability,
			"trust_boundary": f.TrustBoundary, "business_sensitivity": f.BusinessSensitivity,
			"reachability_evidence": f.ReachabilityEvidence, "dataflow_evidence": f.DataflowEvidence,
			"control_suspicion": f.ControlSuspicion, "analysis_quality": f.AnalysisQuality,
			"novelty": f.Novelty, "information_gain": f.InformationGain, "reuse_value": f.ReuseValue,
			"estimated_cost": f.EstimatedCost, "dedup_discount": f.DedupDiscount,
		} {
			if value < 0 || value > 1 {
				t.Errorf("%s = %v, want a normalised feature in [0,1]", name, value)
			}
		}
		if f.DataflowEvidence != 0 {
			t.Errorf("dataflow evidence = %v, want 0: this phase has no dataflow analysis", f.DataflowEvidence)
		}
		if !strings.Contains(f.Reasons["dataflow_evidence"], "no dataflow analysis") {
			t.Errorf("the missing dataflow evidence is not explained: %q", f.Reasons["dataflow_evidence"])
		}

		wantRisk := 0.25*f.Exposure + 0.20*f.Impact + 0.20*f.Controllability + 0.20*f.TrustBoundary + 0.15*f.BusinessSensitivity
		wantSupport := 0.35*f.ReachabilityEvidence + 0.25*f.DataflowEvidence + 0.25*f.ControlSuspicion + 0.15*f.AnalysisQuality
		wantUtility := 0.40*f.Novelty + 0.35*f.InformationGain + 0.25*f.ReuseValue
		wantPriority := 100 * (0.55*wantRisk + 0.25*wantSupport + 0.20*wantUtility) * f.DedupDiscount / (1 + 0.30*f.EstimatedCost)
		if diff := p.Score.Risk - round4(wantRisk); diff > 0.0002 || diff < -0.0002 {
			t.Errorf("risk = %v, want %v (features %+v)", p.Score.Risk, round4(wantRisk), f)
		}
		if diff := p.Score.Support - round4(wantSupport); diff > 0.0002 || diff < -0.0002 {
			t.Errorf("support = %v, want %v", p.Score.Support, round4(wantSupport))
		}
		if diff := p.Score.Utility - round4(wantUtility); diff > 0.0002 || diff < -0.0002 {
			t.Errorf("utility = %v, want %v", p.Score.Utility, round4(wantUtility))
		}
		if diff := p.Score.Priority - round4(wantPriority); diff > 0.0002 || diff < -0.0002 {
			t.Errorf("priority = %v, want %v", p.Score.Priority, round4(wantPriority))
		}
		if p.Score.ScoreVersion != ScoreVersion {
			t.Errorf("score version = %d, want %d", p.Score.ScoreVersion, ScoreVersion)
		}
		for _, key := range []string{"risk.exposure", "support.dataflow_evidence", "utility.novelty", "priority.risk", "priority.cost_penalty"} {
			if _, ok := p.Score.Weights[key]; !ok {
				t.Errorf("weights do not record %s: %v", key, p.Score.Weights)
			}
		}
		if len(p.Features.Reasons) < 10 {
			t.Errorf("feature reasons are too thin to audit: %v", p.Features.Reasons)
		}
	}

	// An unprotected path carries more suspicion than one with a registered
	// control, and the score says so instead of hiding it in a comment.
	sql := scoreOf(t, scored, "asgn-sink-sql")
	unprotected := sql
	unprotected.Controls = nil
	unprotected.Steps = withoutProtectedBy(unprotected.Steps)
	unprotected = ScorePath(unprotected, ScoreInput{Covered: NewCoverageSet()})
	if unprotected.Features.ControlSuspicion <= sql.Features.ControlSuspicion {
		t.Errorf("control suspicion did not rise without controls: %v vs %v",
			unprotected.Features.ControlSuspicion, sql.Features.ControlSuspicion)
	}
	if unprotected.Score.Support <= sql.Score.Support {
		t.Errorf("support did not rise with suspicion: %v vs %v", unprotected.Score.Support, sql.Score.Support)
	}
}

func TestScoringIsReplayable(t *testing.T) {
	t.Parallel()
	result := mustGenerate(t, fixtureReader(), GenerateOptions{AuditID: "audit-1"})
	in := ScoreInput{Covered: NewCoverageSet(), Now: "2024-05-01T12:00:00Z"}
	first := ScorePath(result.Paths[0], in)
	second := ScorePath(result.Paths[0], in)
	if first.Score.Priority != second.Score.Priority || first.Score.Risk != second.Score.Risk ||
		first.Score.Support != second.Score.Support || first.Score.Utility != second.Score.Utility {
		t.Errorf("scoring is not deterministic: %+v vs %+v", first.Score, second.Score)
	}
	a, _ := json.Marshal(first.Features)
	b, _ := json.Marshal(second.Features)
	if string(a) != string(b) {
		t.Error("feature snapshots differ between two scorings of the same path")
	}
	if got := PriorityBreakdown(first); !strings.Contains(got, "P=") || !strings.Contains(got, "K=") {
		t.Errorf("breakdown = %q, want the arithmetic", got)
	}
}

func TestStateMachineRejectsIllegalChanges(t *testing.T) {
	t.Parallel()
	legal := [][2]Status{
		{StatusDiscovered, StatusQueued},
		{StatusQueued, StatusAnalyzing},
		{StatusAnalyzing, StatusLocalExploring},
		{StatusLocalExploring, StatusAnalyzing},
		{StatusAnalyzing, StatusHypothesisFormed},
		{StatusHypothesisFormed, StatusVerifying},
		{StatusVerifying, StatusConcluded},
		{StatusAnalyzing, StatusConcluded},
		{StatusAnalyzing, StatusBlocked},
		{StatusBlocked, StatusQueued},
		{StatusAnalyzing, StatusPaused},
		{StatusPaused, StatusQueued},
		{StatusAnalyzing, StatusInterrupted},
		{StatusInterrupted, StatusQueued},
		{StatusAnalyzing, StatusFailed},
		{StatusFailed, StatusQueued},
		{StatusQueued, StatusCancelled},
	}
	for _, pair := range legal {
		if err := ValidateTransition(pair[0], pair[1]); err != nil {
			t.Errorf("%s -> %s was rejected: %v", pair[0], pair[1], err)
		}
	}
	illegal := [][2]Status{
		{StatusConcluded, StatusAnalyzing},
		{StatusCancelled, StatusQueued},
		{StatusQueued, StatusConcluded},
		{StatusDiscovered, StatusAnalyzing},
		{StatusAnalyzing, StatusAnalyzing},
		{StatusPaused, StatusVerifying},
	}
	for _, pair := range illegal {
		err := ValidateTransition(pair[0], pair[1])
		if err == nil {
			t.Errorf("%s -> %s was accepted", pair[0], pair[1])
			continue
		}
		if !errIs(err, ErrInvalidTransition) {
			t.Errorf("%s -> %s error = %v, want ErrInvalidTransition", pair[0], pair[1], err)
		}
	}
	if !strings.Contains(ValidateTransition(StatusQueued, StatusConcluded).Error(), "legal targets") {
		t.Error("the transition error does not tell the caller what would have been legal")
	}

	if !StatusQueued.Claimable() || StatusAnalyzing.Claimable() || StatusPaused.Claimable() {
		t.Error("Claimable is wrong")
	}
	if !StatusAnalyzing.Active() || !StatusVerifying.Active() || StatusConcluded.Active() {
		t.Error("Active is wrong")
	}
	if !StatusConcluded.Terminal() || !StatusCancelled.Terminal() || StatusQueued.Terminal() {
		t.Error("Terminal is wrong")
	}
	if !StatusPaused.Waiting() || !StatusFailed.Waiting() || StatusAnalyzing.Waiting() {
		t.Error("Waiting is wrong")
	}
}

func TestPickerReservesExplorationAndFollowsCoverage(t *testing.T) {
	t.Parallel()
	limits := DefaultLimits()
	limits.ExplorationFraction = 0.20

	// Ten candidates: descending priority, disjoint nodes except for the last two,
	// which share their attack surface with the first candidate.
	candidates := make([]Path, 0, 10)
	for i := 0; i < 8; i++ {
		candidates = append(candidates, Path{
			ID:          "path-" + string(rune('a'+i)),
			EntryNodeID: "asgn-entry1", TargetNodeID: "asgn-sink-" + string(rune('a'+i)),
			Score:   Score{Priority: float64(100 - i*5)},
			ASGRefs: []string{"asgn-entry1", "asgn-sink-" + string(rune('a'+i))},
		})
	}
	high := candidates[0]
	overlapping := high
	overlapping.ID = "path-overlap"
	overlapping.Score.Priority = 99
	candidates = append(candidates, overlapping)
	lowValue := Path{
		ID: "path-low", EntryNodeID: "asgn-entry1", TargetNodeID: "asgn-sink-low",
		Score: Score{Priority: 10}, ASGRefs: []string{"asgn-entry1", "asgn-new-node-a", "asgn-new-node-b"},
	}
	candidates = append(candidates, lowValue)

	plan := Plan(limits, NewCoverageSet(), candidates)
	if len(plan.Order) != len(candidates) {
		t.Fatalf("plan covers %d of %d candidates", len(plan.Order), len(candidates))
	}
	if len(plan.ExplorationPicks) == 0 {
		t.Fatal("the exploration reserve never fired")
	}
	// The fifth pick is the reserved one: 20% of picks, taken periodically.
	if plan.ExplorationPicks[0] != plan.Order[4].ID {
		t.Errorf("exploration pick %s is not the fifth pick (%s)", plan.ExplorationPicks[0], plan.Order[4].ID)
	}
	// Marginal coverage: by the time the overlapping path is considered, its nodes
	// are taken, so it must not be served before genuinely new work.
	position := map[string]int{}
	for i, p := range plan.Order {
		position[p.ID] = i
	}
	if position["path-overlap"] < position["path-low"] {
		t.Errorf("the overlapping path (%d) was served before the uncovered one (%d)", position["path-overlap"], position["path-low"])
	}
	if again := Plan(limits, NewCoverageSet(), candidates); joined(idsOf(again.Order)) != joined(idsOf(plan.Order)) {
		t.Error("scheduling is not deterministic")
	}

	picker := NewPicker(limits, NewCoverageSet())
	pick, ok := picker.Next(candidates)
	if !ok || pick.ID == "" {
		t.Fatal("picker returned nothing")
	}
	effectiveBefore := picker.EffectivePriority(overlapping)
	picker.Observe(pick)
	if after := picker.EffectivePriority(overlapping); after > effectiveBefore {
		t.Errorf("effective priority rose after coverage: %v -> %v", effectiveBefore, after)
	}
}

func TestServiceQueueLifecycle(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	reader := fixtureReader()
	service := fixedService(store, reader)
	limits := DefaultLimits()
	limits.MaxActiveLeases = 1

	created, err := service.CreateAudit(context.Background(), CreateAuditRequest{
		SnapshotID: "snap-0123456789abcdef0123456789abcdef", Limits: limits,
	})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	if created.Audit.Status != AuditReady {
		t.Errorf("audit status = %q, want READY", created.Audit.Status)
	}
	if created.Replayed {
		t.Error("a fresh audit was reported as a replay")
	}
	if created.Audit.PathCount != len(created.Paths) || created.Audit.PathCount == 0 {
		t.Errorf("audit path count = %d, paths = %d", created.Audit.PathCount, len(created.Paths))
	}
	for _, p := range created.Paths {
		if p.Status != StatusQueued {
			t.Errorf("path %s status = %q, want QUEUED", p.ID, p.Status)
		}
		if p.AuditID != created.Audit.ID {
			t.Errorf("path %s belongs to audit %q", p.ID, p.AuditID)
		}
		if p.ScoreSeq != 1 {
			t.Errorf("path %s score seq = %d, want 1", p.ID, p.ScoreSeq)
		}
	}
	if created.Audit.CountsByStatus[string(StatusQueued)] != len(created.Paths) {
		t.Errorf("counts = %v", created.Audit.CountsByStatus)
	}
	events, err := service.Events(EventQuery{AuditID: created.Audit.ID})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	if len(events) != len(created.Paths)+2 {
		t.Errorf("events = %d, want one per path plus created and ready", len(events))
	}
	for i := 1; i < len(events); i++ {
		if events[i].Seq <= events[i-1].Seq {
			t.Errorf("event sequences are not increasing: %d then %d", events[i-1].Seq, events[i].Seq)
		}
	}

	// The same request replays the audit instead of producing a second ranking.
	replay, err := service.CreateAudit(context.Background(), CreateAuditRequest{
		SnapshotID: "snap-0123456789abcdef0123456789abcdef", Limits: limits,
	})
	if err != nil {
		t.Fatalf("CreateAudit replay: %v", err)
	}
	if !replay.Replayed || replay.Audit.ID != created.Audit.ID || len(replay.Paths) != len(created.Paths) {
		t.Errorf("replay = %+v", replay.Audit)
	}

	// The queue serves the highest-priority path first.
	next, err := service.Next(created.Audit.ID)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if next.Score.Priority != created.Paths[0].Score.Priority {
		t.Errorf("Next served priority %v, top of queue is %v", next.Score.Priority, created.Paths[0].Score.Priority)
	}

	claimed, err := service.Claim(context.Background(), created.Audit.ID, "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if claimed.Status != StatusAnalyzing || claimed.LeaseOwner != "worker-1" || claimed.LeaseUntil == "" {
		t.Errorf("claimed path = %+v", claimed)
	}
	// The active-lease ceiling is a property of the audit.
	if _, err := service.Claim(context.Background(), created.Audit.ID, "worker-2", time.Minute); !errIs(err, ErrBudgetExceeded) {
		t.Errorf("second concurrent claim = %v, want ErrBudgetExceeded", err)
	}
	if _, err := service.Heartbeat(claimed.ID, "worker-2", time.Minute); !errIs(err, ErrLeaseHeld) {
		t.Errorf("heartbeat by another owner = %v, want ErrLeaseHeld", err)
	}
	renewed, err := service.Heartbeat(claimed.ID, "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if renewed.LeaseUntil < claimed.LeaseUntil {
		t.Errorf("heartbeat did not extend the lease: %s -> %s", claimed.LeaseUntil, renewed.LeaseUntil)
	}
	released, err := service.Release(claimed.ID, "worker-1", "handing back")
	if err != nil {
		t.Fatalf("Release: %v", err)
	}
	if released.Status != StatusQueued || released.LeaseOwner != "" {
		t.Errorf("released path = %+v", released)
	}

	// Pause, resume and cancel go through the state machine and leave events.
	paused, err := service.Pause(released.ID, "operator", "waiting for a fixture")
	if err != nil {
		t.Fatalf("Pause: %v", err)
	}
	if paused.Status != StatusPaused {
		t.Errorf("paused path status = %q", paused.Status)
	}
	if _, err := service.Transition(paused.ID, StatusConcluded, "operator", "sneaky"); !errIs(err, ErrInvalidTransition) {
		t.Errorf("paused -> CONCLUDED = %v, want ErrInvalidTransition", err)
	}
	resumed, err := service.Resume(paused.ID, "operator", "fixture ready")
	if err != nil {
		t.Fatalf("Resume: %v", err)
	}
	if resumed.Status != StatusQueued {
		t.Errorf("resumed path status = %q", resumed.Status)
	}
	cancelled, err := service.Cancel(resumed.ID, "operator", "out of scope")
	if err != nil {
		t.Fatalf("Cancel: %v", err)
	}
	if cancelled.Status != StatusCancelled || !cancelled.Status.Terminal() {
		t.Errorf("cancelled path = %+v", cancelled)
	}
	if _, err := service.Transition(cancelled.ID, StatusQueued, "operator", "undo"); err == nil {
		t.Error("a cancelled path was queued again")
	}
}

func TestServiceRecoversExpiredLeases(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	service := fixedService(store, fixtureReader())
	created, err := service.CreateAudit(context.Background(), CreateAuditRequest{SnapshotID: "snap-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	claimed, err := service.Claim(context.Background(), created.Audit.ID, "worker-crashed", time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}

	// A live lease is not reclaimed.
	recovered, err := service.ReclaimExpired(10)
	if err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	if len(recovered) != 0 {
		t.Errorf("a live lease was reclaimed: %+v", recovered)
	}

	// A crashed worker's lease is: the scheduler must not need the worker's help.
	service.Now = func() time.Time { return time.Date(2024, 5, 1, 13, 0, 0, 0, time.UTC) }
	recovered, err = service.ReclaimExpired(10)
	if err != nil {
		t.Fatalf("ReclaimExpired: %v", err)
	}
	if len(recovered) != 1 || recovered[0].ID != claimed.ID {
		t.Fatalf("recovered = %+v, want the expired path", recovered)
	}
	if recovered[0].Status != StatusQueued || recovered[0].LeaseOwner != "" {
		t.Errorf("recovered path = %+v", recovered[0])
	}
	events, err := service.Events(EventQuery{AuditID: created.Audit.ID, PathID: claimed.ID})
	if err != nil {
		t.Fatalf("Events: %v", err)
	}
	sawExpiry := false
	for _, event := range events {
		if event.Type == EventPathLeaseExpired {
			sawExpiry = true
		}
	}
	if !sawExpiry {
		t.Errorf("no lease-expiry event was appended: %+v", events)
	}
}

func TestServiceRescoreReplaysAndAppendsVersions(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	service := fixedService(store, fixtureReader())
	created, err := service.CreateAudit(context.Background(), CreateAuditRequest{SnapshotID: "snap-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	before := map[string]float64{}
	for _, p := range created.Paths {
		before[p.ID] = p.Score.Priority
	}
	audit, err := service.Rescore(created.Audit.ID)
	if err != nil {
		t.Fatalf("Rescore: %v", err)
	}
	if strings.Contains(joined(audit.Limitations), "changed priority") {
		t.Errorf("the replay drifted: %v", audit.Limitations)
	}
	for _, p := range created.Paths {
		current, records, err := service.Path(p.ID)
		if err != nil {
			t.Fatalf("Path: %v", err)
		}
		if current.Score.Priority != before[p.ID] {
			t.Errorf("path %s priority changed on replay: %v -> %v", p.ID, before[p.ID], current.Score.Priority)
		}
		if len(records) != 2 {
			t.Errorf("path %s has %d feature snapshots, want 2 (generation and replay)", p.ID, len(records))
		}
		if records[0].Priority != records[1].Priority {
			t.Errorf("feature snapshots disagree: %v vs %v", records[0].Priority, records[1].Priority)
		}
		if records[1].Seq <= records[0].Seq {
			t.Errorf("score sequences are not increasing: %d then %d", records[0].Seq, records[1].Seq)
		}
	}
	if audit.ScoreVersion != ScoreVersion {
		t.Errorf("audit score version = %d", audit.ScoreVersion)
	}

	// A forced regeneration keeps the ids and appends another score version.
	forced, err := service.CreateAudit(context.Background(), CreateAuditRequest{
		SnapshotID: "snap-0123456789abcdef0123456789abcdef", Force: true,
	})
	if err != nil {
		t.Fatalf("CreateAudit force: %v", err)
	}
	if forced.Replayed {
		t.Error("a forced run was reported as a replay")
	}
	if len(forced.Paths) != len(created.Paths) {
		t.Fatalf("forced run produced %d paths, want %d", len(forced.Paths), len(created.Paths))
	}
	for i := range forced.Paths {
		if forced.Paths[i].ID != created.Paths[i].ID {
			t.Errorf("forced run changed a path id: %s -> %s", created.Paths[i].ID, forced.Paths[i].ID)
		}
		if forced.Paths[i].ScoreSeq != 3 {
			t.Errorf("forced run score seq = %d, want 3", forced.Paths[i].ScoreSeq)
		}
	}
}

func TestServiceScopesAuditsToOneSnapshot(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	service := fixedService(store, fixtureReader())
	created, err := service.CreateAudit(context.Background(), CreateAuditRequest{SnapshotID: "snap-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	if _, _, err := service.Audits(AuditQuery{SnapshotID: "snap-ffffffffffffffffffffffffffffffff"}); err != nil {
		t.Fatalf("Audits: %v", err)
	}
	audits, total, err := service.Audits(AuditQuery{SnapshotID: "snap-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("Audits: %v", err)
	}
	if total != 1 || len(audits) != 1 || audits[0].ID != created.Audit.ID {
		t.Errorf("audits = %+v", audits)
	}
	if removed, err := store.DeleteAuditsForSnapshot("snap-0123456789abcdef0123456789abcdef"); err != nil || removed != 1 {
		t.Errorf("DeleteAuditsForSnapshot = %d, %v", removed, err)
	}
	if _, err := service.Audit(created.Audit.ID); !errIs(err, ErrNotFound) {
		t.Errorf("audit survived deletion: %v", err)
	}
	if _, _, err := service.Paths(PathQuery{AuditID: created.Audit.ID}); err != nil {
		t.Fatalf("Paths: %v", err)
	}
	paths, total, err := service.Paths(PathQuery{SnapshotID: "snap-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("Paths: %v", err)
	}
	if total != 0 || len(paths) != 0 {
		t.Errorf("paths survived the snapshot deletion: %+v", paths)
	}
}

func TestConfigHashDistinguishesRequests(t *testing.T) {
	t.Parallel()
	base := ConfigHash("snap-1", DefaultBudget(), DefaultLimits(), nil)
	if base != ConfigHash("snap-1", DefaultBudget(), DefaultLimits(), nil) {
		t.Error("the config hash is not stable")
	}
	if base == ConfigHash("snap-2", DefaultBudget(), DefaultLimits(), nil) {
		t.Error("the config hash ignores the snapshot")
	}
	other := DefaultLimits()
	other.MaxEntries = 5
	if base == ConfigHash("snap-1", DefaultBudget(), other, nil) {
		t.Error("the config hash ignores the limits")
	}
	if base == ConfigHash("snap-1", DefaultBudget(), DefaultLimits(), map[string]float64{"orders": 0.9}) {
		t.Error("the config hash ignores sensitivity overrides")
	}
	if AuditID("snap-1", base) == AuditID("snap-2", base) {
		t.Error("audit ids do not depend on the snapshot")
	}
}

func stepKinds(p *Path) []string {
	out := make([]string, 0, len(p.Steps))
	for _, step := range p.Steps {
		out = append(out, step.Layer+":"+step.Kind)
	}
	return out
}

func describePaths(paths []Path) string {
	var parts []string
	for _, p := range paths {
		parts = append(parts, p.EntryNodeID+"->"+p.TargetNodeID+"/"+string(p.PathStatus))
	}
	return strings.Join(parts, " ")
}

func scoreOf(t *testing.T, paths []Path, targetID string) Path {
	t.Helper()
	for _, p := range paths {
		if p.TargetNodeID == targetID {
			return p
		}
	}
	t.Fatalf("no scored path for target %s", targetID)
	return Path{}
}

func withoutProtectedBy(steps []Step) []Step {
	out := make([]Step, 0, len(steps))
	for _, step := range steps {
		if step.Kind == "PROTECTED_BY" {
			continue
		}
		out = append(out, step)
	}
	return out
}

func idsOf(paths []Path) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, p.ID)
	}
	return out
}

// TestClusteredScoringReplaysExactly covers the interaction that makes the score
// reproducible: the duplicate discount depends on cluster membership, membership
// depends on priority, and a replay must land on the same numbers anyway.
func TestClusteredScoringReplaysExactly(t *testing.T) {
	t.Parallel()
	reader := fixtureReader()
	// Two distinct chains from the same handler to the same caller: one entry point,
	// one target, two paths, one cluster.
	reader.chains["sym-handler->sym-sqlcaller"] = append(reader.chains["sym-handler->sym-sqlcaller"], CallChain{
		Symbols: []SymbolFact{
			{ID: "sym-handler", QualifiedName: "svc.getOrder", File: "web/server.go", Line: 30},
			{ID: "sym-middle", QualifiedName: "svc.middle", File: "web/middle.go", Line: 5},
			{ID: "sym-sqlcaller", QualifiedName: "svc.runQuery", File: "web/db.go", Line: 12},
		},
		Hops: []CallHop{
			{From: "sym-handler", To: "sym-middle", EdgeID: "scg-edge-m1", Kind: "CALLS", Resolution: "resolved"},
			{From: "sym-middle", To: "sym-sqlcaller", EdgeID: "scg-edge-m2", Kind: "CALLS", Resolution: "resolved"},
		},
	})
	result := mustGenerate(t, reader, GenerateOptions{AuditID: "audit-1"})
	var sqlPaths []Path
	for _, p := range result.Paths {
		if p.TargetNodeID == "asgn-sink-sql" && p.EntryNodeID == "asgn-entry1" {
			sqlPaths = append(sqlPaths, p)
		}
	}
	if len(sqlPaths) != 2 {
		t.Fatalf("paths to the SQL sink = %d, want 2 (two chains): %s", len(sqlPaths), describePaths(result.Paths))
	}
	if sqlPaths[0].Signature == sqlPaths[1].Signature {
		t.Error("two different chains share a signature")
	}

	store := newFakeStore()
	service := fixedService(store, reader)
	created, err := service.CreateAudit(context.Background(), CreateAuditRequest{SnapshotID: "snap-0123456789abcdef0123456789abcdef"})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	clustered := 0
	for _, p := range created.Paths {
		if p.Cluster.Size > 1 {
			clustered++
			if p.Cluster.ID == "" {
				t.Errorf("path %s is in a multi-member cluster without an id", p.ID)
			}
		}
	}
	if clustered != 2 {
		t.Errorf("paths in a multi-member cluster = %d, want 2 (both chains to the SQL sink)", clustered)
	}

	audit, err := service.Rescore(created.Audit.ID)
	if err != nil {
		t.Fatalf("Rescore: %v", err)
	}
	if strings.Contains(joined(audit.Limitations), "changed priority") {
		t.Errorf("replaying clustered scoring drifted: %v", audit.Limitations)
	}
}

// TestInterruptedAuditIsNotReplayedAsAResult pins the difference between "this
// audit is done" and "this audit is a trace of a run that died". A caller that
// cannot tell them apart will treat a partial path set as the answer.
func TestInterruptedAuditIsNotReplayedAsAResult(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	service := fixedService(store, fixtureReader())
	request := CreateAuditRequest{SnapshotID: "snap-0123456789abcdef0123456789abcdef"}

	created, err := service.CreateAudit(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	// Simulate a run that died before flipping the audit to READY.
	interrupted := created.Audit
	interrupted.Status = AuditGenerating
	if err := store.UpdateAudit(interrupted, 0); err != nil {
		t.Fatalf("UpdateAudit: %v", err)
	}
	again, err := service.CreateAudit(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateAudit after interruption: %v", err)
	}
	if again.Replayed {
		t.Error("an unfinished audit was replayed as a result")
	}
	if again.Audit.Status != AuditReady || again.Audit.PathCount == 0 {
		t.Errorf("regenerated audit = %+v", again.Audit)
	}

	// A failed run is regenerated too.
	failed := again.Audit
	failed.Status = AuditFailed
	if err := store.UpdateAudit(failed, 0); err != nil {
		t.Fatalf("UpdateAudit: %v", err)
	}
	third, err := service.CreateAudit(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateAudit after failure: %v", err)
	}
	if third.Replayed {
		t.Error("a failed audit was replayed as a result")
	}
	// And a finished one is replayed.
	fourth, err := service.CreateAudit(context.Background(), request)
	if err != nil {
		t.Fatalf("CreateAudit replay: %v", err)
	}
	if !fourth.Replayed {
		t.Error("a finished audit was regenerated instead of replayed")
	}
}

// TestConcludingAPathReleasesItsLease keeps the audit's active-lease accounting
// honest: a concluded path is not work in progress.
func TestConcludingAPathReleasesItsLease(t *testing.T) {
	t.Parallel()
	store := newFakeStore()
	service := fixedService(store, fixtureReader())
	created, err := service.CreateAudit(context.Background(), CreateAuditRequest{
		SnapshotID: "snap-0123456789abcdef0123456789abcdef", Limits: DefaultLimits(),
	})
	if err != nil {
		t.Fatalf("CreateAudit: %v", err)
	}
	claimed, err := service.Claim(context.Background(), created.Audit.ID, "worker-1", time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	concluded, err := service.Transition(claimed.ID, StatusConcluded, "worker-1", "analysis finished")
	if err != nil {
		t.Fatalf("Transition: %v", err)
	}
	if concluded.LeaseOwner != "" || concluded.LeaseUntil != "" {
		t.Errorf("concluded path still holds a lease: %+v", concluded)
	}
	// The state machine still refuses to resurrect it.
	if _, err := service.Transition(concluded.ID, StatusAnalyzing, "worker-1", "again"); !errIs(err, ErrInvalidTransition) {
		t.Errorf("concluded -> ANALYZING = %v, want ErrInvalidTransition", err)
	}
}
