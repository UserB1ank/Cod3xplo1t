package storage

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

const (
	auditSnapID      = "snap-0123456789abcdef0123456789abcdef"
	auditOtherSnapID = "snap-fedcba9876543210fedcba9876543210"
	auditAbsentSnap  = "snap-00000000000000000000000000000000"
	auditMainID      = "audit-00000000000000000000000000000001"
	auditSecondID    = "audit-00000000000000000000000000000002"
	auditAbsentID    = "audit-000000000000000000000000000000ff"
)

// newAuditFixture builds a deterministic audit document. Fixed timestamps and
// ids keep the fixture comparable across both backends.
func newAuditFixture(auditID, snapshotID string, version int64) path.Audit {
	return path.Audit{
		ID: auditID, SnapshotID: snapshotID, SCGVersion: "graph-1", ASGVersion: "asg-1",
		Status: path.AuditReady, Budget: path.DefaultBudget(), Limits: path.DefaultLimits(),
		ScoreVersion: path.ScoreVersion, ConfigHash: "config-" + auditID, PathCount: 0,
		CountsByStatus: map[string]int{}, CountsByPathStatus: map[string]int{},
		Coverage: path.Coverage{
			EntryPointsExamined: 2, EntryPointsSkipped: 1, SinksExamined: 3, ChainsResolved: 2,
			ChainsUnresolved: 1, ChainQueries: 4, ChainQueryBudget: 100, PathsConsidered: 5,
			PathsEmitted: 0, DuplicatePaths: 2, Clusters: 1, Truncated: true,
			TruncationReasons: []string{"entry point budget"},
		},
		Limitations: []string{"dynamic dispatch is not resolved"},
		CreatedAt:   "2024-05-01T12:00:00Z", UpdatedAt: "2024-05-01T12:00:00Z", Version: version,
	}
}

// newPathFixture builds a path with every nested document the schema stores, so a
// round trip that loses a JSON column fails the comparison.
func newPathFixture(pathID, auditID, snapshotID, entryNodeID, targetNodeID string, priority float64) path.Path {
	return path.Path{
		ID: pathID, AuditID: auditID, SnapshotID: snapshotID, SCGVersion: "graph-1", ASGVersion: "asg-1",
		EntryNodeID: entryNodeID, TargetNodeID: targetNodeID, PathKind: "entry_to_sink",
		PathStatus: path.PathStaticallySupported, Status: path.StatusQueued,
		Steps: []path.Step{
			{
				Layer: "asg", From: entryNodeID, To: targetNodeID, Kind: "REACHES",
				Subject: "sink:sql_execution", File: "internal/db/query.go", Line: 17,
				Evidence: "observed", Confidence: "observed", Resolution: "resolved",
			},
			{
				Layer: "scg", From: "sym-handler", To: "sym-sql", Kind: "CALLS",
				File: "internal/api/handler.go", Line: 42, Evidence: "observed",
				Confidence: "inferred", Resolution: "resolved_best_effort",
			},
		},
		Signature: "signature-" + pathID,
		Cluster: path.Cluster{
			ID: "pcluster-" + targetNodeID, Representative: true, Size: 2,
			Differences: []string{"branch a is guarded", "branch b is not"},
		},
		SCGRefs: []string{"cs-1", "sym-1"}, ASGRefs: []string{"asgn-1", "asgn-2"},
		Objectives: []string{"injection"}, Boundaries: []string{"network"},
		Controls: []string{"parameterization"}, Inputs: []string{"asgn-input-1"},
		Assets: []string{"asgn-asset-1"}, OpenQuestions: []string{"is the id parameterized?"},
		Limitations: []string{"dynamic dispatch is not resolved"},
		Depth:       2, BranchCount: 1, Budget: path.DefaultBudget(),
		Features: path.Features{
			Exposure: 0.7, Impact: 0.8, Controllability: 0.5, TrustBoundary: 0.6,
			BusinessSensitivity: 0.4, ReachabilityEvidence: 0.9, DataflowEvidence: 0.3,
			ControlSuspicion: 0.2, AnalysisQuality: 0.8, Novelty: 0.5, InformationGain: 0.6,
			ReuseValue: 0.3, EstimatedCost: 0.4, DedupDiscount: 0.1,
			Reasons: map[string]string{"exposure": "public route", "novelty": "not covered before"},
		},
		Score: path.Score{
			Risk: 0.6, Support: 0.7, Utility: 0.5, Priority: priority, ScoreVersion: path.ScoreVersion,
			Weights:    map[string]float64{"risk": 0.5, "support": 0.3, "utility": 0.2},
			ComputedAt: "2024-05-01T12:00:00Z",
		},
		ScoreSeq: 1, MaxAttempts: 3,
		CreatedAt: "2024-05-01T12:00:00Z", UpdatedAt: "2024-05-01T12:00:00Z", Version: 1,
	}
}

func newFeatureFixture(p path.Path, seq int64) path.FeatureRecord {
	return path.FeatureRecord{
		PathID: p.ID, AuditID: p.AuditID, Seq: seq, ScoreVersion: path.ScoreVersion,
		Risk: p.Score.Risk, Support: p.Score.Support, Utility: p.Score.Utility, Priority: p.Score.Priority,
		Features: p.Features, Weights: p.Score.Weights, Reasons: p.Features.Reasons,
		ComputedAt: fmt.Sprintf("2024-05-01T12:00:0%dZ", seq),
	}
}

func newEventFixture(auditID, pathID string, seq int64, eventType string) path.Event {
	return path.Event{
		AuditID: auditID, PathID: pathID, Seq: seq, Type: eventType, Actor: "system",
		From: path.StatusDiscovered, To: path.StatusQueued, Reason: "fixture event",
		Detail:    map[string]string{"source": "fixture"},
		CreatedAt: "2024-05-01T12:00:00Z",
	}
}

func seedAudit(t *testing.T, store FullStore, audit path.Audit, paths ...path.Path) {
	t.Helper()
	if err := store.CreateAudit(audit); err != nil {
		t.Fatalf("CreateAudit(%s): %v", audit.ID, err)
	}
	if len(paths) > 0 {
		if err := store.ReplacePaths(audit.ID, paths); err != nil {
			t.Fatalf("ReplacePaths(%s): %v", audit.ID, err)
		}
	}
}

func mustGetPath(t *testing.T, store FullStore, pathID string) path.Path {
	t.Helper()
	p, err := store.GetPath(pathID)
	if err != nil {
		t.Fatalf("GetPath(%s): %v", pathID, err)
	}
	return *p
}

func mustGetAudit(t *testing.T, store FullStore, auditID string) path.Audit {
	t.Helper()
	audit, err := store.GetAudit(auditID)
	if err != nil {
		t.Fatalf("GetAudit(%s): %v", auditID, err)
	}
	return *audit
}

func listEvents(t *testing.T, store FullStore, q path.EventQuery) []path.Event {
	t.Helper()
	events, err := store.ListEvents(q)
	if err != nil {
		t.Fatalf("ListEvents(%+v): %v", q, err)
	}
	return events
}

func pathIDs(paths []path.Path) []string {
	out := make([]string, 0, len(paths))
	for _, p := range paths {
		out = append(out, p.ID)
	}
	return out
}

func clockNearFuture() string { return path.NowString(time.Now().UTC().Add(time.Hour)) }
func clockNearPast() string   { return path.NowString(time.Now().UTC().Add(-time.Hour)) }

func TestAuditRoundTrip(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			want := newAuditFixture(auditMainID, auditSnapID, 1)
			if err := store.CreateAudit(want); err != nil {
				t.Fatalf("CreateAudit: %v", err)
			}
			if err := store.CreateAudit(want); !errors.Is(err, path.ErrConflict) {
				t.Errorf("CreateAudit twice = %v, want path.ErrConflict", err)
			}
			if got := mustGetAudit(t, store, auditMainID); !reflect.DeepEqual(got, want) {
				t.Errorf("GetAudit = %+v, want %+v", got, want)
			}
			if _, err := store.GetAudit(auditAbsentID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("GetAudit(absent) = %v, want path.ErrNotFound", err)
			}

			list, total, err := store.ListAudits(path.AuditQuery{SnapshotID: auditSnapID})
			if err != nil || total != 1 || len(list) != 1 {
				t.Fatalf("ListAudits by snapshot = %d/%d, %v", len(list), total, err)
			}
			if list[0].ID != auditMainID {
				t.Errorf("ListAudits returned %s", list[0].ID)
			}
			if _, total, err := store.ListAudits(path.AuditQuery{Status: path.AuditReady}); err != nil || total != 1 {
				t.Errorf("ListAudits by status = %d, %v", total, err)
			}
			if _, total, err := store.ListAudits(path.AuditQuery{Status: path.AuditFailed}); err != nil || total != 0 {
				t.Errorf("ListAudits by another status = %d, %v", total, err)
			}
			if _, total, err := store.ListAudits(path.AuditQuery{SnapshotID: auditOtherSnapID}); err != nil || total != 0 {
				t.Errorf("ListAudits by another snapshot = %d, %v", total, err)
			}

			// A successful update with the right version, then a stale one that must
			// change nothing.
			updated := want
			updated.Status = path.AuditFailed
			updated.PathCount = 7
			updated.Limitations = append(updated.Limitations, "generation failed")
			if err := store.UpdateAudit(updated, 1); err != nil {
				t.Fatalf("UpdateAudit: %v", err)
			}
			stored := mustGetAudit(t, store, auditMainID)
			if stored.Status != path.AuditFailed || stored.PathCount != 7 || stored.Version != 2 {
				t.Fatalf("UpdateAudit stored %+v", stored)
			}
			if !reflect.DeepEqual(stored.Limitations, updated.Limitations) {
				t.Errorf("limitations = %v, want %v", stored.Limitations, updated.Limitations)
			}

			stale := want
			stale.Status = path.AuditReady
			if err := store.UpdateAudit(stale, 1); !errors.Is(err, path.ErrConflict) {
				t.Errorf("UpdateAudit with a stale version = %v, want path.ErrConflict", err)
			}
			if got := mustGetAudit(t, store, auditMainID); !reflect.DeepEqual(got, stored) {
				t.Errorf("a stale update changed the row: %+v", got)
			}
			if err := store.UpdateAudit(want, 0); err != nil {
				t.Fatalf("UpdateAudit without a version check: %v", err)
			}
			if got := mustGetAudit(t, store, auditMainID); got.Version <= stored.Version {
				t.Errorf("version did not advance: %d then %d", stored.Version, got.Version)
			}
			if err := store.UpdateAudit(newAuditFixture(auditAbsentID, auditSnapID, 1), 0); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("UpdateAudit(absent) = %v, want path.ErrNotFound", err)
			}
		})
	}
}

func TestReplacePathsReplacesTheWholeGeneration(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			p2 := newPathFixture("path-0002", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-exec", 0.5)
			p3 := newPathFixture("path-0003", auditMainID, auditSnapID, "asgn-entry-2", "asgn-sink-sql", 0.7)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1, p2, p3)

			listed, total, err := store.ListPaths(path.PathQuery{AuditID: auditMainID, Sort: "priority"})
			if err != nil || total != 3 || len(listed) != 3 {
				t.Fatalf("ListPaths = %d/%d, %v", len(listed), total, err)
			}
			if order := pathIDs(listed); !reflect.DeepEqual(order, []string{"path-0001", "path-0003", "path-0002"}) {
				t.Errorf("priority order = %v", order)
			}

			// The whole generation is replaced, so the paths that left it are gone.
			if err := store.ReplacePaths(auditMainID, []path.Path{p3}); err != nil {
				t.Fatalf("ReplacePaths: %v", err)
			}
			for _, gone := range []string{p1.ID, p2.ID} {
				if _, err := store.GetPath(gone); !errors.Is(err, path.ErrNotFound) {
					t.Errorf("GetPath(%s) after replacement = %v, want path.ErrNotFound", gone, err)
				}
			}
			if got := mustGetPath(t, store, p3.ID); got.ID != p3.ID {
				t.Errorf("GetPath(%s) = %+v", p3.ID, got)
			}
			if _, total, err := store.ListPaths(path.PathQuery{AuditID: auditMainID}); err != nil || total != 1 {
				t.Errorf("after replacement total = %d, %v", total, err)
			}

			// A duplicate signature is a rejected generation, not a silent overwrite.
			dupA := newPathFixture("path-0004", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.4)
			dupB := newPathFixture("path-0005", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-exec", 0.4)
			dupB.Signature = dupA.Signature
			if err := store.ReplacePaths(auditMainID, []path.Path{dupA, dupB}); !errors.Is(err, path.ErrConflict) {
				t.Errorf("ReplacePaths with a duplicate signature = %v, want path.ErrConflict", err)
			}
			if _, total, err := store.ListPaths(path.PathQuery{AuditID: auditMainID}); err != nil || total != 1 {
				t.Errorf("a rejected generation changed the stored one: total %d, %v", total, err)
			}

			missing := newPathFixture("path-0007", auditAbsentID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.2)
			if err := store.ReplacePaths(auditAbsentID, []path.Path{missing}); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("ReplacePaths for an absent audit = %v, want path.ErrNotFound", err)
			}
			foreign := newPathFixture("path-0006", auditSecondID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.2)
			if err := store.ReplacePaths(auditMainID, []path.Path{foreign}); !errors.Is(err, path.ErrInvalidArgument) {
				t.Errorf("ReplacePaths with a foreign path = %v, want path.ErrInvalidArgument", err)
			}
		})
	}
}

func TestListPathsFilters(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			p2 := newPathFixture("path-0002", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-exec", 0.5)
			p2.PathStatus = path.PathCandidate
			p3 := newPathFixture("path-0003", auditMainID, auditSnapID, "asgn-entry-2", "asgn-sink-sql", 0.7)
			p3.Status = path.StatusPaused
			p3.PathStatus = path.PathUnresolved
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1, p2, p3)

			other := newPathFixture("path-0004", auditSecondID, auditOtherSnapID, "asgn-entry-9", "asgn-sink-other", 0.99)
			seedAudit(t, store, newAuditFixture(auditSecondID, auditOtherSnapID, 1), other)

			cases := []struct {
				name  string
				q     path.PathQuery
				want  []string
				total int
			}{
				{"audit", path.PathQuery{AuditID: auditMainID}, []string{"path-0001", "path-0003", "path-0002"}, 3},
				{"snapshot", path.PathQuery{SnapshotID: auditSnapID, Sort: "path_id"}, []string{"path-0001", "path-0002", "path-0003"}, 3},
				{"status", path.PathQuery{AuditID: auditMainID, Status: []path.Status{path.StatusQueued}, Sort: "path_id"}, []string{"path-0001", "path-0002"}, 2},
				{"path status", path.PathQuery{AuditID: auditMainID, PathStatus: []path.PathStatus{path.PathCandidate}, Sort: "path_id"}, []string{"path-0002"}, 1},
				{"entry", path.PathQuery{AuditID: auditMainID, EntryNodeID: "asgn-entry-1", Sort: "path_id"}, []string{"path-0001", "path-0002"}, 2},
				{"target", path.PathQuery{AuditID: auditMainID, TargetNodeID: "asgn-sink-sql", Sort: "path_id"}, []string{"path-0001", "path-0003"}, 2},
				{"min priority", path.PathQuery{AuditID: auditMainID, MinPriority: 0.6, Sort: "path_id"}, []string{"path-0001", "path-0003"}, 2},
				{"combined", path.PathQuery{AuditID: auditMainID, EntryNodeID: "asgn-entry-1", Status: []path.Status{path.StatusQueued}, PathStatus: []path.PathStatus{path.PathCandidate}}, []string{"path-0002"}, 1},
				{"path id order", path.PathQuery{AuditID: auditMainID, Sort: "path_id"}, []string{"path-0001", "path-0002", "path-0003"}, 3},
				{"created order", path.PathQuery{AuditID: auditMainID, Sort: "created"}, []string{"path-0001", "path-0002", "path-0003"}, 3},
			}
			for _, c := range cases {
				got, total, err := store.ListPaths(c.q)
				if err != nil {
					t.Fatalf("%s: ListPaths: %v", c.name, err)
				}
				if total != c.total {
					t.Errorf("%s: total = %d, want %d", c.name, total, c.total)
				}
				if ids := pathIDs(got); !reflect.DeepEqual(ids, c.want) {
					t.Errorf("%s: ids = %v, want %v", c.name, ids, c.want)
				}
			}

			first, total, err := store.ListPaths(path.PathQuery{AuditID: auditMainID, Sort: "priority", Limit: 2})
			if err != nil || total != 3 || len(first) != 2 {
				t.Fatalf("first page = %d/%d, %v", len(first), total, err)
			}
			second, total, err := store.ListPaths(path.PathQuery{AuditID: auditMainID, Sort: "priority", Limit: 2, Offset: 2})
			if err != nil || total != 3 || len(second) != 1 {
				t.Fatalf("second page = %d/%d, %v", len(second), total, err)
			}
			if second[0].ID == first[0].ID {
				t.Errorf("offset was ignored: both pages start at %s", first[0].ID)
			}
			if _, err := store.GetPath(auditAbsentID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("GetPath(absent) = %v, want path.ErrNotFound", err)
			}
		})
	}
}

func TestPathDocumentSurvivesTheRounding(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1))
			want := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			if err := store.ReplacePaths(auditMainID, []path.Path{want}); err != nil {
				t.Fatalf("ReplacePaths: %v", err)
			}

			// Writing must not keep a reference to the caller's slices or maps.
			want.Steps[0].Kind = "MUTATED"
			want.Features.Reasons["exposure"] = "mutated"
			want.Score.Weights["risk"] = 99
			want.OpenQuestions = append(want.OpenQuestions, "mutated")
			want.Limitations = append(want.Limitations, "mutated")
			want.Cluster.Differences[0] = "mutated"

			fresh := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			got := mustGetPath(t, store, "path-0001")
			if !reflect.DeepEqual(got, fresh) {
				t.Errorf("GetPath = %+v, want %+v", got, fresh)
			}
			if len(got.Steps) != 2 || !reflect.DeepEqual(got.Features.Reasons, fresh.Features.Reasons) ||
				!reflect.DeepEqual(got.Score.Weights, fresh.Score.Weights) ||
				!reflect.DeepEqual(got.Cluster.Differences, fresh.Cluster.Differences) ||
				!reflect.DeepEqual(got.OpenQuestions, fresh.OpenQuestions) ||
				!reflect.DeepEqual(got.Limitations, fresh.Limitations) {
				t.Errorf("a nested document was lost: %+v", got)
			}

			// Reading must not hand out a view into the stored document either.
			got.Steps[0].Kind = "MUTATED"
			got.Features.Reasons["exposure"] = "mutated"
			got.Score.Weights["risk"] = 99
			if again := mustGetPath(t, store, "path-0001"); !reflect.DeepEqual(again, fresh) {
				t.Errorf("a read leaked the stored document: %+v", again)
			}

			listed, _, err := store.ListPaths(path.PathQuery{AuditID: auditMainID})
			if err != nil || len(listed) != 1 {
				t.Fatalf("ListPaths = %v, %v", listed, err)
			}
			if !reflect.DeepEqual(listed[0], fresh) {
				t.Errorf("ListPaths lost a nested document: %+v", listed[0])
			}
		})
	}
}

func TestFeatureSnapshotsAreAppendOnly(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1)

			first := newFeatureFixture(p1, 1)
			second := newFeatureFixture(p1, 2)
			second.Priority = 0.8
			if err := store.AppendFeatures([]path.FeatureRecord{first}); err != nil {
				t.Fatalf("AppendFeatures: %v", err)
			}
			if err := store.AppendFeatures([]path.FeatureRecord{second}); err != nil {
				t.Fatalf("AppendFeatures: %v", err)
			}
			records, err := store.ListFeatures(p1.ID, 0)
			if err != nil || len(records) != 2 {
				t.Fatalf("ListFeatures = %d records, %v", len(records), err)
			}
			if records[0].Seq != 1 || records[1].Seq != 2 {
				t.Errorf("snapshots are not ordered by seq: %d, %d", records[0].Seq, records[1].Seq)
			}
			if !reflect.DeepEqual(records[0], first) || !reflect.DeepEqual(records[1], second) {
				t.Errorf("snapshots changed on the round trip: %+v", records)
			}
			recent, err := store.ListFeatures(p1.ID, 1)
			if err != nil || len(recent) != 1 || recent[0].Seq != 2 {
				t.Errorf("ListFeatures(limit 1) = %+v, %v", recent, err)
			}
			if err := store.AppendFeatures([]path.FeatureRecord{first}); !errors.Is(err, path.ErrConflict) {
				t.Errorf("AppendFeatures with a used sequence = %v, want path.ErrConflict", err)
			}
			missing := newFeatureFixture(p1, 1)
			missing.PathID = "path-missing"
			if err := store.AppendFeatures([]path.FeatureRecord{missing}); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("AppendFeatures for a missing path = %v, want path.ErrNotFound", err)
			}
			if records, err := store.ListFeatures("path-missing", 0); err != nil || len(records) != 0 {
				t.Errorf("ListFeatures(missing) = %+v, %v", records, err)
			}

			// A rerun keeps the history of a surviving path and drops the history of
			// a path that left the generation.
			if err := store.ReplacePaths(auditMainID, []path.Path{p1}); err != nil {
				t.Fatalf("ReplacePaths (rerun): %v", err)
			}
			if records, err := store.ListFeatures(p1.ID, 0); err != nil || len(records) != 2 {
				t.Errorf("a rerun dropped the score history: %d records, %v", len(records), err)
			}
			p9 := newPathFixture("path-0009", auditMainID, auditSnapID, "asgn-entry-3", "asgn-sink-sql", 0.3)
			if err := store.ReplacePaths(auditMainID, []path.Path{p9}); err != nil {
				t.Fatalf("ReplacePaths: %v", err)
			}
			if records, err := store.ListFeatures(p1.ID, 0); err != nil || len(records) != 0 {
				t.Errorf("features of a removed path survived: %+v, %v", records, err)
			}
		})
	}
}

func TestEventLog(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			p2 := newPathFixture("path-0002", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-exec", 0.5)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1, p2)
			seedAudit(t, store, newAuditFixture(auditSecondID, auditOtherSnapID, 1))

			seq, err := store.NextEventSeq(auditMainID)
			if err != nil || seq != 1 {
				t.Fatalf("NextEventSeq = %d, %v", seq, err)
			}
			if err := store.AppendEvents([]path.Event{newEventFixture(auditMainID, p1.ID, seq, path.EventPathQueued)}); err != nil {
				t.Fatalf("AppendEvents: %v", err)
			}
			// A rerun must keep appending to the same audit log.
			if err := store.ReplacePaths(auditMainID, []path.Path{p1, p2}); err != nil {
				t.Fatalf("ReplacePaths (rerun): %v", err)
			}
			next, err := store.NextEventSeq(auditMainID)
			if err != nil || next <= seq {
				t.Fatalf("NextEventSeq after a rerun = %d, %v (was %d)", next, err, seq)
			}
			if err := store.AppendEvents([]path.Event{newEventFixture(auditMainID, p2.ID, next, path.EventPathQueued)}); err != nil {
				t.Fatalf("AppendEvents after a rerun: %v", err)
			}
			if err := store.AppendEvents([]path.Event{newEventFixture(auditMainID, p2.ID, seq, path.EventPathQueued)}); !errors.Is(err, path.ErrConflict) {
				t.Errorf("AppendEvents with a used sequence = %v, want path.ErrConflict", err)
			}
			if _, err := store.NextEventSeq(auditSecondID); err != nil {
				t.Fatalf("NextEventSeq of a second audit: %v", err)
			}
			if seq2, _ := store.NextEventSeq(auditSecondID); seq2 != 1 {
				t.Errorf("event sequences are not audit-scoped: second audit starts at %d", seq2)
			}

			all := listEvents(t, store, path.EventQuery{AuditID: auditMainID})
			if len(all) != 2 || all[0].Seq != 1 || all[1].Seq != 2 {
				t.Fatalf("events = %+v", all)
			}
			if all[0].ID == "" || all[1].ID == "" {
				t.Errorf("event ids were not derived: %+v", all)
			}
			if !reflect.DeepEqual(all[0].Detail, map[string]string{"source": "fixture"}) {
				t.Errorf("event detail = %v", all[0].Detail)
			}
			if after := listEvents(t, store, path.EventQuery{AuditID: auditMainID, AfterSeq: 1}); len(after) != 1 || after[0].Seq != 2 {
				t.Errorf("AfterSeq = %+v", after)
			}
			if only := listEvents(t, store, path.EventQuery{AuditID: auditMainID, PathID: p1.ID}); len(only) != 1 || only[0].PathID != p1.ID {
				t.Errorf("per-path filter = %+v", only)
			}
			if none := listEvents(t, store, path.EventQuery{AuditID: auditMainID, PathID: "path-absent"}); len(none) != 0 {
				t.Errorf("per-path filter leaked events: %+v", none)
			}
			if _, err := store.NextEventSeq(auditAbsentID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("NextEventSeq(absent) = %v, want path.ErrNotFound", err)
			}
			orphan := newEventFixture(auditAbsentID, "", 1, path.EventPathQueued)
			if err := store.AppendEvents([]path.Event{orphan}); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("AppendEvents for an absent audit = %v, want path.ErrNotFound", err)
			}
		})
	}
}

func TestOptimisticConcurrency(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			want := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), want)

			stale := want
			stale.Score.Priority = 0.01
			if err := store.UpdatePath(stale, 5); !errors.Is(err, path.ErrConflict) {
				t.Errorf("UpdatePath with a stale version = %v, want path.ErrConflict", err)
			}
			if got := mustGetPath(t, store, want.ID); !reflect.DeepEqual(got, want) {
				t.Errorf("a stale update changed the row: %+v", got)
			}
			if err := store.UpdatePath(stale, 1); err != nil {
				t.Fatalf("UpdatePath: %v", err)
			}
			if got := mustGetPath(t, store, want.ID); got.Score.Priority != 0.01 || got.Version != 2 {
				t.Errorf("UpdatePath stored %+v", got)
			}
			absent := newPathFixture("path-0002", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.2)
			if err := store.UpdatePath(absent, 0); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("UpdatePath(absent) = %v, want path.ErrNotFound", err)
			}
		})
	}
}

func TestTransitionAppliesStateAndEvent(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			p2 := newPathFixture("path-0002", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-exec", 0.5)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1, p2)

			moved, err := store.Transition(path.TransitionRequest{
				PathID: p1.ID, To: path.StatusAnalyzing, ExpectedVersion: 1, Actor: "operator",
				Reason: "starting the audit",
			})
			if err != nil {
				t.Fatalf("Transition: %v", err)
			}
			if moved.Status != path.StatusAnalyzing || moved.Version != 2 {
				t.Fatalf("Transition returned %+v", moved)
			}
			events := listEvents(t, store, path.EventQuery{AuditID: auditMainID})
			if len(events) != 1 {
				t.Fatalf("a transition appended %d events, want exactly 1", len(events))
			}
			event := events[0]
			if event.Type != path.EventPathStatusChange || event.From != path.StatusQueued ||
				event.To != path.StatusAnalyzing || event.Actor != "operator" || event.PathID != p1.ID {
				t.Errorf("event = %+v", event)
			}

			// An illegal transition changes nothing at all.
			if _, err := store.Transition(path.TransitionRequest{
				PathID: p1.ID, To: path.StatusVerifying, ExpectedVersion: 2, Actor: "operator",
			}); !errors.Is(err, path.ErrInvalidTransition) {
				t.Errorf("illegal transition = %v, want path.ErrInvalidTransition", err)
			}
			if _, err := store.Transition(path.TransitionRequest{
				PathID: p1.ID, To: path.StatusLocalExploring, ExpectedVersion: 99, Actor: "operator",
			}); !errors.Is(err, path.ErrConflict) {
				t.Errorf("transition with a stale version = %v, want path.ErrConflict", err)
			}
			after := mustGetPath(t, store, p1.ID)
			if after.Status != path.StatusAnalyzing || after.Version != 2 {
				t.Errorf("a rejected transition changed the path: %+v", after)
			}
			if len(listEvents(t, store, path.EventQuery{AuditID: auditMainID})) != 1 {
				t.Errorf("a rejected transition appended an event")
			}

			// A transition may carry a new score and new features, and it keeps a
			// lease it does not clear.
			claimed, err := store.ClaimPath(p2.ID, "worker-1", clockNearFuture(), []path.Status{path.StatusQueued}, "worker-1")
			if err != nil {
				t.Fatalf("ClaimPath: %v", err)
			}
			if claimed.Status != path.StatusAnalyzing || claimed.LeaseOwner != "worker-1" {
				t.Fatalf("ClaimPath returned %+v", claimed)
			}
			if _, err := store.Transition(path.TransitionRequest{
				PathID: p2.ID, To: path.StatusHypothesisFormed, ExpectedVersion: claimed.Version,
				Owner: "worker-2", Actor: "worker-2",
			}); !errors.Is(err, path.ErrLeaseHeld) {
				t.Errorf("a foreign owner transitioned a leased path: %v", err)
			}
			newScore := path.Score{
				Risk: 0.11, Support: 0.22, Utility: 0.33, Priority: 0.99, ScoreVersion: path.ScoreVersion,
				Weights: map[string]float64{"risk": 1.0}, ComputedAt: "2024-06-01T00:00:00Z",
			}
			newFeatures := path.Features{Exposure: 0.05, Reasons: map[string]string{"exposure": "rescored"}}
			rescored, err := store.Transition(path.TransitionRequest{
				PathID: p2.ID, To: path.StatusHypothesisFormed, ExpectedVersion: claimed.Version,
				Owner: "worker-1", Actor: "worker-1", Score: &newScore, Features: &newFeatures,
			})
			if err != nil {
				t.Fatalf("Transition with a score: %v", err)
			}
			if !reflect.DeepEqual(rescored.Score, newScore) {
				t.Errorf("score = %+v, want %+v", rescored.Score, newScore)
			}
			if !reflect.DeepEqual(rescored.Features, newFeatures) {
				t.Errorf("features = %+v, want %+v", rescored.Features, newFeatures)
			}
			if rescored.LeaseOwner != "worker-1" {
				t.Errorf("the lease was dropped without ClearLease: %+v", rescored)
			}
			if stored := mustGetPath(t, store, p2.ID); !reflect.DeepEqual(stored.Score, newScore) {
				t.Errorf("the stored score is %+v", stored.Score)
			}

			paused, err := store.Transition(path.TransitionRequest{
				PathID: p2.ID, To: path.StatusPaused, ExpectedVersion: rescored.Version,
				Owner: "worker-1", ClearLease: true, Actor: "worker-1", Reason: "operator paused it",
			})
			if err != nil {
				t.Fatalf("Transition with ClearLease: %v", err)
			}
			if paused.LeaseOwner != "" || paused.LeaseUntil != "" || paused.HeartbeatAt != "" {
				t.Errorf("ClearLease left a lease behind: %+v", paused)
			}
			if _, err := store.Transition(path.TransitionRequest{
				PathID: "path-absent", To: path.StatusAnalyzing, Actor: "operator",
			}); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("Transition on an absent path = %v, want path.ErrNotFound", err)
			}
		})
	}
}

func TestClaimPathLeases(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			p2 := newPathFixture("path-0002", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-exec", 0.5)
			p3 := newPathFixture("path-0003", auditMainID, auditSnapID, "asgn-entry-2", "asgn-sink-sql", 0.4)
			p3.Status = path.StatusDiscovered
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1, p2, p3)

			until := clockNearFuture()
			claimed, err := store.ClaimPath(p1.ID, "worker-1", until, []path.Status{path.StatusQueued}, "worker-1")
			if err != nil {
				t.Fatalf("ClaimPath: %v", err)
			}
			if claimed.Status != path.StatusAnalyzing || claimed.LeaseOwner != "worker-1" ||
				claimed.LeaseUntil != until || claimed.Version != 2 || claimed.HeartbeatAt == "" {
				t.Fatalf("ClaimPath returned %+v", claimed)
			}
			events := listEvents(t, store, path.EventQuery{AuditID: auditMainID, PathID: p1.ID})
			if len(events) != 1 || events[0].Type != path.EventPathClaimed ||
				events[0].From != path.StatusQueued || events[0].To != path.StatusAnalyzing {
				t.Errorf("claim event = %+v", events)
			}
			if _, err := store.ClaimPath(p1.ID, "worker-2", until, []path.Status{path.StatusQueued}, "worker-2"); !errors.Is(err, path.ErrNotClaimable) && !errors.Is(err, path.ErrLeaseHeld) {
				t.Errorf("second claim = %v, want path.ErrNotClaimable or path.ErrLeaseHeld", err)
			}
			if _, err := store.ClaimPath(p3.ID, "worker-1", until, []path.Status{path.StatusQueued}, "worker-1"); !errors.Is(err, path.ErrNotClaimable) {
				t.Errorf("claim outside the allowed sources = %v, want path.ErrNotClaimable", err)
			}
			if _, err := store.ClaimPath(p2.ID, "", until, []path.Status{path.StatusQueued}, ""); !errors.Is(err, path.ErrInvalidArgument) {
				t.Errorf("claim without an owner = %v, want path.ErrInvalidArgument", err)
			}
			if _, err := store.ClaimPath("path-absent", "worker-1", until, []path.Status{path.StatusQueued}, "worker-1"); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("claim on an absent path = %v, want path.ErrNotFound", err)
			}

			// A queued path somebody already holds is a lease conflict, not a
			// status conflict.
			held := mustGetPath(t, store, p2.ID)
			held.LeaseOwner = "worker-9"
			held.LeaseUntil = until
			if err := store.UpdatePath(held, held.Version); err != nil {
				t.Fatalf("UpdatePath: %v", err)
			}
			if _, err := store.ClaimPath(p2.ID, "worker-2", until, []path.Status{path.StatusQueued}, "worker-2"); !errors.Is(err, path.ErrLeaseHeld) {
				t.Errorf("claim on a path held by another owner = %v, want path.ErrLeaseHeld", err)
			}
		})
	}
}

func TestLeaseLifecycle(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			p2 := newPathFixture("path-0002", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-exec", 0.5)
			p3 := newPathFixture("path-0003", auditMainID, auditSnapID, "asgn-entry-2", "asgn-sink-sql", 0.4)
			p4 := newPathFixture("path-0004", auditMainID, auditSnapID, "asgn-entry-2", "asgn-sink-exec", 0.3)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1, p2, p3, p4)

			future := clockNearFuture()
			claimed, err := store.ClaimPath(p1.ID, "worker-1", future, []path.Status{path.StatusQueued}, "worker-1")
			if err != nil {
				t.Fatalf("ClaimPath: %v", err)
			}
			extended := path.NowString(time.Now().UTC().Add(2 * time.Hour))
			renewed, err := store.RenewLease(p1.ID, "worker-1", extended, "worker-1")
			if err != nil {
				t.Fatalf("RenewLease: %v", err)
			}
			if renewed.LeaseUntil != extended || renewed.Version != claimed.Version+1 {
				t.Fatalf("RenewLease returned %+v", renewed)
			}
			heartbeats := listEvents(t, store, path.EventQuery{AuditID: auditMainID, PathID: p1.ID})
			if len(heartbeats) != 2 || heartbeats[1].Type != path.EventPathHeartbeat {
				t.Errorf("renewal events = %+v", heartbeats)
			}
			if _, err := store.RenewLease(p1.ID, "worker-2", extended, "worker-2"); !errors.Is(err, path.ErrLeaseHeld) {
				t.Errorf("RenewLease by a foreign owner = %v, want path.ErrLeaseHeld", err)
			}
			if _, err := store.ReleaseLease(p1.ID, "worker-2", "worker-2", "not mine"); !errors.Is(err, path.ErrLeaseHeld) {
				t.Errorf("ReleaseLease by a foreign owner = %v, want path.ErrLeaseHeld", err)
			}
			if got := mustGetPath(t, store, p1.ID); got.LeaseUntil != extended || got.Version != renewed.Version {
				t.Errorf("a rejected lease change altered the row: %+v", got)
			}

			released, err := store.ReleaseLease(p1.ID, "worker-1", "worker-1", "handing back")
			if err != nil {
				t.Fatalf("ReleaseLease: %v", err)
			}
			if released.Status != path.StatusQueued || released.LeaseOwner != "" || released.LeaseUntil != "" {
				t.Fatalf("ReleaseLease returned %+v", released)
			}
			events := listEvents(t, store, path.EventQuery{AuditID: auditMainID, PathID: p1.ID})
			if last := events[len(events)-1]; last.Type != path.EventPathReleased || last.To != path.StatusQueued {
				t.Errorf("release event = %+v", last)
			}
			if _, err := store.RenewLease(p1.ID, "worker-1", extended, "worker-1"); !errors.Is(err, path.ErrLeaseExpired) {
				t.Errorf("RenewLease after release = %v, want path.ErrLeaseExpired", err)
			}

			// An expired lease cannot be extended: the scheduler owns recovery.
			expired, err := store.ClaimPath(p2.ID, "worker-1", clockNearPast(), []path.Status{path.StatusQueued}, "worker-1")
			if err != nil {
				t.Fatalf("ClaimPath with an expired lease: %v", err)
			}
			if _, err := store.RenewLease(p2.ID, "worker-1", extended, "worker-1"); !errors.Is(err, path.ErrLeaseExpired) {
				t.Errorf("RenewLease on an expired lease = %v, want path.ErrLeaseExpired", err)
			}
			if got := mustGetPath(t, store, p2.ID); got.LeaseUntil != expired.LeaseUntil || got.Version != expired.Version {
				t.Errorf("a rejected renewal altered the row: %+v", got)
			}

			// Only expired leases are reclaimed, and the recovery is logged.
			if _, err := store.ClaimPath(p3.ID, "worker-1", future, []path.Status{path.StatusQueued}, "worker-1"); err != nil {
				t.Fatalf("ClaimPath: %v", err)
			}
			if _, err := store.ClaimPath(p4.ID, "worker-1", clockNearPast(), []path.Status{path.StatusQueued}, "worker-1"); err != nil {
				t.Fatalf("ClaimPath: %v", err)
			}
			now := path.NowString(time.Now().UTC())
			recovered, err := store.ReclaimExpired(now, 1, "scheduler")
			if err != nil {
				t.Fatalf("ReclaimExpired: %v", err)
			}
			if len(recovered) != 1 || recovered[0].ID != p2.ID {
				t.Fatalf("ReclaimExpired = %+v, want just %s", pathIDs(recovered), p2.ID)
			}
			if recovered[0].Status != path.StatusQueued || recovered[0].LeaseOwner != "" {
				t.Errorf("recovered path = %+v", recovered[0])
			}
			recoveryEvents := listEvents(t, store, path.EventQuery{AuditID: auditMainID, PathID: p2.ID})
			if last := recoveryEvents[len(recoveryEvents)-1]; last.Type != path.EventPathLeaseExpired || last.To != path.StatusQueued {
				t.Errorf("recovery event = %+v", last)
			}
			stillHeld := mustGetPath(t, store, p3.ID)
			if stillHeld.LeaseOwner != "worker-1" || stillHeld.Status != path.StatusAnalyzing {
				t.Errorf("a live lease was reclaimed: %+v", stillHeld)
			}
			rest, err := store.ReclaimExpired(now, 10, "scheduler")
			if err != nil || len(rest) != 1 || rest[0].ID != p4.ID {
				t.Fatalf("second ReclaimExpired = %+v, %v", pathIDs(rest), err)
			}
			if none, err := store.ReclaimExpired(now, 10, "scheduler"); err != nil || len(none) != 0 {
				t.Errorf("ReclaimExpired with nothing to do = %+v, %v", none, err)
			}
		})
	}
}

func TestDeleteAuditsForSnapshot(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			first := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), first)
			second := newPathFixture("path-0002", auditSecondID, auditOtherSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			seedAudit(t, store, newAuditFixture(auditSecondID, auditOtherSnapID, 1), second)
			for _, seed := range []struct {
				auditID string
				pathID  string
			}{{auditMainID, first.ID}, {auditSecondID, second.ID}} {
				if err := store.AppendFeatures([]path.FeatureRecord{newFeatureFixture(
					path.Path{ID: seed.pathID, AuditID: seed.auditID, Score: path.Score{}, Features: path.Features{}}, 1)}); err != nil {
					t.Fatalf("AppendFeatures: %v", err)
				}
				seq, err := store.NextEventSeq(seed.auditID)
				if err != nil {
					t.Fatalf("NextEventSeq: %v", err)
				}
				if err := store.AppendEvents([]path.Event{newEventFixture(seed.auditID, seed.pathID, seq, path.EventPathQueued)}); err != nil {
					t.Fatalf("AppendEvents: %v", err)
				}
			}

			if removed, err := store.DeleteAuditsForSnapshot(auditAbsentSnap); err != nil || removed != 0 {
				t.Errorf("DeleteAuditsForSnapshot(absent) = %d, %v", removed, err)
			}
			removed, err := store.DeleteAuditsForSnapshot(auditSnapID)
			if err != nil || removed != 1 {
				t.Fatalf("DeleteAuditsForSnapshot = %d, %v", removed, err)
			}
			if _, err := store.GetAudit(auditMainID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("the audit survived: %v", err)
			}
			if _, err := store.GetPath(first.ID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("the path survived: %v", err)
			}
			if records, err := store.ListFeatures(first.ID, 0); err != nil || len(records) != 0 {
				t.Errorf("the features survived: %+v, %v", records, err)
			}
			if events := listEvents(t, store, path.EventQuery{AuditID: auditMainID}); len(events) != 0 {
				t.Errorf("the events survived: %+v", events)
			}
			if _, err := store.NextEventSeq(auditMainID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("NextEventSeq after deletion = %v, want path.ErrNotFound", err)
			}

			if _, err := store.GetAudit(auditSecondID); err != nil {
				t.Fatalf("deleting one snapshot removed another audit: %v", err)
			}
			if _, err := store.GetPath(second.ID); err != nil {
				t.Fatalf("deleting one snapshot removed another path: %v", err)
			}
			if records, err := store.ListFeatures(second.ID, 0); err != nil || len(records) != 1 {
				t.Errorf("the surviving features = %+v, %v", records, err)
			}
			if events := listEvents(t, store, path.EventQuery{AuditID: auditSecondID}); len(events) != 1 {
				t.Errorf("the surviving events = %+v", events)
			}
			if seq, err := store.NextEventSeq(auditSecondID); err != nil || seq != 2 {
				t.Errorf("the surviving event sequence = %d, %v", seq, err)
			}
		})
	}
}

func TestDeleteSnapshotRemovesAudits(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			ctx := context.Background()
			project := testProject("proj-audit")
			if err := store.PutProject(ctx, project); err != nil {
				t.Fatalf("PutProject: %v", err)
			}
			if err := store.PutSnapshot(ctx, project.ID, testSnapshot(auditSnapID)); err != nil {
				t.Fatalf("PutSnapshot: %v", err)
			}
			p1 := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p1)
			if err := store.AppendFeatures([]path.FeatureRecord{newFeatureFixture(p1, 1)}); err != nil {
				t.Fatalf("AppendFeatures: %v", err)
			}
			if err := store.AppendEvents([]path.Event{newEventFixture(auditMainID, p1.ID, 1, path.EventPathQueued)}); err != nil {
				t.Fatalf("AppendEvents: %v", err)
			}

			if err := store.DeleteSnapshot(ctx, auditSnapID); err != nil {
				t.Fatalf("DeleteSnapshot: %v", err)
			}
			if _, err := store.GetAudit(auditMainID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("GetAudit after DeleteSnapshot = %v, want path.ErrNotFound", err)
			}
			if _, err := store.GetPath(p1.ID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("GetPath after DeleteSnapshot = %v, want path.ErrNotFound", err)
			}
			if _, total, err := store.ListAudits(path.AuditQuery{SnapshotID: auditSnapID}); err != nil || total != 0 {
				t.Errorf("ListAudits after DeleteSnapshot = %d, %v", total, err)
			}
			if events := listEvents(t, store, path.EventQuery{AuditID: auditMainID}); len(events) != 0 {
				t.Errorf("ListEvents after DeleteSnapshot = %+v", events)
			}
			if _, err := store.NextEventSeq(auditMainID); !errors.Is(err, path.ErrNotFound) {
				t.Errorf("NextEventSeq after DeleteSnapshot = %v, want path.ErrNotFound", err)
			}
			if records, err := store.ListFeatures(p1.ID, 0); err != nil || len(records) != 0 {
				t.Errorf("ListFeatures after DeleteSnapshot = %+v, %v", records, err)
			}
		})
	}
}

// Fixed retry times. They are RFC3339 strings, so a string comparison is a time
// comparison, and the expectations below do not depend on the wall clock.
const (
	retryEarly = "2024-05-01T12:00:00Z"
	retryMid   = "2024-05-01T12:05:00Z"
	retryLate  = "2024-05-01T12:10:00Z"
)

// seedRetrySchedule stores five paths of one audit with distinct retry times:
// path-0001 was never deferred (an empty NextAttemptAt, which counts as due),
// path-0002 is deferred to the latest time, path-0003 and path-0004 share the
// middle time (so the path id has to break the tie) and path-0005 is paused, so
// it is deferred but not queued.
func seedRetrySchedule(t *testing.T, store FullStore, auditID, snapshotID string) {
	t.Helper()
	neverDeferred := newPathFixture("path-0001", auditID, snapshotID, "asgn-entry-1", "asgn-sink-sql", 0.9)
	deferredLate := newPathFixture("path-0002", auditID, snapshotID, "asgn-entry-1", "asgn-sink-exec", 0.5)
	deferredLate.NextAttemptAt = retryLate
	deferredMid := newPathFixture("path-0003", auditID, snapshotID, "asgn-entry-2", "asgn-sink-sql", 0.7)
	deferredMid.NextAttemptAt = retryMid
	deferredTie := newPathFixture("path-0004", auditID, snapshotID, "asgn-entry-2", "asgn-sink-exec", 0.6)
	deferredTie.NextAttemptAt = retryMid
	paused := newPathFixture("path-0005", auditID, snapshotID, "asgn-entry-3", "asgn-sink-sql", 0.3)
	paused.Status = path.StatusPaused
	paused.NextAttemptAt = retryMid
	seedAudit(t, store, newAuditFixture(auditID, snapshotID, 1),
		neverDeferred, deferredLate, deferredMid, deferredTie, paused)
}

func TestListDuePathsHonoursTheRetrySchedule(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			seedRetrySchedule(t, store, auditMainID, auditSnapID)
			// A second audit proves the query is audit-scoped. Path ids are the
			// primary key, so it needs ids of its own.
			otherDue := newPathFixture("path-0009", auditSecondID, auditOtherSnapID, "asgn-entry-9", "asgn-sink-sql", 0.4)
			seedAudit(t, store, newAuditFixture(auditSecondID, auditOtherSnapID, 1), otherDue)

			cases := []struct {
				name  string
				now   string
				limit int
				want  []string
			}{
				{"before the first deferral elapses", retryEarly, 0, []string{"path-0001"}},
				{"exactly at a deferred time", retryMid, 0, []string{"path-0001", "path-0003", "path-0004"}},
				{"after every deferral", retryLate, 0, []string{"path-0001", "path-0003", "path-0004", "path-0002"}},
				{"past every deferral", "2030-01-01T00:00:00Z", 0, []string{"path-0001", "path-0003", "path-0004", "path-0002"}},
				{"limit", retryLate, 2, []string{"path-0001", "path-0003"}},
				{"limit of one", retryLate, 1, []string{"path-0001"}},
			}
			for _, c := range cases {
				due, err := store.ListDuePaths(auditMainID, c.now, c.limit)
				if err != nil {
					t.Fatalf("%s: ListDuePaths: %v", c.name, err)
				}
				if ids := pathIDs(due); !reflect.DeepEqual(ids, c.want) {
					t.Errorf("%s: due = %v, want %v", c.name, ids, c.want)
				}
			}

			// The due time survives the round trip, which is what makes the order a
			// durable schedule and not an accident of the fixture's insertion order.
			due, err := store.ListDuePaths(auditMainID, retryLate, 0)
			if err != nil {
				t.Fatalf("ListDuePaths: %v", err)
			}
			if due[0].NextAttemptAt != "" || due[1].NextAttemptAt != retryMid || due[3].NextAttemptAt != retryLate {
				t.Errorf("the due times were lost: %q, %q, %q", due[0].NextAttemptAt, due[1].NextAttemptAt, due[3].NextAttemptAt)
			}

			// A paused path is deferred out of the queue: it is never due, whatever
			// `now` says, and its own audit does not borrow the main one's paths.
			for _, now := range []string{retryEarly, retryMid, retryLate} {
				due, err := store.ListDuePaths(auditMainID, now, 0)
				if err != nil {
					t.Fatalf("ListDuePaths(%s): %v", now, err)
				}
				for _, p := range due {
					if p.ID == "path-0005" {
						t.Errorf("a paused path was due at %s", now)
					}
					if p.Status != path.StatusQueued {
						t.Errorf("ListDuePaths returned a %s path: %+v", p.Status, p)
					}
				}
			}
			due, err = store.ListDuePaths(auditSecondID, retryEarly, 0)
			if err != nil {
				t.Fatalf("ListDuePaths for the second audit: %v", err)
			}
			if ids := pathIDs(due); !reflect.DeepEqual(ids, []string{"path-0009"}) {
				t.Errorf("the second audit's due paths = %v, want [path-0009]", ids)
			}
			// A listing for an audit that does not exist is empty, not an error: the
			// scheduler asks for every audit it knows about.
			if due, err := store.ListDuePaths(auditAbsentID, retryLate, 0); err != nil || len(due) != 0 {
				t.Errorf("ListDuePaths(absent) = %v, %v, want no paths and no error", pathIDs(due), err)
			}
		})
	}
}

func TestTransitionPersistsAndClearsTheRetryTime(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			p := newPathFixture("path-0001", auditMainID, auditSnapID, "asgn-entry-1", "asgn-sink-sql", 0.9)
			seedAudit(t, store, newAuditFixture(auditMainID, auditSnapID, 1), p)

			// A failed attempt happens to a running path, so the run is claimed first;
			// the failure then records when the retry may run, together with the
			// attempt and the error that produced it.
			claimed, err := store.ClaimPath(p.ID, "worker-1", clockNearFuture(), []path.Status{path.StatusQueued}, "worker-1")
			if err != nil {
				t.Fatalf("ClaimPath: %v", err)
			}
			failed, err := store.Transition(path.TransitionRequest{
				PathID: p.ID, To: path.StatusFailed, ExpectedVersion: claimed.Version, Owner: "worker-1",
				ClearLease: true, Actor: "worker-1", Reason: "the adapter timed out",
				IncrementAttempts: true, LastError: "timeout", NextAttemptAt: retryLate,
			})
			if err != nil {
				t.Fatalf("Transition to FAILED: %v", err)
			}
			if failed.NextAttemptAt != retryLate || failed.Attempts != 1 || failed.LastError != "timeout" {
				t.Fatalf("the failure was stored as %+v", failed)
			}
			if stored := mustGetPath(t, store, p.ID); stored.NextAttemptAt != retryLate {
				t.Errorf("the retry time did not survive the write: %q", stored.NextAttemptAt)
			}
			// A failed path is not queued, so it is not due however long the backoff
			// has been: only an explicit requeue makes it runnable again.
			if due, err := store.ListDuePaths(auditMainID, "2030-01-01T00:00:00Z", 0); err != nil || len(due) != 0 {
				t.Errorf("a failed path was due = %v, %v", pathIDs(due), err)
			}

			// The requeue is the other half of the policy: the path returns to QUEUED
			// carrying the deferral, so the scheduler skips it until the backoff
			// elapses.
			queued, err := store.Transition(path.TransitionRequest{
				PathID: p.ID, To: path.StatusQueued, ExpectedVersion: failed.Version, Actor: "scheduler",
				Reason: "retry scheduled", NextAttemptAt: retryLate,
			})
			if err != nil {
				t.Fatalf("Transition to QUEUED: %v", err)
			}
			if queued.NextAttemptAt != retryLate {
				t.Fatalf("the requeue stored %q, want %q", queued.NextAttemptAt, retryLate)
			}
			if due, err := store.ListDuePaths(auditMainID, retryMid, 0); err != nil || len(due) != 0 {
				t.Errorf("a deferred path was due early = %v, %v", pathIDs(due), err)
			}
			due, err := store.ListDuePaths(auditMainID, retryLate, 0)
			if err != nil {
				t.Fatalf("ListDuePaths: %v", err)
			}
			if ids := pathIDs(due); !reflect.DeepEqual(ids, []string{p.ID}) {
				t.Errorf("once the backoff elapsed, due = %v, want [%s]", ids, p.ID)
			}

			// A claim consumes the deferral: the worker is running the path now.
			claimed, err = store.ClaimPath(p.ID, "worker-1", clockNearFuture(), []path.Status{path.StatusQueued}, "worker-1")
			if err != nil {
				t.Fatalf("ClaimPath: %v", err)
			}
			if claimed.NextAttemptAt != "" || mustGetPath(t, store, p.ID).NextAttemptAt != "" {
				t.Errorf("a claimed path kept its deferral: %q", claimed.NextAttemptAt)
			}

			// A settlement clears it too, even when it was written outside a
			// transition (a recovered row, an operator edit): an explicit empty value
			// is the instruction to run the path now.
			active := mustGetPath(t, store, p.ID)
			active.NextAttemptAt = retryLate
			if err := store.UpdatePath(active, active.Version); err != nil {
				t.Fatalf("UpdatePath: %v", err)
			}
			if stored := mustGetPath(t, store, p.ID); stored.NextAttemptAt != retryLate {
				t.Fatalf("UpdatePath stored %q, want %q", stored.NextAttemptAt, retryLate)
			}
			beforeSettlement := mustGetPath(t, store, p.ID)
			settled, err := store.Transition(path.TransitionRequest{
				PathID: p.ID, To: path.StatusConcluded, ExpectedVersion: beforeSettlement.Version,
				Owner: "worker-1", ClearLease: true, Actor: "worker-1", Reason: "the verdict was recorded",
			})
			if err != nil {
				t.Fatalf("Transition to CONCLUDED: %v", err)
			}
			if settled.NextAttemptAt != "" {
				t.Errorf("the settlement kept a retry time: %q", settled.NextAttemptAt)
			}
			if stored := mustGetPath(t, store, p.ID); stored.NextAttemptAt != "" {
				t.Errorf("the stored settlement kept a retry time: %q", stored.NextAttemptAt)
			}
		})
	}
}

func TestListPathsDueBeforeIsTheSameQuestionAsListDuePaths(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			store := tc.store
			seedRetrySchedule(t, store, auditMainID, auditSnapID)

			cases := []struct {
				name      string
				dueBefore string
				status    []path.Status
				want      []string
			}{
				{"before the first deferral", retryEarly, nil, []string{"path-0001"}},
				{"at a deferred time", retryMid, nil, []string{"path-0001", "path-0003", "path-0004", "path-0005"}},
				{"after every deferral", retryLate, nil, []string{"path-0001", "path-0002", "path-0003", "path-0004", "path-0005"}},
				{"queued only", retryMid, []path.Status{path.StatusQueued}, []string{"path-0001", "path-0003", "path-0004"}},
				{"paused only", retryMid, []path.Status{path.StatusPaused}, []string{"path-0005"}},
			}
			for _, c := range cases {
				got, total, err := store.ListPaths(path.PathQuery{
					AuditID: auditMainID, DueBefore: c.dueBefore, Status: c.status, Sort: "path_id",
				})
				if err != nil {
					t.Fatalf("%s: ListPaths: %v", c.name, err)
				}
				if total != len(c.want) {
					t.Errorf("%s: total = %d, want %d", c.name, total, len(c.want))
				}
				if ids := pathIDs(got); !reflect.DeepEqual(ids, c.want) {
					t.Errorf("%s: ids = %v, want %v", c.name, ids, c.want)
				}
			}

			// No DueBefore is no filter: the retry time does not hide a path from the
			// ordinary listing.
			if _, total, err := store.ListPaths(path.PathQuery{AuditID: auditMainID, Sort: "path_id"}); err != nil || total != 5 {
				t.Errorf("an unfiltered listing = %d paths, %v, want 5", total, err)
			}

			// The dedicated query and the filtered listing are two spellings of the
			// same question, so they must agree at every point in time.
			for _, now := range []string{retryEarly, retryMid, retryLate} {
				due, err := store.ListDuePaths(auditMainID, now, 0)
				if err != nil {
					t.Fatalf("ListDuePaths(%s): %v", now, err)
				}
				listed, _, err := store.ListPaths(path.PathQuery{
					AuditID: auditMainID, Status: []path.Status{path.StatusQueued}, DueBefore: now, Sort: "path_id",
				})
				if err != nil {
					t.Fatalf("ListPaths(due before %s): %v", now, err)
				}
				if len(due) != len(listed) {
					t.Fatalf("at %s: ListDuePaths = %v, ListPaths = %v", now, pathIDs(due), pathIDs(listed))
				}
				dueIDs := make(map[string]bool, len(due))
				for _, p := range due {
					dueIDs[p.ID] = true
				}
				for _, p := range listed {
					if !dueIDs[p.ID] {
						t.Errorf("at %s: %s is due by the listing but not by ListDuePaths", now, p.ID)
					}
				}
			}
		})
	}
}
