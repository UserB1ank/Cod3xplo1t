package storage

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

const (
	asgSnapshotID      = "snap-0123456789abcdef0123456789abcdef"
	asgOtherSnapshotID = "snap-fedcba9876543210fedcba9876543210"
	asgAbsentSnapshot  = "snap-00000000000000000000000000000000"
)

// asgFixture builds a small deterministic document (fixed timestamps, ids
// derived from the snapshot) so the same fixture can stand in for two snapshots
// without colliding on primary keys.
func asgFixture(snapshotID string) *asg.Document {
	engine := asg.Engine{Name: "rules", Version: "1.4.0"}
	entryID := asg.NodeID(snapshotID, asg.NodeEntryPoint, "http_route:GET /users/:id", "")
	inputID := asg.NodeID(snapshotID, asg.NodeAttackerControlledInput, "input:query:id", "")
	sinkID := asg.NodeID(snapshotID, asg.NodeSensitiveOperation, "sink:sql_execution", "")
	controlID := asg.NodeID(snapshotID, asg.NodeSecurityControl, "control:authz_check", "")

	return &asg.Document{
		SchemaVersion: asg.SchemaVersion,
		SnapshotID:    snapshotID,
		ASGVersion:    asg.Version(snapshotID, "scg-v1", engine, "ruleset-abc"),
		SCGVersion:    "scg-v1",
		Engine:        engine,
		RulesetHash:   "ruleset-abc",
		Nodes: []asg.Node{
			{
				ID: entryID, SnapshotID: snapshotID, Kind: asg.NodeEntryPoint,
				Subject: "http_route:GET /users/:id", Label: "GET /users/:id",
				Detail:   map[string]string{"framework": "chi", "method": "GET", "path": "/users/:id"},
				Evidence: asg.StatusObserved, Confidence: scg.Observed,
				Generator: "rule.route", ModuleID: "mod-api", File: "internal/api/routes.go", Line: 42,
				SCGRefs: []string{"sym-0001", "cs-0001", "file-0001"},
			},
			{
				ID: inputID, SnapshotID: snapshotID, Kind: asg.NodeAttackerControlledInput,
				Subject: "input:query:id", Label: "query id",
				Evidence: asg.StatusInferred, Confidence: scg.Inferred,
				Generator: "rule.input", File: "internal/api/routes.go", Line: 43,
				SCGRefs: []string{"sym-0001", "cs-0001"},
			},
			{
				ID: sinkID, SnapshotID: snapshotID, Kind: asg.NodeSensitiveOperation,
				Subject: "sink:sql_execution", Label: "SQL execution",
				Evidence: asg.StatusObserved, Confidence: scg.Observed,
				Generator: "rule.sink", File: "internal/db/query.go", Line: 17,
				SCGRefs: []string{"sym-0002", "cs-0002"},
			},
			{
				ID: controlID, SnapshotID: snapshotID, Kind: asg.NodeSecurityControl,
				Subject: "control:authz_check", Label: "authorization check",
				Evidence: asg.StatusObserved, Confidence: scg.Observed,
				Generator: "rule.control", File: "internal/api/middleware.go", Line: 9,
				SCGRefs: []string{"sym-0003"},
			},
		},
		Edges: []asg.Edge{
			{
				ID:         asg.EdgeID(snapshotID, asg.EdgeReaches, entryID, sinkID, "cs-0001"),
				SnapshotID: snapshotID, From: entryID, To: sinkID, Kind: asg.EdgeReaches,
				Evidence: asg.StatusObserved, Confidence: scg.Observed, Generator: "rule.reach",
				Detail: map[string]string{"depth": "2"}, SCGRefs: []string{"cs-0001"},
			},
			{
				ID:         asg.EdgeID(snapshotID, asg.EdgeMayAffect, inputID, sinkID, "cs-0001"),
				SnapshotID: snapshotID, From: inputID, To: sinkID, Kind: asg.EdgeMayAffect,
				Evidence: asg.StatusInferred, Confidence: scg.Inferred, Generator: "rule.input",
				SCGRefs: []string{"cs-0001"},
			},
			{
				ID:         asg.EdgeID(snapshotID, asg.EdgeProtectedBy, sinkID, controlID, "cs-0003"),
				SnapshotID: snapshotID, From: sinkID, To: controlID, Kind: asg.EdgeProtectedBy,
				Evidence: asg.StatusObserved, Confidence: scg.Observed, Generator: "rule.control",
				SCGRefs: []string{"cs-0003"},
			},
		},
		Coverage: asg.Coverage{
			CallSitesExamined: 12, SymbolsExamined: 8, NodesSkipped: 1, EdgesSkipped: 2,
			ReachabilityDepth: 3, ReachabilityBudget: 100, EntryPointsTruncated: 1,
		},
		Limitations:     []string{"dynamic dispatch is not resolved", "only HTTP entry points were considered"},
		BuiltAt:         "2024-01-02T03:04:05Z",
		BuildDurationMS: 123,
	}
}

// asgNodeOf returns the fixture node with the given id.
func asgNodeOf(t *testing.T, doc *asg.Document, id string) asg.Node {
	t.Helper()
	for _, n := range doc.Nodes {
		if n.ID == id {
			return n
		}
	}
	t.Fatalf("fixture has no node %s", id)
	return asg.Node{}
}

// asgEdgeOf returns the fixture edge with the given id.
func asgEdgeOf(t *testing.T, doc *asg.Document, id string) asg.Edge {
	t.Helper()
	for _, e := range doc.Edges {
		if e.ID == id {
			return e
		}
	}
	t.Fatalf("fixture has no edge %s", id)
	return asg.Edge{}
}

func asgNodeKinds(doc *asg.Document) map[string]int {
	out := map[string]int{}
	for _, n := range doc.Nodes {
		out[string(n.Kind)]++
	}
	return out
}

func asgEdgeKinds(doc *asg.Document) map[string]int {
	out := map[string]int{}
	for _, e := range doc.Edges {
		out[string(e.Kind)]++
	}
	return out
}

func asgEvidenceCounts(doc *asg.Document) map[string]int {
	out := map[string]int{}
	for _, n := range doc.Nodes {
		out[string(n.Evidence)]++
	}
	return out
}

// assertASGNodeOrder checks the store's documented ordering so both
// implementations are held to the same contract.
func assertASGNodeOrder(t *testing.T, nodes []asg.Node) {
	t.Helper()
	for i := 1; i < len(nodes); i++ {
		a, b := nodes[i-1], nodes[i]
		if a.Kind > b.Kind {
			t.Fatalf("nodes are out of kind order: %s before %s", a.Kind, b.Kind)
		}
		if a.Kind == b.Kind && a.Label > b.Label {
			t.Fatalf("nodes are out of label order: %q before %q", a.Label, b.Label)
		}
		if a.Kind == b.Kind && a.Label == b.Label && a.ID > b.ID {
			t.Fatalf("nodes are out of id order: %s before %s", a.ID, b.ID)
		}
	}
}

func TestASGRoundTrip(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			doc := asgFixture(asgSnapshotID)
			if err := tc.store.ReplaceASG(ctx, asgSnapshotID, doc); err != nil {
				t.Fatalf("ReplaceASG: %v", err)
			}

			summary, err := tc.store.ASGSummary(ctx, asgSnapshotID)
			if err != nil {
				t.Fatalf("ASGSummary: %v", err)
			}
			if summary.Nodes != len(doc.Nodes) || summary.Edges != len(doc.Edges) {
				t.Fatalf("summary %+v does not match the document (%d nodes, %d edges)", summary, len(doc.Nodes), len(doc.Edges))
			}
			if summary.ASGVersion != doc.ASGVersion || summary.SCGVersion != doc.SCGVersion || summary.Engine != doc.Engine {
				t.Errorf("summary lost the document identity: %+v", summary)
			}
			if summary.RulesetHash != doc.RulesetHash {
				t.Errorf("summary lost the rule set hash: %+v", summary)
			}
			if summary.Coverage != doc.Coverage {
				t.Errorf("coverage was not persisted: got %+v, want %+v", summary.Coverage, doc.Coverage)
			}
			if !reflect.DeepEqual(summary.Limitations, doc.Limitations) {
				t.Errorf("limitations were not persisted: got %v, want %v", summary.Limitations, doc.Limitations)
			}
			if !reflect.DeepEqual(summary.NodesByKind, asgNodeKinds(doc)) {
				t.Errorf("nodes by kind = %v, want %v", summary.NodesByKind, asgNodeKinds(doc))
			}
			if !reflect.DeepEqual(summary.EdgesByKind, asgEdgeKinds(doc)) {
				t.Errorf("edges by kind = %v, want %v", summary.EdgesByKind, asgEdgeKinds(doc))
			}
			if !reflect.DeepEqual(summary.EvidenceCounts, asgEvidenceCounts(doc)) {
				t.Errorf("evidence counts = %v, want %v", summary.EvidenceCounts, asgEvidenceCounts(doc))
			}

			all, total, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{SnapshotID: asgSnapshotID, Limit: 100})
			if err != nil {
				t.Fatalf("ListASGNodes: %v", err)
			}
			if total != len(doc.Nodes) || len(all) != len(doc.Nodes) {
				t.Fatalf("ListASGNodes returned %d/%d nodes, want %d", len(all), total, len(doc.Nodes))
			}
			assertASGNodeOrder(t, all)

			byKind, kindTotal, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{
				SnapshotID: asgSnapshotID,
				Kinds:      []asg.NodeKind{asg.NodeSensitiveOperation},
			})
			if err != nil || kindTotal != 1 || len(byKind) != 1 {
				t.Fatalf("kind filter returned %d/%d nodes, err %v", len(byKind), kindTotal, err)
			}
			if byKind[0].Kind != asg.NodeSensitiveOperation {
				t.Errorf("kind filter leaked %s", byKind[0].Kind)
			}

			bySubject, subjectTotal, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{
				SnapshotID: asgSnapshotID,
				Subject:    "sink:sql_execution",
			})
			if err != nil || subjectTotal != 1 || len(bySubject) != 1 || bySubject[0].Subject != "sink:sql_execution" {
				t.Fatalf("subject filter returned %+v (%d total), err %v", bySubject, subjectTotal, err)
			}

			byGenerator, generatorTotal, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{
				SnapshotID: asgSnapshotID,
				Generator:  "rule.sink",
			})
			if err != nil || generatorTotal != 1 || len(byGenerator) != 1 || byGenerator[0].Generator != "rule.sink" {
				t.Fatalf("generator filter returned %+v (%d total), err %v", byGenerator, generatorTotal, err)
			}

			byFile, fileTotal, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{
				SnapshotID: asgSnapshotID,
				File:       "internal/api/routes.go",
			})
			if err != nil || fileTotal != 2 || len(byFile) != 2 {
				t.Fatalf("file filter returned %d/%d nodes, err %v", len(byFile), fileTotal, err)
			}

			paged, pagedTotal, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{SnapshotID: asgSnapshotID, Limit: 2})
			if err != nil || len(paged) != 2 || pagedTotal != len(doc.Nodes) {
				t.Fatalf("paging returned %d nodes and total %d, err %v", len(paged), pagedTotal, err)
			}
			assertASGNodeOrder(t, paged)
			rest, restTotal, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{SnapshotID: asgSnapshotID, Limit: 2, Offset: 2})
			if err != nil || len(rest) != 2 || restTotal != len(doc.Nodes) {
				t.Fatalf("second page returned %d nodes and total %d, err %v", len(rest), restTotal, err)
			}
			if paged[0].ID == rest[0].ID {
				t.Errorf("offset was ignored: both pages start at %s", paged[0].ID)
			}

			entryID := asg.NodeID(asgSnapshotID, asg.NodeEntryPoint, "http_route:GET /users/:id", "")
			got, err := tc.store.GetASGNode(ctx, asgSnapshotID, entryID)
			if err != nil {
				t.Fatalf("GetASGNode: %v", err)
			}
			if got.ID != entryID || got.Kind != asg.NodeEntryPoint {
				t.Errorf("GetASGNode returned %+v", got)
			}

			edges, err := tc.store.ListASGEdges(ctx, ASGEdgeQuery{SnapshotID: asgSnapshotID})
			if err != nil {
				t.Fatalf("ListASGEdges: %v", err)
			}
			if len(edges) != len(doc.Edges) {
				t.Fatalf("ListASGEdges returned %d edges, want %d", len(edges), len(doc.Edges))
			}
			if edges[0].ID > edges[1].ID {
				t.Errorf("edges are not ordered by edge_id: %s before %s", edges[0].ID, edges[1].ID)
			}

			reachesID := asg.EdgeID(asgSnapshotID, asg.EdgeReaches, entryID,
				asg.NodeID(asgSnapshotID, asg.NodeSensitiveOperation, "sink:sql_execution", ""), "cs-0001")
			byEdgeKind, err := tc.store.ListASGEdges(ctx, ASGEdgeQuery{
				SnapshotID: asgSnapshotID,
				Kinds:      []asg.EdgeKind{asg.EdgeProtectedBy},
			})
			if err != nil || len(byEdgeKind) != 1 || byEdgeKind[0].Kind != asg.EdgeProtectedBy {
				t.Fatalf("edge kind filter returned %+v, err %v", byEdgeKind, err)
			}

			fromEntry, err := tc.store.ListASGEdges(ctx, ASGEdgeQuery{SnapshotID: asgSnapshotID, From: []string{entryID}})
			if err != nil || len(fromEntry) != 1 || fromEntry[0].ID != reachesID {
				t.Fatalf("from filter returned %+v, err %v", fromEntry, err)
			}

			toSink, err := tc.store.ListASGEdges(ctx, ASGEdgeQuery{
				SnapshotID: asgSnapshotID,
				To:         []string{asg.NodeID(asgSnapshotID, asg.NodeSensitiveOperation, "sink:sql_execution", "")},
			})
			if err != nil || len(toSink) != 2 {
				t.Fatalf("to filter returned %d edges, err %v", len(toSink), err)
			}
			for _, e := range toSink {
				if e.To != asg.NodeID(asgSnapshotID, asg.NodeSensitiveOperation, "sink:sql_execution", "") {
					t.Errorf("to filter leaked an edge: %+v", e)
				}
			}

			bounded, err := tc.store.ListASGEdges(ctx, ASGEdgeQuery{SnapshotID: asgSnapshotID, Limit: 1})
			if err != nil || len(bounded) != 1 {
				t.Fatalf("edge limit returned %d edges, err %v", len(bounded), err)
			}
		})
	}
}

func TestReplaceASGIsIdempotentAndValidated(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			doc := asgFixture(asgSnapshotID)
			for i := 0; i < 3; i++ {
				if err := tc.store.ReplaceASG(ctx, asgSnapshotID, doc); err != nil {
					t.Fatalf("ReplaceASG run %d: %v", i, err)
				}
			}
			summary, err := tc.store.ASGSummary(ctx, asgSnapshotID)
			if err != nil {
				t.Fatal(err)
			}
			if summary.Nodes != len(doc.Nodes) || summary.Edges != len(doc.Edges) {
				t.Fatalf("rebuild duplicated rows: %+v", summary)
			}
			_, total, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{SnapshotID: asgSnapshotID, Limit: 100})
			if err != nil {
				t.Fatal(err)
			}
			if total != len(doc.Nodes) {
				t.Fatalf("rebuild duplicated node rows: %d, want %d", total, len(doc.Nodes))
			}

			if err := tc.store.ReplaceASG(ctx, asgSnapshotID, nil); !errors.Is(err, ErrConflict) {
				t.Errorf("ReplaceASG(nil) = %v, want ErrConflict", err)
			}
			other := *doc
			other.SnapshotID = asgOtherSnapshotID
			if err := tc.store.ReplaceASG(ctx, asgSnapshotID, &other); !errors.Is(err, ErrConflict) {
				t.Errorf("ReplaceASG with a mismatched snapshot = %v, want ErrConflict", err)
			}
		})
	}
}

func TestASGReadsWithoutADocumentAreNotFound(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			if _, err := tc.store.ASGSummary(ctx, asgAbsentSnapshot); !errors.Is(err, ErrNotFound) {
				t.Errorf("ASGSummary = %v, want ErrNotFound", err)
			}
			if _, _, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{SnapshotID: asgAbsentSnapshot}); !errors.Is(err, ErrNotFound) {
				t.Errorf("ListASGNodes = %v, want ErrNotFound", err)
			}
			if _, err := tc.store.GetASGNode(ctx, asgAbsentSnapshot, "asgn-missing"); !errors.Is(err, ErrNotFound) {
				t.Errorf("GetASGNode = %v, want ErrNotFound", err)
			}
			if _, err := tc.store.ListASGEdges(ctx, ASGEdgeQuery{SnapshotID: asgAbsentSnapshot}); !errors.Is(err, ErrNotFound) {
				t.Errorf("ListASGEdges = %v, want ErrNotFound", err)
			}
			if err := tc.store.DeleteASG(ctx, asgAbsentSnapshot); err != nil {
				t.Errorf("DeleteASG on a missing snapshot should be a no-op: %v", err)
			}
		})
	}
}

func TestDeleteASGIsScopedToSnapshot(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			first := asgFixture(asgSnapshotID)
			second := asgFixture(asgOtherSnapshotID)
			if err := tc.store.ReplaceASG(ctx, asgSnapshotID, first); err != nil {
				t.Fatal(err)
			}
			if err := tc.store.ReplaceASG(ctx, asgOtherSnapshotID, second); err != nil {
				t.Fatal(err)
			}
			if err := tc.store.DeleteASG(ctx, asgSnapshotID); err != nil {
				t.Fatalf("DeleteASG: %v", err)
			}
			if _, err := tc.store.ASGSummary(ctx, asgSnapshotID); !errors.Is(err, ErrNotFound) {
				t.Errorf("ASGSummary after delete = %v, want ErrNotFound", err)
			}
			if _, _, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{SnapshotID: asgSnapshotID}); !errors.Is(err, ErrNotFound) {
				t.Errorf("ListASGNodes after delete = %v, want ErrNotFound", err)
			}
			if _, err := tc.store.ListASGEdges(ctx, ASGEdgeQuery{SnapshotID: asgSnapshotID}); !errors.Is(err, ErrNotFound) {
				t.Errorf("ListASGEdges after delete = %v, want ErrNotFound", err)
			}

			summary, err := tc.store.ASGSummary(ctx, asgOtherSnapshotID)
			if err != nil {
				t.Fatalf("deleting one ASG removed another: %v", err)
			}
			if summary.Nodes != len(second.Nodes) || summary.Edges != len(second.Edges) {
				t.Fatalf("surviving snapshot lost rows: %+v", summary)
			}
			otherNode := asgNodeOf(t, second, second.Nodes[0].ID)
			got, err := tc.store.GetASGNode(ctx, asgOtherSnapshotID, otherNode.ID)
			if err != nil || got.ID != otherNode.ID {
				t.Fatalf("GetASGNode on the surviving snapshot = %+v, %v", got, err)
			}
			// The first snapshot's ids must not have been readable through the
			// second one either.
			if _, err := tc.store.GetASGNode(ctx, asgOtherSnapshotID, first.Nodes[0].ID); !errors.Is(err, ErrNotFound) {
				t.Errorf("node id from another snapshot was readable: %v", err)
			}
		})
	}
}

func TestASGNodeContentSurvivesTheRoundTrip(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			doc := asgFixture(asgSnapshotID)
			entryID := asg.NodeID(asgSnapshotID, asg.NodeEntryPoint, "http_route:GET /users/:id", "")
			want := asgNodeOf(t, doc, entryID)
			if len(want.Detail) < 2 || len(want.SCGRefs) < 2 {
				t.Fatalf("fixture node is not rich enough to test JSON columns: %+v", want)
			}
			if err := tc.store.ReplaceASG(ctx, asgSnapshotID, doc); err != nil {
				t.Fatal(err)
			}
			got, err := tc.store.GetASGNode(ctx, asgSnapshotID, entryID)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Detail, want.Detail) {
				t.Errorf("detail = %v, want %v", got.Detail, want.Detail)
			}
			if !reflect.DeepEqual(got.SCGRefs, want.SCGRefs) {
				t.Errorf("scg refs = %v, want %v", got.SCGRefs, want.SCGRefs)
			}
			if got.Evidence != want.Evidence || got.Confidence != want.Confidence || got.Generator != want.Generator {
				t.Errorf("node provenance was not persisted: got %+v, want %+v", got, want)
			}

			// The listing path must preserve the same JSON columns.
			listed, _, err := tc.store.ListASGNodes(ctx, ASGNodeQuery{SnapshotID: asgSnapshotID, Subject: want.Subject})
			if err != nil || len(listed) != 1 {
				t.Fatalf("ListASGNodes = %+v, %v", listed, err)
			}
			if !reflect.DeepEqual(listed[0].Detail, want.Detail) || !reflect.DeepEqual(listed[0].SCGRefs, want.SCGRefs) {
				t.Errorf("listed node lost JSON content: %+v", listed[0])
			}
		})
	}
}
