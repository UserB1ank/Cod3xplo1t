package storage

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func postgresKnowledgeStores(t *testing.T) (*SQL, *SQL) {
	t.Helper()
	raw, err := os.ReadFile(testpostgres.DSNFile(t))
	if err != nil {
		t.Fatal(err)
	}
	open := func() *SQL {
		s, err := OpenSQL(context.Background(), "pgx", string(raw))
		if err != nil {
			t.Fatal("open PostgreSQL")
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	a, b := open(), open()
	if err := a.EnsureSchema(context.Background(), migrations.Postgres); err != nil {
		t.Fatal(err)
	}
	return a, b
}

func TestPostgresFailedOutboxRollsBackNativeIndexesAndRevision(t *testing.T) {
	s, _ := postgresKnowledgeStores(t)
	ctx := context.Background()
	g := graphFixture(t)
	if err := s.PutProject(ctx, testProject("owner")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSnapshot(ctx, "owner", testSnapshot(g.SnapshotID)); err != nil {
		t.Fatal(err)
	}
	scope := publication.Scope{ProjectID: "owner", SnapshotID: g.SnapshotID}
	producer := artifact.Producer{PluginID: "fixture.analyzer", PluginVersion: "1.0.0", InvocationID: "inv-native", ConfigDigest: strings.Repeat("0", 64)}
	first, err := publication.NewPublisher(s).Publish(ctx, publication.Batch{ID: "first", Scope: scope, BaseRevision: "rev-0", Producer: producer})
	if err != nil {
		t.Fatal(err)
	}
	events, err := s.ListKnowledgeOutbox(ctx, scope, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("outbox: %v", err)
	}
	surface := asgFixture(g.SnapshotID)
	surface.SCGVersion = g.GraphVersion
	surface.ASGVersion = asg.Version(g.SnapshotID, g.GraphVersion, surface.Engine, surface.RulesetHash)
	ref := artifact.Ref{ID: "native-report", Kind: "report.document", Scope: artifact.Scope{ProjectID: "owner", SourceID: "legacy-owner", SnapshotID: g.SnapshotID}, Producer: producer, SHA256: strings.Repeat("1", 64), Bytes: 1, MediaType: "application/json", SchemaID: "codexploit/builtin-native/v1"}
	index := &publication.AnalysisIndex{Graph: g, Surface: surface, Summary: publication.AnalysisSummary{ID: producer.InvocationID, Producer: producer, NativeArtifact: ref, SCGVersion: g.GraphVersion, ASGVersion: surface.ASGVersion}}
	if err := s.PublishArtifact(ctx, ref); err != nil {
		t.Fatal(err)
	}
	revision := *first
	revision.ID = "rev-2"
	revision.Number = 2
	revision.BatchID = "must-rollback"
	revision.BaseRevision = "rev-1"
	document := publication.RevisionDocument{Revision: revision, Analysis: index}
	// Reusing an existing event id forces a real database constraint failure
	// after the native indexes and revision have been written in this transaction.
	badEvent := events[0]
	badEvent.Revision = "rev-2"
	if err := s.PublishKnowledge(ctx, "rev-1", document, badEvent); err == nil {
		t.Fatal("duplicate outbox event succeeded")
	}
	if _, err := s.GraphSummary(ctx, g.SnapshotID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("SCG leaked from rollback: %v", err)
	}
	if _, err := s.ASGSummary(ctx, g.SnapshotID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("ASG leaked from rollback: %v", err)
	}
	if rows, err := s.ListKnowledgeAnalyses(ctx, scope, 10); err != nil || len(rows) != 0 {
		t.Fatalf("analysis leaked: %d %v", len(rows), err)
	}
	if _, err := s.GetKnowledgeRevision(ctx, scope, "rev-2"); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("revision leaked: %v", err)
	}
	if rows, err := s.ListKnowledgeOutbox(ctx, scope, 10); err != nil || len(rows) != 1 {
		t.Fatalf("outbox changed: %d %v", len(rows), err)
	}
	goodEvent := badEvent
	goodEvent.ID = "outbox-retry"
	if err := s.PublishKnowledge(ctx, "rev-1", document, goodEvent); err != nil {
		t.Fatalf("rollback blocked retry: %v", err)
	}
	if _, err := s.GraphSummary(ctx, g.SnapshotID); err != nil {
		t.Fatal(err)
	}
}

func TestPostgresActiveInvocationFencesSnapshotAndRetiresGraphIndexes(t *testing.T) {
	s, _ := postgresKnowledgeStores(t)
	ctx := context.Background()
	g := graphFixture(t)
	if err := s.PutProject(ctx, testProject("owner")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSnapshot(ctx, "owner", testSnapshot(g.SnapshotID)); err != nil {
		t.Fatal(err)
	}
	if err := s.ReplaceGraph(ctx, g.SnapshotID, g); err != nil {
		t.Fatal(err)
	}
	surface := asgFixture(g.SnapshotID)
	surface.SCGVersion = g.GraphVersion
	if err := s.ReplaceASG(ctx, g.SnapshotID, surface); err != nil {
		t.Fatal(err)
	}
	scope, err := s.ArtifactScope(ctx, "owner", g.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	inv := plugin.Invocation{ID: "inv-active", Status: "CREATED", Version: 1, RequestDigest: "fixture-request", Request: plugin.Request{Scope: scope}}
	if _, created, err := s.CreateInvocation(ctx, inv); err != nil || !created {
		t.Fatalf("create invocation: %v", err)
	}
	inv.Status = "RUNNING"
	inv.Version = 2
	if err := s.SaveInvocation(ctx, inv, 1); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginSnapshotDeletion(ctx, g.SnapshotID); !errors.Is(err, ErrConflict) {
		t.Fatalf("active invocation did not fence deletion: %v", err)
	}
	inv.Status = "CANCELLED"
	inv.Version = 3
	if err := s.SaveInvocation(ctx, inv, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.BeginSnapshotDeletion(ctx, g.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeleteSnapshot(ctx, g.SnapshotID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.GraphSummary(ctx, g.SnapshotID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retired SCG remains: %v", err)
	}
	if _, err := s.ASGSummary(ctx, g.SnapshotID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("retired ASG remains: %v", err)
	}
}

type publicationReadBarrier struct {
	arrived atomic.Int32
	ready   chan struct{}
}
type synchronizedPublicationStore struct {
	publication.Store
	barrier *publicationReadBarrier
}

func (s synchronizedPublicationStore) KnowledgeHead(ctx context.Context, scope publication.Scope) (string, error) {
	head, err := s.Store.KnowledgeHead(ctx, scope)
	if err != nil {
		return "", err
	}
	if s.barrier.arrived.Add(1) == 2 {
		close(s.barrier.ready)
	}
	select {
	case <-s.barrier.ready:
		return head, nil
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

func TestPostgresConcurrentIdenticalPublicationReplaysOriginalRevision(t *testing.T) {
	a, b := postgresKnowledgeStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.PutProject(ctx, testProject("owner")); err != nil {
		t.Fatal(err)
	}
	if err := a.PutSnapshot(ctx, "owner", testSnapshot("snap-shared")); err != nil {
		t.Fatal(err)
	}
	scope := publication.Scope{ProjectID: "owner", SnapshotID: "snap-shared"}
	batch := publication.Batch{ID: "same-batch", Scope: scope, BaseRevision: "rev-0", Producer: artifact.Producer{PluginID: "fixture.analyzer", PluginVersion: "1.0.0", InvocationID: "inv-shared"}, Facts: []publication.BatchFact{{ID: "fact-shared", Kind: "symbol", Label: "shared"}}}
	barrier := &publicationReadBarrier{ready: make(chan struct{})}
	results := make(chan error, 2)
	for _, store := range []*SQL{a, b} {
		go func() {
			revision, err := publication.NewPublisher(synchronizedPublicationStore{store, barrier}).Publish(ctx, batch)
			if err == nil && revision.ID != "rev-1" {
				err = errors.New("replay changed revision")
			}
			results <- err
		}()
	}
	for range 2 {
		if err := <-results; err != nil {
			t.Fatalf("identical concurrent publication: %v", err)
		}
	}
	rows, err := a.ListKnowledgeRevisions(ctx, scope, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("duplicate revisions: %d %v", len(rows), err)
	}
	events, err := b.ListKnowledgeOutbox(ctx, scope, 10)
	if err != nil || len(events) != 1 {
		t.Fatalf("duplicate outbox events: %d %v", len(events), err)
	}
}

func TestPostgresConcurrentDistinctPublicationsHaveOneCASWinner(t *testing.T) {
	a, b := postgresKnowledgeStores(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := a.PutProject(ctx, testProject("owner")); err != nil {
		t.Fatal(err)
	}
	if err := a.PutSnapshot(ctx, "owner", testSnapshot("snap-cas")); err != nil {
		t.Fatal(err)
	}
	scope := publication.Scope{ProjectID: "owner", SnapshotID: "snap-cas"}
	barrier := &publicationReadBarrier{ready: make(chan struct{})}
	results := make(chan error, 2)
	for i, store := range []*SQL{a, b} {
		go func() {
			batch := publication.Batch{ID: []string{"batch-a", "batch-b"}[i], Scope: scope, BaseRevision: "rev-0", Producer: artifact.Producer{PluginID: "fixture.analyzer", InvocationID: []string{"inv-a", "inv-b"}[i]}, Facts: []publication.BatchFact{{ID: "fact", Kind: "symbol"}}}
			_, err := publication.NewPublisher(synchronizedPublicationStore{store, barrier}).Publish(ctx, batch)
			results <- err
		}()
	}
	wins, conflicts := 0, 0
	for range 2 {
		err := <-results
		if err == nil {
			wins++
		} else if errors.Is(err, publication.ErrVersionConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("CAS wins=%d conflicts=%d", wins, conflicts)
	}
	revisions, err := a.ListKnowledgeRevisions(ctx, scope, 10)
	if err != nil || len(revisions) != 1 {
		t.Fatalf("revisions=%d %v", len(revisions), err)
	}
	events, err := b.ListKnowledgeOutbox(ctx, scope, 10)
	if err != nil || len(events) != 1 || events[0].Revision != revisions[0].ID {
		t.Fatalf("events=%v %v", events, err)
	}
}

func TestPostgresInvocationOutputConflictRollsBackStateAndEarlierOutputs(t *testing.T) {
	s, _ := postgresKnowledgeStores(t)
	ctx := context.Background()
	if err := s.PutProject(ctx, testProject("owner")); err != nil {
		t.Fatal(err)
	}
	if err := s.PutSnapshot(ctx, "owner", testSnapshot("snap-inv")); err != nil {
		t.Fatal(err)
	}
	scope, err := s.ArtifactScope(ctx, "owner", "snap-inv")
	if err != nil {
		t.Fatal(err)
	}
	inv := plugin.Invocation{ID: "inv-atomic", Status: "CREATED", Version: 1, RequestDigest: "fixture", Request: plugin.Request{Scope: scope}}
	if _, created, err := s.CreateInvocation(ctx, inv); err != nil || !created {
		t.Fatalf("create: %v", err)
	}
	inv.Status, inv.Version = "RUNNING", 2
	if err := s.SaveInvocation(ctx, inv, 1); err != nil {
		t.Fatal(err)
	}
	ref := artifact.Ref{ID: "output-existing", Kind: "report.document", Scope: scope, Producer: artifact.Producer{PluginID: "fixture.analyzer", PluginVersion: "1.0.0", InvocationID: inv.ID, ConfigDigest: strings.Repeat("0", 64)}, SHA256: strings.Repeat("1", 64), Bytes: 1, MediaType: "application/json", SchemaID: "codexploit/builtin-native/v1"}
	if err := s.PublishArtifact(ctx, ref); err != nil {
		t.Fatal(err)
	}
	newRef := ref
	newRef.ID = "output-new"
	conflicting := ref
	conflicting.SHA256 = strings.Repeat("2", 64)
	inv.Status, inv.Version, inv.Outputs = "SUCCEEDED", 3, []artifact.Ref{newRef, conflicting}
	if err := s.SaveInvocation(ctx, inv, 2); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("output conflict: %v", err)
	}
	current, err := s.GetInvocation(ctx, scope, inv.ID)
	if err != nil || current.Status != "RUNNING" || current.Version != 2 || len(current.Outputs) != 0 {
		t.Fatalf("state leaked: %+v %v", current, err)
	}
	if _, err := s.LookupArtifact(ctx, scope, newRef.ID); !errors.Is(err, artifact.ErrNotFound) {
		t.Fatalf("output leaked: %v", err)
	}
	inv.Outputs = []artifact.Ref{newRef, ref}
	if err := s.SaveInvocation(ctx, inv, 2); err != nil {
		t.Fatal(err)
	}
	if err := s.SaveInvocation(ctx, inv, 2); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("stale terminal write: %v", err)
	}
}
