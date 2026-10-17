package publication_test

import (
	"context"
	"errors"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

const (
	pubProject  = "proj-publication"
	pubSnapshot = "snap-33333333333333333333333333333333"
)

type pubFixture struct {
	store     *storage.Memory
	publisher *publication.Publisher
}

func newPubFixture(t *testing.T) *pubFixture {
	t.Helper()
	store := storage.NewMemory()
	ctx := context.Background()
	if err := store.PutProject(ctx, storage.Project{ID: pubProject}); err != nil {
		t.Fatal(err)
	}
	if err := store.PutSnapshot(ctx, pubProject, &repository.Snapshot{SnapshotID: pubSnapshot}); err != nil {
		t.Fatal(err)
	}
	return &pubFixture{store: store, publisher: publication.NewPublisher(store)}
}

func (f *pubFixture) scope() publication.Scope {
	return publication.Scope{ProjectID: pubProject, SnapshotID: pubSnapshot}
}

func (f *pubFixture) producer(task string) artifact.Producer {
	return artifact.Producer{PluginID: "builtin.security-semantics", PluginVersion: "1.0.0", InvocationID: "inv-" + task, TaskID: task, ConfigDigest: "cfg"}
}

func TestPublisherCreatesAnImmutableRevision(t *testing.T) {
	f := newPubFixture(t)
	ctx := context.Background()
	rev, err := f.publisher.Publish(ctx, publication.Batch{
		ID:           "batch-1",
		Scope:        f.scope(),
		BaseRevision: "rev-0",
		Producer:     f.producer("audit-1"),
		Facts: []publication.BatchFact{{
			ID:         "node-entry",
			Kind:       "EntryPoint",
			Label:      "GET /run",
			Location:   &publication.Location{File: "main.go", StartLine: 10},
			Confidence: "observed",
		}},
	})
	if err != nil {
		t.Fatalf("Publish: %v", err)
	}
	if rev.ID != "rev-1" || rev.BaseRevision != "rev-0" {
		t.Fatalf("revision = %+v", rev)
	}
	if rev.Producer.TaskID != "audit-1" || rev.Digest == "" {
		t.Fatalf("revision lost its producer or digest: %+v", rev)
	}
	head, err := f.store.KnowledgeHead(ctx, f.scope())
	if err != nil || head != "rev-1" {
		t.Fatalf("head = %q %v", head, err)
	}
	stored, err := f.store.GetKnowledgeRevision(ctx, f.scope(), "rev-1")
	if err != nil || len(stored.Facts) != 1 || stored.Facts[0].ID != "node-entry" {
		t.Fatalf("stored revision = %+v %v", stored, err)
	}
	if obs := stored.Facts[0].Observations; len(obs) != 1 || obs[0].Producer.TaskID != "audit-1" {
		t.Fatalf("observations = %+v", obs)
	}
	events, err := f.store.ListKnowledgeOutbox(ctx, f.scope(), 10)
	if err != nil || len(events) != 1 || events[0].Revision != "rev-1" {
		t.Fatalf("outbox = %+v %v", events, err)
	}
}

func (f *pubFixture) publish(t *testing.T, batch publication.Batch) *publication.Revision {
	t.Helper()
	revision, err := f.publisher.Publish(context.Background(), batch)
	if err != nil {
		t.Fatalf("publish %s: %v", batch.ID, err)
	}
	return revision
}

func TestRevisionsAccumulateAndEarlierRevisionsStayImmutable(t *testing.T) {
	f := newPubFixture(t)
	first := f.publish(t, publication.Batch{
		ID: "batch-a", Scope: f.scope(), BaseRevision: "rev-0", Producer: f.producer("audit-1"),
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /run"}},
	})
	second := f.publish(t, publication.Batch{
		ID: "batch-b", Scope: f.scope(), BaseRevision: first.ID, Producer: f.producer("audit-2"),
		Facts: []publication.BatchFact{{ID: "node-b", Kind: "SensitiveOperation", Label: "exec"}},
		Edges: []publication.BatchEdge{{From: "node-a", To: "node-b", Kind: "REACHES"}},
	})
	if second.ID != "rev-2" || second.BaseRevision != "rev-1" {
		t.Fatalf("second revision = %+v", second)
	}
	head, err := f.store.GetKnowledgeRevision(context.Background(), f.scope(), "rev-2")
	if err != nil || len(head.Facts) != 2 || len(head.Edges) != 1 {
		t.Fatalf("head revision = %+v %v", head, err)
	}
	earlier, err := f.store.GetKnowledgeRevision(context.Background(), f.scope(), "rev-1")
	if err != nil || len(earlier.Facts) != 1 || earlier.Facts[0].ID != "node-a" {
		t.Fatalf("earlier revision changed: %+v %v", earlier, err)
	}
	events, _ := f.store.ListKnowledgeOutbox(context.Background(), f.scope(), 10)
	if len(events) != 2 {
		t.Fatalf("outbox = %+v", events)
	}
}

func TestStaleBaseRevisionIsRejectedWithoutSideEffects(t *testing.T) {
	f := newPubFixture(t)
	ctx := context.Background()
	f.publish(t, publication.Batch{ID: "batch-a", Scope: f.scope(), BaseRevision: "rev-0", Producer: f.producer("audit-1"),
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /run"}}})
	_, err := f.publisher.Publish(ctx, publication.Batch{ID: "batch-stale", Scope: f.scope(), BaseRevision: "rev-0", Producer: f.producer("audit-2"),
		Facts: []publication.BatchFact{{ID: "node-b", Kind: "Asset", Label: "db"}}})
	if !errors.Is(err, publication.ErrVersionConflict) {
		t.Fatalf("stale base: %v", err)
	}
	head, _ := f.store.KnowledgeHead(ctx, f.scope())
	if head != "rev-1" {
		t.Fatalf("head moved to %s", head)
	}
	if _, err := f.store.GetKnowledgeRevision(ctx, f.scope(), "rev-2"); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("stale batch became visible: %v", err)
	}
	events, _ := f.store.ListKnowledgeOutbox(ctx, f.scope(), 10)
	if len(events) != 1 {
		t.Fatalf("outbox = %+v", events)
	}
}

func TestReplayedBatchReturnsItsRevisionAndDifferentContentConflicts(t *testing.T) {
	f := newPubFixture(t)
	ctx := context.Background()
	batch := publication.Batch{ID: "batch-a", Scope: f.scope(), BaseRevision: "rev-0", Producer: f.producer("audit-1"),
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /run"}}}
	first, err := f.publisher.Publish(ctx, batch)
	if err != nil {
		t.Fatal(err)
	}
	again, err := f.publisher.Publish(ctx, batch)
	if err != nil || again.ID != first.ID || again.Digest != first.Digest {
		t.Fatalf("replay = %+v %v", again, err)
	}
	head, _ := f.store.KnowledgeHead(ctx, f.scope())
	if head != first.ID {
		t.Fatalf("replay advanced the head to %s", head)
	}
	batch.Facts = append(batch.Facts, publication.BatchFact{ID: "node-b", Kind: "Asset", Label: "db"})
	if _, err := f.publisher.Publish(ctx, batch); !errors.Is(err, publication.ErrBatchConflict) {
		t.Fatalf("same batch, new content: %v", err)
	}
	events, _ := f.store.ListKnowledgeOutbox(ctx, f.scope(), 10)
	if len(events) != 1 {
		t.Fatalf("outbox = %+v", events)
	}
}

func TestOrphanEdgesAndForeignScopesAreRejected(t *testing.T) {
	f := newPubFixture(t)
	ctx := context.Background()
	_, err := f.publisher.Publish(ctx, publication.Batch{ID: "batch-orphan", Scope: f.scope(), BaseRevision: "rev-0", Producer: f.producer("audit-1"),
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /run"}},
		Edges: []publication.BatchEdge{{From: "node-a", To: "node-missing", Kind: "REACHES"}}})
	if !errors.Is(err, publication.ErrOrphanEdge) {
		t.Fatalf("orphan edge: %v", err)
	}
	head, _ := f.store.KnowledgeHead(ctx, f.scope())
	if head != "rev-0" {
		t.Fatalf("orphan batch advanced the head to %s", head)
	}
	foreign := publication.Batch{ID: "batch-foreign", Scope: publication.Scope{ProjectID: "proj-other", SnapshotID: pubSnapshot}, Producer: f.producer("audit-1"),
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /run"}}}
	if _, err := f.publisher.Publish(ctx, foreign); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("foreign scope: %v", err)
	}
}

func TestConflictingObservationsArePreserved(t *testing.T) {
	f := newPubFixture(t)
	ctx := context.Background()
	f.publish(t, publication.Batch{ID: "batch-a", Scope: f.scope(), BaseRevision: "rev-0", Producer: f.producer("audit-1"),
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /run", Confidence: "observed",
			Location: &publication.Location{File: "main.go", StartLine: 10}}}})
	second := f.producer("audit-2")
	second.PluginID = "team.scanner.example"
	f.publish(t, publication.Batch{ID: "batch-b", Scope: f.scope(), BaseRevision: "rev-1", Producer: second,
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /execute", Confidence: "inferred",
			Location: &publication.Location{File: "server.go", StartLine: 42}}}})
	head, err := f.store.GetKnowledgeRevision(ctx, f.scope(), "rev-2")
	if err != nil {
		t.Fatal(err)
	}
	var fact *publication.Fact
	for i := range head.Facts {
		if head.Facts[i].ID == "node-a" {
			fact = &head.Facts[i]
		}
	}
	if fact == nil {
		t.Fatal("fact disappeared")
	}
	if fact.Label != "GET /run" || len(fact.Observations) != 2 {
		t.Fatalf("fact = %+v", fact)
	}
	var scanner *publication.Observation
	for i := range fact.Observations {
		if fact.Observations[i].Producer.PluginID == "team.scanner.example" {
			scanner = &fact.Observations[i]
		}
	}
	if scanner == nil || scanner.Attributes["label"] != "GET /execute" || scanner.Attributes["file"] != "server.go" {
		t.Fatalf("second observation lost its claim: %+v", fact.Observations)
	}
}

type failingStore struct {
	publication.Store
	err error
}

func (f failingStore) PublishKnowledge(context.Context, string, publication.RevisionDocument, publication.OutboxEvent) error {
	return f.err
}

func TestAFailedCommitLeavesNoRevisionHeadOrOutbox(t *testing.T) {
	f := newPubFixture(t)
	ctx := context.Background()
	broken := publication.NewPublisher(failingStore{Store: f.store, err: errors.New("disk full")})
	_, err := broken.Publish(ctx, publication.Batch{ID: "batch-a", Scope: f.scope(), BaseRevision: "rev-0", Producer: f.producer("audit-1"),
		Facts: []publication.BatchFact{{ID: "node-a", Kind: "EntryPoint", Label: "GET /run"}}})
	if err == nil {
		t.Fatal("failed commit reported success")
	}
	head, _ := f.store.KnowledgeHead(ctx, f.scope())
	if head != "rev-0" {
		t.Fatalf("head moved to %s", head)
	}
	if _, err := f.store.GetKnowledgeRevision(ctx, f.scope(), "rev-1"); !errors.Is(err, publication.ErrNotFound) {
		t.Fatalf("failed batch became visible: %v", err)
	}
	events, _ := f.store.ListKnowledgeOutbox(ctx, f.scope(), 10)
	if len(events) != 0 {
		t.Fatalf("failed batch emitted an outbox event: %+v", events)
	}
}
