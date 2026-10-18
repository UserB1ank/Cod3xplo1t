package publication

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sort"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
)

// Publication errors. Each one maps to a distinct operator action.
var (
	ErrVersionConflict = errors.New("publication: base revision is stale")
	ErrBatchConflict   = errors.New("publication: batch id was already published with different content")
	ErrInvalidBatch    = errors.New("publication: invalid batch")
	ErrOrphanEdge      = errors.New("publication: edge endpoint is not part of the revision")
	// ErrNotFound reports that the scope has no such revision or batch.
	ErrNotFound = errors.New("publication: revision not found")
)

// Scope is the data boundary of a revision: one project and one snapshot.
type Scope struct {
	ProjectID  string `json:"project_id"`
	SnapshotID string `json:"snapshot_id"`
}

// Location is the code position a fact was derived from.
type Location struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

// BatchFact is one canonical fact claimed by one producer.
type BatchFact struct {
	ID         string
	Kind       string
	Label      string
	Location   *Location
	Confidence string
	Attributes map[string]string
	Evidence   []string
}

// BatchEdge links two facts of the same revision.
type BatchEdge struct {
	From string
	To   string
	Kind string
}

// Batch is one producer's atomic publication: facts, edges and the coverage
// statement they were derived under.
type Batch struct {
	Analysis     *AnalysisIndex
	ID           string
	Scope        Scope
	BaseRevision string
	Producer     artifact.Producer
	Layer        string
	Facts        []BatchFact
	Edges        []BatchEdge
	Coverage     BatchCoverage
	Limitations  []string
}

// BatchCoverage restates what the producing invocation actually saw.
type BatchCoverage struct {
	FilesSeen     int      `json:"files_seen"`
	FilesAnalyzed int      `json:"files_analyzed"`
	FilesSkipped  int      `json:"files_skipped"`
	Limitations   []string `json:"limitations,omitempty"`
}

// Observation is one producer's view of a fact. Two tools that disagree keep
// two observations instead of overwriting each other.
type Observation struct {
	ID         string            `json:"observation_id"`
	Producer   artifact.Producer `json:"producer"`
	Attributes map[string]string `json:"attributes,omitempty"`
	Evidence   []string          `json:"evidence_refs,omitempty"`
}

// Fact is the canonical, revision-scoped view of one node with every
// observation that supports or challenges it.
type Fact struct {
	ID           string        `json:"id"`
	Kind         string        `json:"kind"`
	Label        string        `json:"label"`
	Location     *Location     `json:"location,omitempty"`
	Confidence   string        `json:"confidence,omitempty"`
	Observations []Observation `json:"observations"`
}

// Edge is a revision-scoped relation between two facts.
type Edge struct {
	From string `json:"from"`
	To   string `json:"to"`
	Kind string `json:"kind"`
}

// Revision is one immutable published version of a scope's shared knowledge.
type Revision struct {
	Scope        Scope             `json:"scope"`
	ID           string            `json:"revision"`
	Number       int               `json:"revision_no"`
	BatchID      string            `json:"batch_id"`
	BaseRevision string            `json:"base_revision"`
	Digest       string            `json:"digest"`
	Layer        string            `json:"layer,omitempty"`
	Producer     artifact.Producer `json:"producer"`
	Coverage     BatchCoverage     `json:"coverage"`
	Limitations  []string          `json:"limitations,omitempty"`
	CreatedAt    string            `json:"created_at"`
}

// RevisionDocument is the immutable state of one revision: its summary, every
// fact with its observations, and every edge.
type RevisionDocument struct {
	Analysis *AnalysisIndex `json:"-"`
	Revision Revision
	Facts    []Fact
	Edges    []Edge
}

// OutboxEvent is written in the same transaction as the revision it describes.
type OutboxEvent struct {
	ID        string          `json:"event_id"`
	Scope     Scope           `json:"scope"`
	Revision  string          `json:"revision"`
	Kind      string          `json:"kind"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	CreatedAt string          `json:"created_at"`
}

// RevisionStore is the persistence contract of the publisher. PublishKnowledge
// must commit the revision, its batch index and the outbox event atomically and
// must reject a head that no longer matches expectedHead.
type Store interface {
	KnowledgeHead(ctx context.Context, scope Scope) (string, error)
	KnowledgeBatch(ctx context.Context, scope Scope, batchID string) (Revision, error)
	GetKnowledgeRevision(ctx context.Context, scope Scope, revision string) (RevisionDocument, error)
	ListKnowledgeRevisions(ctx context.Context, scope Scope, limit int) ([]Revision, error)
	ListKnowledgeOutbox(ctx context.Context, scope Scope, limit int) ([]OutboxEvent, error)
	PublishKnowledge(ctx context.Context, expectedHead string, doc RevisionDocument, event OutboxEvent) error
}

// digestBatch canonicalises a batch so the same invocation replayed byte for
// byte produces the same digest.
func digestBatch(batch Batch) (string, error) {
	facts := append([]BatchFact(nil), batch.Facts...)
	sort.Slice(facts, func(i, j int) bool { return facts[i].ID < facts[j].ID })
	edges := append([]BatchEdge(nil), batch.Edges...)
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Kind < edges[j].Kind
	})
	payload := struct {
		ID           string            `json:"id"`
		Scope        Scope             `json:"scope"`
		BaseRevision string            `json:"base_revision"`
		Producer     artifact.Producer `json:"producer"`
		Layer        string            `json:"layer"`
		Facts        []BatchFact       `json:"facts"`
		Edges        []BatchEdge       `json:"edges"`
		Coverage     BatchCoverage     `json:"coverage"`
		Limitations  []string          `json:"limitations"`
	}{batch.ID, batch.Scope, batch.BaseRevision, batch.Producer, batch.Layer, facts, edges, batch.Coverage, batch.Limitations}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func observationID(producer artifact.Producer, attributes map[string]string) string {
	raw, _ := json.Marshal(struct {
		Invocation string            `json:"invocation"`
		Attributes map[string]string `json:"attributes"`
	}{producer.InvocationID, attributes})
	sum := sha256.Sum256(raw)
	return "obs-" + hex.EncodeToString(sum[:8])
}
