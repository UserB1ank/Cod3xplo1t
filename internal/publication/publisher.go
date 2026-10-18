package publication

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

// Publisher turns a producer's batch into one immutable revision. A stale base
// revision, a replayed batch with different content and an orphan edge are
// rejected before anything becomes visible.
type Publisher struct {
	Store Store
	Now   func() time.Time
}

// NewPublisher builds a publisher over a revision store.
func NewPublisher(store Store) *Publisher {
	return &Publisher{Store: store, Now: func() time.Time { return time.Now().UTC() }}
}

// Publish validates the batch, merges it onto the current head and commits the
// new revision, its batch index and an outbox event in one store call.
func (p *Publisher) Publish(ctx context.Context, batch Batch) (*Revision, error) {
	if batch.ID == "" || batch.Scope.ProjectID == "" || batch.Scope.SnapshotID == "" {
		return nil, fmt.Errorf("%w: batch id, project and snapshot are required", ErrInvalidBatch)
	}
	if batch.Producer.PluginID == "" || batch.Producer.InvocationID == "" {
		return nil, fmt.Errorf("%w: producer plugin and invocation are required", ErrInvalidBatch)
	}
	if batch.BaseRevision == "" {
		batch.BaseRevision = "rev-0"
	}
	digest, err := digestBatch(batch)
	if err != nil {
		return nil, err
	}
	// A replayed batch returns its original revision; different content under the
	// same id is a conflict rather than a silent overwrite.
	if prior, err := p.Store.KnowledgeBatch(ctx, batch.Scope, batch.ID); err == nil {
		if prior.Digest != digest {
			return nil, fmt.Errorf("%w: %s was published with %s", ErrBatchConflict, batch.ID, prior.Digest[:12])
		}
		return &prior, nil
	} else if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	head, err := p.Store.KnowledgeHead(ctx, batch.Scope)
	if err != nil {
		return nil, err
	}
	if batch.BaseRevision != head {
		if prior, replayErr := p.replay(ctx, batch, digest); prior != nil || replayErr != nil {
			return prior, replayErr
		}
		return nil, fmt.Errorf("%w: base %s, head %s", ErrVersionConflict, batch.BaseRevision, head)
	}
	base := RevisionDocument{Revision: Revision{Scope: batch.Scope, ID: "rev-0"}}
	if head != "rev-0" {
		base, err = p.Store.GetKnowledgeRevision(ctx, batch.Scope, head)
		if err != nil {
			return nil, err
		}
	}
	document, err := mergeBatch(base, batch, digest, nextRevision(head), p.Now().UTC().Format(time.RFC3339))
	if err != nil {
		return nil, err
	}
	payload, err := json.Marshal(document.Revision)
	if err != nil {
		return nil, err
	}
	event := OutboxEvent{
		ID:        "outbox-" + document.Revision.ID + "-" + digest[:8],
		Scope:     batch.Scope,
		Revision:  document.Revision.ID,
		Kind:      "knowledge.revision.published",
		Payload:   payload,
		CreatedAt: document.Revision.CreatedAt,
	}
	if err := p.Store.PublishKnowledge(ctx, head, document, event); err != nil {
		if errors.Is(err, ErrVersionConflict) || errors.Is(err, ErrBatchConflict) {
			if prior, replayErr := p.replay(ctx, batch, digest); prior != nil || replayErr != nil {
				return prior, replayErr
			}
		}
		return nil, err
	}
	return &document.Revision, nil
}

// Another publisher may commit this same batch between the initial replay
// check and the CAS. A committed identical batch is still a successful replay.
func (p *Publisher) replay(ctx context.Context, batch Batch, digest string) (*Revision, error) {
	prior, err := p.Store.KnowledgeBatch(ctx, batch.Scope, batch.ID)
	if errors.Is(err, ErrNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if prior.Digest != digest {
		return nil, ErrBatchConflict
	}
	return &prior, nil
}

// mergeBatch folds one batch onto the base revision. Facts keep their canonical
// fields from the first producer and gain an observation per producer, so two
// tools that disagree stay visible side by side.
func mergeBatch(base RevisionDocument, batch Batch, digest, revisionID, now string) (RevisionDocument, error) {
	facts := make(map[string]Fact, len(base.Facts)+len(batch.Facts))
	for _, fact := range base.Facts {
		facts[fact.ID] = cloneFact(fact)
	}
	edges := append([]Edge(nil), base.Edges...)
	seenEdges := make(map[string]bool, len(edges))
	for _, edge := range edges {
		seenEdges[edgeKey(edge)] = true
	}
	for _, incoming := range batch.Facts {
		if incoming.ID == "" || incoming.Kind == "" {
			return RevisionDocument{}, fmt.Errorf("%w: a fact needs an id and a kind", ErrInvalidBatch)
		}
		attributes := batchAttributes(incoming)
		observation := Observation{
			ID:         observationID(batch.Producer, attributes),
			Producer:   batch.Producer,
			Attributes: attributes,
			Evidence:   incoming.Evidence,
		}
		if existing, ok := facts[incoming.ID]; ok {
			if !hasObservation(existing.Observations, observation.ID) {
				existing.Observations = append(existing.Observations, observation)
				facts[incoming.ID] = existing
			}
			continue
		}
		facts[incoming.ID] = Fact{
			ID:           incoming.ID,
			Kind:         incoming.Kind,
			Label:        incoming.Label,
			Location:     incoming.Location,
			Confidence:   incoming.Confidence,
			Observations: []Observation{observation},
		}
	}
	for _, incoming := range batch.Edges {
		if incoming.From == "" || incoming.To == "" {
			return RevisionDocument{}, fmt.Errorf("%w: an edge needs both endpoints", ErrInvalidBatch)
		}
		if _, ok := facts[incoming.From]; !ok {
			return RevisionDocument{}, fmt.Errorf("%w: %s", ErrOrphanEdge, incoming.From)
		}
		if _, ok := facts[incoming.To]; !ok {
			return RevisionDocument{}, fmt.Errorf("%w: %s", ErrOrphanEdge, incoming.To)
		}
		edge := Edge(incoming)
		if !seenEdges[edgeKey(edge)] {
			edges = append(edges, edge)
			seenEdges[edgeKey(edge)] = true
		}
	}
	ids := make([]string, 0, len(facts))
	for id := range facts {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	ordered := make([]Fact, 0, len(ids))
	for _, id := range ids {
		fact := facts[id]
		sort.Slice(fact.Observations, func(i, j int) bool { return fact.Observations[i].ID < fact.Observations[j].ID })
		ordered = append(ordered, fact)
	}
	sort.Slice(edges, func(i, j int) bool {
		if edges[i].From != edges[j].From {
			return edges[i].From < edges[j].From
		}
		if edges[i].To != edges[j].To {
			return edges[i].To < edges[j].To
		}
		return edges[i].Kind < edges[j].Kind
	})
	return RevisionDocument{
		Analysis: batch.Analysis,
		Revision: Revision{
			Scope:        batch.Scope,
			ID:           revisionID,
			Number:       revisionNumber(revisionID),
			BatchID:      batch.ID,
			BaseRevision: batch.BaseRevision,
			Digest:       digest,
			Layer:        batch.Layer,
			Producer:     batch.Producer,
			Coverage:     batch.Coverage,
			Limitations:  batch.Limitations,
			CreatedAt:    now,
		},
		Facts: ordered,
		Edges: edges,
	}, nil
}

func cloneFact(fact Fact) Fact {
	clone := fact
	clone.Observations = append([]Observation(nil), fact.Observations...)
	if fact.Location != nil {
		location := *fact.Location
		clone.Location = &location
	}
	return clone
}

func hasObservation(observations []Observation, id string) bool {
	for _, observation := range observations {
		if observation.ID == id {
			return true
		}
	}
	return false
}

func edgeKey(edge Edge) string {
	return edge.From + "\x00" + edge.To + "\x00" + edge.Kind
}

// batchAttributes records the claim exactly as the producer made it, including
// fields that disagree with the canonical fact.
func batchAttributes(fact BatchFact) map[string]string {
	attributes := map[string]string{
		"kind":       fact.Kind,
		"label":      fact.Label,
		"confidence": fact.Confidence,
	}
	if fact.Location != nil {
		attributes["file"] = fact.Location.File
		attributes["start_line"] = strconv.Itoa(fact.Location.StartLine)
		attributes["end_line"] = strconv.Itoa(fact.Location.EndLine)
	}
	for key, value := range fact.Attributes {
		attributes[key] = value
	}
	return attributes
}

func nextRevision(head string) string {
	return "rev-" + strconv.Itoa(revisionNumber(head)+1)
}

func revisionNumber(revision string) int {
	number, err := strconv.Atoi(strings.TrimPrefix(revision, "rev-"))
	if err != nil || number < 0 {
		return 0
	}
	return number
}
