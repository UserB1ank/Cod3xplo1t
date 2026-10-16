package asg

import (
	"context"
	"fmt"
	"time"
)

// DefaultEngine identifies the P3 attack-surface extractor.
var DefaultEngine = Engine{Name: "codexploit/asg", Version: "0.1.0"}

// Builder derives an ASG candidate and stamps it with its identity.
//
// The builder owns the document-level invariants: the version (snapshot + SCG
// version + engine + rule set), the timestamps, deterministic ordering and the
// validation that rejects a claim without evidence. The extractor owns the rules.
type Builder struct {
	Extractor *Extractor
	Engine    Engine
	Now       func() time.Time
}

// NewBuilder builds a Builder over an SCG reader, using the default rule set.
func NewBuilder(reader SCGReader) *Builder {
	return &Builder{
		Extractor: NewExtractor(reader),
		Engine:    DefaultEngine,
		Now:       func() time.Time { return time.Now().UTC() },
	}
}

// Build derives the ASG candidate of one snapshot.
func (b *Builder) Build(ctx context.Context, snapshotID string) (*Document, error) {
	if b.Extractor == nil {
		return nil, fmt.Errorf("%w: no extractor is configured", ErrInvalidDocument)
	}
	if b.Now == nil {
		b.Now = func() time.Time { return time.Now().UTC() }
	}
	engine := b.Engine
	if engine.Name == "" {
		engine = DefaultEngine
	}
	started := b.Now()

	doc, err := b.Extractor.Extract(ctx, snapshotID)
	if err != nil {
		return nil, err
	}
	// The version must be recomputed here: it depends on the engine, and the
	// extractor does not know which runtime is asking for the document.
	doc.Engine = engine
	doc.ASGVersion = Version(doc.SnapshotID, doc.SCGVersion, engine, doc.RulesetHash)
	doc.Limitations = append(doc.Limitations, fmt.Sprintf(
		"attack surface derived by %s@%s with rule set %s from SCG %s",
		engine.Name, engine.Version, doc.RulesetHash, doc.SCGVersion))
	doc.normalize()
	doc.sortForDeterminism()
	if err := doc.Validate(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidDocument, err)
	}
	doc.BuiltAt = started.Format(time.RFC3339)
	doc.BuildDurationMS = b.Now().Sub(started).Milliseconds()
	return doc, nil
}

// RulesetHash exposes the rule set identity of the configured extractor.
func (b *Builder) RulesetHash() string {
	if b.Extractor == nil {
		return ""
	}
	return b.Extractor.RulesetHash()
}
