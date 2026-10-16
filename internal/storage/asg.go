package storage

import (
	"context"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
)

// ASGNodeQuery filters an ASG node listing. Zero values mean "no filter".
type ASGNodeQuery struct {
	SnapshotID string
	Kinds      []asg.NodeKind
	// Subject matches exactly; it is how a caller asks for one route or one sink
	// class without knowing its id.
	Subject   string
	Generator string
	File      string
	Limit     int
	Offset    int
}

// ASGEdgeQuery filters an ASG edge listing.
type ASGEdgeQuery struct {
	SnapshotID string
	From       []string
	To         []string
	Kinds      []asg.EdgeKind
	Limit      int
}

// ASGStore persists and reads ASG candidate documents.
//
// Like the SCG store, ReplaceASG is the only write: it swaps the whole document
// of one snapshot inside a transaction, so the ASG can never be half-updated and
// a rebuild is idempotent. The ASG is kept in its own tables because it is
// derived: it must be possible to drop it and rebuild from the SCG without
// touching a single SCG fact.
type ASGStore interface {
	ReplaceASG(ctx context.Context, snapshotID string, doc *asg.Document) error
	DeleteASG(ctx context.Context, snapshotID string) error
	ASGSummary(ctx context.Context, snapshotID string) (*asg.Summary, error)
	ListASGNodes(ctx context.Context, q ASGNodeQuery) ([]asg.Node, int, error)
	GetASGNode(ctx context.Context, snapshotID, nodeID string) (asg.Node, error)
	ListASGEdges(ctx context.Context, q ASGEdgeQuery) ([]asg.Edge, error)
}
