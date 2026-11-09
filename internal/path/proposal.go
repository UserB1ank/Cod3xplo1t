package path

import (
	"context"
	"fmt"
	"strings"
)

// ProposalOrigin is bound by the supervisor host, never decoded from a model
// argument. Storage rechecks it against the active run before persisting.
type ProposalOrigin struct {
	SessionID      string
	RunID          string
	ExecutionOwner string
	LeaseEpoch     int64
}

type proposalOriginKey struct{}

func WithProposalOrigin(ctx context.Context, origin ProposalOrigin) context.Context {
	return context.WithValue(ctx, proposalOriginKey{}, origin)
}

func ProposalOriginFrom(ctx context.Context) ProposalOrigin {
	origin, _ := ctx.Value(proposalOriginKey{}).(ProposalOrigin)
	return origin
}

// DiscoveryEvidence is one host-validated reference supplied with a path
// proposal. Source excerpts are re-read from the frozen tree by the evidence UI;
// this record only fixes identity and location.
type DiscoveryEvidence struct {
	Kind      string `json:"kind"` // source, symbol, call_site, asg_node, evidence or artifact
	ID        string `json:"id,omitempty"`
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
	SHA256    string `json:"sha256,omitempty"`
}

// PathDiscovery records who proposed a path and against which pinned view. It is
// deliberately separate from the path's structural identity: another investigator
// finding the same endpoints appends an observation instead of overwriting the
// first source.
type PathDiscovery struct {
	Source          string              `json:"source"` // supervisor or human
	Tool            string              `json:"tool,omitempty"`
	SessionID       string              `json:"session_id,omitempty"`
	RunID           string              `json:"run_id,omitempty"`
	KnowledgeViewID string              `json:"knowledge_view_id"`
	RequestKey      string              `json:"request_key"`
	RequestDigest   string              `json:"request_digest,omitempty"`
	Basis           string              `json:"basis"` // call_reachability or hypothesis
	RelatedPathIDs  []string            `json:"related_path_ids,omitempty"`
	Evidence        []DiscoveryEvidence `json:"evidence"`
	CreatedAt       string              `json:"created_at"`
}

// ProposalStore is the atomic write boundary for agent-discovered paths. It is
// separate from Store so older read-only path stores do not need to pretend they
// can accept writes.
type ProposalStore interface {
	Store
	AddProposedPath(ctx context.Context, p Path, actor, requestKey string, maxPerRun int) (*Path, bool, error)
}

// AddProposedPath persists one validated candidate in the dedicated discovery
// audit. Exact structural identity is deduplicated; a different investigator may
// append another discovery observation.
func (s *Service) AddProposedPath(ctx context.Context, p Path, actor string, maxPerRun int) (*Path, bool, error) {
	store, ok := s.Store.(ProposalStore)
	if !ok {
		return nil, false, fmt.Errorf("%w: proposal store is unavailable", ErrInvalidArgument)
	}
	if strings.TrimSpace(p.AuditID) == "" || strings.TrimSpace(p.SnapshotID) == "" ||
		strings.TrimSpace(p.EntryNodeID) == "" || strings.TrimSpace(p.TargetNodeID) == "" ||
		strings.TrimSpace(p.Signature) == "" || len(p.Discoveries) == 0 {
		return nil, false, fmt.Errorf("%w: incomplete proposed path", ErrInvalidArgument)
	}
	if maxPerRun <= 0 {
		maxPerRun = 20
	}
	return store.AddProposedPath(ctx, p, actor, p.Discoveries[0].RequestKey, maxPerRun)
}

// MergeDiscovery appends one source observation while preserving stable path
// identity. It is exported for both storage implementations and tests.
func MergeDiscovery(p *Path, observation PathDiscovery) (bool, error) {
	for _, existing := range p.Discoveries {
		if existing.RequestKey == observation.RequestKey {
			if existing.RequestDigest != "" && observation.RequestDigest != "" && existing.RequestDigest != observation.RequestDigest {
				return false, fmt.Errorf("%w: request key was replayed with different content", ErrConflict)
			}
			if existing.SessionID != observation.SessionID || existing.RunID != observation.RunID || existing.KnowledgeViewID != observation.KnowledgeViewID {
				return false, fmt.Errorf("%w: request key belongs to another discovery context", ErrConflict)
			}
			return false, nil
		}
	}
	p.Discoveries = append(p.Discoveries, observation)
	return true, nil
}

// DiscoveryRequestKey returns the request key if this path was proposed with one.
func DiscoveryRequestKey(p Path) string {
	if len(p.Discoveries) == 0 {
		return ""
	}
	return p.Discoveries[0].RequestKey
}
