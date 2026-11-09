// Package claim records investigation knowledge without granting models the
// authority to change verification verdicts. Records are append-only.
package claim

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"strings"
	"time"
)

var (
	ErrInvalid     = errors.New("claim: invalid request")
	ErrNotFound    = errors.New("claim: reference not found in scope")
	ErrConflict    = errors.New("claim: request key or version conflicts")
	ErrUnavailable = errors.New("claim: knowledge store unavailable")
)

type Scope struct {
	ProjectID  string `json:"project_id"`
	SnapshotID string `json:"snapshot_id"`
}

type Target struct {
	File      string `json:"file"`
	StartLine int    `json:"start_line"`
	EndLine   int    `json:"end_line"`
}

type Reference struct {
	Kind   string  `json:"kind"`
	ID     string  `json:"id,omitempty"`
	Target *Target `json:"target,omitempty"`
	// Content and digest are supplied by the host, never by model arguments.
	Content        string `json:"content,omitempty"`
	SHA256         string `json:"sha256,omitempty"`
	Redacted       bool   `json:"redacted,omitempty"`
	RedactionNotes string `json:"redaction_notes,omitempty"`
}

type Record struct {
	ID         string     `json:"record_id"`
	ClaimID    string     `json:"claim_id"`
	Scope      Scope      `json:"scope"`
	Kind       string     `json:"kind"`
	Status     string     `json:"status"`
	Category   string     `json:"category,omitempty"`
	Statement  string     `json:"statement"`
	Conditions string     `json:"conditions,omitempty"`
	Target     *Target    `json:"target,omitempty"`
	Reference  *Reference `json:"reference,omitempty"`
	Relation   string     `json:"relation,omitempty"`
	Actor      string     `json:"actor"`
	RunID      string     `json:"run_id,omitempty"`
	SessionID  string     `json:"session_id,omitempty"`
	CreatedAt  string     `json:"created_at"`
	Revision   int64      `json:"revision"`
	RequestKey string     `json:"-"`
	Digest     string     `json:"-"`
}

type Query struct {
	Scope   Scope
	ClaimID string
	// Zero Revision opens the current ledger. Continuations pin the returned
	// revision; changes appended later cannot move an existing page boundary.
	Revision int64
	Cursor   int64
	Limit    int
}

type Page struct {
	Records      []Record `json:"records"`
	Revision     int64    `json:"revision"`
	HeadRevision int64    `json:"head_revision"`
	NextCursor   int64    `json:"next_cursor"`
	HasMore      bool     `json:"has_more"`
}

type Store interface {
	AppendClaimRecord(context.Context, Record) (Record, bool, error)
	ReadClaimRecords(context.Context, Query) (Page, error)
}

// Input intentionally has no status, role, actor, run ID or content fields.
type Input struct {
	SnapshotID string          `json:"snapshot_id,omitempty"`
	RequestKey string          `json:"request_key"`
	Category   string          `json:"category,omitempty"`
	Statement  string          `json:"statement"`
	Conditions string          `json:"conditions,omitempty"`
	Target     *Target         `json:"target,omitempty"`
	Reference  *ReferenceInput `json:"reference,omitempty"`
	Relation   string          `json:"relation,omitempty"`
}

type ReferenceInput struct {
	Kind   string  `json:"kind"`
	ID     string  `json:"id,omitempty"`
	Target *Target `json:"target,omitempty"`
}

type Service struct {
	Store Store
	// Resolve validates and captures source or evidence inside the current scope.
	Resolve func(context.Context, Scope, ReferenceInput) (Reference, error)
}

// Origin is bound by the host when a supervisor run starts, never decoded from
// a request body. Persistence checks the run owner and generation under the
// transaction lock.
type Origin struct {
	SessionID string
	RunID     string
	Owner     string
	Epoch     int64
}
type originKey struct{}

func WithOrigin(ctx context.Context, origin Origin) context.Context {
	return context.WithValue(ctx, originKey{}, origin)
}
func OriginFrom(ctx context.Context) Origin {
	origin, _ := ctx.Value(originKey{}).(Origin)
	return origin
}

func Hash(v any) string {
	raw, _ := json.Marshal(v)
	h := sha256.Sum256(raw)
	return hex.EncodeToString(h[:])
}

func ValidTarget(t *Target) bool {
	if t == nil || !fs.ValidPath(t.File) || t.File == "." || strings.ContainsAny(t.File, "\\:\x00\r\n") || len(t.File) > 1024 || t.StartLine < 1 || t.EndLine < t.StartLine || t.EndLine-t.StartLine >= 200 {
		return false
	}
	for _, part := range strings.Split(strings.ToLower(t.File), "/") {
		if strings.HasPrefix(part, ".env") || part == ".ssh" || part == ".git" || strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".key") {
			return false
		}
	}
	return true
}

func (s *Service) Submit(ctx context.Context, project, actor, kind, claimID string, in Input) (Record, bool, error) {
	if s.Store == nil || s.Resolve == nil {
		return Record{}, false, ErrUnavailable
	}
	in.Statement = strings.TrimSpace(in.Statement)
	if project == "" || actor == "" || in.SnapshotID == "" || len(in.RequestKey) < 1 || len(in.RequestKey) > 128 || len(in.Statement) < 1 || len(in.Statement) > 4000 || len(in.Conditions) > 2000 {
		return Record{}, false, ErrInvalid
	}
	r := Record{Scope: Scope{project, in.SnapshotID}, Kind: kind, ClaimID: claimID, Statement: in.Statement, Actor: actor, RequestKey: in.RequestKey, CreatedAt: time.Now().UTC().Format(time.RFC3339Nano)}
	origin := OriginFrom(ctx)
	r.SessionID, r.RunID = origin.SessionID, origin.RunID
	r.ID = "kr-" + Hash([]string{project, in.SnapshotID, in.RequestKey})
	switch kind {
	case "claim":
		if !ValidTarget(in.Target) || in.Reference != nil || in.Relation != "" || (in.Category != "vulnerability" && in.Category != "control" && in.Category != "business_rule") {
			return Record{}, false, ErrInvalid
		}
		if _, err := s.Resolve(ctx, r.Scope, ReferenceInput{Kind: "source", Target: in.Target}); err != nil {
			return Record{}, false, err
		}
		r.Category, r.Conditions, r.Target, r.Status = in.Category, in.Conditions, in.Target, "conjecture"
		// Exact structured content only: no title or fuzzy similarity merging.
		r.ClaimID = "kc-" + Hash(struct {
			Scope                           Scope
			Category, Statement, Conditions string
			Target                          *Target
		}{r.Scope, r.Category, r.Statement, r.Conditions, r.Target})
	case "question", "evidence":
		if claimID == "" || in.Category != "" || in.Target != nil || in.Conditions != "" {
			return Record{}, false, ErrInvalid
		}
		if kind == "question" {
			if in.Reference != nil || in.Relation != "" {
				return Record{}, false, ErrInvalid
			}
			r.Status = "open"
		} else {
			if in.Reference == nil || (in.Relation != "supports" && in.Relation != "contradicts" && in.Relation != "context") {
				return Record{}, false, ErrInvalid
			}
			ref, err := s.Resolve(ctx, r.Scope, *in.Reference)
			if err != nil {
				return Record{}, false, err
			}
			r.Reference, r.Relation, r.Status = &ref, in.Relation, "recorded"
		}
	default:
		return Record{}, false, ErrInvalid
	}
	// Includes identity but excludes host timestamps and evidence contents. A
	// replay returns the original captured evidence, not a newly sampled excerpt.
	r.Digest = Hash(struct {
		Kind, ClaimID, Actor string
		Input                Input
	}{kind, r.ClaimID, actor, in})
	return s.Store.AppendClaimRecord(ctx, r)
}

func (s *Service) Read(ctx context.Context, q Query) (Page, error) {
	if s.Store == nil {
		return Page{}, ErrUnavailable
	}
	if q.Scope.ProjectID == "" || q.Scope.SnapshotID == "" || q.Revision < 0 || q.Cursor < 0 || q.Limit < 0 || q.Limit > 100 || (q.Revision > 0 && q.Cursor > q.Revision) {
		return Page{}, ErrInvalid
	}
	if q.Limit == 0 {
		q.Limit = 25
	}
	return s.Store.ReadClaimRecords(ctx, q)
}
