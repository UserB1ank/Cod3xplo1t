package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/claim"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func writeClaimError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, artifact.ErrIntegrity):
		writeError(w, http.StatusConflict, "artifact_integrity", artifact.ErrIntegrity)
	case errors.Is(err, artifact.ErrBudget):
		writeError(w, http.StatusRequestEntityTooLarge, "artifact_budget_exceeded", artifact.ErrBudget)
	case errors.Is(err, claim.ErrInvalid):
		writeError(w, http.StatusBadRequest, "invalid_claim", claim.ErrInvalid)
	case errors.Is(err, claim.ErrNotFound):
		writeError(w, http.StatusNotFound, "claim_not_found", claim.ErrNotFound)
	case errors.Is(err, claim.ErrConflict):
		writeError(w, http.StatusConflict, "claim_conflict", claim.ErrConflict)
	default:
		writeError(w, http.StatusServiceUnavailable, "claim_unavailable", claim.ErrUnavailable)
	}
}

func (s *Server) claimScope(ctx context.Context, scope claim.Scope) error {
	if _, err := s.Store.GetProject(ctx, scope.ProjectID); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return claim.ErrNotFound
		}
		return err
	}
	rows, err := s.Store.ListSnapshots(ctx, scope.ProjectID)
	if err != nil {
		return err
	}
	for _, row := range rows {
		if row.SnapshotID == scope.SnapshotID {
			return nil
		}
	}
	return claim.ErrNotFound
}

func (s *Server) claimService() *claim.Service {
	store, _ := s.Store.(claim.Store)
	return &claim.Service{Store: store, Resolve: s.resolveClaimReference}
}

func (s *Server) resolveClaimReference(ctx context.Context, scope claim.Scope, in claim.ReferenceInput) (claim.Reference, error) {
	if err := s.claimScope(ctx, scope); err != nil {
		return claim.Reference{}, err
	}
	if in.Kind == "evidence" {
		if in.ID == "" || in.Target != nil {
			return claim.Reference{}, claim.ErrInvalid
		}
		e, err := s.Store.GetEvidence(in.ID)
		if errors.Is(err, verify.ErrNotFound) || errors.Is(err, storage.ErrNotFound) {
			return claim.Reference{}, claim.ErrNotFound
		}
		if err != nil {
			return claim.Reference{}, err
		}
		if e == nil || e.SnapshotID != scope.SnapshotID {
			return claim.Reference{}, claim.ErrNotFound
		}
		digest := sha256.Sum256([]byte(e.Content))
		hexDigest := hex.EncodeToString(digest[:])
		if strings.TrimPrefix(e.ContentHash, "sha256:") != hexDigest {
			return claim.Reference{}, artifact.ErrIntegrity
		}
		return claim.Reference{Kind: "evidence", ID: e.ID, SHA256: hexDigest}, nil
	}
	if in.Kind == "artifact" {
		if in.ID == "" || in.Target != nil {
			return claim.Reference{}, claim.ErrInvalid
		}
		if s.Artifacts == nil {
			return claim.Reference{}, claim.ErrUnavailable
		}
		index, ok := s.Store.(artifact.Index)
		if !ok {
			return claim.Reference{}, claim.ErrUnavailable
		}
		aScope, err := index.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID)
		if err != nil {
			return claim.Reference{}, err
		}
		ref, err := s.Artifacts.Stat(ctx, aScope, in.ID, 16<<20)
		if errors.Is(err, artifact.ErrNotFound) {
			return claim.Reference{}, claim.ErrNotFound
		}
		if err != nil {
			return claim.Reference{}, err
		}
		if ref.SchemaID == artifact.SourceDirectorySchema {
			return claim.Reference{}, claim.ErrInvalid
		}
		return claim.Reference{Kind: "artifact", ID: ref.ID, SHA256: ref.SHA256}, nil
	}
	if in.Kind != "source" || in.ID != "" || !claim.ValidTarget(in.Target) {
		return claim.Reference{}, claim.ErrInvalid
	}
	if s.Manager == nil {
		return claim.Reference{}, claim.ErrUnavailable
	}
	snapshot, err := s.Manager.Load(scope.SnapshotID)
	if err != nil {
		return claim.Reference{}, claim.ErrUnavailable
	}
	root, err := os.OpenRoot(snapshot.TreeDir())
	if err != nil {
		return claim.Reference{}, claim.ErrUnavailable
	}
	defer root.Close()
	info, err := root.Lstat(in.Target.File)
	if err != nil || !info.Mode().IsRegular() {
		return claim.Reference{}, claim.ErrNotFound
	}
	if info.Size() > 4<<20 {
		return claim.Reference{}, claim.ErrInvalid
	}
	f, err := root.Open(in.Target.File)
	if err != nil {
		return claim.Reference{}, claim.ErrUnavailable
	}
	defer f.Close()
	scanner := bufio.NewScanner(io.LimitReader(f, 4<<20+1))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var text strings.Builder
	line := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return claim.Reference{}, err
		}
		line++
		if line < in.Target.StartLine {
			continue
		}
		if text.Len()+len(scanner.Text())+1 > 16000 || !utf8.ValidString(scanner.Text()) || strings.ContainsRune(scanner.Text(), 0) {
			return claim.Reference{}, claim.ErrInvalid
		}
		text.WriteString(scanner.Text())
		text.WriteByte('\n')
		if line == in.Target.EndLine {
			break
		}
	}
	if scanner.Err() != nil {
		return claim.Reference{}, claim.ErrUnavailable
	}
	if line < in.Target.EndLine {
		return claim.Reference{}, claim.ErrNotFound
	}
	content, redacted, notes := verify.Redact(text.String())
	if len(content) > 16000 {
		return claim.Reference{}, claim.ErrInvalid
	}
	return claim.Reference{Kind: "source", Target: in.Target, Content: content, Redacted: redacted, RedactionNotes: notes}, nil
}

func (s *Server) handleSubmitClaim(w http.ResponseWriter, r *http.Request) {
	s.submitClaimRecord(w, r, "claim")
}
func (s *Server) handleOpenClaimQuestion(w http.ResponseWriter, r *http.Request) {
	s.submitClaimRecord(w, r, "question")
}
func (s *Server) handleAttachClaimEvidence(w http.ResponseWriter, r *http.Request) {
	s.submitClaimRecord(w, r, "evidence")
}
func (s *Server) submitClaimRecord(w http.ResponseWriter, r *http.Request, kind string) {
	var in claim.Input
	if !s.decode(w, r, &in) {
		return
	}
	scope := claim.Scope{ProjectID: r.PathValue("projectID"), SnapshotID: in.SnapshotID}
	if err := s.claimScope(r.Context(), scope); err != nil {
		writeClaimError(w, err)
		return
	}
	p, ok := PrincipalFrom(r.Context())
	if !ok {
		writeError(w, http.StatusUnauthorized, "unauthorized", errors.New("authentication required"))
		return
	}
	record, created, err := s.claimService().Submit(r.Context(), scope.ProjectID, p.Name, kind, r.PathValue("claimID"), in)
	if err != nil {
		writeClaimError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeClaimDocument(w, status, map[string]any{"api_version": "codexploit/v1", "record": record, "created": created})
}

func (s *Server) handleReadClaims(w http.ResponseWriter, r *http.Request) {
	q := claim.Query{Scope: claim.Scope{ProjectID: r.PathValue("projectID"), SnapshotID: r.URL.Query().Get("snapshot_id")}, ClaimID: r.PathValue("claimID")}
	for key, out := range map[string]*int64{"revision": &q.Revision, "cursor": &q.Cursor} {
		if raw := r.URL.Query().Get(key); raw != "" {
			value, err := strconv.ParseInt(raw, 10, 64)
			if err != nil {
				writeClaimError(w, claim.ErrInvalid)
				return
			}
			*out = value
		}
	}
	if raw := r.URL.Query().Get("limit"); raw != "" {
		limit, err := strconv.Atoi(raw)
		if err != nil {
			writeClaimError(w, claim.ErrInvalid)
			return
		}
		q.Limit = limit
	}
	if err := s.claimScope(r.Context(), q.Scope); err != nil {
		writeClaimError(w, err)
		return
	}
	page, err := s.claimService().Read(r.Context(), q)
	if err != nil {
		writeClaimError(w, err)
		return
	}
	writeClaimDocument(w, http.StatusOK, page)
}

func writeClaimDocument(w http.ResponseWriter, status int, document any) {
	if err := claim.ValidateDocument(document); err != nil {
		writeError(w, http.StatusInternalServerError, "contract_violation", errors.New("investigation knowledge response violates its contract"))
		return
	}
	writeJSON(w, status, document)
}
