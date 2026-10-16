// Package api exposes the P1 snapshot chain over HTTP.
//
// Endpoints:
//
//	GET    /healthz
//	POST   /api/projects                       create or reuse a project
//	GET    /api/projects                       list projects
//	GET    /api/projects/{id}                  read one project
//	POST   /api/projects/{id}/snapshots        freeze a snapshot and analyse it
//	GET    /api/snapshots?project_id=          list snapshot records
//	GET    /api/snapshots/{id}                 read snapshot metadata
//	DELETE /api/snapshots/{id}                 remove a snapshot and its records
//	GET    /api/snapshots/{id}/manifest        read the repository manifest
//
// Write operations accept an Idempotency-Key header: replaying the same key
// returns the first response instead of doing the work twice. The cache is
// per-process for P1; moving it into the store is a P7 task and is noted in
// docs so nobody mistakes it for durable exactly-once semantics.
package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/analysis"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// maxBodyBytes bounds request bodies; the API has no large payloads in P1.
const maxBodyBytes = 1 << 20

// idempotencyTTL is how long a replayed response stays valid.
const idempotencyTTL = 10 * time.Minute

// maxIdempotencyEntries bounds the replay cache.
const maxIdempotencyEntries = 1024

// Server serves the REST API.
type Server struct {
	Store    storage.FullStore
	Manager  *repository.Manager
	Analyzer *analysis.Analyzer
	Graph    *graph.Service
	Builder  *scg.Builder
	// ASG and ASGBuilder are the attack-surface read and build paths. They are
	// separate from Graph/Builder so a deployment can serve the SCG without the
	// P3 layer, in which case every ASG route answers 501 instead of guessing.
	ASG        *graph.ASGService
	ASGBuilder *asg.Builder
	// Audit is the path engine. It is separate from the graph services so a
	// deployment can serve the SCG/ASG without the P4 layer, in which case every
	// audit route answers 501 instead of pretending an audit is missing.
	Audit *path.Service
	// Agent is the P5 orchestrator. Like Audit it is separate from the graph
	// services so a deployment can serve the P4 surface without the P5 layer, in
	// which case every run route answers 501 instead of pretending a run is
	// missing.
	Agent        *agent.Runner
	AllowNetwork bool
	Logger       *slog.Logger
	// Auth decides who may do what. When it is nil the server refuses every API
	// call, because an unprotected audit API is worse than an unavailable one.
	Auth *Authenticator
	// IdempotencyTTL bounds how long a stored response may be replayed.
	IdempotencyTTL time.Duration

	handler http.Handler
}

// Option customises a Server.
type Option func(*Server)

// WithAllowNetwork permits remote git sources for this server.
func WithAllowNetwork(allow bool) Option { return func(s *Server) { s.AllowNetwork = allow } }

// WithLogger sets the structured logger.
func WithLogger(l *slog.Logger) Option { return func(s *Server) { s.Logger = l } }

// WithGraph attaches the graph query service, which enables the SCG endpoints.
func WithGraph(svc *graph.Service) Option { return func(s *Server) { s.Graph = svc } }

// WithBuilder attaches the SCG builder, which enables graph construction.
func WithBuilder(b *scg.Builder) Option { return func(s *Server) { s.Builder = b } }

// WithASG attaches the attack-surface query service, which enables the ASG
// endpoints.
func WithASG(svc *graph.ASGService) Option { return func(s *Server) { s.ASG = svc } }

// WithASGBuilder attaches the ASG builder, which enables attack-surface
// construction.
func WithASGBuilder(b *asg.Builder) Option { return func(s *Server) { s.ASGBuilder = b } }

// WithAuth attaches the authenticator. Without it the API answers 401 to every
// request: authentication is opt-out by configuration, never by accident.
func WithAuth(a *Authenticator) Option { return func(s *Server) { s.Auth = a } }

// WithIdempotencyTTL overrides how long stored responses can be replayed.
func WithIdempotencyTTL(ttl time.Duration) Option {
	return func(s *Server) {
		if ttl > 0 {
			s.IdempotencyTTL = ttl
		}
	}
}

// NewServer builds a server. The store, manager and analyzer must be wired by
// the caller, which keeps the API free of configuration and driver choices.
func NewServer(store storage.FullStore, mgr *repository.Manager, analyzer *analysis.Analyzer, opts ...Option) *Server {
	s := &Server{
		Store:          store,
		Manager:        mgr,
		Analyzer:       analyzer,
		Logger:         slog.Default(),
		IdempotencyTTL: defaultIdempotencyTTL,
	}
	for _, opt := range opts {
		opt(s)
	}
	if s.Manager != nil {
		s.AllowNetwork = s.Manager.AllowNetwork
	}
	s.handler = s.routes()
	return s
}

// Handler returns the HTTP handler, including recovery, logging and JSON error
// middleware. The innermost wrapper turns the mux's plain-text 404/405 responses
// into the same JSON error shape as every other failure, so clients only ever
// parse one format.
func (s *Server) Handler() http.Handler {
	return s.recoverer(s.logRequests(s.authenticate(s.jsonErrors(s.handler))))
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", s.handleHealth)
	mux.HandleFunc("POST /api/projects", s.withIdempotency(s.handleCreateProject))
	mux.HandleFunc("GET /api/projects", s.handleListProjects)
	mux.HandleFunc("GET /api/projects/{id}", s.handleGetProject)
	mux.HandleFunc("PATCH /api/projects/{id}", s.handlePatchProject)
	mux.HandleFunc("POST /api/projects/{id}/snapshots", s.withIdempotency(s.handleCreateSnapshot))
	mux.HandleFunc("GET /api/snapshots", s.handleListSnapshots)
	mux.HandleFunc("GET /api/snapshots/{id}", s.handleGetSnapshot)
	mux.HandleFunc("DELETE /api/snapshots/{id}", s.handleDeleteSnapshot)
	mux.HandleFunc("GET /api/snapshots/{id}/manifest", s.handleGetManifest)
	mux.HandleFunc("POST /api/snapshots/{id}/graph", s.withIdempotency(s.handleBuildGraph))
	mux.HandleFunc("GET /api/snapshots/{id}/graph", s.handleGraphSummary)
	mux.HandleFunc("GET /api/snapshots/{id}/modules", s.handleListModules)
	mux.HandleFunc("GET /api/snapshots/{id}/symbols", s.handleListSymbols)
	mux.HandleFunc("GET /api/snapshots/{id}/symbols/{symbolID}", s.handleGetSymbol)
	mux.HandleFunc("GET /api/snapshots/{id}/symbols/{symbolID}/callers", s.handleCallers)
	mux.HandleFunc("GET /api/snapshots/{id}/symbols/{symbolID}/callees", s.handleCallees)
	mux.HandleFunc("GET /api/snapshots/{id}/unresolved-calls", s.handleUnresolvedCalls)
	mux.HandleFunc("POST /api/snapshots/{id}/graph/paths", s.handleCallPaths)
	mux.HandleFunc("POST /api/snapshots/{id}/graph/slice", s.handleSlice)
	mux.HandleFunc("POST /api/snapshots/{id}/asg", s.withIdempotency(s.handleBuildASG))
	mux.HandleFunc("GET /api/snapshots/{id}/asg", s.handleASGSummary)
	mux.HandleFunc("GET /api/snapshots/{id}/asg/nodes", s.handleASGNodes)
	mux.HandleFunc("GET /api/snapshots/{id}/asg/nodes/{nodeID}", s.handleASGNode)
	mux.HandleFunc("GET /api/snapshots/{id}/asg/entrypoints", s.handleASGEntryPoints)
	mux.HandleFunc("GET /api/snapshots/{id}/asg/edges", s.handleASGEdges)
	mux.HandleFunc("POST /api/audits", s.withIdempotency(s.handleCreateAudit))
	mux.HandleFunc("GET /api/audits", s.handleListAudits)
	mux.HandleFunc("GET /api/audits/{id}", s.handleGetAudit)
	mux.HandleFunc("GET /api/audits/{id}/paths", s.handleAuditPaths)
	mux.HandleFunc("GET /api/audits/{id}/events", s.handleAuditEvents)
	mux.HandleFunc("GET /api/audits/{id}/next", s.handleAuditNext)
	mux.HandleFunc("POST /api/audits/{id}/reclaim-expired", s.handleReclaimExpired)
	mux.HandleFunc("POST /api/audits/{id}/rescore", s.handleRescore)
	mux.HandleFunc("GET /api/paths/{id}", s.handleGetPath)
	mux.HandleFunc("POST /api/paths/{id}/pause", s.handlePathTransition("pause"))
	mux.HandleFunc("POST /api/paths/{id}/resume", s.handlePathTransition("resume"))
	mux.HandleFunc("POST /api/paths/{id}/cancel", s.handlePathTransition("cancel"))
	mux.HandleFunc("POST /api/audits/{id}/claim", s.handleClaimAudit)
	mux.HandleFunc("POST /api/audits/{id}/runs", s.withIdempotency(s.handleAuditRuns))
	mux.HandleFunc("POST /api/paths/{id}/claim", s.handleClaimPath)
	mux.HandleFunc("POST /api/paths/{id}/heartbeat", s.handleHeartbeat)
	mux.HandleFunc("POST /api/paths/{id}/release", s.handleReleasePath)
	mux.HandleFunc("POST /api/paths/{id}/runs", s.withIdempotency(s.handlePathRuns))
	mux.HandleFunc("GET /api/runs", s.handleListRuns)
	mux.HandleFunc("GET /api/runs/{id}", s.handleGetRun)
	mux.HandleFunc("GET /api/runs/{id}/events", s.handleRunEvents)
	mux.HandleFunc("GET /api/hypotheses", s.handleListHypotheses)
	mux.HandleFunc("GET /api/hypotheses/{id}", s.handleGetHypothesis)
	mux.HandleFunc("GET /api/paths/{id}/hypotheses", s.handlePathHypotheses)
	return mux
}

// --- handlers ---------------------------------------------------------------

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "time": time.Now().UTC().Format(time.RFC3339)})
}

type createProjectRequest struct {
	Name   string `json:"name"`
	Source string `json:"source"`
}

type projectResponse struct {
	Project  storage.Project `json:"project"`
	Existing bool            `json:"existing"`
}

func (s *Server) handleCreateProject(w http.ResponseWriter, r *http.Request) {
	var req createProjectRequest
	if !s.decode(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Source) == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("source is required"))
		return
	}
	resolved, err := s.Manager.Resolve(r.Context(), repository.Source{Raw: req.Source})
	if err != nil {
		writeStorageError(w, err)
		return
	}
	id := projectID(resolved.Identity)
	existing := false
	if _, err := s.Store.GetProject(r.Context(), id); err == nil {
		existing = true
	} else if !errors.Is(err, storage.ErrNotFound) {
		writeStorageError(w, err)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = projectName(resolved.Identity)
	}
	project := storage.Project{
		ID:           id,
		Name:         name,
		Source:       req.Source,
		IdentityKind: resolved.Identity.Kind,
		Identity:     resolved.Identity.Name,
	}
	if err := s.Store.PutProject(r.Context(), project); err != nil {
		writeStorageError(w, err)
		return
	}
	stored, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	status := http.StatusCreated
	if existing {
		status = http.StatusOK
	}
	w.Header().Set("ETag", projectETag(stored))
	writeJSON(w, status, projectResponse{Project: stored, Existing: existing})
}

// handlePatchProject renames a project. It requires If-Match, so a client cannot
// overwrite a change it never saw: the design doc asks for optimistic
// concurrency on writes, and a rename is the one mutable field P2 has.
func (s *Server) handlePatchProject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	project, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	current := projectETag(project)
	ifMatch := strings.TrimSpace(r.Header.Get("If-Match"))
	if ifMatch == "" {
		writeError(w, http.StatusPreconditionRequired, "precondition_required",
			errors.New("PATCH requires If-Match with the ETag of the project you read"))
		return
	}
	if !etagMatches(ifMatch, current) {
		writeError(w, http.StatusPreconditionFailed, "precondition_failed",
			fmt.Errorf("project %s has ETag %s, not %s", id, current, ifMatch))
		return
	}
	var req patchProjectRequest
	if !s.decode(w, r, &req) {
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		writeError(w, http.StatusBadRequest, "invalid_request", errors.New("name must not be empty"))
		return
	}
	project.Name = name
	if err := s.Store.PutProject(r.Context(), project); err != nil {
		writeStorageError(w, err)
		return
	}
	updated, err := s.Store.GetProject(r.Context(), id)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	w.Header().Set("ETag", projectETag(updated))
	writeJSON(w, http.StatusOK, updated)
}

type patchProjectRequest struct {
	Name string `json:"name"`
}

// projectETag is a strong validator over every mutable field of a project.
func projectETag(p storage.Project) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s\x00%s\x00%s\x00%s\x00%s\x00%d",
		p.ID, p.Name, p.Source, p.IdentityKind, p.Identity, p.UpdatedAt.UnixNano())))
	return `"` + hex.EncodeToString(sum[:8]) + `"`
}

// etagMatches accepts a single ETag or a comma separated list, including "*".
func etagMatches(header, etag string) bool {
	for _, candidate := range strings.Split(header, ",") {
		candidate = strings.TrimSpace(candidate)
		if candidate == "*" || candidate == etag {
			return true
		}
		candidate = strings.TrimPrefix(candidate, "W/")
		if candidate == etag {
			return true
		}
	}
	return false
}

func (s *Server) handleListProjects(w http.ResponseWriter, r *http.Request) {
	projects, err := s.Store.ListProjects(r.Context())
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"projects": projects})
}

func (s *Server) handleGetProject(w http.ResponseWriter, r *http.Request) {
	project, err := s.Store.GetProject(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	w.Header().Set("ETag", projectETag(project))
	writeJSON(w, http.StatusOK, project)
}

type createSnapshotRequest struct {
	Ref string `json:"ref"`
	// SkipAnalysis freezes the snapshot without analysing it.
	SkipAnalysis bool `json:"skip_analysis"`
	// BuildGraph builds the SCG after the manifest, so one request produces the
	// whole P1+P2 chain for a snapshot.
	BuildGraph bool `json:"build_graph"`
	// BuildASG builds the attack surface after the graph. It needs an SCG from
	// this request or an earlier one; without one it is a client mistake and is
	// reported as scg_missing rather than as an empty attack surface.
	BuildASG bool `json:"build_asg"`
}

type snapshotResponse struct {
	Snapshot snapshotSummary  `json:"snapshot"`
	Manifest *manifestSummary `json:"manifest,omitempty"`
	Graph    *scg.Summary     `json:"graph,omitempty"`
	ASG      *asg.Summary     `json:"asg,omitempty"`
	Existing bool             `json:"existing"`
}

type snapshotSummary struct {
	SnapshotID     string   `json:"snapshot_id"`
	ProjectID      string   `json:"project_id"`
	VCS            string   `json:"vcs"`
	Commit         string   `json:"commit"`
	WorktreeDirty  bool     `json:"worktree_dirty"`
	Files          int      `json:"files"`
	Bytes          int64    `json:"bytes"`
	SkippedTotal   int      `json:"skipped_total"`
	Limitations    []string `json:"limitations"`
	SubmoduleCount int      `json:"submodule_count"`
	LFSDetected    bool     `json:"lfs_detected"`
	SymlinkCount   int      `json:"symlink_count"`
	DirtyPathCount int      `json:"dirty_path_count"`
	CreatedAt      string   `json:"created_at"`
}

type manifestSummary struct {
	AnalysisID      string   `json:"analysis_id"`
	RulesetHash     string   `json:"ruleset_hash"`
	ConfigHash      string   `json:"config_hash"`
	PrimaryLanguage string   `json:"primary_language"`
	Languages       []string `json:"languages"`
	Frameworks      []string `json:"frameworks"`
	Entrypoints     int      `json:"entrypoints"`
	BuildConfigs    int      `json:"build_configs"`
	Packages        int      `json:"packages"`
	Unknowns        []string `json:"unknowns"`
	GeneratedAt     string   `json:"generated_at"`
}

func (s *Server) handleCreateSnapshot(w http.ResponseWriter, r *http.Request) {
	projectIDValue := r.PathValue("id")
	project, err := s.Store.GetProject(r.Context(), projectIDValue)
	if err != nil {
		writeStorageError(w, err)
		return
	}
	var req createSnapshotRequest
	if !s.decode(w, r, &req) {
		return
	}
	snap, err := s.Manager.Create(r.Context(), repository.Source{
		Raw:          project.Source,
		Ref:          req.Ref,
		NameOverride: project.Identity,
	})
	if err != nil {
		writeStorageError(w, err)
		return
	}
	// "existing" means the snapshot was already registered before this request,
	// which is checked before writing the record: no timestamp guessing.
	existing := false
	switch _, err := s.Store.GetSnapshot(r.Context(), snap.SnapshotID); {
	case err == nil:
		existing = true
	case errors.Is(err, storage.ErrNotFound):
	default:
		writeStorageError(w, err)
		return
	}
	if err := s.Store.PutSnapshot(r.Context(), projectIDValue, snap); err != nil {
		writeStorageError(w, err)
		return
	}

	resp := snapshotResponse{
		Snapshot: summaryOf(snap, projectIDValue),
		Existing: existing,
	}

	if !req.SkipAnalysis {
		mf, err := s.Analyzer.Analyze(r.Context(), snap)
		if err != nil {
			writeStorageError(w, err)
			return
		}
		if err := s.persistManifest(r.Context(), snap, mf); err != nil {
			writeStorageError(w, err)
			return
		}
		resp.Manifest = manifestSummaryOf(mf)
	}

	if req.BuildGraph {
		if s.Builder == nil || s.Graph == nil {
			writeError(w, http.StatusNotImplemented, "graph_unavailable",
				errors.New("this server was started without the SCG builder"))
			return
		}
		g, berr := s.Builder.Build(r.Context(), snap)
		if berr != nil {
			writeStorageError(w, berr)
			return
		}
		if err := s.Store.ReplaceGraph(r.Context(), snap.SnapshotID, g); err != nil {
			writeStorageError(w, err)
			return
		}
		if err := s.persistGraphArtifact(snap, g); err != nil {
			writeStorageError(w, err)
			return
		}
		resp.Graph = g.Summarize()
	}

	if req.BuildASG {
		summary, _, ok := s.buildASG(w, r, snap.SnapshotID, false)
		if !ok {
			return
		}
		resp.ASG = summary
	}

	status := http.StatusCreated
	if existing {
		status = http.StatusOK
	}
	writeJSON(w, status, resp)
}

// persistGraphArtifact writes the SCG document next to the frozen tree. The file
// name carries the graph version and a content hash, so a rebuild with different
// bytes adds an artifact instead of replacing the previous graph: the history of
// what was analysed, with which rules, stays readable.
func (s *Server) persistGraphArtifact(snap *repository.Snapshot, g *scg.Graph) error {
	doc, err := g.JSON()
	if err != nil {
		return err
	}
	name, err := g.ArtifactName()
	if err != nil {
		return err
	}
	return snap.WriteArtifact(name, doc)
}

// persistManifest stores the manifest in the database and next to the frozen
// tree. The on-disk artifact is authoritative, so a pre-existing identical file
// is fine while a different one is a conflict.
func (s *Server) persistManifest(ctx context.Context, snap *repository.Snapshot, mf *analysis.Manifest) error {
	want, err := mf.JSON()
	if err != nil {
		return err
	}
	if err := snap.WriteManifest(want); err != nil {
		got, rerr := snap.ReadManifest()
		if rerr != nil {
			return fmt.Errorf("%w: %s already holds a manifest: %v", storage.ErrConflict, snap.ManifestPath(), err)
		}
		var prev analysis.Manifest
		if json.Unmarshal(got, &prev) != nil || prev.AnalysisID != mf.AnalysisID {
			return fmt.Errorf("%w: %s already holds a different analysis: %v", storage.ErrConflict, snap.ManifestPath(), err)
		}
		// Re-analysis of the same identity: the stored document wins and the
		// store keeps the same facts.
		mf = &prev
	}
	return s.Store.PutManifest(ctx, snap.SnapshotID, mf)
}

func (s *Server) handleListSnapshots(w http.ResponseWriter, r *http.Request) {
	records, err := s.Store.ListSnapshots(r.Context(), r.URL.Query().Get("project_id"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	if records == nil {
		records = []storage.SnapshotRecord{}
	}
	writeJSON(w, http.StatusOK, map[string]any{"snapshots": records})
}

func (s *Server) handleGetSnapshot(w http.ResponseWriter, r *http.Request) {
	snap, err := s.Store.GetSnapshot(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	projectIDValue := ""
	if records, lerr := s.Store.ListSnapshots(r.Context(), ""); lerr == nil {
		for _, rec := range records {
			if rec.SnapshotID == snap.SnapshotID {
				projectIDValue = rec.ProjectID
				break
			}
		}
	}
	writeJSON(w, http.StatusOK, snapshotResponse{Snapshot: summaryOf(snap, projectIDValue)})
}

func (s *Server) handleDeleteSnapshot(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if err := s.Store.DeleteSnapshot(r.Context(), id); err != nil {
		writeStorageError(w, err)
		return
	}
	if err := s.Manager.Remove(id); err != nil && !errors.Is(err, repository.ErrSnapshotNotFound) {
		writeStorageError(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleGetManifest(w http.ResponseWriter, r *http.Request) {
	mf, err := s.Store.GetManifest(r.Context(), r.PathValue("id"))
	if err != nil {
		writeStorageError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mf)
}

// --- helpers ----------------------------------------------------------------

func summaryOf(snap *repository.Snapshot, projectID string) snapshotSummary {
	return snapshotSummary{
		SnapshotID:     snap.SnapshotID,
		ProjectID:      projectID,
		VCS:            snap.VCS,
		Commit:         snap.Commit,
		WorktreeDirty:  snap.WorktreeDirty,
		Files:          snap.Stats.Files,
		Bytes:          snap.Stats.Bytes,
		SkippedTotal:   snap.Stats.SkippedTotal(),
		Limitations:    snap.Limitations,
		SubmoduleCount: len(snap.SubmoduleState),
		LFSDetected:    snap.LFS.Detected,
		SymlinkCount:   len(snap.Symlinks),
		DirtyPathCount: snap.DirtyPathCount,
		CreatedAt:      snap.CreatedAt,
	}
}

func manifestSummaryOf(mf *analysis.Manifest) *manifestSummary {
	out := &manifestSummary{
		AnalysisID:      mf.AnalysisID,
		RulesetHash:     mf.RulesetHash,
		ConfigHash:      mf.ConfigHash,
		PrimaryLanguage: mf.PrimaryLanguage,
		Entrypoints:     len(mf.Entrypoints),
		BuildConfigs:    len(mf.BuildConfigs),
		Packages:        mf.Dependencies.PackageCount,
		Unknowns:        mf.Unknowns,
		GeneratedAt:     mf.GeneratedAt,
	}
	for _, l := range mf.Languages {
		out.Languages = append(out.Languages, l.Name)
	}
	for _, f := range mf.Frameworks {
		out.Frameworks = append(out.Frameworks, f.Name)
	}
	return out
}

func projectID(identity repository.Identity) string {
	sum := sha256.Sum256([]byte(identity.Kind + "\x00" + identity.Name))
	return "proj-" + hex.EncodeToString(sum[:8])
}

func projectName(identity repository.Identity) string {
	name := identity.Name
	name = strings.TrimSuffix(name, "/")
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 && i+1 < len(name) {
		name = name[i+1:]
	}
	name = strings.TrimSuffix(name, ".git")
	if name == "" {
		name = identity.Name
	}
	return name
}

// decode reads a JSON body, rejecting unknown fields and oversized payloads.
func (s *Server) decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Body == nil {
		return true
	}
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
	if err != nil {
		writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", err)
		return false
	}
	if len(strings.TrimSpace(string(body))) == 0 {
		return true
	}
	dec := json.NewDecoder(strings.NewReader(string(body)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", err)
		return false
	}
	return true
}

type errorResponse struct {
	Error string `json:"error"`
	Code  string `json:"code"`
}

func writeJSON(w http.ResponseWriter, status int, body any) {
	data, err := json.MarshalIndent(body, "", "  ")
	if err != nil {
		http.Error(w, `{"error":"failed to encode response","code":"internal"}`, http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	w.Write(append(data, '\n'))
}

func writeError(w http.ResponseWriter, status int, code string, err error) {
	msg := "request failed"
	if err != nil {
		msg = err.Error()
	}
	writeJSON(w, status, errorResponse{Error: msg, Code: code})
}

// writeStorageError maps domain errors onto HTTP status codes.
func writeStorageError(w http.ResponseWriter, err error) {
	switch {
	case err == nil:
		return
	case errors.Is(err, storage.ErrNotFound), errors.Is(err, repository.ErrSnapshotNotFound):
		writeError(w, http.StatusNotFound, "not_found", err)
	case errors.Is(err, repository.ErrSourceNotFound):
		writeError(w, http.StatusNotFound, "source_not_found", err)
	case errors.Is(err, storage.ErrConflict):
		writeError(w, http.StatusConflict, "conflict", err)
	case errors.Is(err, repository.ErrNetworkDisabled):
		writeError(w, http.StatusForbidden, "network_disabled", err)
	case errors.Is(err, repository.ErrLimitExceeded):
		writeError(w, http.StatusUnprocessableEntity, "limit_exceeded", err)
	case errors.Is(err, repository.ErrSourceChanged):
		writeError(w, http.StatusConflict, "source_changed", err)
	case errors.Is(err, graph.ErrNoGraph):
		writeError(w, http.StatusNotFound, "graph_missing", err)
	case errors.Is(err, graph.ErrTreeUnavailable):
		writeError(w, http.StatusConflict, "tree_unavailable", err)
	case errors.Is(err, graph.ErrInvalidArgument):
		writeError(w, http.StatusBadRequest, "invalid_request", err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusGatewayTimeout, "canceled", err)
	default:
		writeError(w, http.StatusInternalServerError, "internal", err)
	}
}

// --- middleware -------------------------------------------------------------

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if rec := recover(); rec != nil {
				s.Logger.Error("panic in handler", "path", r.URL.Path, "panic", rec)
				writeError(w, http.StatusInternalServerError, "internal", fmt.Errorf("panic: %v", rec))
			}
		}()
		next.ServeHTTP(w, r)
	})
}

func (s *Server) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		s.Logger.Debug("request", "method", r.Method, "path", r.URL.Path, "status", rec.status, "duration_ms", time.Since(start).Milliseconds())
	})
}

type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (r *statusRecorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

// jsonErrors rewrites the mux's own 404/405 responses, which are plain text,
// into the API's JSON error shape.
func (s *Server) jsonErrors(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(&jsonErrorWriter{ResponseWriter: w}, r)
	})
}

type jsonErrorWriter struct {
	http.ResponseWriter
	intercepted bool
	wroteHeader bool
}

func (j *jsonErrorWriter) WriteHeader(status int) {
	if j.wroteHeader {
		return
	}
	j.wroteHeader = true
	// Only the mux's own plain-text 404/405 responses are rewritten: a handler
	// that already produced a JSON error (with its own code) keeps it.
	if (status != http.StatusNotFound && status != http.StatusMethodNotAllowed) ||
		strings.Contains(j.ResponseWriter.Header().Get("Content-Type"), "application/json") {
		j.ResponseWriter.WriteHeader(status)
		return
	}
	code := "not_found"
	if status == http.StatusMethodNotAllowed {
		code = "method_not_allowed"
	}
	body, err := json.Marshal(errorResponse{Error: http.StatusText(status), Code: code})
	if err != nil {
		j.ResponseWriter.WriteHeader(status)
		return
	}
	body = append(body, '\n')
	j.intercepted = true
	j.ResponseWriter.Header().Set("Content-Type", "application/json; charset=utf-8")
	j.ResponseWriter.Header().Set("Content-Length", strconv.Itoa(len(body)))
	j.ResponseWriter.WriteHeader(status)
	j.ResponseWriter.Write(body)
}

func (j *jsonErrorWriter) Write(p []byte) (int, error) {
	if j.intercepted {
		// The handler's plain-text body is replaced by the JSON error.
		return len(p), nil
	}
	return j.ResponseWriter.Write(p)
}

// --- idempotency ------------------------------------------------------------

// defaultIdempotencyTTL is how long a stored response may be replayed. It is
// short enough that the table cannot grow without bound and long enough for a
// client to retry a slow freeze.
const defaultIdempotencyTTL = 24 * time.Hour

// withIdempotency makes write retries safe.
//
// The key, the request fingerprint and the principal are all part of the claim:
// replaying a key with a different body or from a different token is refused
// instead of answered with someone else's response. Claims live in the store, so
// the guarantee survives a restart or a load-balancer hop to another process.
func (s *Server) withIdempotency(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
		if key == "" || s.Store == nil {
			next(w, r)
			return
		}
		body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, maxBodyBytes))
		if err != nil {
			writeError(w, http.StatusRequestEntityTooLarge, "body_too_large", err)
			return
		}
		r.Body = io.NopCloser(bytes.NewReader(body))

		ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), 10*time.Second)
		defer cancel()
		// Expired claims are removed on the write path: the table stays bounded
		// without a background worker, and a purge never blocks a read.
		if removed, perr := s.Store.PurgeExpiredIdempotency(ctx, time.Now().UTC()); perr != nil {
			s.Logger.Warn("idempotency purge failed", "error", perr)
		} else if removed > 0 {
			s.Logger.Debug("idempotency purge", "removed", removed)
		}

		principal, _ := PrincipalFrom(r.Context())
		scope := r.Method + " " + r.URL.Path
		claim, err := s.Store.ClaimIdempotent(ctx, storage.IdempotencyRecord{
			Scope:       scope,
			Key:         key,
			RequestHash: requestFingerprint(body),
			Principal:   principal.Name,
			ExpiresAt:   time.Now().UTC().Add(s.IdempotencyTTL),
		})
		if err != nil {
			writeStorageError(w, err)
			return
		}
		switch claim.State {
		case storage.ClaimReplay:
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			w.Header().Set("Idempotent-Replay", "true")
			w.WriteHeader(claim.Record.Status)
			w.Write(claim.Record.Body)
			return
		case storage.ClaimInProgress:
			w.Header().Set("Retry-After", "1")
			writeError(w, http.StatusConflict, "idempotency_in_progress",
				errors.New("a request with this Idempotency-Key is still running; retry once it finishes"))
			return
		case storage.ClaimMismatch:
			writeError(w, http.StatusConflict, "idempotency_key_reuse",
				errors.New("this Idempotency-Key was already used for a different request or a different token"))
			return
		}

		rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
		capture := &bodyCapture{ResponseWriter: rec}
		next(capture, r)
		switch {
		case rec.status >= 500:
			// The server failed: let the client retry the same key rather than
			// caching a transient failure.
			if rerr := s.Store.ReleaseIdempotent(ctx, scope, key); rerr != nil {
				s.Logger.Warn("idempotency release failed", "error", rerr)
			}
		default:
			if cerr := s.Store.CompleteIdempotent(ctx, scope, key, rec.status, capture.body); cerr != nil {
				s.Logger.Warn("idempotency completion failed", "error", cerr)
			}
		}
	}
}

// requestFingerprint identifies a request body for idempotency purposes.
func requestFingerprint(body []byte) string {
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:16])
}

// bodyCapture records the response body for the idempotency cache.
type bodyCapture struct {
	http.ResponseWriter
	body []byte
}

func (c *bodyCapture) Write(p []byte) (int, error) {
	c.body = append(c.body, p...)
	return c.ResponseWriter.Write(p)
}
