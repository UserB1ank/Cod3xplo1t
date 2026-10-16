package api

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

// asgUnavailable reports that the server was built without the attack-surface
// service, mirroring graphUnavailable: "not configured" must never be answered
// as "this snapshot has no attack surface".
func (s *Server) asgUnavailable(w http.ResponseWriter) bool {
	if s.ASG == nil {
		writeError(w, http.StatusNotImplemented, "asg_unavailable",
			errors.New("this server was started without the ASG service"))
		return true
	}
	return false
}

// buildASGRequest is the POST /asg body. Force rebuilds even when a stored
// attack surface exists, which is what a changed rule set needs.
type buildASGRequest struct {
	Force bool `json:"force"`
}

// asgResponse is the answer to a build: the summary and whether the document
// was produced now or came from the store.
type asgResponse struct {
	ASG   *asg.Summary `json:"asg"`
	Built bool         `json:"built"`
}

// buildASG derives and stores the attack surface of one snapshot. It is shared
// by POST /api/snapshots/{id}/asg and the build_asg flag of snapshot creation,
// so the two paths cannot drift.
func (s *Server) buildASG(w http.ResponseWriter, r *http.Request, snapshotID string, force bool) (*asg.Summary, bool, bool) {
	if s.asgUnavailable(w) {
		return nil, false, false
	}
	if s.ASGBuilder == nil {
		writeError(w, http.StatusNotImplemented, "asg_unavailable",
			errors.New("this server was started without the ASG builder"))
		return nil, false, false
	}
	if !force {
		if summary, err := s.ASG.Summary(r.Context(), snapshotID); err == nil {
			return summary, false, true
		} else if !errors.Is(err, graph.ErrNoASG) && !errors.Is(err, storage.ErrNotFound) {
			writeStorageError(w, err)
			return nil, false, false
		}
	}
	snap, err := s.Manager.Load(snapshotID)
	if err != nil {
		writeStorageError(w, err)
		return nil, false, false
	}
	doc, err := s.ASGBuilder.Build(r.Context(), snapshotID)
	if err != nil {
		if errors.Is(err, asg.ErrNoSCG) {
			// An attack surface without an SCG is not "not found": the caller can
			// fix it by building the graph, so the code says exactly that.
			writeError(w, http.StatusConflict, "scg_missing", fmt.Errorf(
				"snapshot %s has no source code graph; build the graph first with POST /api/snapshots/%s/graph: %w",
				snapshotID, snapshotID, err))
			return nil, false, false
		}
		writeStorageError(w, err)
		return nil, false, false
	}
	name, err := doc.ArtifactName()
	if err != nil {
		writeStorageError(w, err)
		return nil, false, false
	}
	data, err := doc.JSON()
	if err != nil {
		writeStorageError(w, err)
		return nil, false, false
	}
	if err := snap.WriteArtifact(name, data); err != nil {
		writeStorageError(w, err)
		return nil, false, false
	}
	if err := s.Store.ReplaceASG(r.Context(), snapshotID, doc); err != nil {
		writeStorageError(w, err)
		return nil, false, false
	}
	return doc.Summarize(), true, true
}

// handleBuildASG answers POST /api/snapshots/{id}/asg.
func (s *Server) handleBuildASG(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var req buildASGRequest
	if !s.decode(w, r, &req) {
		return
	}
	summary, built, ok := s.buildASG(w, r, id, req.Force)
	if !ok {
		return
	}
	status := http.StatusOK
	if built {
		status = http.StatusCreated
	}
	writeJSON(w, status, asgResponse{ASG: summary, Built: built})
}

// handleASGSummary answers GET /api/snapshots/{id}/asg.
func (s *Server) handleASGSummary(w http.ResponseWriter, r *http.Request) {
	if s.asgUnavailable(w) {
		return
	}
	summary, err := s.ASG.Summary(r.Context(), r.PathValue("id"))
	if err != nil {
		s.writeASGError(w, err, r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, summary)
}

// handleASGNodes answers GET /api/snapshots/{id}/asg/nodes.
func (s *Server) handleASGNodes(w http.ResponseWriter, r *http.Request) {
	if s.asgUnavailable(w) {
		return
	}
	q := r.URL.Query()
	kinds, ok := parseASGNodeKinds(q.Get("kind"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("unknown node kind %q; valid kinds are %s", q.Get("kind"), strings.Join(nodeKindNames(), ", ")))
		return
	}
	page, err := s.ASG.Nodes(r.Context(), r.PathValue("id"), graph.ASGNodeQuery{
		Kinds:     kinds,
		Subject:   q.Get("subject"),
		Generator: q.Get("generator"),
		File:      q.Get("file"),
		Limit:     queryInt(q.Get("limit"), 0),
		Offset:    queryInt(q.Get("offset"), 0),
	})
	if err != nil {
		s.writeASGError(w, err, r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// handleASGNode answers GET /api/snapshots/{id}/asg/nodes/{nodeID}.
func (s *Server) handleASGNode(w http.ResponseWriter, r *http.Request) {
	if s.asgUnavailable(w) {
		return
	}
	view, err := s.ASG.Node(r.Context(), r.PathValue("id"), r.PathValue("nodeID"))
	if err != nil {
		s.writeASGError(w, err, r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, view)
}

// handleASGEntryPoints answers GET /api/snapshots/{id}/asg/entrypoints.
//
// The page alone is not an answer: the coverage, the evidence histogram and the
// limitations are attached to every response, because an attack surface read
// without them looks more complete than it is.
func (s *Server) handleASGEntryPoints(w http.ResponseWriter, r *http.Request) {
	if s.asgUnavailable(w) {
		return
	}
	id := r.PathValue("id")
	page, err := s.ASG.EntryPoints(r.Context(), id, queryInt(r.URL.Query().Get("limit"), 0), queryInt(r.URL.Query().Get("offset"), 0))
	if err != nil {
		s.writeASGError(w, err, id)
		return
	}
	summary, err := s.ASG.Summary(r.Context(), id)
	if err != nil {
		s.writeASGError(w, err, id)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"entry_points":    page.EntryPoints,
		"total":           page.Total,
		"meta":            page.Meta,
		"limitations":     summary.Limitations,
		"coverage":        summary.Coverage,
		"evidence_counts": summary.EvidenceCounts,
	})
}

// handleASGEdges answers GET /api/snapshots/{id}/asg/edges.
func (s *Server) handleASGEdges(w http.ResponseWriter, r *http.Request) {
	if s.asgUnavailable(w) {
		return
	}
	q := r.URL.Query()
	kinds, ok := parseASGEdgeKinds(q.Get("kind"))
	if !ok {
		writeError(w, http.StatusBadRequest, "invalid_request",
			fmt.Errorf("unknown edge kind %q; valid kinds are %s", q.Get("kind"), strings.Join(edgeKindNames(), ", ")))
		return
	}
	page, err := s.ASG.Edges(r.Context(), r.PathValue("id"), commaList(q.Get("from")), commaList(q.Get("to")), kinds, queryInt(q.Get("limit"), 0))
	if err != nil {
		s.writeASGError(w, err, r.PathValue("id"))
		return
	}
	writeJSON(w, http.StatusOK, page)
}

// writeASGError maps the one attack-surface error that is not a storage error.
// "no ASG here" is distinct from "no such node": the first is a missing build,
// the second is a bad id.
func (s *Server) writeASGError(w http.ResponseWriter, err error, snapshotID string) {
	switch {
	case errors.Is(err, graph.ErrNoASG):
		writeError(w, http.StatusNotFound, "asg_missing", fmt.Errorf(
			"snapshot %s has no attack surface yet; build it with POST /api/snapshots/%s/asg: %w",
			snapshotID, snapshotID, err))
	case errors.Is(err, storage.ErrNotFound):
		// The document exists, so this is a bad node id rather than a missing build.
		writeError(w, http.StatusNotFound, "not_found", err)
	default:
		writeStorageError(w, err)
	}
}

// parseASGNodeKinds validates a comma-separated kind list against the ASG
// vocabulary, so a typo is a 400 instead of an empty page that reads like "none".
func parseASGNodeKinds(value string) ([]asg.NodeKind, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, true
	}
	valid := map[string]asg.NodeKind{}
	for _, k := range asg.AllNodeKinds() {
		valid[string(k)] = k
	}
	var out []asg.NodeKind
	for _, part := range commaList(value) {
		kind, ok := valid[part]
		if !ok {
			return nil, false
		}
		out = append(out, kind)
	}
	return out, true
}

// parseASGEdgeKinds validates a comma-separated edge kind list.
func parseASGEdgeKinds(value string) ([]asg.EdgeKind, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, true
	}
	valid := map[string]bool{}
	for _, k := range asg.AllEdgeKinds() {
		valid[string(k)] = true
	}
	var out []asg.EdgeKind
	for _, part := range commaList(value) {
		if !valid[part] {
			return nil, false
		}
		out = append(out, asg.EdgeKind(part))
	}
	return out, true
}

// commaList splits a comma-separated parameter, dropping empty entries.
func commaList(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	out := make([]string, 0, strings.Count(value, ",")+1)
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			out = append(out, part)
		}
	}
	return out
}

func nodeKindNames() []string {
	kinds := asg.AllNodeKinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}

func edgeKindNames() []string {
	kinds := asg.AllEdgeKinds()
	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, string(k))
	}
	return out
}
