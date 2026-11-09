package api

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

const maxProposalItems = 32

type proposalStep struct {
	Layer       string `json:"layer"`
	FromRef     string `json:"from_ref"`
	ToRef       string `json:"to_ref"`
	RelationRef string `json:"relation_ref"`
}

type proposalEvidenceInput struct {
	Kind      string `json:"kind"`
	ID        string `json:"id,omitempty"`
	File      string `json:"file,omitempty"`
	StartLine int    `json:"start_line,omitempty"`
	EndLine   int    `json:"end_line,omitempty"`
}

type proposalInput struct {
	RequestKey     string                  `json:"request_key"`
	EntryRef       string                  `json:"entry_ref"`
	TargetRef      string                  `json:"target_ref"`
	Basis          string                  `json:"basis"`
	Steps          []proposalStep          `json:"steps,omitempty"`
	Evidence       []proposalEvidenceInput `json:"evidence"`
	RelatedPathIDs []string                `json:"related_path_ids,omitempty"`
	Limitations    []string                `json:"limitations,omitempty"`
	MaxPerRun      int                     `json:"max_per_run,omitempty"`
}

func (s *Server) handleProposePath(w http.ResponseWriter, r *http.Request) {
	reader, ok := s.knowledgeReader(w)
	if !ok {
		return
	}
	projectID, viewID := r.PathValue("projectID"), r.PathValue("viewID")
	scope, err := reader.ScopeOf(r.Context(), projectID, viewID)
	if err != nil {
		if errors.Is(err, knowledge.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid_path_view", errors.New("view_id must be a complete multi-layer knowledge view opened for this snapshot; publication revision ids are not view pins"))
			return
		}
		writeKnowledgeError(w, err)
		return
	}
	view, err := reader.Describe(r.Context(), scope, viewID)
	if err != nil {
		if errors.Is(err, knowledge.ErrInvalid) {
			writeError(w, http.StatusBadRequest, "invalid_path_view", errors.New("view_id must be a complete multi-layer knowledge view opened for this snapshot"))
			return
		}
		writeKnowledgeError(w, err)
		return
	}
	for _, layer := range []string{knowledge.LayerSCG, knowledge.LayerASG, knowledge.LayerPaths} {
		info, mounted := view.Layers[layer]
		if !mounted || info.Status != knowledge.StatusAvailable {
			writeKnowledgeError(w, knowledge.ErrLayerUnavailable)
			return
		}
	}
	var in proposalInput
	if !s.decode(w, r, &in) {
		return
	}
	if s.ASG == nil || s.Graph == nil || s.Audit == nil {
		writeError(w, http.StatusNotImplemented, "path_proposal_unavailable", errors.New("graph services are unavailable"))
		return
	}
	if len(in.RequestKey) == 0 || len(in.RequestKey) > 200 || len(in.Steps) > maxProposalItems ||
		len(in.Evidence) == 0 || len(in.Evidence) > maxProposalItems || len(in.RelatedPathIDs) > maxProposalItems ||
		len(in.Limitations) > maxProposalItems {
		writeError(w, http.StatusBadRequest, "invalid_path_proposal", errors.New("invalid proposal bounds"))
		return
	}
	if in.Basis != "call_reachability" && in.Basis != "hypothesis" {
		writeError(w, http.StatusBadRequest, "invalid_path_proposal", errors.New("basis must be call_reachability or hypothesis"))
		return
	}
	entry, err := s.ASG.Node(r.Context(), scope.SnapshotID, in.EntryRef)
	if err != nil || entry.Node.Kind != asg.NodeEntryPoint {
		writeError(w, http.StatusBadRequest, "invalid_path_endpoint", errors.New("entry_ref must name an attack-surface entry point in the pinned view"))
		return
	}
	target, err := s.ASG.Node(r.Context(), scope.SnapshotID, in.TargetRef)
	if err != nil || target.Node.Kind != asg.NodeSensitiveOperation {
		writeError(w, http.StatusBadRequest, "invalid_path_endpoint", errors.New("target_ref must name a sensitive operation in the pinned view"))
		return
	}
	steps, edgeIDs, err := s.validateProposalSteps(r.Context(), scope.SnapshotID, in)
	if err != nil {
		writeProposalError(w, err)
		return
	}
	if in.Basis == "call_reachability" && len(steps) == 0 {
		steps, edgeIDs, err = s.inferCallReachability(r.Context(), scope.SnapshotID, entry, target, steps, edgeIDs)
		if err != nil {
			writeProposalError(w, err)
			return
		}
	}
	if in.Basis == "call_reachability" && (len(steps) == 0 || steps[0].From != in.EntryRef || steps[len(steps)-1].To != in.TargetRef) {
		// The inferred SCG path uses symbol refs, not ASG endpoints. The explicit
		// evidence is recorded on the path below; only user-supplied ASG steps must
		// connect the attack-surface endpoint ids.
		if len(in.Steps) > 0 {
			writeError(w, http.StatusBadRequest, "invalid_path_chain", errors.New("call_reachability requires a connected observed edge chain from entry to target"))
			return
		}
	}
	evidence, err := s.validateProposalEvidence(r.Context(), scope, in.Evidence)
	if err != nil {
		writeProposalError(w, err)
		return
	}
	for _, related := range in.RelatedPathIDs {
		existing, err := s.Store.GetPath(related)
		if err != nil || existing.SnapshotID != scope.SnapshotID {
			writeError(w, http.StatusNotFound, "related_path_not_found", errors.New("related path is not part of this snapshot"))
			return
		}
	}
	audit, err := s.ensureDiscoveryAudit(r.Context(), scope, view)
	if err != nil {
		writeProposalError(w, err)
		return
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	origin := path.ProposalOriginFrom(r.Context())
	source, tool := "human", "api"
	if origin.SessionID != "" || origin.RunID != "" {
		if err := s.requireActiveProposalRun(r.Context(), scope.ProjectID, scope.SnapshotID, origin); err != nil {
			writeProposalError(w, err)
			return
		}
		source, tool = "supervisor", "propose_path"
	}
	pathKind, pathStatus, risk, support, priority := "hypothesis", path.PathUnresolved, 0.1, 0.15, 0.15
	if in.Basis == "call_reachability" {
		pathKind, pathStatus, risk, support, priority = path.PathKindCallGraph, path.PathStaticallySupported, 0.4, 0.7, 0.55
	}
	signature := path.Signature(scope.SnapshotID, entry.Node.ID, target.Node.ID, pathKind, edgeIDs)
	observation := path.PathDiscovery{
		Source: source, Tool: tool, SessionID: origin.SessionID, RunID: origin.RunID,
		KnowledgeViewID: view.ID, RequestKey: in.RequestKey,
		RequestDigest:  proposalRequestDigest(view.ID, signature, in.Basis, steps, evidence, in.RelatedPathIDs, in.Limitations),
		Basis:          in.Basis,
		RelatedPathIDs: append([]string(nil), in.RelatedPathIDs...),
		Evidence:       evidence, CreatedAt: now,
	}
	proposal := path.Path{
		ID:      path.PathID(audit.ID, scope.SnapshotID, entry.Node.ID, target.Node.ID, edgeIDs, pathKind),
		AuditID: audit.ID, SnapshotID: scope.SnapshotID,
		SCGVersion: view.Layers[knowledge.LayerSCG].Version, ASGVersion: view.Layers[knowledge.LayerASG].Version,
		EntryNodeID: entry.Node.ID, EntryKind: string(entry.Node.Kind), EntrySubject: entry.Node.Subject,
		TargetNodeID: target.Node.ID, TargetSubject: target.Node.Subject, TargetKind: string(target.Node.Kind),
		PathKind: pathKind, PathStatus: pathStatus, Status: path.StatusQueued,
		Steps: steps, Signature: signature,
		SCGRefs: []string{}, ASGRefs: []string{entry.Node.ID, target.Node.ID},
		EvidenceRefs: proposalEvidenceIDs(evidence),
		Objectives:   []string{"agent_discovered:" + in.Basis},
		Limitations: append([]string{
			"Agent proposal; candidate selection does not establish source control, data flow, control failure or exploitability.",
		}, in.Limitations...),
		Depth: len(steps), Budget: path.DefaultBudget(),
		MaxAttempts: audit.Limits.Normalize().MaxAttempts,
		Features: path.Features{
			ReachabilityEvidence: support, Impact: risk,
			Reasons: map[string]string{
				"discovery_basis": in.Basis, "knowledge_view_id": view.ID, "request_key": in.RequestKey,
				path.AwaitingSelectionReasonKey: "true",
			},
		},
		Score:       path.Score{Risk: risk, Support: support, Utility: 0.2, Priority: priority, ScoreVersion: path.ScoreVersion, Weights: map[string]float64{"discovery_support": 1}, ComputedAt: now},
		Discoveries: []path.PathDiscovery{observation},
		CreatedAt:   now, UpdatedAt: now, Version: 1,
	}
	proposal.ASGRefs = append(proposal.ASGRefs, edgeIDs...)
	stored, created, err := s.Audit.AddProposedPath(r.Context(), proposal, principalName(r), min(in.MaxPerRun, maxProposalItems))
	if err != nil {
		writeProposalError(w, err)
		return
	}
	status := http.StatusOK
	if created {
		status = http.StatusCreated
	}
	writeJSON(w, status, map[string]any{"api_version": "codexploit/v1", "path": stored, "created": created})
}

func (s *Server) inferCallReachability(ctx context.Context, snapshotID string, entry, target *graph.ASGNodeView, _ []path.Step, _ []string) ([]path.Step, []string, error) {
	entrySymbol := entry.Node.Detail["handler_symbol_id"]
	targetSymbol := ""
	for _, ref := range target.DerivedFrom {
		if ref.Kind == "symbol" {
			targetSymbol = ref.ID
			break
		}
	}
	if targetSymbol == "" && s.Graph != nil {
		for _, ref := range target.DerivedFrom {
			if ref.Kind == "call_site" {
				if site, err := s.Graph.GetCallSite(ctx, snapshotID, ref.ID); err == nil && site.CallerSymbolID != "" {
					targetSymbol = site.CallerSymbolID
					break
				}
			}
		}
	}
	if entrySymbol == "" || targetSymbol == "" {
		return nil, nil, fmt.Errorf("%w: entry handler or sink caller symbol is unresolved", path.ErrInvalidArgument)
	}
	set, err := s.Graph.CallPaths(ctx, snapshotID, graph.PathRequest{
		Source: entrySymbol, Sink: targetSymbol, MaxPaths: 1, Options: graph.Options{MaxDepth: 10},
	})
	if err != nil {
		return nil, nil, err
	}
	if len(set.Paths) == 0 {
		return nil, nil, fmt.Errorf("%w: no observed call path connects the selected entry and sink", path.ErrInvalidArgument)
	}
	found := set.Paths[0]
	if len(found.Symbols) == 1 && len(found.EdgeIDs) == 0 {
		return []path.Step{}, []string{}, nil
	}
	if len(found.Symbols) < 2 || len(found.EdgeIDs) != len(found.Symbols)-1 {
		return nil, nil, fmt.Errorf("%w: call path is incomplete", path.ErrInvalidArgument)
	}
	steps := make([]path.Step, 0, len(found.EdgeIDs))
	for i, edgeID := range found.EdgeIDs {
		from, to := found.Symbols[i], found.Symbols[i+1]
		steps = append(steps, path.Step{
			Layer: "scg", From: from.ID, To: to.ID, Kind: "CALLS",
			File: to.File, Line: to.StartLine, Evidence: edgeID, Confidence: "observed",
		})
	}
	return steps, append([]string(nil), found.EdgeIDs...), nil
}

func (s *Server) validateProposalSteps(ctx context.Context, snapshotID string, in proposalInput) ([]path.Step, []string, error) {
	steps := make([]path.Step, 0, len(in.Steps))
	edgeIDs := make([]string, 0, len(in.Steps))
	for _, input := range in.Steps {
		if input.Layer != "asg" || input.FromRef == "" || input.ToRef == "" || input.RelationRef == "" {
			return nil, nil, fmt.Errorf("%w: steps must use observed ASG relations", path.ErrInvalidArgument)
		}
		page, err := s.ASG.Edges(ctx, snapshotID, []string{input.FromRef}, []string{input.ToRef}, []asg.EdgeKind{asg.EdgeReaches}, 10)
		if err != nil {
			return nil, nil, err
		}
		var selected *asg.Edge
		for i := range page.Edges {
			if page.Edges[i].ID == input.RelationRef {
				selected = &page.Edges[i]
				break
			}
		}
		if selected == nil || selected.Evidence != asg.StatusObserved {
			return nil, nil, fmt.Errorf("%w: relation %s is not an observed edge in the pinned attack surface", path.ErrInvalidArgument, input.RelationRef)
		}
		targetView, err := s.ASG.Node(ctx, snapshotID, selected.To)
		if err != nil {
			return nil, nil, err
		}
		steps = append(steps, path.Step{
			Layer: "asg", From: selected.From, To: selected.To, Kind: string(selected.Kind),
			Subject: targetView.Node.Subject, File: targetView.Node.File, Line: targetView.Node.Line,
			Evidence: string(selected.Evidence), Confidence: string(selected.Confidence),
		})
		edgeIDs = append(edgeIDs, selected.ID)
		if len(steps) > 1 && steps[len(steps)-2].To != steps[len(steps)-1].From {
			return nil, nil, fmt.Errorf("%w: path steps are not connected", path.ErrInvalidArgument)
		}
	}
	if len(steps) > 0 && (steps[0].From != in.EntryRef || steps[len(steps)-1].To != in.TargetRef) && in.Basis == "call_reachability" {
		return nil, nil, fmt.Errorf("%w: path does not connect the selected endpoints", path.ErrInvalidArgument)
	}
	return steps, edgeIDs, nil
}

func (s *Server) validateProposalEvidence(ctx context.Context, scope knowledge.Scope, inputs []proposalEvidenceInput) ([]path.DiscoveryEvidence, error) {
	out := make([]path.DiscoveryEvidence, 0, len(inputs))
	for _, input := range inputs {
		item := path.DiscoveryEvidence{Kind: input.Kind, ID: input.ID, File: input.File, StartLine: input.StartLine, EndLine: input.EndLine}
		switch input.Kind {
		case "source":
			if input.ID != "" || !proposalSourceTarget(input) {
				return nil, path.ErrInvalidArgument
			}
			digest, err := s.validateProposalSource(ctx, scope.SnapshotID, input)
			if err != nil {
				return nil, err
			}
			item.SHA256 = digest
		case "evidence":
			if input.ID == "" || input.File != "" || input.StartLine != 0 || input.EndLine != 0 {
				return nil, path.ErrInvalidArgument
			}
			itemRecord, err := s.Store.GetEvidence(input.ID)
			if errors.Is(err, verify.ErrNotFound) || errors.Is(err, storage.ErrNotFound) {
				return nil, storage.ErrNotFound
			}
			if err != nil {
				return nil, err
			}
			if itemRecord == nil || itemRecord.SnapshotID != scope.SnapshotID {
				return nil, storage.ErrNotFound
			}
			digest := sha256.Sum256([]byte(itemRecord.Content))
			if strings.TrimPrefix(itemRecord.ContentHash, "sha256:") != hex.EncodeToString(digest[:]) {
				return nil, artifact.ErrIntegrity
			}
			item.SHA256 = hex.EncodeToString(digest[:])
		case "artifact":
			if input.ID == "" || input.File != "" || input.StartLine != 0 || input.EndLine != 0 || s.Artifacts == nil {
				return nil, path.ErrInvalidArgument
			}
			index, ok := s.Store.(artifact.Index)
			if !ok {
				return nil, path.ErrInvalidArgument
			}
			artifactScope, err := index.ArtifactScope(ctx, scope.ProjectID, scope.SnapshotID)
			if err != nil {
				return nil, err
			}
			ref, err := s.Artifacts.Stat(ctx, artifactScope, input.ID, 16<<20)
			if errors.Is(err, artifact.ErrNotFound) {
				return nil, storage.ErrNotFound
			}
			if err != nil {
				return nil, err
			}
			if ref.SchemaID == artifact.SourceDirectorySchema {
				return nil, path.ErrInvalidArgument
			}
			item.SHA256 = ref.SHA256
		case "asg_node":
			if input.ID == "" {
				return nil, path.ErrInvalidArgument
			}
			node, err := s.ASG.Node(ctx, scope.SnapshotID, input.ID)
			if err != nil {
				return nil, err
			}
			item.File, item.StartLine = node.Node.File, node.Node.Line
		case "symbol", "call_site":
			if input.ID == "" || s.Graph == nil {
				return nil, path.ErrInvalidArgument
			}
			if input.Kind == "symbol" {
				symbol, _, err := s.Graph.Symbol(ctx, scope.SnapshotID, input.ID, graph.Options{})
				if err != nil {
					return nil, err
				}
				item.File, item.StartLine = symbol.File, symbol.StartLine
			} else {
				site, err := s.Graph.GetCallSite(ctx, scope.SnapshotID, input.ID)
				if err != nil {
					return nil, err
				}
				item.File, item.StartLine = site.File, site.Line
			}
		default:
			return nil, path.ErrInvalidArgument
		}
		out = append(out, item)
	}
	return out, nil
}

func proposalSourceTarget(input proposalEvidenceInput) bool {
	file := input.File
	if file == "" || filepath.IsAbs(file) || strings.ContainsAny(file, "\\:\x00\r\n") ||
		filepath.ToSlash(filepath.Clean(file)) != file || file == ".." || strings.HasPrefix(file, "../") ||
		input.StartLine < 1 || input.EndLine < input.StartLine || input.EndLine-input.StartLine >= 200 {
		return false
	}
	for _, part := range strings.Split(strings.ToLower(file), "/") {
		if strings.HasPrefix(part, ".env") || part == ".ssh" || part == ".git" || strings.HasSuffix(part, ".pem") || strings.HasSuffix(part, ".key") {
			return false
		}
	}
	return true
}

func (s *Server) validateProposalSource(ctx context.Context, snapshotID string, input proposalEvidenceInput) (string, error) {
	if s.Manager == nil {
		return "", path.ErrInvalidArgument
	}
	snapshot, err := s.Manager.Load(snapshotID)
	if err != nil {
		return "", path.ErrInvalidArgument
	}
	root, err := os.OpenRoot(snapshot.TreeDir())
	if err != nil {
		return "", path.ErrInvalidArgument
	}
	defer root.Close()
	info, err := root.Lstat(input.File)
	if err != nil || !info.Mode().IsRegular() {
		return "", storage.ErrNotFound
	}
	if info.Size() > 4<<20 {
		return "", path.ErrInvalidArgument
	}
	file, err := root.Open(input.File)
	if err != nil {
		return "", path.ErrInvalidArgument
	}
	defer file.Close()
	scanner := bufio.NewScanner(io.LimitReader(file, 4<<20+1))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	var content strings.Builder
	line := 0
	for scanner.Scan() {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		line++
		if line < input.StartLine {
			continue
		}
		text := scanner.Text()
		if content.Len()+len(text)+1 > 16000 || !utf8.ValidString(text) || strings.ContainsRune(text, 0) {
			return "", path.ErrInvalidArgument
		}
		content.WriteString(text)
		content.WriteByte('\n')
		if line == input.EndLine {
			break
		}
	}
	if scanner.Err() != nil || line < input.EndLine {
		return "", path.ErrInvalidArgument
	}
	digest := sha256.Sum256([]byte(content.String()))
	return hex.EncodeToString(digest[:]), nil
}

func proposalEvidenceIDs(evidence []path.DiscoveryEvidence) []string {
	out := make([]string, 0, len(evidence))
	for _, item := range evidence {
		if item.ID != "" {
			out = append(out, item.ID)
		} else if item.File != "" {
			out = append(out, fmt.Sprintf("source:%s:%d-%d", item.File, item.StartLine, item.EndLine))
		}
	}
	return out
}

func proposalRequestDigest(viewID, signature, basis string, steps []path.Step, evidence []path.DiscoveryEvidence, related, limitations []string) string {
	canonicalEvidence := append([]path.DiscoveryEvidence(nil), evidence...)
	sort.Slice(canonicalEvidence, func(i, j int) bool {
		left, _ := json.Marshal(canonicalEvidence[i])
		right, _ := json.Marshal(canonicalEvidence[j])
		return string(left) < string(right)
	})
	canonicalRelated := append([]string(nil), related...)
	sort.Strings(canonicalRelated)
	canonicalLimitations := append([]string(nil), limitations...)
	sort.Strings(canonicalLimitations)
	document := struct {
		ViewID      string                   `json:"view_id"`
		Signature   string                   `json:"signature"`
		Basis       string                   `json:"basis"`
		Steps       []path.Step              `json:"steps"`
		Evidence    []path.DiscoveryEvidence `json:"evidence"`
		Related     []string                 `json:"related_path_ids"`
		Limitations []string                 `json:"limitations"`
	}{
		ViewID: viewID, Signature: signature, Basis: basis, Steps: steps,
		Evidence: canonicalEvidence, Related: canonicalRelated, Limitations: canonicalLimitations,
	}
	raw, _ := json.Marshal(document)
	sum := sha256.Sum256(append([]byte("codexploit/path-proposal/request/v1\x00"), raw...))
	return hex.EncodeToString(sum[:])
}

func (s *Server) ensureDiscoveryAudit(ctx context.Context, scope knowledge.Scope, view *knowledge.View) (path.Audit, error) {
	digest := sha256.Sum256([]byte("codexploit/agent-path-discovery/v1\x00" + view.ID))
	configHash := hex.EncodeToString(digest[:16])
	auditID := path.AuditID(scope.SnapshotID, configHash)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	audit := path.Audit{
		Name: "Agent 新发现", Objective: "Agent-proposed paths awaiting human selection",
		SnapshotID: scope.SnapshotID, Status: path.AuditReady,
		SCGVersion: view.Layers[knowledge.LayerSCG].Version,
		ASGVersion: view.Layers[knowledge.LayerASG].Version,
		Budget:     path.DefaultBudget(), Limits: path.DefaultLimits(), ScoreVersion: path.ScoreVersion,
		ConfigHash: configHash, CountsByStatus: map[string]int{}, CountsByPathStatus: map[string]int{},
		Coverage: path.Coverage{}, Limitations: []string{"Paths are proposals from an agent, not tool-generated facts or confirmed vulnerabilities."},
		CreatedAt: now, UpdatedAt: now, Version: 1,
	}
	audit.ID = auditID
	existing, err := s.Store.GetAudit(auditID)
	if err == nil {
		if existing.SnapshotID != audit.SnapshotID || existing.SCGVersion != audit.SCGVersion || existing.ASGVersion != audit.ASGVersion {
			return path.Audit{}, knowledge.ErrViewSuperseded
		}
		return *existing, nil
	}
	if !errors.Is(err, path.ErrNotFound) {
		return path.Audit{}, err
	}
	if err := s.Store.CreateAudit(audit); err != nil {
		if existing, getErr := s.Store.GetAudit(auditID); getErr == nil {
			return *existing, nil
		}
		return path.Audit{}, err
	}
	return audit, nil
}

func (s *Server) requireActiveProposalRun(ctx context.Context, projectID, snapshotID string, origin path.ProposalOrigin) error {
	if origin.SessionID == "" || origin.RunID == "" {
		return fmt.Errorf("%w: supervisor path proposals need a session and run", path.ErrInvalidArgument)
	}
	store, ok := s.Store.(storage.SupervisorStore)
	if !ok {
		return fmt.Errorf("%w: supervisor state is unavailable", path.ErrInvalidArgument)
	}
	session, err := store.GetSupervisorSession(ctx, projectID, origin.SessionID)
	if err != nil {
		return err
	}
	if err := storage.ValidateSupervisorProposalRun(
		session, projectID, snapshotID,
		path.PathDiscovery{Source: "supervisor", SessionID: origin.SessionID, RunID: origin.RunID},
		origin, time.Now().UTC(),
	); err != nil {
		return fmt.Errorf("%w: supervisor run is no longer active: %v", path.ErrConflict, err)
	}
	return nil
}

func writeProposalError(w http.ResponseWriter, err error) {
	switch {
	case errors.Is(err, knowledge.ErrViewSuperseded):
		writeError(w, http.StatusConflict, "view_superseded", err)
	case errors.Is(err, artifact.ErrIntegrity):
		writeError(w, http.StatusConflict, "path_proposal_evidence_integrity", err)
	case errors.Is(err, artifact.ErrBudget):
		writeError(w, http.StatusRequestEntityTooLarge, "path_proposal_evidence_budget", err)
	case errors.Is(err, path.ErrInvalidArgument), errors.Is(err, graph.ErrNoASG):
		writeError(w, http.StatusBadRequest, "invalid_path_proposal", err)
	case errors.Is(err, storage.ErrNotFound):
		writeError(w, http.StatusNotFound, "path_proposal_reference_not_found", err)
	case errors.Is(err, path.ErrConflict):
		writeError(w, http.StatusConflict, "path_proposal_conflict", err)
	case errors.Is(err, path.ErrBudgetExceeded):
		writeError(w, http.StatusTooManyRequests, "path_proposal_budget_exceeded", err)
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		writeError(w, http.StatusRequestTimeout, "path_proposal_cancelled", err)
	default:
		writeError(w, http.StatusServiceUnavailable, "path_proposal_unavailable", errors.New("path proposal unavailable"))
	}
}
