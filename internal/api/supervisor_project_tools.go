package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"unicode/utf8"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/claim"
	projectmcp "github.com/open-mcp-ai/Codexploit/internal/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

type projectOperation struct {
	Operation  string   `json:"operation"`
	Parameters []string `json:"parameters"`
}

// The operation directory is collected from the real router, so adding a
// project endpoint cannot silently leave the supervisor on an older API.
type projectMux struct {
	*http.ServeMux
	server *Server
}

func (m *projectMux) HandleFunc(pattern string, handler func(http.ResponseWriter, *http.Request)) {
	m.ServeMux.HandleFunc(pattern, handler)
	_, path, _ := strings.Cut(pattern, " ")
	parts := strings.Split(strings.Trim(path, "/"), "/")
	projectRoute := strings.HasPrefix(path, "/api/v1/projects/{") || strings.HasPrefix(path, "/api/projects/{")
	snapshotRoute := path == "/api/snapshots" || strings.HasPrefix(path, "/api/snapshots/{")
	objectRoute := len(parts) >= 2 && slices.Contains([]string{"sources", "tasks", "audits", "paths", "runs", "hypotheses", "verifications", "findings", "evidence"}, parts[1]) && (len(parts) == 2 || strings.HasPrefix(parts[2], "{"))
	objectRoute = objectRoute || strings.HasPrefix(path, "/api/v1/sources/{")
	if !projectRoute && !snapshotRoute && !objectRoute && path != "/api/knowledge/findings/{id}" {
		return
	}
	params := []string{}
	for i, part := range parts {
		if strings.HasPrefix(part, "{") {
			if i > 0 && parts[i-1] == "projects" {
				continue
			}
			params = append(params, strings.Trim(part, "{}"))
		}
	}
	m.server.projectOperations = append(m.server.projectOperations, projectOperation{pattern, params})
}

func (s *Server) wireSupervisorProjectTools() {
	if s.Supervisor == nil || s.Graph == nil {
		return
	}
	s.Supervisor.ProjectMCPClient = func(ctx context.Context, project, snapshot string) (*sdk.ClientSession, error) {
		claimOrigin := claim.OriginFrom(ctx)
		pathOrigin := path.ProposalOriginFrom(ctx)
		principal, ok := PrincipalFrom(ctx)
		if !ok {
			return nil, errors.New("project tools require an authenticated operator")
		}
		return projectmcp.NewProjectClientWithTools(ctx, s.Graph, s.Store, project, snapshot, s.PluginCatalog, func(server *sdk.Server) {
			s.registerClaimTools(server, principal, project, snapshot, claimOrigin)
			s.registerPathProposalTools(server, principal, project, snapshot, pathOrigin)
			sdk.AddTool(server, &sdk.Tool{Name: "list_project_operations", Description: "Discover the current project's full application API: snapshots/graphs, source, analysis, tasks, workflows, Agent runs, findings, reports, artifacts and controls. Search by English route term; operation is the exact registered METHOD /path template. Project identity is injected by the host."}, func(ctx context.Context, _ *sdk.CallToolRequest, in projectOperationsInput) (*sdk.CallToolResult, any, error) {
				if in.Offset < 0 || in.Limit < 0 {
					return nil, nil, errors.New("invalid_argument: negative page")
				}
				limit := in.Limit
				if limit == 0 || limit > 30 {
					limit = 20
				}
				rows := []projectOperation{}
				for _, op := range s.projectOperations {
					if strings.Contains(strings.ToLower(op.Operation), strings.ToLower(in.Search)) {
						rows = append(rows, op)
					}
				}
				slices.SortFunc(rows, func(a, b projectOperation) int { return strings.Compare(a.Operation, b.Operation) })
				start := min(in.Offset, len(rows))
				end := min(start+limit, len(rows))
				return nil, map[string]any{"project_id": project, "default_snapshot_id": snapshot, "operations": rows[start:end], "total": len(rows), "next_offset": end, "truncated": end < len(rows), "usage": "Call project_api with operation, params for the listed placeholders, query, structured body, and optional if_match/idempotency_key. HTTP status and errors are preserved. Only this project's objects are accessible."}, nil
			})
			sdk.AddTool(server, &sdk.Tool{Name: "project_api", Description: "Read or operate on any current-project resource through the formal application API. Discover exact operation templates with list_project_operations. Uses the sending operator's permissions and the same validation, CAS, idempotency and execution gates as WebUI. For large GET responses follow next_offset with response_offset and expected_sha256; JSON fragments are explicitly marked text windows, never complete documents."}, func(ctx context.Context, _ *sdk.CallToolRequest, in projectAPIInput) (*sdk.CallToolResult, any, error) {
				ctx = claim.WithOrigin(ctx, claimOrigin)
				ctx = path.WithProposalOrigin(ctx, pathOrigin)
				return s.callProjectAPI(ctx, principal, project, in)
			})
		})
	}
}

type projectOperationsInput struct {
	Search string `json:"search,omitempty"`
	Offset int    `json:"offset,omitempty"`
	Limit  int    `json:"limit,omitempty"`
}
type projectAPIInput struct {
	Operation      string            `json:"operation"`
	Params         map[string]string `json:"params,omitempty"`
	Query          map[string]string `json:"query,omitempty"`
	Body           map[string]any    `json:"body,omitempty"`
	IfMatch        string            `json:"if_match,omitempty"`
	IdempotencyKey string            `json:"idempotency_key,omitempty"`
	ResponseOffset int               `json:"response_offset,omitempty"`
	ExpectedSHA256 string            `json:"expected_sha256,omitempty"`
}

func (s *Server) callProjectAPI(ctx context.Context, principal Principal, project string, in projectAPIInput) (*sdk.CallToolResult, any, error) {
	fail := func(message string) (*sdk.CallToolResult, any, error) { return nil, nil, errors.New(message) }
	if ctx.Err() != nil {
		return fail("cancelled: project operation cancelled")
	}
	var op *projectOperation
	for i := range s.projectOperations {
		if s.projectOperations[i].Operation == in.Operation {
			op = &s.projectOperations[i]
			break
		}
	}
	if op == nil {
		return fail("unsupported: discover a registered project operation first")
	}
	method, path, _ := strings.Cut(op.Operation, " ")
	if in.ResponseOffset < 0 || (in.ResponseOffset > 0 && method != http.MethodGet) {
		return fail("invalid_argument: response windows require GET")
	}
	if _, err := s.Store.GetProject(ctx, project); err != nil {
		if errors.Is(err, storage.ErrNotFound) {
			return fail("not_found: project unavailable")
		}
		return fail("storage_unavailable: project catalog unavailable")
	}
	for key := range in.Params {
		if !slices.Contains(op.Parameters, key) {
			return fail("invalid_argument: unknown path parameter")
		}
	}
	parts := strings.Split(path, "/")
	for i, part := range parts {
		if !strings.HasPrefix(part, "{") {
			continue
		}
		key := strings.Trim(part, "{}")
		value := in.Params[key]
		if i > 0 && parts[i-1] == "projects" {
			value = project
		}
		if value == "" || value == "." || value == ".." || strings.ContainsAny(value, "/%?#\\\x00") {
			return fail("invalid_argument: missing or invalid path parameter " + key)
		}
		parts[i] = value
	}
	path = strings.Join(parts, "/")
	// Legacy object routes lack a project prefix. Resolve ownership before the
	// real handler can read or mutate the object, including its events/children.
	rows, err := s.Store.ListSnapshots(ctx, project)
	if err != nil {
		return fail("storage_unavailable: snapshot catalog unavailable")
	}
	allowed := func(snapshot string) bool {
		for _, row := range rows {
			if row.SnapshotID == snapshot {
				return true
			}
		}
		return false
	}
	if strings.HasPrefix(path, "/api/v1/sources/") {
		id := strings.Split(strings.TrimPrefix(path, "/api/v1/sources/"), "/")[0]
		if _, err := s.projectObjectSnapshot(ctx, project, "sources", id); err != nil {
			return fail("not_found: source outside current project")
		}
	}
	if len(parts) >= 4 && parts[1] == "api" && !slices.Contains([]string{"projects", "v1", "v2"}, parts[2]) {
		kind, id := parts[2], parts[3]
		if kind == "knowledge" && len(parts) >= 5 {
			kind, id = "findings", parts[4]
		}
		snapshot, err := s.projectObjectSnapshot(ctx, project, kind, id)
		if err != nil || (snapshot != "" && !allowed(snapshot)) {
			return fail("not_found: object outside current project")
		}
	}
	query := url.Values{}
	for key, value := range in.Query {
		query.Set(key, value)
	}
	if path == "/api/snapshots" {
		query.Set("project_id", project)
	}
	if slices.Contains([]string{"/api/audits", "/api/runs", "/api/hypotheses", "/api/verifications", "/api/findings"}, path) && query.Get("snapshot_id") == "" {
		input, err := s.Store.GetProjectInput(ctx, project)
		if err != nil || input.SnapshotID == "" {
			return fail("invalid_argument: select a project snapshot_id for this listing")
		}
		query.Set("snapshot_id", input.SnapshotID)
	}
	for _, key := range []string{"project_id", "projectID"} {
		if value := query.Get(key); value != "" && value != project {
			return fail("not_found: project scope mismatch")
		}
	}
	for key, value := range query {
		if key == "snapshot_id" && !allowed(value[0]) {
			return fail("not_found: snapshot outside current project")
		}
	}
	for key, kind := range map[string]string{"audit_id": "audits", "task_id": "tasks", "path_id": "paths", "hypothesis_id": "hypotheses", "finding_id": "findings", "source_id": "sources"} {
		id := query.Get(key)
		if id == "" {
			id, _ = in.Body[key].(string)
		}
		if id != "" {
			snapshot, err := s.projectObjectSnapshot(ctx, project, kind, id)
			if err != nil || (snapshot != "" && !allowed(snapshot)) {
				return fail("not_found: referenced object outside current project")
			}
		}
	}
	if value, ok := in.Body["snapshot_id"].(string); ok && !allowed(value) {
		return fail("not_found: snapshot outside current project")
	}
	if value, ok := in.Body["project_id"].(string); ok && value != project {
		return fail("not_found: project scope mismatch")
	}
	need, known := requiredCapability(method, path)
	if !known || !principal.Capabilities.Allows(need) {
		return fail("forbidden: operator cannot perform this operation")
	}
	body, err := json.Marshal(in.Body)
	if err != nil || len(body) > 1<<20 {
		return fail("invalid_argument: invalid or oversized request body")
	}
	if in.Body == nil {
		body = []byte("{}")
	}
	req, err := http.NewRequestWithContext(withPrincipal(ctx, principal), method, path+"?"+query.Encode(), bytes.NewReader(body))
	if err != nil {
		return fail("invalid_argument: invalid request")
	}
	req.Header.Set("Content-Type", "application/json")
	if in.IfMatch != "" {
		req.Header.Set("If-Match", in.IfMatch)
	}
	if in.IdempotencyKey != "" {
		req.Header.Set("Idempotency-Key", in.IdempotencyKey)
	}
	w := &projectResponseWindow{header: http.Header{}, offset: in.ResponseOffset, digest: sha256.New()}
	s.recoverer(s.jsonErrors(s.handler)).ServeHTTP(w, req)
	digest := hex.EncodeToString(w.digest.Sum(nil))
	if in.ExpectedSHA256 != "" && in.ExpectedSHA256 != digest {
		return fail("view_superseded: response changed; read again from offset zero")
	}
	out := map[string]any{"project_id": project, "operation": op.Operation, "status": w.status, "ok": w.status >= 200 && w.status < 300, "etag": w.header.Get("ETag"), "sha256": digest, "total_bytes": w.total}
	var value any
	if in.ResponseOffset == 0 && w.total <= len(w.data) && json.Unmarshal(w.data, &value) == nil {
		out["data"] = value
	} else {
		data := w.data
		for i := 0; i < utf8.UTFMax-1 && len(data) > 0 && !utf8.Valid(data); i++ {
			data = data[:len(data)-1]
		}
		if utf8.Valid(data) && !bytes.ContainsRune(data, 0) {
			out["content"] = string(data)
			out["format"] = "text_window"
		} else {
			data = w.data
			out["content"] = base64.StdEncoding.EncodeToString(data)
			out["format"] = "base64_window"
		}
		out["offset"] = in.ResponseOffset
		out["next_offset"] = in.ResponseOffset + len(data)
		out["truncated"] = in.ResponseOffset+len(data) < w.total
	}
	return &sdk.CallToolResult{IsError: w.status >= 400}, out, nil
}

// Stream the response through a bounded window; never buffer a whole report or
// artifact in model memory. The digest covers all bytes, including omitted ones.
type projectResponseWindow struct {
	header                http.Header
	status, offset, total int
	data                  []byte
	digest                hash.Hash
}

func (w *projectResponseWindow) Header() http.Header { return w.header }
func (w *projectResponseWindow) WriteHeader(status int) {
	if w.status == 0 {
		w.status = status
	}
}
func (w *projectResponseWindow) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.WriteHeader(http.StatusOK)
	}
	_, _ = w.digest.Write(p)
	start := max(0, w.offset-w.total)
	// JSON may escape each input byte into six output bytes. Keep even that
	// worst case inside the supervisor's 32 KiB structured-result budget.
	if start < len(p) && len(w.data) < 4000 {
		w.data = append(w.data, p[start:min(len(p), start+4000-len(w.data))]...)
	}
	w.total += len(p)
	return len(p), nil
}

var _ http.ResponseWriter = (*projectResponseWindow)(nil)

func (s *Server) projectObjectSnapshot(ctx context.Context, project, kind, id string) (string, error) {
	switch kind {
	case "snapshots":
		_, err := s.Store.GetSnapshot(ctx, id)
		return id, err
	case "sources":
		repo, ok := s.Store.(storage.SourceRepository)
		if !ok {
			return "", errors.New("source catalog unavailable")
		}
		r, err := repo.GetSource(ctx, id)
		if err == nil && r.ProjectID != project {
			err = errors.New("outside project")
		}
		return "", err
	case "tasks", "audits":
		r, err := s.Store.GetAudit(id)
		if err != nil {
			return "", err
		}
		return r.SnapshotID, nil
	case "paths":
		r, err := s.Store.GetPath(id)
		if err != nil {
			return "", err
		}
		return r.SnapshotID, nil
	case "runs":
		r, err := s.Store.GetRun(id)
		if err != nil {
			return "", err
		}
		return r.SnapshotID, nil
	case "hypotheses":
		r, err := s.Store.GetHypothesis(id)
		if err != nil {
			return "", err
		}
		return r.SnapshotID, nil
	case "verifications":
		r, err := s.Store.GetVerificationRun(id)
		if err != nil {
			return "", err
		}
		return r.SnapshotID, nil
	case "findings":
		r, err := s.Store.GetFinding(id)
		if err != nil {
			return "", err
		}
		return r.SnapshotID, nil
	case "evidence":
		r, err := s.Store.GetEvidence(id)
		if err != nil {
			return "", err
		}
		return r.SnapshotID, nil
	default:
		return "", errors.New("unknown object kind")
	}
}
