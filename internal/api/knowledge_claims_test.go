package api

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/claim"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestKnowledgeClaimCanBeSubmittedAndRead(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source)
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	base := "/api/v1/projects/" + project.Project.ID + "/knowledge/claims"
	created := do(t, env.ts, http.MethodPost, base, map[string]any{
		"snapshot_id": snapshot.Snapshot.SnapshotID,
		"request_key": "claim-first",
		"category":    "vulnerability",
		"statement":   "The entry point may pass untrusted input to a sensitive operation",
		"conditions":  "Production entry with an untrusted caller",
		"target":      map[string]any{"file": "main.go", "start_line": 1, "end_line": 2},
	}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("submit claim: %d %s", created.status, created.body)
	}
	var out struct {
		Record struct {
			ClaimID string `json:"claim_id"`
			Status  string `json:"status"`
		} `json:"record"`
	}
	created.decode(t, &out)
	if out.Record.ClaimID == "" || out.Record.Status != "conjecture" {
		t.Fatalf("claim must remain a conjecture: %s", created.body)
	}
	read := do(t, env.ts, http.MethodGet, base+"/"+out.Record.ClaimID+"?snapshot_id="+snapshot.Snapshot.SnapshotID, nil, nil)
	if read.status != http.StatusOK || !containsString(read.body, "untrusted input") {
		t.Fatalf("read claim: %d %s", read.status, read.body)
	}
}

func TestSupervisorCanWriteAndQueryKnowledgeThroughMCP(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, env.source)
	input, err := env.rt.Store.GetProjectInput(context.Background(), project)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapWrite})
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "propose_claim", Arguments: map[string]any{"request_key": "mcp-claim", "category": "vulnerability", "statement": "Inspect the entry boundary", "target": map[string]any{"file": "main.go", "start_line": 1, "end_line": 2}}})
	if err != nil || result.IsError {
		t.Fatalf("MCP submit failed: %v %+v", err, result)
	}
	page, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "query_investigation_knowledge", Arguments: map[string]any{}})
	raw, _ := json.Marshal(page)
	if err != nil || page.IsError || !containsString(raw, "Inspect the entry boundary") {
		t.Fatalf("MCP read failed: %v %s", err, raw)
	}
	read := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+project+"/knowledge/claims?snapshot_id="+input.SnapshotID, nil, nil)
	var stored claim.Page
	read.decode(t, &stored)
	if len(stored.Records) != 1 {
		t.Fatalf("MCP record missing: %s", read.body)
	}
	id := stored.Records[0].ClaimID
	for _, tool := range []struct {
		name string
		args map[string]any
	}{
		{"open_question", map[string]any{"claim_id": id, "request_key": "mcp-question", "statement": "Does an upstream caller constrain this input?"}},
		{"attach_evidence", map[string]any{"claim_id": id, "request_key": "mcp-evidence", "statement": "The declaration is context only", "relation": "context", "reference": map[string]any{"kind": "source", "target": map[string]any{"file": "main.go", "start_line": 1, "end_line": 2}}}},
	} {
		result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: tool.name, Arguments: tool.args})
		raw, _ := json.Marshal(result)
		if err != nil || result.IsError {
			t.Fatalf("MCP %s: %v %s", tool.name, err, raw)
		}
	}
	reader := withPrincipal(context.Background(), Principal{Name: "reader", Capabilities: CapRead})
	readonly, err := env.rt.Supervisor.ProjectMCPClient(reader, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer readonly.Close()
	denied, err := readonly.CallTool(reader, &sdk.CallToolParams{Name: "open_question", Arguments: map[string]any{"claim_id": id, "request_key": "reader-question", "statement": "Must be denied"}})
	if err != nil || !denied.IsError {
		t.Fatalf("reader MCP write accepted: %v %+v", err, denied)
	}
}

func TestKnowledgeClaimsPinPagesAndPreserveObservations(t *testing.T) {
	env := newTestEnv(t, false)
	project := createAnalysisProject(t, env, env.source)
	input, _ := env.rt.Store.GetProjectInput(context.Background(), project)
	base := "/api/v1/projects/" + project + "/knowledge/claims"
	newClaim := func(key, statement string) claim.Record {
		r := do(t, env.ts, http.MethodPost, base, map[string]any{"snapshot_id": input.SnapshotID, "request_key": key, "category": "vulnerability", "statement": statement, "target": map[string]any{"file": "main.go", "start_line": 1, "end_line": 2}}, nil)
		if r.status != 201 {
			t.Fatalf("submit: %d %s", r.status, r.body)
		}
		var out struct {
			Record claim.Record `json:"record"`
		}
		r.decode(t, &out)
		return out.Record
	}
	first := newClaim("first", "First issue")
	second := newClaim("second", "Second issue")
	r := do(t, env.ts, http.MethodGet, base+"?snapshot_id="+input.SnapshotID+"&limit=1", nil, nil)
	var page claim.Page
	r.decode(t, &page)
	if len(page.Records) != 1 || !page.HasMore || page.Revision != 2 {
		t.Fatalf("first page: %s", r.body)
	}
	newClaim("third", "Later issue")
	r = do(t, env.ts, http.MethodGet, fmt.Sprintf("%s?snapshot_id=%s&limit=1&revision=%d&cursor=%d", base, input.SnapshotID, page.Revision, page.NextCursor), nil, nil)
	r.decode(t, &page)
	if len(page.Records) != 1 || page.Records[0].ClaimID != second.ClaimID || page.HasMore || page.HeadRevision != 3 {
		t.Fatalf("unstable continuation: %s", r.body)
	}
	duplicate := newClaim("independent-observer", "First issue")
	if duplicate.ClaimID != first.ClaimID || duplicate.Kind != "observation" {
		t.Fatalf("lost identity/provenance: %+v", duplicate)
	}
	r = do(t, env.ts, http.MethodGet, base+"/"+first.ClaimID+"?snapshot_id="+input.SnapshotID, nil, nil)
	r.decode(t, &page)
	if len(page.Records) != 2 || page.Records[1].Kind != "observation" {
		t.Fatalf("lost observation: %s", r.body)
	}
}

func TestKnowledgeAgentCannotWriteAfterRunCancellation(t *testing.T) {
	env := newTestEnv(t, false)
	assertKnowledgeCancellation(t, env)
}

func assertKnowledgeCancellation(t *testing.T, env *testEnv) {
	t.Helper()
	project := createAnalysisProject(t, env, newTestSource(t))
	input, _ := env.rt.Store.GetProjectInput(context.Background(), project)
	session, err := env.rt.Store.CreateSupervisorSession(context.Background(), storage.SupervisorSession{ID: "ss-knowledge", ProjectID: project, SnapshotID: input.SnapshotID, State: "ACTIVE", Runs: []storage.SupervisorRun{{ID: "srun-knowledge", Status: "RUNNING"}}})
	if err != nil {
		t.Fatal(err)
	}
	ctx := claim.WithOrigin(withPrincipal(context.Background(), Principal{Name: "operator", Capabilities: CapWrite}), claim.Origin{SessionID: session.ID, RunID: "srun-knowledge"})
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project, input.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	args := map[string]any{"request_key": "running", "category": "control", "statement": "Inspect entry controls", "target": map[string]any{"file": "main.go", "start_line": 1, "end_line": 2}}
	result, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "propose_claim", Arguments: args})
	if err != nil || result.IsError {
		t.Fatalf("active submit: %v %+v", err, result)
	}
	base := "/api/v1/projects/" + project
	cancelled := do(t, env.ts, http.MethodPost, base+"/agent-sessions/"+session.ID+"/runs/srun-knowledge/cancel", map[string]any{"reason": "stop investigation"}, nil)
	if cancelled.status != 200 {
		t.Fatalf("cancel: %d %s", cancelled.status, cancelled.body)
	}
	args["request_key"] = "late"
	result, err = client.CallTool(ctx, &sdk.CallToolParams{Name: "propose_claim", Arguments: args})
	if err != nil || !result.IsError {
		t.Fatalf("late submit accepted: %v %+v", err, result)
	}
	read := do(t, env.ts, http.MethodGet, base+"/knowledge/claims?snapshot_id="+input.SnapshotID, nil, nil)
	var page claim.Page
	read.decode(t, &page)
	if page.Revision != 1 || len(page.Records) != 1 || page.Records[0].RunID != "srun-knowledge" {
		t.Fatalf("late write/provenance: %s", read.body)
	}
}

func TestKnowledgeClaimQuestionsEvidenceAndPermissions(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source)
	captured := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{}, nil)
	var snapshot snapshotResponse
	captured.decode(t, &snapshot)
	snap := snapshot.Snapshot.SnapshotID
	base := "/api/v1/projects/" + project.Project.ID + "/knowledge/claims"
	body := map[string]any{"snapshot_id": snap, "request_key": "same-claim", "category": "control", "statement": "The entry may require authorization", "conditions": "Production caller", "target": map[string]any{"file": "main.go", "start_line": 1, "end_line": 2}}
	created := do(t, env.ts, http.MethodPost, base, body, nil)
	var out struct {
		Record struct {
			ClaimID  string `json:"claim_id"`
			Revision int64  `json:"revision"`
		} `json:"record"`
	}
	created.decode(t, &out)
	detail := base + "/" + out.Record.ClaimID
	replayed := do(t, env.ts, http.MethodPost, base, body, nil)
	var replay struct {
		Created bool `json:"created"`
	}
	replayed.decode(t, &replay)
	if replayed.status != http.StatusOK || replay.Created {
		t.Fatalf("replay: %d %s", replayed.status, replayed.body)
	}
	body["statement"] = "Different meaning"
	if got := do(t, env.ts, http.MethodPost, base, body, nil); got.status != http.StatusConflict {
		t.Fatalf("key conflict: %d %s", got.status, got.body)
	}
	question := do(t, env.ts, http.MethodPost, detail+"/questions", map[string]any{"snapshot_id": snap, "request_key": "question", "statement": "Which callers enforce authorization?"}, nil)
	if question.status != http.StatusCreated {
		t.Fatalf("question: %d %s", question.status, question.body)
	}
	evidence := map[string]any{"snapshot_id": snap, "request_key": "source-evidence", "statement": "Review the actual entry declaration", "relation": "context", "reference": map[string]any{"kind": "source", "target": map[string]any{"file": "main.go", "start_line": 1, "end_line": 2}}}
	if got := do(t, env.ts, http.MethodPost, detail+"/evidence", evidence, nil); got.status != http.StatusCreated {
		t.Fatalf("evidence: %d %s", got.status, got.body)
	}
	read := do(t, env.ts, http.MethodGet, detail+"?snapshot_id="+snap, nil, nil)
	if !containsString(read.body, "package main") || !containsString(read.body, "Which callers") {
		t.Fatalf("missing persisted knowledge: %s", read.body)
	}
	for _, illegal := range []map[string]any{
		{"status": "fact"}, {"actor": "reviewer"}, {"run_id": "invented"},
	} {
		raw, _ := json.Marshal(body)
		var request map[string]any
		_ = json.Unmarshal(raw, &request)
		for k, v := range illegal {
			request[k] = v
		}
		if got := do(t, env.ts, http.MethodPost, base, request, nil); got.status != http.StatusBadRequest {
			t.Fatalf("forged authority accepted: %s", got.body)
		}
	}
	if got := do(t, env.ts, http.MethodPost, base, body, map[string]string{"Authorization": "Bearer " + readerSecret}); got.status != http.StatusForbidden {
		t.Fatalf("reader write: %d %s", got.status, got.body)
	}
	other := createProject(t, env.ts, newTestSource(t))
	if got := do(t, env.ts, http.MethodGet, "/api/v1/projects/"+other.Project.ID+"/knowledge/claims/"+out.Record.ClaimID+"?snapshot_id="+snap, nil, nil); got.status != http.StatusNotFound {
		t.Fatalf("cross project: %d %s", got.status, got.body)
	}
	evidence["reference"] = map[string]any{"kind": "source", "target": map[string]any{"file": "absent.go", "start_line": 1, "end_line": 1}}
	if got := do(t, env.ts, http.MethodPost, detail+"/evidence", evidence, nil); got.status != http.StatusNotFound {
		t.Fatalf("missing evidence: %d %s", got.status, got.body)
	}
	// Existing evidence/artifacts must be resolved, not accepted by ID alone.
	evidence["reference"] = map[string]any{"kind": "evidence", "id": "missing"}
	if got := do(t, env.ts, http.MethodPost, detail+"/evidence", evidence, nil); got.status != http.StatusNotFound {
		t.Fatalf("missing evidence id: %d %s", got.status, got.body)
	}
	ctx := context.Background()
	checked, err := verify.NewEvidence(verify.EvidenceStaticQuery, "Recorded query result", verify.EvidenceOptions{Tool: "fixture-query", SnapshotID: snap})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.rt.Store.AppendEvidence([]verify.Evidence{checked}); err != nil {
		t.Fatal(err)
	}
	evidence["request_key"] = "existing-evidence"
	evidence["reference"] = map[string]any{"kind": "evidence", "id": checked.ID}
	if got := do(t, env.ts, http.MethodPost, detail+"/evidence", evidence, nil); got.status != http.StatusCreated {
		t.Fatalf("valid evidence: %d %s", got.status, got.body)
	}
	index := env.rt.Store.(artifact.Index)
	scope, err := index.ArtifactScope(ctx, project.Project.ID, snap)
	if err != nil {
		t.Fatal(err)
	}
	content := "Verified report bytes"
	ref := artifact.Ref{ID: "artifact-investigation-report", Kind: "report.document", Scope: scope, SHA256: fmt.Sprintf("%x", sha256.Sum256([]byte(content))), Bytes: int64(len(content)), MediaType: "text/plain", SchemaID: "codexploit/example/v1", Producer: artifact.Producer{PluginID: "builtin.reporter", PluginVersion: "1.0.0", InvocationID: "investigation-report", ConfigDigest: strings.Repeat("0", 64)}}
	if _, err := env.server.Artifacts.Put(ctx, ref, strings.NewReader(content), ref.Bytes); err != nil {
		t.Fatal(err)
	}
	evidence["request_key"] = "existing-artifact"
	evidence["reference"] = map[string]any{"kind": "artifact", "id": ref.ID}
	if got := do(t, env.ts, http.MethodPost, detail+"/evidence", evidence, nil); got.status != http.StatusCreated {
		t.Fatalf("valid artifact: %d %s", got.status, got.body)
	}
	if err := os.WriteFile(filepath.Join(env.rt.Manager.Root, "artifacts", "objects", ref.SHA256), []byte(strings.Repeat("x", len(content))), 0600); err != nil {
		t.Fatal(err)
	}
	evidence["request_key"] = "corrupt-artifact"
	if got := do(t, env.ts, http.MethodPost, detail+"/evidence", evidence, nil); got.status != http.StatusConflict {
		t.Fatalf("corrupt artifact accepted: %d %s", got.status, got.body)
	}
}
