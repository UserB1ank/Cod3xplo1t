package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestAgentPathProposalIsPinnedIdempotentAndHumanSelectable(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	capture := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if capture.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", capture.status, capture.body)
	}
	var snapshot snapshotResponse
	capture.decode(t, &snapshot)
	snapshotID := snapshot.Snapshot.SnapshotID
	ctx := context.Background()
	task := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/tasks",
		map[string]any{"name": "baseline paths", "objective": "review entry to sink", "snapshot_id": snapshotID}, nil)
	if task.status != http.StatusCreated {
		t.Fatalf("baseline task: %d %s", task.status, task.body)
	}
	viewPath := "/api/v1/projects/" + project.Project.ID + "/knowledge/views"
	opened := do(t, env.ts, http.MethodPost, viewPath, map[string]any{
		"api_version": "codexploit/v1", "snapshot_id": snapshotID,
		"layers": []string{knowledge.LayerSCG, knowledge.LayerASG, knowledge.LayerPaths},
	}, nil)
	if opened.status != http.StatusOK {
		t.Fatalf("open knowledge view: %d %s", opened.status, opened.body)
	}
	var view knowledgeViewResponse
	opened.decode(t, &view)
	entries, _, err := env.rt.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeEntryPoint}, Limit: 10,
	})
	sinks, _, err2 := env.rt.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeSensitiveOperation}, Limit: 10,
	})
	if err != nil || err2 != nil || len(entries) == 0 || len(sinks) == 0 {
		t.Fatalf("fixture lacks proposal endpoints: %v %v", err, err2)
	}
	body := map[string]any{
		"request_key": "manual-path-proposal", "entry_ref": entries[0].ID,
		"target_ref": sinks[0].ID, "basis": "hypothesis",
		"evidence":         []map[string]any{{"kind": "source", "file": "main.go", "start_line": 1, "end_line": 2}},
		"related_path_ids": []string{},
		"limitations":      []string{"The input-to-sink connection still needs investigation."},
	}
	endpoint := viewPath + "/" + view.View.ID + "/path-proposals"
	readerBody := map[string]any{}
	for key, value := range body {
		readerBody[key] = value
	}
	readerBody["request_key"] = "reader-path-proposal"
	if denied := doAs(t, env.ts, readerSecret, http.MethodPost, endpoint, readerBody, nil); denied.status != http.StatusForbidden {
		t.Fatalf("reader path proposal = %d %s, want 403", denied.status, denied.body)
	}
	created := do(t, env.ts, http.MethodPost, endpoint, body, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("proposal: %d %s", created.status, created.body)
	}
	var result struct {
		Created bool      `json:"created"`
		Path    path.Path `json:"path"`
	}
	created.decode(t, &result)
	if !result.Created || result.Path.Status != path.StatusQueued || result.Path.PathStatus != path.PathUnresolved ||
		result.Path.SCGVersion == "" || len(result.Path.Discoveries) != 1 ||
		result.Path.Discoveries[0].Source != "human" || len(result.Path.EvidenceRefs) == 0 ||
		result.Path.Features.Reasons[path.AwaitingSelectionReasonKey] != "true" {
		t.Fatalf("proposal lost provenance or review state: %s", created.body)
	}
	replayed := do(t, env.ts, http.MethodPost, endpoint, body, nil)
	var replay struct {
		Created bool `json:"created"`
	}
	replayed.decode(t, &replay)
	if replayed.status != http.StatusOK || replay.Created {
		t.Fatalf("same request was not idempotent: %d %s", replayed.status, replayed.body)
	}
	originalEvidence := body["evidence"]
	body["evidence"] = []map[string]any{{"kind": "source", "file": "main.go", "start_line": 2, "end_line": 3}}
	changed := do(t, env.ts, http.MethodPost, endpoint, body, nil)
	if changed.status != http.StatusConflict || !bytes.Contains([]byte(changed.body), []byte("path_proposal_conflict")) {
		t.Fatalf("same request key with changed evidence = %d %s, want conflict", changed.status, changed.body)
	}
	body["evidence"] = originalEvidence
	listed := auditPaths(t, env.ts, result.Path.AuditID, "")
	if len(listed.Paths) != 1 || listed.Paths[0].Signature != result.Path.Signature {
		t.Fatalf("proposal missing from path directory: %+v", listed)
	}
	body["request_key"] = "different-key-same-path"
	observed := do(t, env.ts, http.MethodPost, endpoint, body, nil)
	var observation struct {
		Path path.Path `json:"path"`
	}
	observed.decode(t, &observation)
	if observed.status != http.StatusOK || len(observation.Path.Discoveries) != 2 {
		t.Fatalf("second source did not append an observation: %d %s", observed.status, observed.body)
	}
	body["request_key"] = "supported-chain"
	body["basis"] = "call_reachability"
	delete(body, "steps")
	supported := do(t, env.ts, http.MethodPost, endpoint, body, nil)
	var supportedResult struct {
		Path path.Path `json:"path"`
	}
	supported.decode(t, &supportedResult)
	if supported.status != http.StatusCreated || supportedResult.Path.PathStatus != path.PathStaticallySupported ||
		supportedResult.Path.PathKind != path.PathKindCallGraph {
		t.Fatalf("observed chain was not preserved distinctly: %d %s", supported.status, supported.body)
	}
	delete(body, "evidence")
	body["request_key"] = "missing-evidence"
	if got := do(t, env.ts, http.MethodPost, endpoint, body, nil); got.status != http.StatusBadRequest {
		t.Fatalf("proposal without evidence = %d, want 400: %s", got.status, got.body)
	}
	revisionView := "view-" + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(
		`{"p":%q,"s":%q,"r":"rev-1"}`, project.Project.ID, snapshotID,
	)))
	invalidView := do(t, env.ts, http.MethodPost, viewPath+"/"+revisionView+"/path-proposals", body, nil)
	if invalidView.status != http.StatusBadRequest || !bytes.Contains([]byte(invalidView.body), []byte("invalid_path_view")) {
		t.Fatalf("publication revision view = %d %s, want invalid_path_view", invalidView.status, invalidView.body)
	}
}

func TestSupervisorProposePathUsesOriginAndDedupes(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, asgFixtureSource(t))
	capture := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if capture.status != http.StatusCreated {
		t.Fatalf("capture: %d %s", capture.status, capture.body)
	}
	var snapshot snapshotResponse
	capture.decode(t, &snapshot)
	snapshotID := snapshot.Snapshot.SnapshotID
	task := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/tasks",
		map[string]any{"name": "baseline paths", "objective": "review entry to sink", "snapshot_id": snapshotID}, nil)
	if task.status != http.StatusCreated {
		t.Fatalf("baseline task: %d %s", task.status, task.body)
	}
	ctx := context.Background()
	entries, _, _ := env.rt.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeEntryPoint}, Limit: 1,
	})
	sinks, _, _ := env.rt.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeSensitiveOperation}, Limit: 1,
	})
	if len(entries) == 0 || len(sinks) == 0 {
		t.Fatal("fixture has no proposal endpoints")
	}
	session, err := env.rt.Store.CreateSupervisorSession(context.Background(), storage.SupervisorSession{
		ID: "ss-path-proposal", ProjectID: project.Project.ID, SnapshotID: snapshotID,
		State: "ACTIVE", Runs: []storage.SupervisorRun{{
			ID: "srun-path-proposal", Status: "RUNNING", ExecutionOwner: "owner-proposal",
			LeaseEpoch: 4,
			LeaseUntil: time.Now().UTC().Add(time.Minute).Format(time.RFC3339Nano),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	origin := path.ProposalOrigin{
		SessionID: session.ID, RunID: "srun-path-proposal", ExecutionOwner: "owner-proposal", LeaseEpoch: 4,
	}
	ctx = path.WithProposalOrigin(withPrincipal(ctx, Principal{Name: "operator", Capabilities: CapWrite}), origin)
	client, err := env.rt.Supervisor.ProjectMCPClient(ctx, project.Project.ID, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	viewResult, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "open_knowledge_view", Arguments: map[string]any{}})
	if err != nil || viewResult.IsError {
		t.Fatalf("open knowledge view through MCP: %v %+v", err, viewResult)
	}
	rawView, _ := json.Marshal(viewResult.StructuredContent)
	var viewEnvelope struct {
		Data struct {
			View knowledge.View `json:"view"`
		} `json:"data"`
	}
	if json.Unmarshal(rawView, &viewEnvelope) != nil || viewEnvelope.Data.View.ID == "" {
		t.Fatalf("MCP knowledge view envelope: %s", rawView)
	}
	view := viewEnvelope.Data.View
	for _, layer := range []string{knowledge.LayerSCG, knowledge.LayerASG, knowledge.LayerPaths} {
		if info, ok := view.Layers[layer]; !ok || info.Status != knowledge.StatusAvailable {
			t.Fatalf("MCP knowledge view did not pin %s: %+v", layer, view.Layers)
		}
	}
	args := map[string]any{
		"view_id": view.ID, "request_key": "mcp-path", "entry_ref": entries[0].ID,
		"target_ref": sinks[0].ID, "basis": "hypothesis",
		"evidence": []map[string]any{{"kind": "source", "file": "main.go", "start_line": 1, "end_line": 2}},
	}
	readerCtx := path.WithProposalOrigin(withPrincipal(context.Background(), Principal{Name: "reader", Capabilities: CapRead}), origin)
	readerClient, err := env.rt.Supervisor.ProjectMCPClient(readerCtx, project.Project.ID, snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	defer readerClient.Close()
	readerArgs := map[string]any{}
	for key, value := range args {
		readerArgs[key] = value
	}
	readerArgs["request_key"] = "reader-mcp-path"
	readerProposal, err := readerClient.CallTool(readerCtx, &sdk.CallToolParams{Name: "propose_path", Arguments: readerArgs})
	if err != nil {
		t.Fatalf("reader MCP proposal protocol: %v", err)
	}
	if !readerProposal.IsError {
		t.Fatalf("reader MCP proposal was accepted: %+v", readerProposal)
	}
	first, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "propose_path", Arguments: args})
	if err != nil || first.IsError {
		t.Fatalf("MCP proposal: %v %+v", err, first)
	}
	second, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "propose_path", Arguments: args})
	if err != nil || second.IsError {
		t.Fatalf("MCP replay: %v %+v", err, second)
	}
	raw, _ := json.Marshal(second.StructuredContent)
	var envelope struct {
		Data struct {
			Created bool      `json:"created"`
			Path    path.Path `json:"path"`
		} `json:"data"`
	}
	if json.Unmarshal(raw, &envelope) != nil || envelope.Data.Path.ID == "" {
		t.Fatalf("MCP proposal envelope: %s", raw)
	}
	stored, err := env.rt.Store.GetPath(envelope.Data.Path.ID)
	if err != nil {
		rawFirst, _ := json.Marshal(first.StructuredContent)
		t.Fatalf("stored proposal absent: %v first=%s second=%s", err, rawFirst, raw)
	}
	if len(stored.Discoveries) != 1 || stored.Discoveries[0].Source != "supervisor" ||
		stored.Discoveries[0].SessionID != session.ID || stored.Discoveries[0].RunID != "srun-path-proposal" {
		t.Fatalf("MCP origin not preserved or replay duplicated it: %+v", stored.Discoveries)
	}
	cancelled := do(t, env.ts, http.MethodPost,
		"/api/v1/projects/"+project.Project.ID+"/agent-sessions/"+session.ID+"/runs/srun-path-proposal/cancel",
		map[string]any{"reason": "stop exploration"}, nil,
	)
	if cancelled.status != http.StatusOK {
		t.Fatalf("cancel: %d %s", cancelled.status, cancelled.body)
	}
	lateArgs := map[string]any{}
	for key, value := range args {
		lateArgs[key] = value
	}
	lateArgs["request_key"] = "late-proposal"
	late, err := client.CallTool(ctx, &sdk.CallToolParams{Name: "propose_path", Arguments: lateArgs})
	if err != nil {
		t.Fatalf("late call protocol: %v", err)
	}
	if !late.IsError {
		t.Fatalf("late proposal after cancellation was accepted: %+v", late)
	}
}
