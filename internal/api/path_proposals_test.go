package api

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/knowledge"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestAgentPathProposalIsPinnedIdempotentAndHumanSelectable(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, pathProposalCallSource(t))
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
	assertInferredProposalRefs(t, supportedResult.Path)
	directory := do(t, env.ts, http.MethodGet, viewPath+"/"+view.View.ID+"/paths?limit=50", nil, nil)
	if directory.status != http.StatusOK {
		t.Fatalf("path directory: %d %s", directory.status, directory.body)
	}
	var page struct {
		Paths []path.Path `json:"paths"`
	}
	directory.decode(t, &page)
	var listedProposal *path.Path
	for i := range page.Paths {
		if page.Paths[i].Signature == supportedResult.Path.Signature {
			listedProposal = &page.Paths[i]
			break
		}
	}
	if listedProposal == nil || !sameStrings(listedProposal.SCGRefs, supportedResult.Path.SCGRefs) ||
		!sameStrings(listedProposal.ASGRefs, supportedResult.Path.ASGRefs) {
		t.Fatalf("path directory changed proposal source layers: %+v", listedProposal)
	}
	filteredDirectory := do(t, env.ts, http.MethodGet,
		viewPath+"/"+view.View.ID+"/paths?audit_id="+supportedResult.Path.AuditID+"&limit=50", nil, nil)
	if filteredDirectory.status != http.StatusOK {
		t.Fatalf("filtered path directory: %d %s", filteredDirectory.status, filteredDirectory.body)
	}
	var filteredPage struct {
		Paths []path.Path `json:"paths"`
	}
	filteredDirectory.decode(t, &filteredPage)
	foundFiltered := false
	for _, item := range filteredPage.Paths {
		if item.Signature == supportedResult.Path.Signature && sameStrings(item.SCGRefs, supportedResult.Path.SCGRefs) {
			foundFiltered = true
			break
		}
	}
	if !foundFiltered {
		t.Fatalf("audit source filter lost inferred SCG refs: %s", filteredDirectory.body)
	}
	var symbolRef string
	for _, ref := range supportedResult.Path.SCGRefs {
		if strings.HasPrefix(ref, "sym-") {
			symbolRef = ref
			break
		}
	}
	if symbolRef == "" {
		t.Fatalf("inferred path has no SCG symbol ref: %v", supportedResult.Path.SCGRefs)
	}
	provenance := do(t, env.ts, http.MethodGet,
		viewPath+"/"+view.View.ID+"/provenance?fact_id="+symbolRef, nil, nil)
	var source struct {
		Provenance knowledge.Provenance `json:"provenance"`
	}
	provenance.decode(t, &source)
	if provenance.status != http.StatusOK || source.Provenance.Kind != "symbol" {
		t.Fatalf("SCG path source cannot be opened as a symbol: %d %s", provenance.status, provenance.body)
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

func TestAgentPathProposalKeepsExplicitASGChainOutOfSCGRefs(t *testing.T) {
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
	entries, _, err := env.rt.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeEntryPoint}, Limit: 1,
	})
	sinks, _, err2 := env.rt.Store.ListASGNodes(ctx, storage.ASGNodeQuery{
		SnapshotID: snapshotID, Kinds: []asg.NodeKind{asg.NodeSensitiveOperation}, Limit: 1,
	})
	if err != nil || err2 != nil || len(entries) == 0 || len(sinks) == 0 {
		t.Fatalf("fixture lacks proposal endpoints: %v %v", err, err2)
	}
	edge := installObservedReachability(t, env, snapshotID, entries[0], sinks[0])
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
	body := map[string]any{
		"request_key": "explicit-asg-proposal", "entry_ref": entries[0].ID,
		"target_ref": sinks[0].ID, "basis": "call_reachability",
		"steps": []map[string]any{{
			"layer": "asg", "from_ref": entries[0].ID, "to_ref": sinks[0].ID, "relation_ref": edge.ID,
		}},
		"evidence": []map[string]any{{"kind": "source", "file": "main.go", "start_line": 1, "end_line": 2}},
	}
	created := do(t, env.ts, http.MethodPost, viewPath+"/"+view.View.ID+"/path-proposals", body, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("explicit ASG proposal: %d %s", created.status, created.body)
	}
	var result struct {
		Path path.Path `json:"path"`
	}
	created.decode(t, &result)
	if len(result.Path.SCGRefs) != 0 {
		t.Fatalf("explicit ASG chain leaked into SCG refs: %v", result.Path.SCGRefs)
	}
	for _, want := range []string{entries[0].ID, sinks[0].ID, edge.ID} {
		if !containsProposalRef(result.Path.ASGRefs, want) {
			t.Fatalf("ASG refs %v missing %s", result.Path.ASGRefs, want)
		}
	}
	if len(result.Path.Steps) != 1 || result.Path.Steps[0].Evidence != edge.ID ||
		result.Path.Steps[0].Resolution != string(edge.Evidence) {
		t.Fatalf("ASG step lost its relation identity: %+v", result.Path.Steps)
	}
}

func TestProposalReferencesRespectTheDeclaredLayer(t *testing.T) {
	scgRefs, asgRefs := proposalReferences(
		"asgn-entry", "asgn-sink",
		[]path.Step{{Layer: "scg", From: "sym-handler", To: "sym-run", Evidence: "cs-call"}},
		[]string{"sym-handler", "sym-run", "cs-call"},
	)
	if !sameStrings(scgRefs, []string{"sym-handler", "sym-run", "cs-call"}) ||
		!sameStrings(asgRefs, []string{"asgn-entry", "asgn-sink"}) {
		t.Fatalf("inferred refs: SCG=%v ASG=%v", scgRefs, asgRefs)
	}
	scgRefs, asgRefs = proposalReferences(
		"asgn-entry", "asgn-sink",
		[]path.Step{{Layer: "asg", From: "asgn-entry", To: "asgn-sink", Evidence: "asge-observed"}},
		nil,
	)
	if len(scgRefs) != 0 ||
		!sameStrings(asgRefs, []string{"asgn-entry", "asgn-sink", "asge-observed"}) {
		t.Fatalf("explicit ASG refs: SCG=%v ASG=%v", scgRefs, asgRefs)
	}
	scgRefs, asgRefs = proposalReferences("asgn-entry", "asgn-sink", nil, []string{"sym-handler"})
	if !sameStrings(scgRefs, []string{"sym-handler"}) ||
		!sameStrings(asgRefs, []string{"asgn-entry", "asgn-sink"}) {
		t.Fatalf("same-symbol refs: SCG=%v ASG=%v", scgRefs, asgRefs)
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

func assertInferredProposalRefs(t *testing.T, proposal path.Path) {
	t.Helper()
	if len(proposal.SCGRefs) == 0 {
		t.Fatalf("inferred call path has no SCG refs: %+v", proposal)
	}
	scgRefs := make(map[string]bool, len(proposal.SCGRefs))
	for _, ref := range proposal.SCGRefs {
		scgRefs[ref] = true
	}
	asgRefs := make(map[string]bool, len(proposal.ASGRefs))
	for _, ref := range proposal.ASGRefs {
		asgRefs[ref] = true
	}
	if len(proposal.Steps) == 0 {
		t.Fatal("inferred call path has no recorded steps")
	}
	for _, step := range proposal.Steps {
		if step.Layer != "scg" {
			t.Fatalf("inferred call step has layer %q", step.Layer)
		}
		for _, ref := range []string{step.From, step.To, step.Evidence} {
			if ref != "" && !scgRefs[ref] {
				t.Fatalf("SCG refs %v missing step ref %s", proposal.SCGRefs, ref)
			}
		}
		if step.Evidence != "" && asgRefs[step.Evidence] {
			t.Fatalf("SCG edge %s was recorded as an ASG ref: %v", step.Evidence, proposal.ASGRefs)
		}
	}
}

func installObservedReachability(t *testing.T, env *testEnv, snapshotID string, entry, sink asg.Node) asg.Edge {
	t.Helper()
	summary, err := env.rt.Store.ASGSummary(context.Background(), snapshotID)
	if err != nil {
		t.Fatal(err)
	}
	edge := asg.Edge{
		ID:         asg.EdgeID(snapshotID, asg.EdgeReaches, entry.ID, sink.ID, "path-proposal-test"),
		SnapshotID: snapshotID, From: entry.ID, To: sink.ID, Kind: asg.EdgeReaches,
		Evidence: asg.StatusObserved, Confidence: scg.Observed,
		Generator: "fixture/observed", SCGRefs: append(append([]string(nil), entry.SCGRefs...), sink.SCGRefs...),
		Detail: map[string]string{"reason": "deterministic proposal test"},
	}
	document := &asg.Document{
		SchemaVersion: asg.SchemaVersion, SnapshotID: snapshotID,
		ASGVersion: summary.ASGVersion, SCGVersion: summary.SCGVersion,
		Engine: summary.Engine, RulesetHash: summary.RulesetHash,
		Nodes: []asg.Node{entry, sink}, Edges: []asg.Edge{edge},
		Coverage: summary.Coverage, Limitations: summary.Limitations,
		BuiltAt: summary.BuiltAt, BuildDurationMS: summary.BuildDurationMS,
	}
	if err := env.rt.Store.ReplaceASG(context.Background(), snapshotID, document); err != nil {
		t.Fatal(err)
	}
	return edge
}

func sameStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for i := range left {
		if left[i] != right[i] {
			return false
		}
	}
	return true
}

func containsProposalRef(refs []string, want string) bool {
	for _, ref := range refs {
		if ref == want {
			return true
		}
	}
	return false
}

func pathProposalCallSource(t *testing.T) string {
	t.Helper()
	source := t.TempDir()
	writeFile(t, source, "go.mod", "module example.invalid/pathproposal\n\ngo 1.24\n")
	writeFile(t, source, "main.go", `package main

import (
	"net/http"
	"os/exec"
)

func run(cmd string) {
	exec.Command("sh", "-c", cmd).Run()
}

func Handler(w http.ResponseWriter, r *http.Request) {
	run(r.URL.Query().Get("cmd"))
}

func main() {
	http.HandleFunc("/run", Handler)
	http.ListenAndServe(":8080", nil)
}
`)
	return source
}
