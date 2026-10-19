package api

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func TestPostgresPathHTTPRequiresOriginalLeaseEpoch(t *testing.T) {
	rt, err := app.Build(context.Background(), postgresConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rt, false)
	snap := createAuditedSnapshot(t, env.ts)
	audit := createAudit(t, env.ts, map[string]any{"snapshot_id": snap})
	claim := do(t, env.ts, "POST", "/api/audits/"+audit.Audit.ID+"/claim", map[string]any{"owner": "worker", "ttl_seconds": 60}, nil)
	if claim.status != 200 {
		t.Fatalf("claim: %d %s", claim.status, claim.body)
	}
	var p path.Path
	claim.decode(t, &p)
	for _, action := range []string{"heartbeat", "release"} {
		url := "/api/paths/" + p.ID + "/" + action
		missing := do(t, env.ts, "POST", url, map[string]any{"owner": "worker"}, nil)
		if missing.status != 400 {
			t.Fatalf("missing epoch %s: %d %s", action, missing.status, missing.body)
		}
		stale := do(t, env.ts, "POST", url, map[string]any{"owner": "worker", "lease_epoch": p.LeaseEpoch + 1}, nil)
		if stale.status != 409 {
			t.Fatalf("stale epoch %s: %d %s", action, stale.status, stale.body)
		}
		valid := do(t, env.ts, "POST", url, map[string]any{"owner": "worker", "lease_epoch": p.LeaseEpoch}, nil)
		if valid.status != 200 {
			t.Fatalf("valid epoch %s: %d %s", action, valid.status, valid.body)
		}
	}
}

func TestPostgresTaskOrganizationSurvivesRuntimeRebuild(t *testing.T) {
	cfg := postgresConfig(t)
	open := func() *testEnv {
		rt, err := app.Build(context.Background(), cfg)
		if err != nil {
			t.Fatal(err)
		}
		return serveTestEnv(t, rt, false)
	}
	env := open()
	project, snapshot := organizationFixture(t, env.ts)
	id := createOrganizedTask(t, env.ts, project, snapshot, "Persistent PostgreSQL task")
	read := do(t, env.ts, "GET", "/api/tasks/"+id, nil, nil)
	pinned := do(t, env.ts, "PATCH", "/api/projects/"+project+"/tasks/"+id, map[string]any{"pinned": true}, map[string]string{"If-Match": read.header.Get("ETag")})
	if pinned.status != 200 {
		t.Fatalf("pin: %d %s", pinned.status, pinned.body)
	}
	env.ts.Close()
	if err := env.rt.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt := open()
	after := do(t, rebuilt.ts, "GET", "/api/tasks/"+id, nil, nil)
	var task struct {
		Pinned   bool   `json:"pinned"`
		Snapshot string `json:"snapshot_id"`
	}
	after.decode(t, &task)
	if after.status != 200 || !task.Pinned || task.Snapshot != snapshot {
		t.Fatalf("task lost after rebuild: %d %s", after.status, after.body)
	}
}

func TestPostgresTwoRunnersKeepOneLiveNodeAndAcceptRemoteControls(t *testing.T) {
	cfg := postgresConfig(t)
	a, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envA := serveTestEnv(t, a, false)
	fixture := newWorkflowControlFixture(t, envA)
	blocked, release := make(chan string, 8), make(chan struct{}, 8)
	a.WorkflowRunner.Executor = controlExecutor{delegate: workflow.PluginExecutor{Host: a.Plugins, Catalog: a.PluginCatalog}, blocked: blocked, release: release}
	run := fixture.startTask(t)
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("first worker did not start")
	}
	b, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envB := serveTestEnv(t, b, false)
	remote := *fixture
	remote.env = envB
	if _, err := b.WorkflowRunner.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	read, err := b.WorkflowRunner.Get(context.Background(), fixture.projectID, run.ID)
	if err != nil || read.Status != "RUNNING" {
		t.Fatalf("second runner stole live work: %+v %v", read, err)
	}
	started := 0
	for _, event := range read.Events {
		if event.Type == "node_started" {
			started++
		}
	}
	if started != 1 {
		t.Fatalf("duplicate live node claims: %d", started)
	}
	if paused := remote.control(t, run.ID, "pause"); paused.Status != "PAUSING" {
		t.Fatalf("remote pause: %s", paused.Status)
	}
	release <- struct{}{}
	remote.wait(t, run.ID, "PAUSED")
	pausedTasks := do(t, envB.ts, "GET", "/api/projects/"+fixture.projectID+"/tasks?state=PAUSED", nil, nil)
	var listing struct {
		Tasks []struct {
			ID string `json:"audit_id"`
		} `json:"tasks"`
	}
	pausedTasks.decode(t, &listing)
	if pausedTasks.status != 200 || len(listing.Tasks) != 1 || listing.Tasks[0].ID != run.TaskID {
		t.Fatalf("paused workflow missing from task filter: %d %s", pausedTasks.status, pausedTasks.body)
	}
	remote.control(t, run.ID, "resume")
	complete := remote.wait(t, run.ID, "SUCCEEDED")
	for i, event := range complete.Events {
		if event.Seq != int64(i+1) {
			t.Fatalf("event gap: %+v", complete.Events)
		}
	}
	starts := map[string]int{}
	for _, event := range complete.Events {
		if event.Type == "node_started" {
			starts[event.NodeID]++
		}
	}
	if starts["parse"] != 1 {
		t.Fatalf("completed parse was executed again: %v", starts)
	}
}

func TestPostgresWorkflowResumesInterruptedNodeAndReusesCompletedParse(t *testing.T) {
	cfg := postgresConfig(t)
	a, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envA := serveTestEnv(t, a, false)
	spec := workflowSpecFixture()
	spec["nodes"] = append(spec["nodes"].([]any), map[string]any{"id": "semantic", "plugin_id": plugin.SemanticID, "plugin_version": "1.2.0", "needs": []string{"parse"}, "config": map[string]any{}, "timeout_seconds": 60})
	fixture := workflowControlFixtureWithSpec(t, envA, spec)
	blocked, release := make(chan string, 8), make(chan struct{}, 8)
	a.WorkflowRunner.Executor = controlExecutor{delegate: workflow.PluginExecutor{Host: a.Plugins, Catalog: a.PluginCatalog}, blocked: blocked, release: release}
	run := fixture.startTask(t)
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("parse did not start")
	}
	release <- struct{}{}
	select {
	case <-blocked:
	case <-time.After(10 * time.Second):
		t.Fatal("second node did not start")
	}
	before, err := a.WorkflowRunner.Get(context.Background(), fixture.projectID, run.ID)
	if err != nil {
		t.Fatal(err)
	}
	parseID := ""
	for _, node := range before.Nodes {
		if node.NodeID == "parse" && node.Status == "SUCCEEDED" {
			parseID = node.InvocationID
		}
	}
	if parseID == "" {
		t.Fatal("parse was not persisted before interruption")
	}
	envA.ts.Close()
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	b, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	envB := serveTestEnv(t, b, false)
	rebuilt := *fixture
	rebuilt.env = envB
	complete := rebuilt.wait(t, run.ID, "SUCCEEDED")
	for _, node := range complete.Nodes {
		if node.NodeID == "parse" && (node.InvocationID != parseID || node.Attempt != 1) {
			t.Fatalf("completed parse was recomputed: %+v", node)
		}
	}
	for i, event := range complete.Events {
		if event.Seq != int64(i+1) {
			t.Fatalf("recovery event gap: %+v", complete.Events)
		}
	}
}

// This barrier interrupts only the coordinator; the parse/publication and the
// recovered candidate runtime use the real services and persistent outputs.
type interruptedAnalysisEffects struct {
	delegate workflow.Effects
	blocked  chan struct{}
}

func (e interruptedAnalysisEffects) Bind(ctx context.Context, enabled bool) (workflow.Effects, workflow.ModelPin, error) {
	inner, pin, err := e.delegate.Bind(ctx, enabled)
	e.delegate = inner
	return e, pin, err
}
func (e interruptedAnalysisEffects) Execute(ctx context.Context, run workflow.Run, plan workflow.Plan, node workflow.NodeRun) (workflow.NodeResult, error) {
	if node.Kind == "candidate_analysis" {
		close(e.blocked)
		<-ctx.Done()
		return workflow.NodeResult{}, ctx.Err()
	}
	return e.delegate.Execute(ctx, run, plan, node)
}
func TestPostgresRecoveryAfterPublicationStillAnalyzesCandidates(t *testing.T) {
	cfg := postgresConfig(t)
	cfg.Agent = app.AgentConfig{Enabled: true, Runtime: app.AgentRuntimeScripted, ScriptedAnswerJSON: agentTestPlaceholderAnswer(t), MaxToolCalls: 30}
	cfg.Scheduler = app.SchedulerConfig{Enabled: true, Interval: time.Hour, MaxConcurrent: 1, LeaseTTL: time.Minute}
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	rt.Agent.Runtime = &echoRuntime{Answer: agentTestAnswer}
	env := serveTestEnv(t, rt, false)
	original := rt.WorkflowRunner
	blocked := make(chan struct{})
	original.Effects = interruptedAnalysisEffects{original.Effects, blocked}
	workflowPublishesAndAnalyzes(t, env, func(run workflow.Run) {
		select {
		case <-blocked:
		case <-time.After(10 * time.Second):
			t.Fatal("analysis stage not reached")
		}
		if err := original.Close(); err != nil {
			t.Fatal(err)
		}
		replacement := workflow.NewRunner(original.Compiler, original.Repository, original.Executor, original.Artifacts)
		replacement.Effects = original.Effects.(interruptedAnalysisEffects).delegate
		t.Cleanup(func() { replacement.Close() })
		rt.WorkflowRunner = replacement
		env.ts.Close()
		rebuilt := serveTestEnv(t, rt, false)
		env.ts = rebuilt.ts
		if _, err := replacement.Recover(context.Background()); err != nil {
			t.Fatal(err)
		}
	})
}

func TestPostgresExecutionUpgradeKeepsHistoricalPluginVersions(t *testing.T) {
	cfg := postgresConfig(t)
	rt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{plugin.SemanticID, "builtin.discovery-paths"} {
		current, err := rt.PluginCatalog.Get(context.Background(), id, "1.2.0")
		if err != nil {
			t.Fatal(err)
		}
		historical := current.Manifest
		historical.Version = "1.1.0"
		raw, err := json.Marshal(historical)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := rt.PluginCatalog.Register(context.Background(), raw, strings.Repeat("a", 64), "previous deployment fixture"); err != nil {
			t.Fatal(err)
		}
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt, err := app.Build(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, rebuilt, false)
	page := do(t, env.ts, "GET", "/api/v1/plugins", nil, nil)
	var result struct {
		Plugins []plugin.Record `json:"plugins"`
	}
	page.decode(t, &result)
	for _, id := range []string{plugin.SemanticID, "builtin.discovery-paths"} {
		oldReadable, currentExecutable := false, false
		for _, record := range result.Plugins {
			if record.Manifest.ID != id {
				continue
			}
			if record.Manifest.Version == "1.1.0" {
				oldReadable = !record.Executable && record.PackageDigest == strings.Repeat("a", 64)
			}
			if record.Manifest.Version == "1.2.0" {
				currentExecutable = record.Executable
			}
		}
		if !oldReadable || !currentExecutable {
			t.Fatalf("upgrade rewrote history or lost executor: %s", id)
		}
	}
}
