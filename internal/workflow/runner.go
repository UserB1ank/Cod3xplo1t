package workflow

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	audit "github.com/open-mcp-ai/Codexploit/internal/path"
)

type TaskDefinition struct {
	Name      string       `json:"name"`
	Objective string       `json:"objective"`
	Scope     []string     `json:"scope"`
	Budget    audit.Budget `json:"budget"`
	Limits    audit.Limits `json:"limits"`
}
type StartRequest struct {
	AcceptPartialNodes []string
	ProjectID          string
	SnapshotID         string
	PlanID             string
	Task               TaskDefinition
	AnalyzeCandidates  bool
}
type RunEvent struct {
	Seq       int64  `json:"seq"`
	Type      string `json:"type"`
	NodeID    string `json:"node_id,omitempty"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}
type NodeRun struct {
	Knowledge    []KnowledgePin `json:"knowledge,omitempty"`
	AgentRunIDs  []string       `json:"agent_run_ids,omitempty"`
	Note         string         `json:"note,omitempty"`
	ID           string         `json:"node_run_id"`
	NodeID       string         `json:"node_id"`
	Kind         string         `json:"kind"`
	Status       string         `json:"status"`
	InvocationID string         `json:"invocation_id,omitempty"`
	Inputs       []artifact.Ref `json:"inputs"`
	Outputs      []artifact.Ref `json:"outputs"`
	ErrorCode    string         `json:"error_code,omitempty"`
	StartedAt    string         `json:"started_at,omitempty"`
	FinishedAt   string         `json:"finished_at,omitempty"`
}

const RunnerVersion = "1.0.0"

type Run struct {
	RunnerVersion      string         `json:"runner_version"`
	Task               TaskDefinition `json:"task"`
	Model              ModelPin       `json:"model"`
	AcceptPartialNodes []string       `json:"accept_partial_nodes"`
	ID                 string         `json:"workflow_run_id"`
	TaskID             string         `json:"task_id"`
	Scope              artifact.Scope `json:"scope"`
	PlanID             string         `json:"plan_id"`
	PlanDigest         string         `json:"plan_digest"`
	Status             string         `json:"status"`
	Version            int64          `json:"version"`
	Nodes              []NodeRun      `json:"nodes"`
	Events             []RunEvent     `json:"events"`
	CreatedAt          string         `json:"created_at"`
	UpdatedAt          string         `json:"updated_at"`
}
type NodeResult struct {
	Knowledge    []KnowledgePin
	AgentRunIDs  []string
	Note         string
	Status       string
	InvocationID string
	Outputs      []artifact.Ref
	ErrorCode    string
}
type NodeExecutor interface {
	Execute(context.Context, CompiledNode, artifact.Scope, []artifact.Ref, string) (NodeResult, error)
}
type RunRepository interface {
	CreateWorkflowRun(context.Context, Run, TaskDefinition) error
	SaveWorkflowRun(context.Context, Run, int64) error
	GetWorkflowRun(context.Context, string, string) (Run, error)
}
type ModelPin struct {
	Runtime        string `json:"runtime"`
	RuntimeVersion string `json:"runtime_version"`
	ConfigVersion  string `json:"config_version"`
	Model          string `json:"model,omitempty"`
}

var ErrRuntimeUnavailable = errors.New("workflow: candidate runtime is not configured")

type Effects interface {
	Bind(context.Context, bool) (Effects, ModelPin, error)
	Execute(context.Context, Run, Plan, NodeRun) (NodeResult, error)
}
type Runner struct {
	Effects    Effects
	Compiler   *Compiler
	Repository RunRepository
	Executor   NodeExecutor
	Artifacts  artifact.Store
	mu         sync.Mutex
	ctx        context.Context
	cancel     context.CancelFunc
	wg         sync.WaitGroup
	closed     bool
}

func NewRunner(compiler *Compiler, repo RunRepository, executor NodeExecutor, objects artifact.Store) *Runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{Compiler: compiler, Repository: repo, Executor: executor, Artifacts: objects, ctx: ctx, cancel: cancel}
}
func RunTerminal(status string) bool { return status != "CREATED" && status != "RUNNING" }
func runNow() string                 { return time.Now().UTC().Format(time.RFC3339Nano) }
func (r *Runner) Start(ctx context.Context, req StartRequest) (Run, error) {
	plan, err := r.Compiler.Get(ctx, req.ProjectID, req.PlanID)
	if err != nil {
		return Run{}, err
	}
	if plan.Scope.SnapshotID != req.SnapshotID {
		return Run{}, ErrNotFound
	}
	for _, ref := range plan.Inputs {
		actual, err := r.Artifacts.Stat(ctx, plan.Scope, ref.ID, plan.MaxInputBytes)
		if err != nil || actual != ref {
			return Run{}, ErrInvalid
		}
	}
	if len(req.AcceptPartialNodes) > len(plan.Nodes)+2 {
		return Run{}, ErrInvalid
	}
	accepted := map[string]bool{}
	for _, id := range req.AcceptPartialNodes {
		found := (id == "$publish" || id == "$analyze") && r.Effects != nil
		for _, node := range plan.Nodes {
			if node.ID == id {
				found = true
			}
		}
		if !found || accepted[id] {
			return Run{}, ErrInvalid
		}
		accepted[id] = true
	}
	effects := r.Effects
	model := ModelPin{Runtime: "disabled", RuntimeVersion: "1", ConfigVersion: "not_applicable"}
	if effects != nil {
		effects, model, err = effects.Bind(ctx, req.AnalyzeCandidates)
		if err != nil {
			return Run{}, err
		}
	}
	now := runNow()
	req.Task.Budget = req.Task.Budget.Normalize()
	req.Task.Limits = req.Task.Limits.Normalize()
	run := Run{RunnerVersion: RunnerVersion, Task: req.Task, Model: model, AcceptPartialNodes: append([]string{}, req.AcceptPartialNodes...), ID: "wrun-" + rand.Text(), TaskID: "task-" + rand.Text(), Scope: plan.Scope, PlanID: plan.ID, PlanDigest: plan.Digest, Status: "CREATED", Version: 1, Nodes: []NodeRun{}, Events: []RunEvent{{Seq: 1, Type: "run_created", Status: "CREATED", CreatedAt: now}}, CreatedAt: now, UpdatedAt: now}
	for i, node := range plan.Nodes {
		run.Nodes = append(run.Nodes, NodeRun{ID: fmt.Sprintf("%s-n%d", run.ID, i+1), NodeID: node.ID, Kind: "plugin", Status: "PENDING", Inputs: []artifact.Ref{}, Outputs: []artifact.Ref{}})
	}
	if effects != nil {
		run.Nodes = append(run.Nodes, NodeRun{ID: run.ID + "-publish", NodeID: "$publish", Kind: "knowledge_publish", Status: "PENDING", Inputs: []artifact.Ref{}, Outputs: []artifact.Ref{}}, NodeRun{ID: run.ID + "-analyze", NodeID: "$analyze", Kind: "candidate_analysis", Status: "PENDING", Inputs: []artifact.Ref{}, Outputs: []artifact.Ref{}})
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return Run{}, ErrInvalid
	}
	if err := r.Repository.CreateWorkflowRun(ctx, run, req.Task); err != nil {
		return Run{}, err
	}
	raw, _ := json.Marshal(run)
	var detached Run
	_ = json.Unmarshal(raw, &detached)
	r.wg.Add(1)
	go func() { defer r.wg.Done(); r.execute(detached, plan, effects) }()
	return run, nil
}
func (r *Runner) Get(ctx context.Context, project, id string) (Run, error) {
	return r.Repository.GetWorkflowRun(ctx, project, id)
}
func (r *Runner) Events(ctx context.Context, project, id string, after int64, limit int) ([]RunEvent, error) {
	if after < 0 || limit < 1 || limit > 200 {
		return nil, ErrInvalid
	}
	run, err := r.Get(ctx, project, id)
	if err != nil {
		return nil, err
	}
	events := []RunEvent{}
	for _, event := range run.Events {
		if event.Seq > after && len(events) < limit {
			events = append(events, event)
		}
	}
	return events, nil
}
func (r *Runner) save(run *Run, kind, node, status string) error {
	prior := run.Version
	run.Version++
	run.UpdatedAt = runNow()
	run.Events = append(run.Events, RunEvent{Seq: int64(len(run.Events) + 1), Type: kind, NodeID: node, Status: status, CreatedAt: run.UpdatedAt})
	return r.Repository.SaveWorkflowRun(context.Background(), *run, prior)
}
func bindNode(plan Plan, run Run, node CompiledNode) ([]artifact.Ref, error) {
	inputs := []artifact.Ref{}
	for _, binding := range node.Inputs {
		candidates := []artifact.Ref{}
		if binding.Source == "root" {
			candidates = plan.Inputs
		} else {
			for _, upstream := range run.Nodes {
				if upstream.NodeID == binding.From && (upstream.Status == "SUCCEEDED" || (upstream.Status == "PARTIAL" && acceptsPartial(run, upstream.NodeID))) {
					candidates = upstream.Outputs
				}
			}
		}
		matches := []artifact.Ref{}
		for _, ref := range candidates {
			if ref.Kind == binding.Kind && ref.SchemaID == binding.SchemaID && (binding.ProducerPlugin == "" || ref.Producer.PluginID == binding.ProducerPlugin) {
				matches = append(matches, ref)
			}
		}
		if len(matches) != 1 {
			return nil, ErrInvalid
		}
		inputs = append(inputs, matches[0])
	}
	return inputs, nil
}

type nodeCompletion struct {
	index  int
	result NodeResult
	err    error
}

func (r *Runner) execute(run Run, plan Plan, effects Effects) {
	ctx, cancel := context.WithCancel(r.ctx)
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	run.Status = "RUNNING"
	if r.save(&run, "run_started", "", run.Status) != nil {
		return
	}
	completed := make(chan nodeCompletion, len(plan.Nodes))
	active, finished := 0, 0
	failed := false
	for finished < len(plan.Nodes) {
		if !failed {
			for i, node := range plan.Nodes {
				if active >= 2 {
					break
				}
				if run.Nodes[i].Status != "PENDING" {
					continue
				}
				ready := true
				for _, need := range node.Needs {
					found := false
					for _, prior := range run.Nodes {
						if prior.NodeID == need && (prior.Status == "SUCCEEDED" || (prior.Status == "PARTIAL" && acceptsPartial(run, prior.NodeID))) {
							found = true
						}
					}
					if !found {
						ready = false
					}
				}
				if !ready {
					continue
				}
				inputs, err := bindNode(plan, run, node)
				if err != nil {
					run.Nodes[i].Status = "FAILED"
					run.Nodes[i].ErrorCode = "input_binding"
					run.Nodes[i].FinishedAt = runNow()
					finished++
					failed = true
					cancel()
					if r.save(&run, "node_finished", node.ID, "FAILED") != nil {
						return
					}
					break
				}
				run.Nodes[i].Inputs = inputs
				run.Nodes[i].InvocationID = "winv-" + rand.Text()
				run.Nodes[i].Status = "RUNNING"
				run.Nodes[i].StartedAt = runNow()
				if r.save(&run, "node_started", node.ID, "RUNNING") != nil {
					return
				}
				active++
				workers.Add(1)
				go func(index int, node CompiledNode, inputs []artifact.Ref, id string) {
					defer workers.Done()
					nodeCtx, done := context.WithTimeout(ctx, time.Duration(node.TimeoutSeconds)*time.Second)
					defer done()
					result, err := r.Executor.Execute(nodeCtx, node, plan.Scope, inputs, id)
					completed <- nodeCompletion{index, result, err}
				}(i, node, inputs, run.Nodes[i].InvocationID)
			}
		}
		if active == 0 {
			break
		}
		completion := <-completed
		active--
		finished++
		nr := &run.Nodes[completion.index]
		result, err := completion.result, completion.err
		if (result.Status == "SUCCEEDED" || result.Status == "PARTIAL") && !r.validOutputs(ctx, plan, plan.Nodes[completion.index], nr.InvocationID, result) {
			result.Status = "FAILED"
			result.ErrorCode = "output_integrity"
			result.Outputs = []artifact.Ref{}
		}
		nr.InvocationID = result.InvocationID
		nr.Outputs = result.Outputs
		if nr.Outputs == nil {
			nr.Outputs = []artifact.Ref{}
		}
		nr.Status = result.Status
		nr.ErrorCode = result.ErrorCode
		nr.FinishedAt = runNow()
		if err != nil || (nr.Status != "SUCCEEDED" && !(nr.Status == "PARTIAL" && acceptsPartial(run, nr.NodeID))) {
			if nr.Status != "PARTIAL" {
				nr.Status = "FAILED"
			} else {
				nr.ErrorCode = "partial_not_accepted"
			}
			if errors.Is(err, context.Canceled) {
				nr.Status = "CANCELLED"
			}
			if errors.Is(err, context.DeadlineExceeded) {
				nr.Status = "TIMED_OUT"
			}
			if nr.ErrorCode == "" {
				nr.ErrorCode = "node_failed"
			}
			failed = true
			cancel()
		}
		if r.save(&run, "node_finished", nr.NodeID, nr.Status) != nil {
			return
		}
	}
	if !failed && effects != nil {
		for i := len(plan.Nodes); i < len(run.Nodes); i++ {
			nr := &run.Nodes[i]
			for j := 0; j < i; j++ {
				nr.Inputs = append(nr.Inputs, run.Nodes[j].Outputs...)
			}
			nr.Status = "RUNNING"
			nr.StartedAt = runNow()
			if r.save(&run, "node_started", nr.NodeID, nr.Status) != nil {
				return
			}
			result, err := effects.Execute(ctx, run, plan, *nr)
			nr.Status = result.Status
			nr.Outputs = result.Outputs
			if nr.Outputs == nil {
				nr.Outputs = []artifact.Ref{}
			}
			nr.Knowledge = result.Knowledge
			nr.AgentRunIDs = result.AgentRunIDs
			nr.Note = result.Note
			nr.ErrorCode = result.ErrorCode
			nr.FinishedAt = runNow()
			if err != nil || (nr.Status != "SUCCEEDED" && nr.Status != "SKIPPED" && !(nr.Status == "PARTIAL" && acceptsPartial(run, nr.NodeID))) {
				if nr.Status != "PARTIAL" {
					nr.Status = "FAILED"
				}
				if nr.Status == "PARTIAL" && nr.ErrorCode == "" {
					nr.ErrorCode = "partial_not_accepted"
				}
				if nr.ErrorCode == "" {
					nr.ErrorCode = "effect_failed"
				}
				failed = true
			}
			if r.save(&run, "node_finished", nr.NodeID, nr.Status) != nil {
				return
			}
			if failed {
				break
			}
		}
	}
	for i := range run.Nodes {
		if run.Nodes[i].Status == "PENDING" {
			run.Nodes[i].Status = "SKIPPED"
			run.Nodes[i].ErrorCode = "upstream_failed"
			if r.save(&run, "node_skipped", run.Nodes[i].NodeID, "SKIPPED") != nil {
				return
			}
			failed = true
		}
	}
	run.Status = "SUCCEEDED"
	for _, node := range run.Nodes {
		if node.Status == "PARTIAL" {
			run.Status = "PARTIAL"
		}
	}
	if failed {
		run.Status = "FAILED"
	}
	_ = r.save(&run, "run_finished", "", run.Status)
}
func (r *Runner) Close() error {
	r.mu.Lock()
	r.closed = true
	r.cancel()
	r.mu.Unlock()
	r.wg.Wait()
	return nil
}

func (r *Runner) validOutputs(ctx context.Context, plan Plan, node CompiledNode, id string, result NodeResult) bool {
	if result.InvocationID != id || len(result.Outputs) > 100 {
		return false
	}
	seen := map[string]bool{}
	var total int64
	for _, ref := range result.Outputs {
		if ref.Scope != plan.Scope || ref.Producer.PluginID != node.PluginID || ref.Producer.PluginVersion != node.PluginVersion || ref.Producer.InvocationID != id || ref.Producer.ConfigDigest != node.ConfigDigest {
			return false
		}
		allowed := false
		for _, kind := range node.Outputs {
			if ref.Kind == kind {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
		actual, err := r.Artifacts.Stat(ctx, plan.Scope, ref.ID, 64<<20)
		if err != nil || actual != ref {
			return false
		}
		total += ref.Bytes
		if total > 64<<20 {
			return false
		}
		seen[ref.Kind] = true
	}
	for _, kind := range node.Outputs {
		if !seen[kind] {
			return false
		}
	}
	return true
}

func acceptsPartial(run Run, node string) bool {
	for _, id := range run.AcceptPartialNodes {
		if id == node {
			return true
		}
	}
	return false
}
