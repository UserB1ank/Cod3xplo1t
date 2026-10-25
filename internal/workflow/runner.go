package workflow

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
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
	// Runtime is the task's runtime choice; empty means the deployment default.
	Runtime string
}
type RunEvent struct {
	Seq       int64  `json:"seq"`
	Type      string `json:"type"`
	NodeID    string `json:"node_id,omitempty"`
	Status    string `json:"status"`
	CreatedAt string `json:"created_at"`
}
type NodeRun struct {
	Knowledge      []KnowledgePin `json:"knowledge,omitempty"`
	AgentRunIDs    []string       `json:"agent_run_ids,omitempty"`
	Note           string         `json:"note,omitempty"`
	Attempt        int            `json:"attempt"`
	NextAttemptAt  string         `json:"next_attempt_at,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
	LeaseOwner     string         `json:"lease_owner,omitempty"`
	LeaseExpiresAt string         `json:"lease_expires_at,omitempty"`
	ID             string         `json:"node_run_id"`
	NodeID         string         `json:"node_id"`
	Kind           string         `json:"kind"`
	Status         string         `json:"status"`
	InvocationID   string         `json:"invocation_id,omitempty"`
	Inputs         []artifact.Ref `json:"inputs"`
	Outputs        []artifact.Ref `json:"outputs"`
	ErrorCode      string         `json:"error_code,omitempty"`
	StartedAt      string         `json:"started_at,omitempty"`
	FinishedAt     string         `json:"finished_at,omitempty"`
}

const RunnerVersion = "1.0.0"

type Run struct {
	RunnerVersion      string         `json:"runner_version"`
	MaxParallel        int            `json:"max_parallel"`
	MaxAttempts        int            `json:"max_attempts"`
	AnalyzeCandidates  bool           `json:"analyze_candidates"`
	RetryOf            string         `json:"retry_of,omitempty"`
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
	// ListRecoverableWorkflowRuns returns runs that are not terminal, so a new
	// host can resume them after a restart.
	ListRecoverableWorkflowRuns(context.Context) ([]Run, error)
}
type ModelPin struct {
	Runtime         string `json:"runtime"`
	RuntimeVersion  string `json:"runtime_version"`
	ConfigVersion   string `json:"config_version"`
	Model           string `json:"model,omitempty"`
	ProtocolVersion string `json:"protocol_version,omitempty"`
	WorkerVersion   string `json:"worker_version,omitempty"`
	PromptVersion   string `json:"prompt_version,omitempty"`
}

var (
	ErrRuntimeUnavailable = errors.New("workflow: candidate runtime is not configured")
	// ErrConfigVersionUnavailable blocks a recovery whose frozen settings version
	// no longer exists: re-binding with the current settings would run the old
	// plan under new credentials.
	ErrConfigVersionUnavailable = errors.New("workflow: the frozen model configuration version is unavailable")
)

type Effects interface {
	// Bind freezes the candidate runtime. prior is the run's existing pin on a
	// recovery, and the zero value at creation; it selects the runtime and blocks
	// a different settings version from being substituted.
	Bind(context.Context, bool, ModelPin) (Effects, ModelPin, error)
	Execute(context.Context, Run, Plan, NodeRun) (NodeResult, error)
}
type Runner struct {
	Effects    Effects
	Compiler   *Compiler
	Repository RunRepository
	Executor   NodeExecutor
	Artifacts  artifact.Store
	// Instance identifies this process in node leases, so a recovered run can
	// tell a stale worker's output from its own.
	InstanceID string
	// Backoff is the retry delay of one attempt; it is injectable for tests.
	Backoff      func(attempt int) time.Duration
	mu           sync.Mutex
	ctx          context.Context
	cancel       context.CancelFunc
	wg           sync.WaitGroup
	closed       bool
	recoveryOnce sync.Once
	executions   map[string]*execution
}

func NewRunner(compiler *Compiler, repo RunRepository, executor NodeExecutor, objects artifact.Store) *Runner {
	ctx, cancel := context.WithCancel(context.Background())
	return &Runner{Compiler: compiler, Repository: repo, Executor: executor, Artifacts: objects, InstanceID: "runner-" + rand.Text(), Backoff: defaultBackoff, ctx: ctx, cancel: cancel, executions: map[string]*execution{}}
}

func parallelFor(limits audit.Limits) int {
	limits = limits.Normalize()
	if limits.MaxActiveLeases < 1 {
		return 1
	}
	if limits.MaxActiveLeases > 16 {
		return 16
	}
	return limits.MaxActiveLeases
}

func attemptsFor(limits audit.Limits) int {
	limits = limits.Normalize()
	if limits.MaxAttempts < 1 {
		return 1
	}
	if limits.MaxAttempts > 10 {
		return 10
	}
	return limits.MaxAttempts
}

func defaultBackoff(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	delay := 100 * time.Millisecond
	for i := 1; i < attempt && delay < 3*time.Second; i++ {
		delay *= 2
	}
	if delay > 3*time.Second {
		delay = 3 * time.Second
	}
	return delay
}

// cloneRun deep-copies a run so the caller never shares the live slices the
// execution goroutine keeps updating.
func cloneRun(run Run) Run {
	raw, err := json.Marshal(run)
	if err != nil {
		return run
	}
	var clone Run
	if err := json.Unmarshal(raw, &clone); err != nil {
		return run
	}
	return clone
}

func RunTerminal(status string) bool {
	switch status {
	case "CREATED", "RUNNING", "PAUSING", "PAUSED", "CANCELLING":
		return false
	}
	return true
}
func runNow() string { return time.Now().UTC().Format(time.RFC3339Nano) }
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
		prior := ModelPin{Runtime: strings.TrimSpace(req.Runtime)}
		effects, model, err = effects.Bind(ctx, req.AnalyzeCandidates, prior)
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
	run.MaxParallel = parallelFor(req.Task.Limits)
	run.MaxAttempts = attemptsFor(req.Task.Limits)
	run.AnalyzeCandidates = req.AnalyzeCandidates
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Run{}, ErrInvalid
	}
	r.mu.Unlock()
	if err := r.Repository.CreateWorkflowRun(ctx, run, req.Task); err != nil {
		return Run{}, err
	}
	exec := &execution{run: &run, plan: plan, effects: effects, signal: make(chan struct{}, 1)}
	result := cloneRun(run)
	r.register(exec)
	r.startLoop(exec)
	return result, nil
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
func bindNode(plan Plan, run Run, node CompiledNode) ([]artifact.Ref, []string, error) {
	inputs := []artifact.Ref{}
	ports := []string{}
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
			if ref.Kind == binding.Kind && ref.SchemaID == binding.SchemaID && (binding.ProducerPlugin == "" || ref.Producer.PluginID == binding.ProducerPlugin) && (binding.OutputPort == "" || ref.Producer.OutputPort == binding.OutputPort) {
				matches = append(matches, ref)
			}
		}
		if len(matches) == 0 && binding.Optional {
			continue
		}
		if len(matches) != 1 && binding.Cardinality != "many" {
			return nil, nil, ErrInvalid
		}
		if len(matches) == 0 {
			return nil, nil, ErrInvalid
		}
		inputs = append(inputs, matches...)
		for range matches {
			ports = append(ports, binding.Port)
		}
	}
	return inputs, ports, nil
}

type nodeCompletion struct {
	index  int
	result NodeResult
	err    error
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
	ports := map[string]int{}
	limit := int64(64 << 20)
	if node.Operation != nil {
		limit = artifact.MaxBytes
	}
	var total int64
	for _, ref := range result.Outputs {
		if ref.Scope != plan.Scope || ref.Producer.PluginID != node.PluginID || ref.Producer.PluginVersion != node.PluginVersion || ref.Producer.InvocationID != id || ref.Producer.ConfigDigest != node.ConfigDigest {
			return false
		}
		allowed := false
		if node.Operation != nil {
			if ref.Producer.OperationID != node.OperationID || ref.Producer.PackageDigest != node.Plugin.PackageDigest {
				return false
			}
			for _, port := range node.Operation.Outputs {
				if ref.Producer.OutputPort == port.Name && ref.Kind == port.Kind && ref.SchemaID == port.SchemaID {
					allowed = true
					ports[port.Name]++
				}
			}
		}
		for _, kind := range node.Outputs {
			if ref.Kind == kind && node.Operation == nil {
				allowed = true
			}
		}
		if !allowed {
			return false
		}
		actual, err := r.Artifacts.Stat(ctx, plan.Scope, ref.ID, limit)
		if err != nil || actual != ref {
			return false
		}
		total += ref.Bytes
		if total > limit {
			return false
		}
		seen[ref.Kind] = true
	}
	if node.Operation != nil {
		for _, port := range node.Operation.Outputs {
			if (port.Required && ports[port.Name] == 0) || (port.Cardinality == "one" && ports[port.Name] > 1) {
				return false
			}
		}
		return true
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
