package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
)

// RuntimeCapabilities describes what an adapter can do, so the orchestrator can
// refuse a task the adapter cannot honour instead of discovering it halfway.
type RuntimeCapabilities struct {
	// Name and Version identify the adapter in the run record.
	Name    string `json:"name"`
	Version string `json:"version"`
	// ToolCalls reports whether the adapter can ask for whitelisted tool calls. An
	// adapter that cannot gets a task without a tool budget.
	ToolCalls bool `json:"tool_calls"`
	// Expansions reports whether the adapter can request more room.
	Expansions bool `json:"expansions"`
	// Resume reports whether a run can continue after a pause. Most CLI adapters
	// cannot, which is why the orchestrator checkpoints instead of trusting a
	// session.
	Resume bool `json:"resume"`
	// Streaming reports whether events arrive while the run is in progress.
	Streaming bool `json:"streaming"`
	// TokenUsage reports whether the adapter reports token counts. Without them the
	// token budget cannot be enforced, and the run says so.
	TokenUsage bool `json:"token_usage"`
	// TurnControl reports whether the adapter asks for permission before each
	// provider request and submits proposed answers for validation. Without it the
	// adapter is still bounded by the tool gate, but its provider requests and
	// repairs are only a legacy estimate.
	TurnControl bool     `json:"turn_control"`
	Notes       []string `json:"notes,omitempty"`
}

// runGenerationKey carries the run's fencing generation to the adapter. The
// orchestrator assigns it; an adapter echoes it in every control frame so a
// decision made for one attempt cannot be replayed by another.
type runGenerationKey struct{}

// WithRunGeneration binds a generation to the adapter context.
func WithRunGeneration(ctx context.Context, generation int64) context.Context {
	if generation <= 0 {
		generation = 1
	}
	return context.WithValue(ctx, runGenerationKey{}, generation)
}

// RunGeneration returns the bound generation, or 1 when an adapter is started
// outside the orchestrator (tests and direct use).
func RunGeneration(ctx context.Context) int64 {
	if value, ok := ctx.Value(runGenerationKey{}).(int64); ok && value > 0 {
		return value
	}
	return 1
}

// Runtime is one agent adapter (implementation guide §9.1).
//
// The interface is intentionally small and push-based: the orchestrator starts a
// run and consumes events until the stream closes. An adapter never receives the
// lease, the budget controller or the tool registry — it receives a task and
// returns events — which is what keeps an agent from widening its own limits.
type Runtime interface {
	// Capabilities is static and safe to call at any time.
	Capabilities() RuntimeCapabilities
	// Start begins a run. It must return promptly; the work continues on the
	// returned channel, which is closed when the run ends.
	Start(ctx context.Context, task Task) (*Handle, error)
}

// Handle is one running agent.
type Handle struct {
	// Events is closed by the adapter when the run is over.
	Events <-chan RuntimeEvent
	// Done carries the terminal result. It is closed or written exactly once.
	Done <-chan RuntimeResult
	// Cancel asks the adapter to stop. It must be safe to call more than once and
	// after the run finished.
	Cancel func()
}

// RuntimeEvent is one thing that happened inside a run. Tool calls and expansion
// requests are requests: the orchestrator decides and answers them.
type RuntimeEvent struct {
	Type string
	// Summary is a short, explicit statement for the event log. It is never a
	// reasoning transcript.
	Summary string
	// Detail carries small structured extras (counts, ids, reasons).
	Detail map[string]string
	// Tool, when set, is a request for a whitelisted tool call.
	Tool *ToolRequest
	// ToolReply is an optional per-request feedback channel. Interactive adapters
	// wait for the orchestrator's bounded result, including explicit denials.
	ToolReply chan<- ToolResult
	// Expansion, when set, is a request for more room.
	Expansion *ExpansionAsk
	// Answer, when set, is the structured final output of an adapter that does not
	// use turn control.
	Answer *Answer
	// Permit, when set, asks for permission to start one provider request. The
	// adapter must not call the provider until the reply says continue.
	Permit      *PermitRequest
	PermitReply chan<- PermitDecision
	// Proposal, when set, offers a structured answer for validation. The
	// orchestrator accepts it, asks for one bounded correction, or rejects it.
	Proposal      *AnswerProposal
	ProposalReply chan<- AnswerDecision
	// Repair, when set, asks whether one protocol correction may be attempted.
	Repair      *RepairRequest
	RepairReply chan<- RepairDecision
	// RequestID ties usage and decisions to the provider request they belong to.
	RequestID string
	// InputTokens and OutputTokens are reported usage, when the adapter knows it.
	InputTokens  int
	OutputTokens int
}

// RuntimeResult is the terminal state of a run as the adapter saw it.
type RuntimeResult struct {
	ExitCode int
	Err      error
	// Answer is the final structured output when the adapter produced one; the
	// orchestrator validates it again and never trusts the adapter's word.
	Answer *Answer
}

// Registry maps tool names to executors. The orchestrator only executes what is
// registered here *and* allowed by the run's policy.
type Registry struct {
	mu      sync.RWMutex
	entries map[string]ToolExecutor
}

// ToolExecutor answers one whitelisted read-only tool call.
type ToolExecutor interface {
	// Name is the tool name the agent asks for.
	Name() string
	// Describe returns a one-line description, which is what a task advertises.
	Describe() string
	// Descriptor is the native tool contract: name, description, JSON Schema and
	// version. The registry validates it at registration time.
	Descriptor() ToolDescriptor
	// Call runs the tool with native JSON arguments. It must be read-only and it
	// must respect the context.
	Call(ctx context.Context, args json.RawMessage) (ToolResult, error)
}

// NewRegistry builds an empty tool registry.
func NewRegistry() *Registry {
	return &Registry{entries: map[string]ToolExecutor{}}
}

// Register adds a tool. A duplicate name is a programming error, so it panics
// rather than silently replacing a read-only tool with another one.
func (r *Registry) Register(executor ToolExecutor) {
	r.mu.Lock()
	defer r.mu.Unlock()
	name := executor.Name()
	if _, exists := r.entries[name]; exists {
		panic("agent: duplicate tool " + name)
	}
	descriptor := executor.Descriptor()
	if descriptor.Name != name || name == "" {
		panic(fmt.Sprintf("agent: tool %q has descriptor name %q", name, descriptor.Name))
	}
	if descriptor.Version == "" {
		panic("agent: tool " + name + " has no descriptor version")
	}
	if _, err := ParseToolSchema(descriptor.InputSchema); err != nil {
		panic(fmt.Sprintf("agent: tool %q has an invalid input schema: %v", name, err))
	}
	r.entries[name] = executor
}

// Descriptor returns one tool's native contract.
func (r *Registry) Descriptor(name string) (ToolDescriptor, bool) {
	executor, ok := r.Lookup(name)
	if !ok {
		return ToolDescriptor{}, false
	}
	return executor.Descriptor(), true
}

// Descriptors returns the contracts of the named tools in the given order, so a
// whitelist and the model's tool list cannot drift apart.
func (r *Registry) Descriptors(names []string) []ToolDescriptor {
	out := make([]ToolDescriptor, 0, len(names))
	for _, name := range names {
		if descriptor, ok := r.Descriptor(name); ok {
			out = append(out, descriptor)
		}
	}
	return out
}

// Lookup finds a tool.
func (r *Registry) Lookup(name string) (ToolExecutor, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	executor, ok := r.entries[name]
	return executor, ok
}

// Names returns the registered tool names, sorted.
func (r *Registry) Names() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for name := range r.entries {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Descriptions returns "name: description" lines, sorted, for task advertising.
func (r *Registry) Descriptions() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]string, 0, len(r.entries))
	for _, executor := range r.entries {
		out = append(out, executor.Name()+": "+executor.Describe())
	}
	sort.Strings(out)
	return out
}

// AliasTable and the rendered task travel with the adapter context: the host
// builds both once per run, persists the table, and hands the projection to the
// adapter. An adapter never allocates aliases and never sees the canonical ids
// behind them except through resolve requests.
type aliasTableKey struct{}

type renderedTaskKey struct{}

// WithAliasTable binds one run's alias table to the adapter context.
func WithAliasTable(ctx context.Context, table *AliasTable) context.Context {
	return context.WithValue(ctx, aliasTableKey{}, table)
}

// AliasTableFrom returns the bound table, or nil for an adapter started outside
// the orchestrator.
func AliasTableFrom(ctx context.Context) *AliasTable {
	table, _ := ctx.Value(aliasTableKey{}).(*AliasTable)
	return table
}

// WithRenderedTask binds the model-facing task projection.
func WithRenderedTask(ctx context.Context, rendered string) context.Context {
	return context.WithValue(ctx, renderedTaskKey{}, rendered)
}

// RenderedTaskFrom returns the rendered task and whether one was bound.
func RenderedTaskFrom(ctx context.Context) (string, bool) {
	rendered, ok := ctx.Value(renderedTaskKey{}).(string)
	return rendered, ok && rendered != ""
}

// ToolScope is the trusted scope the host injects into a tool call. A model
// cannot widen it: scope fields are not part of any tool's input schema, and the
// executor reads them here rather than from the request.
type ToolScope struct {
	SnapshotID string
	PathID     string
	AuditID    string
	RunID      string
}

type toolScopeKey struct{}

// WithToolScope binds the run's trusted scope to one tool call.
func WithToolScope(ctx context.Context, scope ToolScope) context.Context {
	return context.WithValue(ctx, toolScopeKey{}, scope)
}

// ToolScopeFrom returns the bound scope.
func ToolScopeFrom(ctx context.Context) ToolScope {
	scope, _ := ctx.Value(toolScopeKey{}).(ToolScope)
	return scope
}

type runIDKey struct{}

// WithRunID binds the run identifier to the adapter context. A worker echoes it in
// every frame so a reply from another attempt cannot be mistaken for this one.
func WithRunID(ctx context.Context, runID string) context.Context {
	return context.WithValue(ctx, runIDKey{}, runID)
}

// RunIDFrom returns the bound run identifier, if any.
func RunIDFrom(ctx context.Context) string {
	value, _ := ctx.Value(runIDKey{}).(string)
	return value
}

// PromptVersion names the model-facing prompt and task projection. A run records
// it so a resumed run does not silently answer a different contract.
const PromptVersion = "1"

// RuntimePin is the public, secret-free identity of the runtime configuration a
// run used. It is recorded with the run and exposed to the API; credentials stay
// in the encrypted settings and never enter this struct.
type RuntimePin struct {
	Runtime          string `json:"runtime"`
	RuntimeVersion   string `json:"runtime_version,omitempty"`
	ProtocolVersion  string `json:"protocol_version,omitempty"`
	WorkerVersion    string `json:"worker_version,omitempty"`
	PromptVersion    string `json:"prompt_version,omitempty"`
	Model            string `json:"model,omitempty"`
	ConfigVersion    string `json:"config_version,omitempty"`
	ToolSchemaDigest string `json:"tool_schema_digest,omitempty"`
}

// Freezer captures the model configuration for a long-lived workflow run. The
// returned runtime is immutable for the workflow, and the returned pin is the
// public record of what it froze.
type Freezer interface {
	FreezeRuntime() (Runtime, RuntimePin, error)
}

// PinProvider is the optional ability to describe the configuration a runtime
// would use now. The orchestrator calls it once per run, before the adapter
// starts, and stores the result with the run.
type PinProvider interface {
	Pin() (RuntimePin, error)
}

// RuntimeInfo is the deployment's answer to "which runtimes can a task choose?".
type RuntimeInfo struct {
	Name            string              `json:"name"`
	Version         string              `json:"version"`
	Ready           bool                `json:"ready"`
	Reason          string              `json:"reason,omitempty"`
	Capabilities    RuntimeCapabilities `json:"capabilities"`
	Model           string              `json:"model,omitempty"`
	ConfigVersion   string              `json:"config_version,omitempty"`
	WorkerVersion   string              `json:"worker_version,omitempty"`
	ProtocolVersion string              `json:"protocol_version,omitempty"`
}

// DescribeRuntime merges readiness and capabilities into one public record.
func DescribeRuntime(name string, runtime Runtime) RuntimeInfo {
	info := RuntimeInfo{Name: name}
	if runtime == nil {
		info.Reason = "runtime is not configured"
		return info
	}
	info.Capabilities = runtime.Capabilities()
	info.Version = info.Capabilities.Version
	if ready, ok := runtime.(interface{ Ready() error }); ok {
		if err := ready.Ready(); err != nil {
			info.Reason = err.Error()
			return info
		}
	}
	info.Ready = true
	if provider, ok := runtime.(PinProvider); ok {
		if pin, err := provider.Pin(); err == nil {
			info.Model = pin.Model
			info.ConfigVersion = pin.ConfigVersion
			info.WorkerVersion = pin.WorkerVersion
			info.ProtocolVersion = pin.ProtocolVersion
		}
	}
	return info
}
