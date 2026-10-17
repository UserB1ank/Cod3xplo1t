package agent

import (
	"context"
	"sort"
	"sync"
)

// RuntimeCapabilities describes what an adapter can do, so the orchestrator can
// refuse a task the adapter cannot honour instead of discovering it halfway.
type RuntimeCapabilities struct {
	// Name and Version identify the adapter in the run record.
	Name    string
	Version string
	// ToolCalls reports whether the adapter can ask for whitelisted tool calls. An
	// adapter that cannot gets a task without a tool budget.
	ToolCalls bool
	// Expansions reports whether the adapter can request more room.
	Expansions bool
	// Resume reports whether a run can continue after a pause. Most CLI adapters
	// cannot, which is why the orchestrator checkpoints instead of trusting a
	// session.
	Resume bool
	// Streaming reports whether events arrive while the run is in progress.
	Streaming bool
	// TokenUsage reports whether the adapter reports token counts. Without them the
	// token budget cannot be enforced, and the run says so.
	TokenUsage bool
	Notes      []string
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
	// Answer, when set, is the structured final output.
	Answer *Answer
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
	// Call runs the tool. It must be read-only and it must respect the context.
	Call(ctx context.Context, args map[string]string) (ToolResult, error)
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
	r.entries[name] = executor
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
