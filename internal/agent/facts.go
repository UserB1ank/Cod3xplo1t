package agent

import "context"

// The task builder and the tool executors need the SCG, the ASG and the path
// engine — and the storage layer implements agent.Store, so this package must not
// import them: `agent → graph → storage → agent` would be a cycle. The same split
// P3 and P4 use applies here: this package declares the narrow read-only surface it
// needs, and the query layer implements it.

// SliceRequest asks for the bounded source an agent may read. The bound is part of
// the request, not a suggestion: a task that carries half a repository is a task
// whose agent will spend its budget reading instead of reasoning.
type SliceRequest struct {
	SnapshotID string
	PathID     string
	// SymbolIDs come from the path's SCG refs: the handler, the intermediate
	// symbols and the symbol that contains the sensitive call.
	SymbolIDs []string
	// Files restricts the slice to the files the path actually touches.
	Files []string
	// MaxLines bounds the whole slice; MaxSections bounds how many windows it is
	// split into.
	MaxLines    int
	MaxSections int
}

// TaskFacts is the read-only view the task builder reads.
type TaskFacts interface {
	// CodeSlice returns the bounded source sections of a path. It must never return
	// more source than the request allows, and it must report truncation through the
	// sections' reasons rather than silently returning less.
	CodeSlice(ctx context.Context, req SliceRequest) ([]SliceSection, error)
	// TaskLimitations returns the upstream limitations a task must carry forward, so
	// an agent does not treat an unresolved call or a truncated walk as settled.
	TaskLimitations(ctx context.Context, snapshotID string) ([]string, error)
}

// BuildOptions configures the standard task builder.
type BuildOptions struct {
	// MaxSliceLines and MaxSliceSections bound the code an agent receives.
	MaxSliceLines    int
	MaxSliceSections int
	// AllowedTools is advertised to the agent, and it is the same list the
	// orchestrator enforces: advertising a tool the gate would refuse teaches the
	// agent to waste its budget on refusals.
	AllowedTools []string
	// MaxEvidenceRefs bounds the facts cited in the task.
	MaxEvidenceRefs int
}

// DefaultBuildOptions returns the starting bounds: a small slice (240 lines in at
// most 6 windows) and at most 40 evidence references.
func DefaultBuildOptions() BuildOptions {
	return BuildOptions{MaxSliceLines: 240, MaxSliceSections: 6, MaxEvidenceRefs: 40}
}

// Normalize fills unset bounds.
func (o BuildOptions) Normalize() BuildOptions {
	d := DefaultBuildOptions()
	if o.MaxSliceLines <= 0 {
		o.MaxSliceLines = d.MaxSliceLines
	}
	if o.MaxSliceSections <= 0 {
		o.MaxSliceSections = d.MaxSliceSections
	}
	if o.MaxEvidenceRefs <= 0 {
		o.MaxEvidenceRefs = d.MaxEvidenceRefs
	}
	if o.AllowedTools == nil {
		o.AllowedTools = []string{}
	}
	return o
}
