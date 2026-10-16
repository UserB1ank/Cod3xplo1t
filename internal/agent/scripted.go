package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// ScriptedRuntime is a deterministic Runtime adapter: it replays a fixed script
// instead of talking to a model.
//
// It exists because the orchestrator has failure paths that must be exercised
// cheaply and repeatably: invalid JSON, an answer that claims confirmation, a tool
// request outside the allowlist, an expansion ask, a deadline. Reproducing those
// against a live CLI costs money and is never deterministic. The same script
// always produces the same events in the same order, which is what lets a test
// assert on the exchange instead of on a timeout.
//
// Holding no lease, budget or registry is deliberate and is the point: this
// adapter emits requests and nothing else, exactly like the real ones.

// runtimeEventNote is the event type an adapter uses for a short explicit
// statement that is not one of the protocol's own events. An unknown type reported
// by a CLI is folded into this one rather than dropped (see cli.go).
const runtimeEventNote = "note"

// defaultScriptedEventBuffer is the event channel capacity when none is set. It
// is larger than one so a short script can complete even if the orchestrator is
// briefly between reads, and it stays small so a stalled consumer is noticed.
const defaultScriptedEventBuffer = 16

// ScriptStepKind names what a script step asks for.
type ScriptStepKind string

const (
	// StepSummary emits one bounded note. A note is an explicit statement, never a
	// reasoning transcript.
	StepSummary ScriptStepKind = "summary"
	// StepTool asks the orchestrator for one whitelisted tool call.
	StepTool ScriptStepKind = "tool"
	// StepExpansion asks the orchestrator for more exploration room.
	StepExpansion ScriptStepKind = "expansion"
	// StepAnswer produces the terminal structured answer.
	StepAnswer ScriptStepKind = "answer"
)

// ScriptStep is one instruction of a script. Kind selects which payload is read;
// the other payload fields are ignored, so a step is built with the constructors
// below rather than by hand.
type ScriptStep struct {
	Kind      ScriptStepKind
	Summary   string
	Detail    map[string]string
	Tool      *ToolRequest
	Expansion *ExpansionAsk
	Answer    *Answer
	// RawAnswer is an alternative to Answer that lets a test inject bytes the
	// protocol is expected to reject: malformed JSON, an unknown field, a
	// `confirmed` status. The adapter never parses it with its own rules; it goes
	// straight through DecodeAnswer.
	RawAnswer []byte
}

// ScriptNote emits a bounded note.
func ScriptNote(summary string) ScriptStep {
	return ScriptStep{Kind: StepSummary, Summary: summary}
}

// ScriptNoteDetail emits a note with small structured extras (counts, ids).
func ScriptNoteDetail(summary string, detail map[string]string) ScriptStep {
	return ScriptStep{Kind: StepSummary, Summary: summary, Detail: detail}
}

// ScriptTool asks for one tool call. Whether it is allowed is not decided here:
// the request is emitted and the orchestrator validates it against the run policy.
func ScriptTool(req ToolRequest) ScriptStep {
	return ScriptStep{Kind: StepTool, Tool: &req}
}

// ScriptExpansion asks for more room. The orchestrator approves, shrinks, defers
// or rejects it; the adapter cannot grant itself anything.
func ScriptExpansion(ask ExpansionAsk) ScriptStep {
	return ScriptStep{Kind: StepExpansion, Expansion: &ask}
}

// ScriptAnswer produces a structured answer. It is still validated by
// DecodeAnswer before it is emitted, so a step that claims `confirmed` fails the
// run exactly as a real adapter's output would.
func ScriptAnswer(answer Answer) ScriptStep {
	return ScriptStep{Kind: StepAnswer, Answer: &answer}
}

// ScriptRawAnswer produces a terminal answer from raw bytes, for tests that need
// output DecodeAnswer must reject.
func ScriptRawAnswer(raw []byte) ScriptStep {
	return ScriptStep{Kind: StepAnswer, RawAnswer: raw}
}

// ErrScriptStepInvalid marks a script that cannot be replayed: an unknown kind or
// a missing payload. It is a programming error in the test or demo, not a run
// failure, so it is reported instead of being silently skipped.
var ErrScriptStepInvalid = errors.New("agent: invalid script step")

// ScriptedRuntime replays a script. The zero value is not usable; build it with
// NewScriptedRuntime and adjust the two optional fields.
type ScriptedRuntime struct {
	name    string
	version string
	steps   []ScriptStep
	// StepDelay pauses before each step. It is small and exists so tests can land
	// a cancellation or a deadline inside a run; zero means the script replays as
	// fast as the consumer reads.
	StepDelay time.Duration
	// EventBuffer is the event channel capacity; zero uses a small default.
	EventBuffer int
}

// NewScriptedRuntime builds an adapter that replays steps in order. The steps
// slice is copied so a caller cannot change a running script.
func NewScriptedRuntime(name string, version string, steps []ScriptStep) *ScriptedRuntime {
	copied := make([]ScriptStep, len(steps))
	copy(copied, steps)
	return &ScriptedRuntime{name: name, version: version, steps: copied}
}

// Compile-time proof that the adapter honours the contract.
var _ Runtime = (*ScriptedRuntime)(nil)

// Capabilities reports what the replay adapter can do. Token usage is false
// because a script has no tokens, and the orchestrator must not believe a token
// budget is enforced when it is not. Resume is false: a replay has no checkpoint.
func (r *ScriptedRuntime) Capabilities() RuntimeCapabilities {
	return RuntimeCapabilities{
		Name:       r.name,
		Version:    r.version,
		ToolCalls:  true,
		Expansions: true,
		Streaming:  true,
		TokenUsage: false,
		Resume:     false,
		Notes: []string{
			"deterministic replay adapter for tests, dry runs and demos",
			"reports no token usage, so a token budget cannot be enforced from it",
			"cannot resume: a script has no checkpoint",
		},
	}
}

// Start validates the task and begins the replay. An invalid task is refused
// rather than replayed: a run over a task the orchestrator should never have built
// produces an answer that cannot be judged.
func (r *ScriptedRuntime) Start(ctx context.Context, task Task) (*Handle, error) {
	if err := ValidateTask(task); err != nil {
		return nil, err
	}
	if ctx == nil {
		ctx = context.Background()
	}
	buffer := r.EventBuffer
	if buffer <= 0 {
		buffer = defaultScriptedEventBuffer
	}
	events := make(chan RuntimeEvent, buffer)
	done := make(chan RuntimeResult, 1)
	runCtx, cancel := context.WithCancel(ctx)
	var once sync.Once
	handle := &Handle{
		Events: events,
		Done:   done,
		Cancel: func() { once.Do(cancel) },
	}
	go r.run(runCtx, task, events, done)
	return handle, nil
}

// run replays the script. Events is closed and Done carries exactly one result
// whatever path the run takes, so a consumer that ranges over Events and then
// reads Done never blocks, even after a cancellation.
func (r *ScriptedRuntime) run(ctx context.Context, task Task, events chan<- RuntimeEvent, done chan<- RuntimeResult) {
	result := RuntimeResult{ExitCode: 0}
	defer func() {
		done <- result
		close(events)
		close(done)
	}()

	fail := func(err error) {
		result.ExitCode = -1
		result.Err = err
	}

	for _, step := range r.steps {
		if !r.waitStep(ctx) {
			fail(ctx.Err())
			return
		}
		switch step.Kind {
		case StepSummary:
			if !sendEvent(ctx, events, RuntimeEvent{
				Type:    runtimeEventNote,
				Summary: step.Summary,
				Detail:  step.Detail,
			}) {
				fail(ctx.Err())
				return
			}
		case StepTool:
			if step.Tool == nil {
				fail(fmt.Errorf("%w: tool step carries no request", ErrScriptStepInvalid))
				return
			}
			if !sendEvent(ctx, events, RuntimeEvent{
				Type:    EventToolRequested,
				Summary: "requested tool " + step.Tool.Tool,
				Detail:  map[string]string{"call_id": step.Tool.CallID},
				Tool:    step.Tool,
			}) {
				fail(ctx.Err())
				return
			}
		case StepExpansion:
			if step.Expansion == nil {
				fail(fmt.Errorf("%w: expansion step carries no request", ErrScriptStepInvalid))
				return
			}
			if !sendEvent(ctx, events, RuntimeEvent{
				Type:      EventExpansionAsked,
				Summary:   "requested expansion of " + step.Expansion.TargetNodeID,
				Expansion: step.Expansion,
			}) {
				fail(ctx.Err())
				return
			}
		case StepAnswer:
			answer, err := r.decodeStepAnswer(step, task)
			if err != nil {
				// The rejected output is itself an event: the orchestrator records
				// why a run produced nothing usable instead of guessing.
				sendEvent(ctx, events, RuntimeEvent{
					Type:    EventOutputRejected,
					Summary: "answer rejected by the protocol",
					Detail:  map[string]string{"error": err.Error()},
				})
				fail(err)
				return
			}
			// DecodeAnswer proved the answer valid; the orchestrator validates it
			// again, because an adapter's word is never taken for it.
			if !sendEvent(ctx, events, RuntimeEvent{
				Type:    EventOutputReceived,
				Summary: "structured answer produced",
				Answer:  answer,
			}) {
				fail(ctx.Err())
				return
			}
			result.Answer = answer
		default:
			fail(fmt.Errorf("%w: unknown kind %q", ErrScriptStepInvalid, step.Kind))
			return
		}
	}
}

// decodeStepAnswer routes both answer forms through the protocol's own decoder so
// a script cannot be more permissive than a real adapter.
func (r *ScriptedRuntime) decodeStepAnswer(step ScriptStep, task Task) (*Answer, error) {
	raw := step.RawAnswer
	if raw == nil {
		if step.Answer == nil {
			return nil, fmt.Errorf("%w: answer step carries no output", ErrScriptStepInvalid)
		}
		encoded, err := json.Marshal(step.Answer)
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrScriptStepInvalid, err)
		}
		raw = encoded
	}
	return DecodeAnswer(raw, task)
}

// waitStep sleeps before a step and reports whether the run may continue. A
// cancelled or expired context stops the replay at the current step.
func (r *ScriptedRuntime) waitStep(ctx context.Context) bool {
	if r.StepDelay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(r.StepDelay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return ctx.Err() == nil
	case <-ctx.Done():
		return false
	}
}

// sendEvent delivers one event or gives up when the run is cancelled. The select
// is what keeps a consumer that stopped reading from pinning the adapter forever:
// the buffer absorbs a burst, and cancellation always wins.
func sendEvent(ctx context.Context, events chan<- RuntimeEvent, event RuntimeEvent) bool {
	select {
	case events <- event:
		return true
	case <-ctx.Done():
		return false
	}
}
