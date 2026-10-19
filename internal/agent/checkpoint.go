package agent

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

// CheckpointVersion is the version of the persisted pause document. A reader that
// does not know a version refuses it rather than guessing what the fields mean.
const CheckpointVersion = 1

const (
	// CheckpointMaxEvidence bounds the evidence references a checkpoint carries.
	CheckpointMaxEvidence = 200
	// CheckpointMaxFrontier bounds the open work a checkpoint carries.
	CheckpointMaxFrontier = 50
)

// Checkpoint is the runtime-independent state a paused attempt leaves behind. It
// is built by Go from the run's own task, evidence, aliases, pin and usage; it
// never carries provider messages or hidden reasoning.
type Checkpoint struct {
	Version    int             `json:"version"`
	Digest     string          `json:"digest"`
	ID         string          `json:"checkpoint_id"`
	RunID      string          `json:"run_id"`
	AuditID    string          `json:"audit_id"`
	PathID     string          `json:"path_id"`
	SnapshotID string          `json:"snapshot_id"`
	Task       Task            `json:"task"`
	Evidence   []string        `json:"evidence,omitempty"`
	Frontier   []string        `json:"frontier"`
	Aliases    *AliasTable     `json:"aliases,omitempty"`
	Pin        *RuntimePin     `json:"pin,omitempty"`
	Usage      CheckpointUsage `json:"usage"`
	Reason     string          `json:"reason"`
	CreatedAt  string          `json:"created_at"`
}

// CheckpointUsage is the budget already spent by the attempt, so a resumed run
// continues the same accounting instead of starting from zero.
type CheckpointUsage struct {
	InputTokens  int `json:"input_tokens"`
	OutputTokens int `json:"output_tokens"`
	ToolCalls    int `json:"tool_calls"`
}

// CheckpointInput is what the builder needs from a paused session. It is a
// deliberate projection, not the session itself: nothing about the adapter leaks
// into the document.
type CheckpointInput struct {
	Run      Run
	Task     Task
	Evidence []string
	Aliases  *AliasTable
	Usage    CheckpointUsage
	Reason   string
	Now      time.Time
	ID       string
}

// BuildCheckpoint projects a paused attempt into a checkpoint. The frontier is
// the task's obligations and unresolved questions, never invented evidence: a run
// that closed nothing still records what is left to do.
func BuildCheckpoint(in CheckpointInput) (Checkpoint, error) {
	task := in.Task
	if err := ValidateTask(task); err != nil {
		return Checkpoint{}, fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}
	run := in.Run
	if strings.TrimSpace(run.ID) == "" || strings.TrimSpace(run.PathID) == "" {
		return Checkpoint{}, fmt.Errorf("%w: a run id and path id are required", ErrInvalidCheckpoint)
	}
	if task.PathID != "" && task.PathID != run.PathID {
		return Checkpoint{}, fmt.Errorf("%w: the task belongs to path %s, not %s", ErrInvalidCheckpoint, task.PathID, run.PathID)
	}
	if task.SnapshotID != "" && run.SnapshotID != "" && task.SnapshotID != run.SnapshotID {
		return Checkpoint{}, fmt.Errorf("%w: the task and the run disagree on the snapshot", ErrInvalidCheckpoint)
	}
	if in.Usage.InputTokens < 0 || in.Usage.OutputTokens < 0 || in.Usage.ToolCalls < 0 {
		return Checkpoint{}, fmt.Errorf("%w: usage cannot be negative", ErrInvalidCheckpoint)
	}
	if strings.TrimSpace(in.Reason) == "" {
		return Checkpoint{}, fmt.Errorf("%w: a pause reason is required", ErrInvalidCheckpoint)
	}

	checkpoint := Checkpoint{
		Version: CheckpointVersion, ID: in.ID, RunID: run.ID,
		AuditID: run.AuditID, PathID: run.PathID, SnapshotID: run.SnapshotID,
		Task: task, Evidence: boundedEvidence(in.Evidence), Frontier: checkpointFrontier(task),
		Aliases: in.Aliases, Pin: run.Pin, Usage: in.Usage,
		Reason: runnerCapText(in.Reason, MaxNotesChars), CreatedAt: NowString(in.Now),
	}
	if strings.TrimSpace(checkpoint.ID) == "" {
		checkpoint.ID = "checkpoint-" + digest16("codexploit/checkpoint/v1", run.ID, fmt.Sprint(run.Version), NowString(in.Now), in.Reason)
	}
	checkpoint.Digest = checkpointDigest(checkpoint)
	if err := checkpoint.Validate(); err != nil {
		return Checkpoint{}, err
	}
	return checkpoint, nil
}

// Validate checks the document a reader is about to trust: known version, a
// digest, a task that still validates, and a frontier that names real open work.
func (c Checkpoint) Validate() error {
	if c.Version != CheckpointVersion {
		return fmt.Errorf("%w: version %d", ErrInvalidCheckpoint, c.Version)
	}
	if strings.TrimSpace(c.ID) == "" || strings.TrimSpace(c.RunID) == "" || strings.TrimSpace(c.PathID) == "" {
		return fmt.Errorf("%w: checkpoint, run and path ids are required", ErrInvalidCheckpoint)
	}
	if len(c.Digest) != 16 {
		return fmt.Errorf("%w: the digest is missing", ErrInvalidCheckpoint)
	}
	if err := ValidateTask(c.Task); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidCheckpoint, err)
	}
	if c.Task.PathID != "" && c.Task.PathID != c.PathID {
		return fmt.Errorf("%w: the task belongs to another path", ErrInvalidCheckpoint)
	}
	if len(c.Frontier) == 0 {
		return fmt.Errorf("%w: a checkpoint must say what remains", ErrInvalidCheckpoint)
	}
	if len(c.Frontier) > CheckpointMaxFrontier {
		return fmt.Errorf("%w: the frontier exceeds %d entries", ErrInvalidCheckpoint, CheckpointMaxFrontier)
	}
	if len(c.Evidence) > CheckpointMaxEvidence {
		return fmt.Errorf("%w: the evidence exceeds %d references", ErrInvalidCheckpoint, CheckpointMaxEvidence)
	}
	if c.Usage.InputTokens < 0 || c.Usage.OutputTokens < 0 || c.Usage.ToolCalls < 0 {
		return fmt.Errorf("%w: usage cannot be negative", ErrInvalidCheckpoint)
	}
	if c.Digest != checkpointDigest(c) {
		return fmt.Errorf("%w: the digest does not match the document", ErrInvalidCheckpoint)
	}
	return nil
}

func checkpointDigest(c Checkpoint) string {
	c.Digest = ""
	encoded, err := json.Marshal(c)
	if err != nil {
		return ""
	}
	return digest16("codexploit/checkpoint/v1", string(encoded))
}

func boundedEvidence(values []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		out = append(out, value)
		if len(out) == CheckpointMaxEvidence {
			break
		}
	}
	sort.Strings(out)
	return out
}

func checkpointFrontier(task Task) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(task.Obligations)+len(task.UnresolvedQuestions))
	add := func(value string) {
		value = strings.TrimSpace(value)
		if value == "" {
			return
		}
		if _, ok := seen[value]; ok {
			return
		}
		seen[value] = struct{}{}
		out = append(out, value)
	}
	for _, obligation := range task.Obligations {
		line := obligation.Kind + ": " + obligation.Question
		add(line)
	}
	for _, question := range task.UnresolvedQuestions {
		add(question)
	}
	if len(out) == 0 {
		out = append(out, "continue the analysis from the recorded evidence")
	}
	if len(out) > CheckpointMaxFrontier {
		out = out[:CheckpointMaxFrontier]
	}
	return out
}
