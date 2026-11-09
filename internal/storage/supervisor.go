package storage

import (
	"context"
	"time"
)

// SupervisorCall is one model-requested tool invocation recorded with a
// message. It is deliberately separate from the path agent's ToolCall type.
type SupervisorCall struct {
	ID        string `json:"call_id"`
	Name      string `json:"name"`
	Arguments string `json:"arguments"`
}

type SupervisorMessage struct {
	ID              string           `json:"message_id"`
	SessionID       string           `json:"session_id"`
	ProjectID       string           `json:"project_id"`
	Role            string           `json:"role"`
	Content         string           `json:"content"`
	ClientMessageID string           `json:"client_message_id,omitempty"`
	Calls           []SupervisorCall `json:"calls,omitempty"`
	ToolCallID      string           `json:"tool_call_id,omitempty"`
	RunID           string           `json:"run_id,omitempty"`
	MessageKind     string           `json:"message_kind,omitempty"`
	Status          string           `json:"status"`
	Seq             int64            `json:"seq"`
	CreatedAt       string           `json:"created_at"`
}

type SupervisorRun struct {
	ID               string                `json:"run_id"`
	SessionID        string                `json:"session_id"`
	ProjectID        string                `json:"project_id"`
	Status           string                `json:"status"`
	Runtime          string                `json:"runtime"`
	Model            string                `json:"model"`
	ConfigVersion    string                `json:"config_version"`
	PromptVersion    string                `json:"prompt_version"`
	ToolDigest       string                `json:"tool_digest"`
	StopReason       string                `json:"stop_reason,omitempty"`
	ModelTurns       int                   `json:"model_turns,omitempty"`
	ToolCalls        int                   `json:"tool_calls,omitempty"`
	ToolErrors       int                   `json:"tool_errors,omitempty"`
	BlockedToolCalls int                   `json:"blocked_tool_calls,omitempty"`
	RoundLimit       int                   `json:"round_limit,omitempty"`
	ToolCallLimit    int                   `json:"tool_call_limit,omitempty"`
	InputTokens      int                   `json:"input_tokens"`
	OutputTokens     int                   `json:"output_tokens"`
	VisibleMessageID string                `json:"visible_message_id,omitempty"`
	FinalizerSource  string                `json:"finalizer_source,omitempty"`
	UserMessageID    string                `json:"user_message_id,omitempty"`
	ResumeOf         string                `json:"resume_of,omitempty"`
	RootRunID        string                `json:"root_run_id,omitempty"`
	Checkpoint       *SupervisorCheckpoint `json:"checkpoint,omitempty"`
	ExecutionOwner   string                `json:"execution_owner,omitempty"`
	LeaseEpoch       int64                 `json:"lease_epoch,omitempty"`
	HeartbeatAt      string                `json:"heartbeat_at,omitempty"`
	LeaseUntil       string                `json:"lease_until,omitempty"`
	ErrorCode        string                `json:"error_code,omitempty"`
	Error            string                `json:"error,omitempty"`
	StartedAt        string                `json:"started_at,omitempty"`
	FinishedAt       string                `json:"finished_at,omitempty"`
	CreatedAt        string                `json:"created_at"`
	UpdatedAt        string                `json:"updated_at"`
	Version          int64                 `json:"version"`
}

type SupervisorCheckpoint struct {
	SchemaVersion int      `json:"schema_version"`
	UserMessageID string   `json:"user_message_id"`
	StopReason    string   `json:"stop_reason"`
	ModelTurns    int      `json:"model_turns"`
	ToolCalls     int      `json:"tool_calls"`
	InputTokens   int      `json:"input_tokens"`
	OutputTokens  int      `json:"output_tokens"`
	Completed     []string `json:"completed"`
	Pending       []string `json:"pending"`
	ClaimIDs      []string `json:"claim_ids"`
	EvidenceIDs   []string `json:"evidence_ids"`
	LastToolError string   `json:"last_tool_error,omitempty"`
	NextAction    string   `json:"next_action"`
	CreatedAt     string   `json:"created_at"`
}

type SupervisorEvent struct {
	ID        string            `json:"event_id"`
	SessionID string            `json:"session_id"`
	RunID     string            `json:"run_id,omitempty"`
	Seq       int64             `json:"seq"`
	Type      string            `json:"type"`
	Summary   string            `json:"summary,omitempty"`
	Detail    map[string]string `json:"detail,omitempty"`
	CreatedAt string            `json:"created_at"`
}

type SupervisorSession struct {
	ID         string              `json:"session_id"`
	ProjectID  string              `json:"project_id"`
	SnapshotID string              `json:"snapshot_id"`
	Title      string              `json:"title"`
	State      string              `json:"state"`
	Messages   []SupervisorMessage `json:"messages"`
	Runs       []SupervisorRun     `json:"runs"`
	Events     []SupervisorEvent   `json:"events"`
	CreatedAt  string              `json:"created_at"`
	UpdatedAt  string              `json:"updated_at"`
	Version    int64               `json:"version"`
}

type SupervisorRunFence struct {
	RunID        string
	Owner        string
	Epoch        int64
	AllowExpired bool
	Now          string
}

// SupervisorStore persists the project-scoped Supervisor session as one
// document. The document is small and bounded; keeping the message/event order
// with the session makes a turn's user message, run and events impossible to
// observe half-written.
type SupervisorStore interface {
	CreateSupervisorSession(ctx context.Context, session SupervisorSession) (SupervisorSession, error)
	GetSupervisorSession(ctx context.Context, projectID, sessionID string) (SupervisorSession, error)
	ListSupervisorSessions(ctx context.Context, projectID string, limit int) ([]SupervisorSession, error)
	SaveSupervisorSession(ctx context.Context, session SupervisorSession, expectedVersion int64) (SupervisorSession, error)
	SaveSupervisorSessionFenced(ctx context.Context, session SupervisorSession, expectedVersion int64, fence SupervisorRunFence) (SupervisorSession, error)
}

func supervisorRunFenceAllows(current, next SupervisorRun, fence SupervisorRunFence) bool {
	if fence.RunID == "" || current.ID != fence.RunID || fence.Owner == "" || fence.Epoch <= 0 {
		return false
	}
	if next.ExecutionOwner != fence.Owner || next.LeaseEpoch != fence.Epoch {
		return false
	}
	if !activeSupervisorRun(current.Status) {
		return false
	}
	if current.ExecutionOwner == fence.Owner && current.LeaseEpoch == fence.Epoch {
		return true
	}
	if !fence.AllowExpired || current.LeaseUntil == "" {
		return false
	}
	now, err := time.Parse(time.RFC3339Nano, fence.Now)
	if err != nil {
		return false
	}
	lease, err := time.Parse(time.RFC3339Nano, current.LeaseUntil)
	return err == nil && !lease.After(now) && fence.Epoch > current.LeaseEpoch
}

func activeSupervisorRun(status string) bool {
	return status == "RUNNING" || status == "FINALIZING"
}
