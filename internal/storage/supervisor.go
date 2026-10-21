package storage

import "context"

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
	Status          string           `json:"status"`
	Seq             int64            `json:"seq"`
	CreatedAt       string           `json:"created_at"`
}

type SupervisorRun struct {
	ID            string `json:"run_id"`
	SessionID     string `json:"session_id"`
	ProjectID     string `json:"project_id"`
	Status        string `json:"status"`
	Runtime       string `json:"runtime"`
	Model         string `json:"model"`
	ConfigVersion string `json:"config_version"`
	PromptVersion string `json:"prompt_version"`
	ToolDigest    string `json:"tool_digest"`
	InputTokens   int    `json:"input_tokens"`
	OutputTokens  int    `json:"output_tokens"`
	ErrorCode     string `json:"error_code,omitempty"`
	Error         string `json:"error,omitempty"`
	StartedAt     string `json:"started_at,omitempty"`
	FinishedAt    string `json:"finished_at,omitempty"`
	CreatedAt     string `json:"created_at"`
	UpdatedAt     string `json:"updated_at"`
	Version       int64  `json:"version"`
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

// SupervisorStore persists the project-scoped Supervisor session as one
// document. The document is small and bounded; keeping the message/event order
// with the session makes a turn's user message, run and events impossible to
// observe half-written.
type SupervisorStore interface {
	CreateSupervisorSession(ctx context.Context, session SupervisorSession) (SupervisorSession, error)
	GetSupervisorSession(ctx context.Context, projectID, sessionID string) (SupervisorSession, error)
	ListSupervisorSessions(ctx context.Context, projectID string, limit int) ([]SupervisorSession, error)
	SaveSupervisorSession(ctx context.Context, session SupervisorSession, expectedVersion int64) (SupervisorSession, error)
}
