package supervisor

import (
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func buildCheckpoint(
	session storage.SupervisorSession,
	run storage.SupervisorRun,
	stopReason string,
	rounds, tools, input, output int,
	pending string,
) *storage.SupervisorCheckpoint {
	userMessageID := run.UserMessageID
	if userMessageID == "" {
		for i := len(session.Messages) - 1; i >= 0; i-- {
			if session.Messages[i].RunID == run.ID && session.Messages[i].Role == "user" {
				userMessageID = session.Messages[i].ID
				break
			}
		}
	}
	lastError := ""
	for i := len(session.Messages) - 1; i >= 0; i-- {
		message := session.Messages[i]
		if message.RunID != run.ID || message.Role != "tool" {
			continue
		}
		if strings.Contains(message.Content, `"error_code"`) || strings.Contains(message.Content, `"code"`) {
			lastError = message.Content
			break
		}
	}
	if len(lastError) > 4000 {
		lastError = lastError[:4000]
	}
	return &storage.SupervisorCheckpoint{
		SchemaVersion: 1,
		UserMessageID: userMessageID,
		StopReason:    stopReason,
		ModelTurns:    rounds,
		ToolCalls:     tools,
		InputTokens:   input,
		OutputTokens:  output,
		Completed:     []string{},
		Pending:       []string{strings.TrimSpace(pending)},
		ClaimIDs:      []string{},
		EvidenceIDs:   []string{},
		LastToolError: lastError,
		NextAction:    "send a new continue request",
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
}
