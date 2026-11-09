package supervisor

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func (s *Service) buildCheckpoint(
	ctx context.Context,
	session storage.SupervisorSession,
	run storage.SupervisorRun,
	stopReason string,
	rounds, tools, input, output int,
	pending string,
) *storage.SupervisorCheckpoint {
	if latest, err := s.Store.GetSupervisorSession(ctx, session.ProjectID, session.ID); err == nil {
		session = latest
		for _, value := range session.Runs {
			if value.ID == run.ID {
				run = value
				break
			}
		}
	}
	userMessageID := run.UserMessageID
	if userMessageID == "" {
		for i := len(session.Messages) - 1; i >= 0; i-- {
			if session.Messages[i].RunID == run.ID && session.Messages[i].Role == "user" {
				userMessageID = session.Messages[i].ID
				break
			}
		}
	}
	operations, completed, pendingItems, claimIDs, evidenceIDs, findingIDs, receiptIDs, lastError := checkpointFacts(session.Messages, run.ID)
	if userMessageID != "" {
		completed = append(completed, "user_message:"+userMessageID)
		pendingItems = append(pendingItems, "complete_user_request:"+userMessageID)
	}
	if strings.TrimSpace(pending) != "" {
		pendingItems = append(pendingItems, "blocked:"+capCheckpointText(pending, 600))
	}
	budget := storage.SupervisorCheckpointBudget{
		RemainingRounds:    max(0, run.RoundLimit-rounds),
		RemainingToolCalls: max(0, run.ToolCallLimit-tools),
	}
	if store, err := s.budgetStore(); err == nil && run.AuditID != "" {
		if ledger, err := store.GetAuditBudget(run.AuditID); err == nil {
			budget.AuditLimitTokens = ledger.LimitTokens
			budget.AuditUsedTokens = ledger.UsedTokens
			budget.AuditReservedTokens = ledger.ReservedTokens
			budget.RemainingTokens = ledger.Available()
		}
	}
	checkpoint := &storage.SupervisorCheckpoint{
		SchemaVersion: 2,
		Trigger:       stopReason,
		UserMessageID: userMessageID,
		StopReason:    stopReason,
		ModelTurns:    rounds,
		ToolCalls:     tools,
		InputTokens:   input,
		OutputTokens:  output,
		Completed:     sortedCheckpointStrings(completed),
		Pending:       sortedCheckpointStrings(pendingItems),
		Operations:    operations,
		ClaimIDs:      sortedCheckpointStrings(claimIDs),
		EvidenceIDs:   sortedCheckpointStrings(evidenceIDs),
		FindingIDs:    sortedCheckpointStrings(findingIDs),
		ReceiptIDs:    sortedCheckpointStrings(receiptIDs),
		LastError:     lastError,
		Budget:        budget,
		NextAction:    checkpointNextAction(stopReason),
		CreatedAt:     time.Now().UTC().Format(time.RFC3339Nano),
	}
	if lastError != nil {
		checkpoint.LastToolError = capCheckpointText(nonEmptyCheckpoint(lastError.Code)+": "+lastError.Message, 4000)
	}
	checkpoint.CheckpointID = checkpointDigest(checkpoint)
	return checkpoint
}

func checkpointFacts(messages []storage.SupervisorMessage, runID string) (
	[]storage.SupervisorCheckpointOperation,
	[]string, []string,
	[]string, []string, []string, []string,
	*storage.SupervisorCheckpointError,
) {
	type callFact struct {
		name string
	}
	calls := map[string]callFact{}
	order := []string{}
	for _, message := range messages {
		if message.RunID != runID || message.Role != "assistant" {
			continue
		}
		for _, call := range message.Calls {
			if call.ID == "" {
				continue
			}
			if _, exists := calls[call.ID]; !exists {
				order = append(order, call.ID)
			}
			calls[call.ID] = callFact{name: call.Name}
		}
	}
	responded := map[string]bool{}
	operations := make([]storage.SupervisorCheckpointOperation, 0, len(order))
	var completed, pending, claimIDs, evidenceIDs, findingIDs, receiptIDs []string
	var lastError *storage.SupervisorCheckpointError
	for _, message := range messages {
		if message.RunID != runID || message.Role != "tool" {
			continue
		}
		call, ok := calls[message.ToolCallID]
		if !ok {
			continue
		}
		responded[message.ToolCallID] = true
		var value any
		_ = json.Unmarshal([]byte(message.Content), &value)
		code, messageText := checkpointError(value)
		ids := checkpointResultIDs(value)
		status := "completed"
		if code != "" || strings.Contains(message.Content, `"ok":false`) {
			status = "failed"
			pending = append(pending, "retry_tool:"+call.name+":"+message.ToolCallID)
			lastError = &storage.SupervisorCheckpointError{
				Code: nonEmptyCheckpoint(code, "TOOL_ERROR"), Message: capCheckpointText(nonEmptyCheckpoint(messageText, message.Content), 4000),
				Tool: call.name, CallID: message.ToolCallID,
			}
		} else {
			completed = append(completed, "tool_ok:"+call.name+":"+message.ToolCallID)
		}
		receiptID := firstCheckpointID(ids.receiptIDs)
		operations = append(operations, storage.SupervisorCheckpointOperation{
			CallID: message.ToolCallID, Tool: call.name, Status: status,
			Summary: capCheckpointText(nonEmptyCheckpoint(messageText, status), 500), ReceiptID: receiptID,
		})
		claimIDs = append(claimIDs, ids.claimIDs...)
		evidenceIDs = append(evidenceIDs, ids.evidenceIDs...)
		findingIDs = append(findingIDs, ids.findingIDs...)
		receiptIDs = append(receiptIDs, ids.receiptIDs...)
	}
	for _, callID := range order {
		if responded[callID] {
			continue
		}
		call := calls[callID]
		pending = append(pending, "unfinished_tool:"+call.name+":"+callID)
		operations = append(operations, storage.SupervisorCheckpointOperation{
			CallID: callID, Tool: call.name, Status: "pending", Summary: "tool result not recorded",
		})
	}
	sort.SliceStable(operations, func(i, j int) bool {
		if operations[i].CallID != operations[j].CallID {
			return operations[i].CallID < operations[j].CallID
		}
		return operations[i].Tool < operations[j].Tool
	})
	return operations, completed, pending, claimIDs, evidenceIDs, findingIDs, receiptIDs, lastError
}

type checkpointIDSet struct {
	claimIDs, evidenceIDs, findingIDs, receiptIDs []string
}

func checkpointResultIDs(value any) checkpointIDSet {
	var result checkpointIDSet
	var walk func(any)
	walk = func(current any) {
		switch typed := current.(type) {
		case map[string]any:
			for key, child := range typed {
				if id, ok := child.(string); ok && id != "" {
					switch strings.ToLower(key) {
					case "claim_id":
						result.claimIDs = append(result.claimIDs, id)
					case "evidence_id":
						result.evidenceIDs = append(result.evidenceIDs, id)
					case "finding_id":
						result.findingIDs = append(result.findingIDs, id)
					case "receipt_id", "ack_id", "read_receipt_id":
						result.receiptIDs = append(result.receiptIDs, id)
					}
				}
				walk(child)
			}
		case []any:
			for _, child := range typed {
				walk(child)
			}
		}
	}
	walk(value)
	return result
}

func checkpointError(value any) (string, string) {
	root, _ := value.(map[string]any)
	if root == nil {
		return "", ""
	}
	if ok, exists := root["ok"].(bool); exists && ok {
		return "", ""
	}
	for _, candidate := range []map[string]any{root, mapValue(root["error"]), mapValue(root["data"])} {
		if candidate == nil {
			continue
		}
		code := nonEmptyCheckpoint(stringValue(candidate["error_code"]), stringValue(candidate["code"]))
		message := nonEmptyCheckpoint(stringValue(candidate["message"]), stringValue(candidate["error"]))
		if code != "" || message != "" {
			return code, message
		}
	}
	return "", ""
}

func mapValue(value any) map[string]any {
	result, _ := value.(map[string]any)
	return result
}

func stringValue(value any) string {
	result, _ := value.(string)
	return result
}

func nonEmptyCheckpoint(values ...string) string {
	for _, value := range values {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return ""
}

func firstCheckpointID(values []string) string {
	values = sortedCheckpointStrings(values)
	if len(values) == 0 {
		return ""
	}
	return values[0]
}

func sortedCheckpointStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func checkpointNextAction(stopReason string) string {
	switch stopReason {
	case StopGlobalBudget:
		return "approve additional audit tokens, then continue from this checkpoint"
	case StopRecovery:
		return "create a new run segment from this recovered checkpoint"
	case StopRoundLimit, StopToolLimit, StopTimeLimit, StopStuck:
		return "continue from this checkpoint without repeating completed writes"
	default:
		return "inspect pending operations and continue from this checkpoint"
	}
}

func checkpointDigest(checkpoint *storage.SupervisorCheckpoint) string {
	copy := *checkpoint
	copy.CheckpointID = ""
	copy.CreatedAt = ""
	raw, _ := json.Marshal(copy)
	sum := sha256.Sum256(raw)
	return "checkpoint-" + hex.EncodeToString(sum[:16])
}

func capCheckpointText(value string, limit int) string {
	value = strings.TrimSpace(value)
	if len(value) <= limit {
		return value
	}
	return value[:limit]
}

func (s *Service) saveSoftCheckpoint(ctx context.Context, session storage.SupervisorSession, run storage.SupervisorRun, rounds, tools, input, output int, trigger string) (bool, error) {
	checkpoint := s.buildCheckpoint(ctx, session, run, trigger, rounds, tools, input, output, "soft budget threshold reached")
	saved := false
	err := s.mutateFenced(ctx, session.ProjectID, session.ID, storage.SupervisorRunFence{
		RunID: run.ID, Owner: run.ExecutionOwner, Epoch: run.LeaseEpoch,
	}, func(latest *storage.SupervisorSession) {
		for i := range latest.Runs {
			if latest.Runs[i].ID != run.ID {
				continue
			}
			if latest.Runs[i].Checkpoint != nil && latest.Runs[i].Checkpoint.CheckpointID == checkpoint.CheckpointID {
				return
			}
			latest.Runs[i].Checkpoint = checkpoint
			latest.Runs[i].Version++
			latest.Events = append(latest.Events, storage.SupervisorEvent{
				ID: "se-" + rand.Text(), SessionID: latest.ID, RunID: run.ID,
				Seq: nextEventSeq(*latest), Type: "checkpoint_saved",
				Summary: "structured checkpoint saved at " + trigger,
				Detail: map[string]string{
					"checkpoint_id": checkpoint.CheckpointID, "trigger": trigger,
					"pending":          fmt.Sprint(len(checkpoint.Pending)),
					"remaining_tokens": fmt.Sprint(checkpoint.Budget.RemainingTokens),
				},
				CreatedAt: checkpoint.CreatedAt,
			})
			saved = true
			return
		}
	})
	return saved, err
}
