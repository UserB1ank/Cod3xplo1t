package supervisor

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

type toolCallBreaker struct {
	failures map[string]int
}

func newToolCallBreaker() *toolCallBreaker {
	return &toolCallBreaker{failures: map[string]int{}}
}

func (b *toolCallBreaker) shouldBlock(call llm.Call) bool {
	return b.failures[callBreakerKey(call)] >= 2
}

func (b *toolCallBreaker) recordFailure(call llm.Call) {
	b.failures[callBreakerKey(call)]++
}

func repeatedCallResult(call llm.Call) string {
	return structuredToolFailure(call, "REPEATED_CALL", "the same tool call already failed twice; execution was blocked", "inspect_tool_schema")
}

func structuredToolFailure(call llm.Call, code, message, action string) string {
	message = strings.TrimSpace(message)
	if len(message) > 8000 {
		message = message[:8000]
	}
	raw, _ := json.Marshal(map[string]any{
		"ok":               false,
		"error_code":       code,
		"tool":             call.Function.Name,
		"message":          message,
		"retryable":        false,
		"schema_ref":       call.Function.Name + "@current",
		"suggested_action": action,
	})
	return string(raw)
}

func callBreakerKey(call llm.Call) string {
	args := strings.TrimSpace(call.Function.Arguments)
	var value any
	if json.Unmarshal([]byte(args), &value) == nil {
		if normalized, err := json.Marshal(value); err == nil {
			args = string(normalized)
		}
	}
	sum := sha256.Sum256([]byte(call.Function.Name + "\x00" + args))
	return hex.EncodeToString(sum[:])
}

func toolErrorCode(result string, err error) string {
	if err == nil {
		return ""
	}
	var value map[string]any
	if json.Unmarshal([]byte(result), &value) == nil {
		if code, _ := value["error_code"].(string); code != "" {
			return code
		}
		if code, _ := value["code"].(string); code != "" {
			return code
		}
		if data, ok := value["data"].(map[string]any); ok {
			if code, _ := data["code"].(string); code != "" {
				return code
			}
		}
	}
	return "TOOL_ERROR"
}
