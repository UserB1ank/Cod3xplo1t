package graph

import (
	"fmt"
	"strings"
	"testing"
)

// One structured answer is paid for out of the model's context, so the tool layer
// bounds it before the orchestrator's own cap. Exceeding the bound must produce a
// complete error, never a cut document.
func TestToolJSONRejectsOversizedAnswer(t *testing.T) {
	blob := strings.Repeat("x", agentToolMaxJSONBytes)
	result, err := toolJSON(ToolListSymbols, map[string]string{"blob": blob}, nil, nil)
	if err != nil {
		t.Fatalf("toolJSON: %v", err)
	}
	if result.OK {
		t.Fatalf("oversized answer was accepted: %d bytes", len(result.Result))
	}
	if !strings.Contains(result.Error, "result_too_large") {
		t.Fatalf("error = %q, want result_too_large", result.Error)
	}
}

func TestToolJSONCapsReportedRefs(t *testing.T) {
	refs := make([]string, 0, agentToolMaxRefs*2)
	for i := 0; i < agentToolMaxRefs*2; i++ {
		refs = append(refs, fmt.Sprintf("sym-%03d", i))
	}
	refs = append(refs, refs[0]) // a duplicate must not survive the cap either

	result, err := toolJSON(ToolGetSymbol, map[string]string{"ok": "1"}, nil, refs)
	if err != nil {
		t.Fatalf("toolJSON: %v", err)
	}
	if !result.OK {
		t.Fatalf("small answer was rejected: %q", result.Error)
	}
	if len(result.Refs) != agentToolMaxRefs {
		t.Fatalf("refs = %d, want %d", len(result.Refs), agentToolMaxRefs)
	}
}
