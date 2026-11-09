package reporting

import (
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/agent"
	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/path"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func TestRenderSummaryShowsReviewableFindingFacts(t *testing.T) {
	capture := Capture{
		Scope:    artifact.Scope{ProjectID: "project-1", SnapshotID: "snap-1"},
		Settings: Settings{CapturedAt: "2026-11-03T00:00:00Z", Counts: map[string]int{"candidate": 1}},
		Paths: []path.Path{{
			ID: "path-1", EntrySubject: "POST /api/deserialize",
			TargetSubject: "ObjectInputStream.readObject",
		}},
		Groups: []Group{{Finding: verify.Finding{
			ID: "find-1", PathID: "path-1", Title: "外部字节流进入反序列化入口",
			Status: verify.FindingCandidate, Severity: "high", Supporting: []string{"ev-source", "ev-flow"},
		}}},
		Reviews: []Review{{
			RunID: "run-1", PathID: "path-1", Status: agent.RunSucceeded,
			Answer: &agent.Answer{
				Hypothesis: agent.HypothesisDraft{Status: agent.HypothesisCandidate},
				Obligations: []agent.ObligationVerdict{{
					Kind: agent.ObligationSource, Verdict: "met", Reason: "request body is attacker controlled",
				}},
				NextAction: "在受控环境验证反序列化 gadget 前提",
			},
		}},
	}
	capture.Summary = &Summary{
		Template: SummaryTemplate, Language: "zh-CN",
		Findings: []SummaryItem{{
			ID: "find-1", PathID: "path-1", Status: "candidate",
			Text: "外部字节流进入反序列化入口", Entry: "POST /api/deserialize",
			Sink: "ObjectInputStream.readObject", Controllability: "外部可控（审查判定）",
			Severity: "high", Evidence: []string{"ev-source", "ev-flow"},
			Next: "在受控环境验证反序列化 gadget 前提",
		}},
		Reviews: []SummaryItem{}, ReviewCounts: map[string]int{},
	}

	document := string(renderSummary(capture))
	for _, want := range []string{
		"入口", "Sink", "可控性", "证据 ID", "严重度",
		"POST /api/deserialize", "ObjectInputStream.readObject",
		"外部可控（审查判定）", "ev-source", "high",
		"在受控环境验证反序列化 gadget 前提",
	} {
		if !strings.Contains(document, want) {
			t.Errorf("summary does not contain %q:\n%s", want, document)
		}
	}
}
