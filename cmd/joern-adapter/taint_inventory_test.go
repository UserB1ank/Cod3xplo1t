package main

import (
	"strings"
	"testing"
)

func TestSecurityFactsKeepMatchedSinksWithoutFlows(t *testing.T) {
	report := flowReport{
		Version: "joern/taint-flows/v2", RulesDigest: "rules",
		Catalog: catalogRef{ID: "java-sink-catalog", Version: "1.0.0", Digest: "catalog-digest", Entries: 1},
		Sinks: []sinkMatch{{
			RuleID: "java.deserialization.object-input", Category: "deserialization",
			CPG: "cpg-java", MethodFullName: "java.io.ObjectInputStream.readObject:java.lang.Object()",
			Node:               flowNode{ID: "call-7", Label: "CALL", Code: "input.readObject()", Filename: "src/Handler.java", MethodID: "method-7", Line: intPtr(42)},
			DangerousArguments: []int{0}, Priority: 0.95, Evidence: "inferred",
			Limitations: []string{"presence is not exploitability"},
		}},
		Flows: []flow{},
	}
	facts, err := securityFacts(report, codeData{})
	if err != nil {
		t.Fatal(err)
	}
	sinks := facts["sinks"].([]any)
	if len(sinks) != 1 || len(facts["relations"].([]any)) != 0 {
		t.Fatalf("zero-flow sink was lost or invented a flow: %+v", facts)
	}
	sink := sinks[0].(map[string]any)
	if sink["operation_kind"] != "sink:deserialization" || sink["catalog_id"] != "java.deserialization.object-input" || sink["has_flow"] != false {
		t.Fatalf("sink metadata = %+v", sink)
	}
	ruleset := facts["ruleset"].(map[string]any)
	if ruleset["catalog_digest"] != "catalog-digest" {
		t.Fatalf("ruleset does not pin the catalog: %+v", ruleset)
	}
	if ruleset["catalog_sink_matches"] != 1 || ruleset["catalog_sink_nodes"] != 1 {
		t.Fatalf("ruleset lost catalogue count distinction: %+v", ruleset)
	}
}

func TestSecurityFactsReuseCatalogSinkIdentityForARealFlow(t *testing.T) {
	report := flowReport{
		Version: "joern/taint-flows/v2", RulesDigest: "rules",
		Catalog: catalogRef{ID: "java-sink-catalog", Version: "1.0.0", Digest: "catalog-digest", Entries: 1},
		Sinks: []sinkMatch{{
			RuleID: "java.deserialization.object-input", Category: "deserialization",
			CPG: "cpg-java", MethodFullName: "java.io.ObjectInputStream.readObject:java.lang.Object()",
			Node:               flowNode{ID: "call-7", Label: "CALL", Code: "input.readObject()", Filename: "src/Handler.java", MethodID: "method-7", Line: intPtr(42)},
			DangerousArguments: []int{0}, Priority: 0.95, Evidence: "inferred",
			Limitations: []string{"presence is not exploitability"},
		}},
		Flows: []flow{{
			RuleID: "joern.input-to-execution", CPG: "cpg-java", SinkCallID: "call-7",
			SinkCatalogIDs: []string{"java.deserialization.object-input"},
			Nodes: []flowNode{
				{ID: "param-1", Label: "PARAM", Code: "body", Filename: "src/Handler.java", MethodID: "method-entry"},
				{ID: "call-7", Label: "CALL", Code: "input.readObject()", Filename: "src/Handler.java", MethodID: "method-7", Line: intPtr(42)},
			},
		}},
	}
	facts, err := securityFacts(report, codeData{})
	if err != nil {
		t.Fatal(err)
	}
	sinks := facts["sinks"].([]any)
	relations := facts["relations"].([]any)
	if len(sinks) != 1 || len(relations) != 1 {
		t.Fatalf("catalog and flow did not share one sink identity: sinks=%+v relations=%+v", sinks, relations)
	}
	sinkID := sinks[0].(map[string]any)["id"]
	if relations[0].(map[string]any)["to"] != sinkID {
		t.Fatalf("flow targets a duplicate sink: sink=%v relation=%+v", sinkID, relations[0])
	}
	if sinks[0].(map[string]any)["has_flow"] != true {
		t.Fatalf("flow association not recorded: %+v", sinks[0])
	}
	if !strings.Contains(sinks[0].(map[string]any)["limitations"].(string), "exploitability") {
		t.Fatalf("catalog limitation was lost: %+v", sinks[0])
	}
}

func intPtr(v int) *int { return &v }

func TestFlowBudgetReservesAShareForEveryRemainingCPG(t *testing.T) {
	cases := []struct {
		remaining, partitions, want int
	}{
		{100, 3, 34}, {100, 4, 25}, {1, 3, 1}, {0, 3, 0}, {20, 0, 0},
	}
	for _, tc := range cases {
		if got := shareBudget(tc.remaining, tc.partitions); got != tc.want {
			t.Errorf("shareBudget(%d,%d) = %d, want %d", tc.remaining, tc.partitions, got, tc.want)
		}
	}
}
