package plugin_test

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/asg"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

func TestNormalizerRejectsForgedProducerAndUnsupportedEvidence(t *testing.T) {
	scope := artifact.Scope{ProjectID: "proj-example", SourceID: "src-example", SnapshotID: "snap-example"}
	inv := plugin.Invocation{ID: "inv-example", ConfigDigest: fmt.Sprintf("%x", sha256.Sum256([]byte("{}"))), Request: plugin.Request{PluginID: plugin.SemanticID, PluginVersion: "1.0.0", Scope: scope}}
	producer := artifact.Producer{PluginID: plugin.SemanticID, PluginVersion: "1.0.0", InvocationID: inv.ID, ConfigDigest: inv.ConfigDigest}
	for _, name := range []string{"valid", "producer", "graph_owner", "edge_evidence", "claim"} {
		t.Run(name, func(t *testing.T) {
			report := plugin.NativeReport{Format: "codexploit/semantic-native/v1", Scope: scope, Graph: &scg.Graph{SnapshotID: scope.SnapshotID, GraphVersion: "scg-example", Symbols: []scg.Symbol{{ID: "sym-example", SnapshotID: scope.SnapshotID}}}, Surface: &asg.Document{SnapshotID: scope.SnapshotID, SCGVersion: "scg-example", Nodes: []asg.Node{{ID: "asgn-example", SnapshotID: scope.SnapshotID, Kind: asg.NodeSensitiveOperation, Subject: "sink:process_execution", Generator: "fixture-rule", Evidence: asg.StatusObserved, SCGRefs: []string{"sym-example"}}}, Edges: []asg.Edge{}}}
			owner := producer
			switch name {
			case "producer":
				owner.PluginID = "forged-plugin"
			case "graph_owner":
				report.Graph.Symbols[0].SnapshotID = "other-snapshot"
			case "edge_evidence":
				report.Surface.Edges = append(report.Surface.Edges, asg.Edge{ID: "asge-example", SnapshotID: scope.SnapshotID, From: "asgn-example", To: "asgn-example", Kind: asg.EdgeReaches, Evidence: asg.StatusVerified, Generator: "fixture-rule", SCGRefs: []string{"sym-example"}})
			}
			raw, _ := json.Marshal(report)
			if name == "claim" {
				raw = append(raw[:len(raw)-1], []byte(`,"status":"confirmed"}`)...)
			}
			ref := artifact.Ref{Scope: scope, Producer: owner, SHA256: fmt.Sprintf("%x", sha256.Sum256(raw)), Bytes: int64(len(raw))}
			_, err := (plugin.Normalizer{}).Normalize(inv, ref, raw)
			if name == "valid" {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, plugin.ErrInvalid) {
				t.Fatalf("forged claim accepted: %v", err)
			}
		})
	}
}
