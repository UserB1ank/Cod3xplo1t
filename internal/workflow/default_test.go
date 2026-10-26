package workflow

import (
	"testing"
)

func TestDefaultAnalysisUsesOnePinnedJoernEngine(t *testing.T) {
	spec := DefaultAnalysisSpec()
	if spec.Version == "1.0.0" || len(spec.Nodes) != 4 {
		t.Fatalf("default did not advance from the legacy Go profile: %+v", spec)
	}
	for i, operation := range []string{"parse", "taint", "paths", "enhance"} {
		node := spec.Nodes[i]
		if node.PluginID != "codexploit.joern" || node.PluginVersion != "2.3.0" || node.OperationID != operation {
			t.Fatalf("stage %d mixes engines: %+v", i, node)
		}
	}
	if spec.Nodes[0].TimeoutSeconds < 900 || len(spec.Nodes[2].Needs) != 2 {
		t.Fatal("Joern must reuse the parse and taint outputs with a realistic JVM budget")
	}
}
