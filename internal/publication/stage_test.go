package publication_test

import (
	"encoding/json"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/publication"
)

func TestStandardCodeFactsPublishWithFixedOperationProvenance(t *testing.T) {
	f := newPubFixture(t)
	document := plugin.StageDocument{Kind: "code.facts", SchemaID: "codexploit/code-facts/v2", Scope: artifact.Scope{ProjectID: pubProject, SnapshotID: pubSnapshot}, Producer: artifact.Producer{PluginID: "example.parser", PluginVersion: "1.0.0", OperationID: "parse", InvocationID: "inv-code-facts", PackageDigest: "fixed-release"}, Data: json.RawMessage(`{"files":[{"file_id":"file-main","path":"main.go","language":"Go","parse_status":"parsed","reason":null}],"symbols":[{"id":"symbol-main","file_id":"file-main","kind":"function","name":"main","qualified_name":"main.main","signature":"func main()","location":{"file":"main.go","start_line":1,"start_column":1,"end_line":1,"end_column":15}}],"calls":[],"native_id_mappings":[]}`)}
	batch, err := publication.BatchFromStage("stage-code", document, "rev-0")
	if err != nil {
		t.Fatal(err)
	}
	revision, err := f.publisher.Publish(t.Context(), batch)
	if err != nil {
		t.Fatal(err)
	}
	fixed, err := f.store.GetKnowledgeRevision(t.Context(), f.scope(), revision.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(fixed.Facts) != 1 || fixed.Facts[0].ID != "symbol-main" || fixed.Facts[0].Observations[0].Producer.OperationID != "parse" {
		t.Fatalf("fixed standard facts: %+v", fixed)
	}
}
