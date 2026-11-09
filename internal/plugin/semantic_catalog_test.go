package plugin_test

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestStageHostAcceptsCataloguedSemanticMetadata(t *testing.T) {
	payload := []byte(`{"entries":[],"sinks":[],"controls":[],"relations":[],"ruleset":{"id":"joern.catalog-taint","version":"2.0.0","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","catalog_id":"java-sink-catalog","catalog_version":"1.0.0","catalog_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","catalog_entries":30,"catalog_sink_matches":0,"catalog_sink_nodes":0}}`)
	done, documents := executeSemanticPayload(t, payload)
	if done.Status != "PARTIAL" || len(documents) != 1 {
		t.Fatalf("valid catalogue metadata was rejected: %+v", done)
	}
	var actual, expected any
	if err := json.Unmarshal(documents[0].Data, &actual); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(payload, &expected); err != nil {
		t.Fatal(err)
	}
	a, _ := json.Marshal(actual)
	b, _ := json.Marshal(expected)
	if string(a) != string(b) {
		t.Fatalf("host changed semantic catalogue facts: %s", a)
	}
}

func TestStageHostRejectsIncompleteCatalogueIdentity(t *testing.T) {
	payload := []byte(`{"entries":[],"sinks":[],"controls":[],"relations":[],"ruleset":{"id":"joern.catalog-taint","version":"2.0.0","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","catalog_id":"java-sink-catalog"}}`)
	done, documents := executeSemanticPayload(t, payload)
	if done.Status != "FAILED" || done.ErrorCode != "output_contract_mismatch" || len(documents) != 0 {
		t.Fatalf("incomplete catalogue identity was accepted: %+v", done)
	}
}

func TestStageHostPreservesCataloguedSinkWithoutAnyFlow(t *testing.T) {
	payload := []byte(`{"entries":[],"sinks":[{"id":"sink-catalogued","operation_kind":"sink:deserialization","symbol_ref":null,"location":null,"sensitivity":"catalog_selected","evidence_refs":[],"catalog_id":"java.deserialization.object-input","catalog_version":"1.0.0","catalog_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","method_full_name":"java.io.ObjectInputStream.readObject:java.lang.Object()","dangerous_arguments":[0],"priority":0.95,"match_evidence":"inferred","has_flow":false,"limitations":"Presence does not establish exploitability."}],"controls":[],"relations":[],"ruleset":{"id":"joern.catalog-taint","version":"2.0.0","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","catalog_id":"java-sink-catalog","catalog_version":"1.0.0","catalog_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","catalog_entries":30,"catalog_sink_matches":1,"catalog_sink_nodes":1}}`)
	done, documents := executeSemanticPayload(t, payload)
	if done.Status != "PARTIAL" || len(documents) != 1 {
		t.Fatalf("valid zero-flow catalogue sink was rejected: %+v", done)
	}
	var facts struct {
		Sinks []struct {
			ID                 string `json:"id"`
			CatalogID          string `json:"catalog_id"`
			HasFlow            bool   `json:"has_flow"`
			DangerousArguments []int  `json:"dangerous_arguments"`
		}
	}
	if err := json.Unmarshal(documents[0].Data, &facts); err != nil {
		t.Fatal(err)
	}
	if len(facts.Sinks) != 1 || facts.Sinks[0].ID != "sink-catalogued" || facts.Sinks[0].CatalogID != "java.deserialization.object-input" || facts.Sinks[0].HasFlow || len(facts.Sinks[0].DangerousArguments) != 1 || facts.Sinks[0].DangerousArguments[0] != 0 {
		t.Fatalf("catalogue sink was lost or promoted to a flow: %s", documents[0].Data)
	}
}

func TestStageHostKeepsLegacySemanticRulesAndRejectsInvalidCatalogueFields(t *testing.T) {
	legacy := `{"id":"custom.rules","version":"1.0.0","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}`
	catalogue := `{"id":"joern.catalog-taint","version":"2.0.0","digest":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","catalog_id":"java-sink-catalog","catalog_version":"1.0.0","catalog_digest":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","catalog_entries":30,"catalog_sink_matches":0,"catalog_sink_nodes":0}`
	for _, tc := range []struct {
		name, ruleset, status string
	}{
		{"legacy-no-catalogue", legacy, "PARTIAL"},
		{"unknown-field", strings.TrimSuffix(catalogue, "}") + `,"confirmed":true}`, "FAILED"},
		{"invalid-digest", strings.Replace(catalogue, strings.Repeat("b", 64), "invalid", 1), "FAILED"},
		{"negative-match-count", strings.Replace(catalogue, `"catalog_sink_matches":0`, `"catalog_sink_matches":-1`, 1), "FAILED"},
		{"fractional-node-count", strings.Replace(catalogue, `"catalog_sink_nodes":0`, `"catalog_sink_nodes":0.5`, 1), "FAILED"},
		{"excessive-catalogue", strings.Replace(catalogue, `"catalog_entries":30`, `"catalog_entries":257`, 1), "FAILED"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := []byte(`{"entries":[],"sinks":[],"controls":[],"relations":[],"ruleset":` + tc.ruleset + `}`)
			done, documents := executeSemanticPayload(t, payload)
			if done.Status != tc.status {
				t.Fatalf("unexpected standard semantic result: %+v", done)
			}
			if tc.status == "FAILED" && (done.ErrorCode != "output_contract_mismatch" || len(documents) != 0) {
				t.Fatalf("invalid semantic metadata escaped the output boundary: %+v", done)
			}
		})
	}
}

func executeSemanticPayload(t *testing.T, payload []byte) (plugin.Invocation, []plugin.StageDocument) {
	t.Helper()
	old, request, objects, index := hostFixture(t, map[string]string{"main.go": "package main\n"})
	if err := old.Close(); err != nil {
		t.Fatal(err)
	}
	code := []byte(`{"api_version":"codexploit/v2","data":{"symbols":[],"calls":[]}}`)
	codeRef := artifact.Ref{ID: "code-catalog-fixture", Kind: "code.facts", SchemaID: "codexploit/code-facts/v2", Scope: request.Scope, Bytes: int64(len(code)), SHA256: fmt.Sprintf("%x", sha256.Sum256(code)), MediaType: "application/json", Producer: artifact.Producer{PluginID: "example.parse", PluginVersion: "0.1.0", InvocationID: "code-catalog-fixture", ConfigDigest: strings.Repeat("a", 64)}}
	codeRef, err := objects.Put(t.Context(), codeRef, strings.NewReader(string(code)), 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/manifests/semantic.json")
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := plugin.NewCatalog(t.Context(), index)
	if err != nil {
		t.Fatal(err)
	}
	executor := plugin.Executor{Manifest: manifest, PackageDigest: strings.Repeat("c", 64), OperationID: "execute", RunOutputs: func(context.Context, plugin.Invocation, [][]byte) (plugin.RawResult, error) {
		one := int64(1)
		return plugin.RawResult{Status: "PARTIAL", Coverage: plugin.StageCoverage{Unit: "cpgs", Seen: &one, Analyzed: &one, Reasons: []string{"static_analysis_limits"}}, Limitations: []string{"Source trust and runtime exploitability remain unassessed."}, Outputs: []plugin.RawOutput{{Port: "security", Kind: "security.facts", SchemaID: "codexploit/security-facts/v2", MediaType: "application/json", Bytes: int64(len(payload)), SHA256: fmt.Sprintf("%x", sha256.Sum256(payload)), Open: func() (io.ReadCloser, error) { return io.NopCloser(strings.NewReader(string(payload))), nil }}}}, nil
	}}
	host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Scopes: index, Artifacts: objects, Executors: []plugin.Executor{executor}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = host.Close() })
	request.ID, request.PluginID, request.PluginVersion, request.OperationID = "semantic-catalog-fixture", "example.semantic", "0.1.0", "execute"
	request.PackageDigest = executor.PackageDigest
	request.Inputs = append(request.Inputs, codeRef)
	inv, err := host.Execute(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	done, err := host.Wait(t.Context(), request.Scope, inv.ID)
	if err != nil {
		t.Fatal(err)
	}
	if done.Status != "PARTIAL" {
		if len(done.Outputs) != 0 {
			t.Fatal("rejected semantic output was published")
		}
		return done, nil
	}
	documents, err := host.StandardResults(t.Context(), request.Scope, inv.ID, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return done, documents
}
