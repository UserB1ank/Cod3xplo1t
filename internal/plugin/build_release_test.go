package plugin_test

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestStageRebuildKeepsDistinctImmutableReleaseIdentities(t *testing.T) {
	old, _, objects, index := hostFixture(t, map[string]string{"main.go": "package main\n"})
	_ = old.Close()
	manifest, err := os.ReadFile("../../plugins/joern/manifest.json")
	if err != nil {
		t.Fatal(err)
	}
	for i, digest := range []string{strings.Repeat("a", 64), strings.Repeat("b", 64)} {
		catalog, err := plugin.NewCatalog(t.Context(), index)
		if err != nil {
			t.Fatal(err)
		}
		host, err := plugin.NewHost(plugin.Deps{Catalog: catalog, Repository: index, Artifacts: objects, Scopes: index, Executors: []plugin.Executor{{Manifest: manifest, PackageDigest: digest, OperationID: "parse", RunOutputs: func(context.Context, plugin.Invocation, [][]byte) (plugin.RawResult, error) {
			return plugin.RawResult{}, plugin.ErrUnsupported
		}}}})
		if err != nil {
			t.Fatalf("rebuild rejected: %v", err)
		}
		_ = host.Close()
		if i == 0 {
			rows, err := index.ListPluginReleases(t.Context(), "codexploit.joern", "2.1.1")
			if err != nil || len(rows) != 1 {
				t.Fatal("initial build missing")
			}
			legacy := rows[0]
			legacy.BuildID = ""
			if err := index.PutPluginRelease(t.Context(), legacy); err != nil {
				t.Fatal(err)
			}
		}

	}
	rows, err := index.ListPluginReleases(t.Context(), "codexploit.joern", "2.1.1")
	if err != nil || len(rows) != 3 {
		t.Fatalf("releases: %+v %v", rows, err)
	}
	for _, row := range rows {
		if row.BuildID != "" && row.BuildID != row.PackageDigest {
			t.Fatal("build identity is not bound to sealed package digest")
		}
	}
}
