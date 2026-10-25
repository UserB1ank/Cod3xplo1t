package contracts_test

import (
	"encoding/json"
	"net/url"
	"os"
	"path"
	"testing"

	"github.com/google/jsonschema-go/jsonschema"
	v1 "github.com/open-mcp-ai/Codexploit/contracts/v1"
	v2 "github.com/open-mcp-ai/Codexploit/contracts/v2"
)

func TestProductionSchemasResolveOfflineAndTemplatesMatch(t *testing.T) {
	load := func(version, name string) (*jsonschema.Schema, error) {
		fs := v2.Files
		if version == "v1" {
			fs = v1.Files
		}
		raw, err := fs.ReadFile(name)
		if err != nil {
			return nil, err
		}
		var s jsonschema.Schema
		err = json.Unmarshal(raw, &s)
		return &s, err
	}
	entries, err := v2.Files.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if path.Ext(entry.Name()) != ".json" || entry.Name() == "stages.json" {
			continue
		}
		t.Run(entry.Name(), func(t *testing.T) {
			schema, err := load("v2", entry.Name())
			if err != nil {
				t.Fatal(err)
			}
			if _, err = schema.Resolve(&jsonschema.ResolveOptions{Loader: func(u *url.URL) (*jsonschema.Schema, error) {
				return load(path.Base(path.Dir(u.Path)), path.Base(u.Path))
			}}); err != nil {
				t.Fatal(err)
			}
		})
	}
	schema, err := load("v2", "manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := schema.Resolve(nil)
	if err != nil {
		t.Fatal(err)
	}
	templates := "../../docs/design/plugin-system-v2/templates/manifests"
	rows, err := os.ReadDir(templates)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 10 {
		t.Fatal("each stage needs a developer template")
	}
	for _, entry := range rows {
		raw, err := os.ReadFile(path.Join(templates, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if json.Unmarshal(raw, &value) != nil || resolved.Validate(value) != nil {
			t.Fatalf("invalid manifest template: %s", entry.Name())
		}
	}
	raw, err := os.ReadFile("../../docs/design/plugin-system-v2/templates/stages.json")
	if err != nil {
		t.Fatal(err)
	}
	actual, _ := v2.Files.ReadFile("stages.json")
	var a, b any
	_ = json.Unmarshal(raw, &a)
	_ = json.Unmarshal(actual, &b)
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	if string(x) != string(y) {
		t.Fatal("template stage registry differs from production")
	}
}
