package workflow_test

import (
	"context"
	"encoding/json"
	"errors"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/workflow"
)

func TestCatalogSerializesConcurrentHeadUpdatesAndReturnsIndependentVersions(t *testing.T) {
	for _, database := range []string{"memory", "sqlite"} {
		t.Run(database, func(t *testing.T) {
			dir := t.TempDir()
			db := "memory"
			if database == "sqlite" {
				db = filepath.Join(dir, "state.db")
			}
			rt, err := app.Build(context.Background(), app.Config{Workspace: dir, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = rt.Close() })
			if err := rt.Store.PutProject(context.Background(), storage.Project{ID: "project-a", Name: "Fixture"}); err != nil {
				t.Fatal(err)
			}
			c := rt.Workflows
			s := fixture()
			raw, _ := json.Marshal(s)
			prior, err := c.Save(context.Background(), "project-a", raw, "")
			if err != nil {
				t.Fatal(err)
			}
			results := make(chan error, 8)
			for i := 0; i < 8; i++ {
				go func(i int) {
					spec := fixture()
					spec.Version = "1.1.0"
					spec.Name = string(rune('A' + i))
					raw, _ := json.Marshal(spec)
					_, err := c.Save(context.Background(), "project-a", raw, prior.Digest)
					results <- err
				}(i)
			}
			success, conflicts := 0, 0
			for i := 0; i < 8; i++ {
				err := <-results
				switch {
				case err == nil:
					success++
				case errors.Is(err, workflow.ErrConflict):
					conflicts++
				default:
					t.Fatalf("update: %v", err)
				}
			}
			if success != 1 || conflicts != 7 {
				t.Fatalf("CAS accepted %d writers, conflicts %d", success, conflicts)
			}
			prior.Spec.Nodes[0].Needs = append(prior.Spec.Nodes[0].Needs, "mutated")
			stored, err := c.Get(context.Background(), "project-a", "discovery", "1.0.0")
			if err != nil || len(stored.Spec.Nodes[0].Needs) != 1 || stored.Spec.Nodes[0].Needs[0] != "semantic" {
				t.Fatalf("returned record mutated old version: %+v %v", stored, err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			s.Version = "1.2.0"
			raw, _ = json.Marshal(s)
			if _, err := c.Save(ctx, "project-a", raw, prior.Digest); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancelled save: %v", err)
			}
		})
	}
}
