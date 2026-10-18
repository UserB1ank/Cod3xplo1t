package api

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestStorageStatusPreservesCompleteMemoryAndSQLiteModes(t *testing.T) {
	for _, driver := range []string{"memory", "sqlite"} {
		t.Run(driver, func(t *testing.T) {
			t.Parallel()
			workspace := t.TempDir()
			db := "memory"
			if driver == "sqlite" {
				db = filepath.Join(workspace, "catalog.db")
			}
			rt, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { rt.Close() })
			ts := httptest.NewServer(NewServer(rt.Store, rt.Manager, rt.Analyzer, WithAuth(testAuthenticator(t))).Handler())
			t.Cleanup(ts.Close)
			r := do(t, ts, "GET", "/api/v1/storage/status", nil, nil)
			var status storage.Status
			r.decode(t, &status)
			if r.status != 200 || status.Driver != driver || status.Profile != "complete" || status.Readiness != "ready" || status.Durable != (driver == "sqlite") {
				t.Fatalf("status: %d %s", r.status, r.body)
			}
			for name, enabled := range status.Capabilities {
				if !enabled {
					t.Errorf("complete mode lost %s", name)
				}
			}
			if r.header.Get("Cache-Control") != "no-store" {
				t.Fatal("status is cacheable")
			}
		})
	}
}
