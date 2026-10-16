package graph_test

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/graph"
	"github.com/open-mcp-ai/Codexploit/internal/path"
)

type claimBudgetGate struct {
	path.Store
	ready   chan<- struct{}
	release <-chan struct{}
}

func (s *claimBudgetGate) ClaimPath(id, owner, until string, from []path.Status, actor string) (*path.Path, error) {
	s.ready <- struct{}{}
	<-s.release
	return s.Store.ClaimPath(id, owner, until, from, actor)
}

func TestConcurrentNamedClaimsRespectAuditBudget(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			fixture := newAgentFixture(t)
			if len(fixture.paths) < 2 {
				t.Fatal("fixture needs two paths")
			}
			audit, err := fixture.store.GetAudit(fixture.auditID)
			if err != nil {
				t.Fatal(err)
			}
			audit.Limits.MaxActiveLeases = 1
			var store path.Store = fixture.store
			if backend == "sqlite" {
				workspace := filepath.Join(t.TempDir(), "work")
				rt, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "store.db")})
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := rt.Close(); err != nil {
						t.Error(err)
					}
				})
				store = rt.Store
				if err := store.CreateAudit(*audit); err != nil {
					t.Fatal(err)
				}
				if err := store.ReplacePaths(audit.ID, fixture.paths); err != nil {
					t.Fatal(err)
				}
			} else if err := store.UpdateAudit(*audit, audit.Version); err != nil {
				t.Fatal(err)
			}
			ready, release := make(chan struct{}, 2), make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(release) })
			gate := &claimBudgetGate{Store: store, ready: ready, release: release}
			coordinator := graph.NewAgentCoordinator(path.NewService(gate, fixture.audit.Engine), "worker")
			results := make(chan error, 2)
			for i := range 2 {
				id, owner := fixture.paths[i].ID, fmt.Sprintf("worker-%d", i)
				go func() {
					_, err := coordinator.ClaimSpecificPath(context.Background(), id, owner, time.Minute)
					results <- err
				}()
			}
			for range 2 {
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Fatal("claim did not reach gate")
				}
			}
			unblock.Do(func() { close(release) })
			success, limited := 0, 0
			for range 2 {
				err := <-results
				if err == nil {
					success++
				} else if errors.Is(err, path.ErrBudgetExceeded) {
					limited++
				} else {
					t.Errorf("claim: %v", err)
				}
			}
			if success != 1 || limited != 1 {
				t.Fatalf("successful=%d limited=%d, want 1 each", success, limited)
			}
		})
	}
}
