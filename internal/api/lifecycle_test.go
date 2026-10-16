package api

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/repository"
)

type gatedProjectBody struct {
	reader  *strings.Reader
	ready   chan<- struct{}
	release <-chan struct{}
	once    sync.Once
}

func (b *gatedProjectBody) Read(p []byte) (int, error) {
	b.once.Do(func() { b.ready <- struct{}{}; <-b.release })
	return b.reader.Read(p)
}

func TestConcurrentProjectUpdatesRequireCurrentVersion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace := filepath.Join(t.TempDir(), "work")
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "store.db")
			}
			rt, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, rt, false)
			project := createProject(t, env.ts, env.source)
			route := "/api/projects/" + project.Project.ID
			get := do(t, env.ts, http.MethodGet, route, nil, nil)
			ready, release := make(chan struct{}, 2), make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(release) })
			results := make(chan *httptest.ResponseRecorder, 2)
			for _, name := range []string{"first", "second"} {
				body := &gatedProjectBody{reader: strings.NewReader(`{"name":"` + name + `"}`), ready: ready, release: release}
				req := httptest.NewRequest(http.MethodPatch, route, body)
				req.Header.Set("Authorization", "Bearer "+adminSecret)
				req.Header.Set("If-Match", get.header.Get("ETag"))
				go func() {
					rec := httptest.NewRecorder()
					env.ts.Config.Handler.ServeHTTP(rec, req)
					results <- rec
				}()
			}
			for range 2 {
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Fatal("PATCH did not reach the body gate")
				}
			}
			unblock.Do(func() { close(release) })
			counts := map[int]int{}
			for range 2 {
				counts[(<-results).Code]++
			}
			if counts[http.StatusOK] != 1 || counts[http.StatusPreconditionFailed] != 1 {
				t.Fatalf("concurrent PATCH responses = %v, want one 200 and one 412", counts)
			}
		})
	}
}

type failedSnapshotRemoval struct{ *repository.Manager }

func (m failedSnapshotRemoval) Remove(string) error {
	return errors.New("injected snapshot filesystem failure")
}

func TestSnapshotDeletionCanRetryAfterFilesystemFailure(t *testing.T) {
	env := newTestEnv(t, false)
	project := createProject(t, env.ts, env.source)
	created := do(t, env.ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{}, nil)
	if created.status != http.StatusCreated {
		t.Fatalf("create: %d %s", created.status, created.body)
	}
	var snap snapshotResponse
	created.decode(t, &snap)
	id := snap.Snapshot.SnapshotID
	broken := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer, WithAuth(testAuthenticator(t)))
	broken.snapshots.Manager = failedSnapshotRemoval{env.rt.Manager}
	req := httptest.NewRequest(http.MethodDelete, "/api/snapshots/"+id, nil)
	req.Header.Set("Authorization", "Bearer "+adminSecret)
	rec := httptest.NewRecorder()
	broken.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("failed delete = %d", rec.Code)
	}
	if _, err := env.rt.Store.GetSnapshot(context.Background(), id); err != nil {
		t.Fatalf("filesystem failure discarded the snapshot record: %v", err)
	}
	if _, err := env.rt.Manager.Load(id); err != nil {
		t.Fatalf("disk snapshot: %v", err)
	}
	retry := do(t, env.ts, http.MethodDelete, "/api/snapshots/"+id, nil, nil)
	if retry.status != http.StatusNoContent {
		t.Fatalf("retry = %d %s", retry.status, retry.body)
	}
	if _, err := env.rt.Manager.Load(id); err == nil {
		t.Fatal("snapshot survived retry")
	}
}
