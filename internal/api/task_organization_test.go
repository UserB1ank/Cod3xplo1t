package api

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
)

func organizationFixture(t *testing.T, ts *httptest.Server) (string, string) {
	t.Helper()
	snapshot := createAuditedSnapshot(t, ts)
	r := do(t, ts, http.MethodGet, "/api/snapshots/"+snapshot, nil, nil)
	var body struct {
		Snapshot struct {
			Project string `json:"project_id"`
		} `json:"snapshot"`
	}
	r.decode(t, &body)
	if r.status != 200 || body.Snapshot.Project == "" {
		t.Fatalf("snapshot project: %d %s", r.status, r.body)
	}
	return body.Snapshot.Project, snapshot
}

func TestPinnedTaskRemainsPinnedAfterDatabaseReopen(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	project, snapshot := organizationFixture(t, env.ts)
	id := createOrganizedTask(t, env.ts, project, snapshot, "Persistent pin")
	read := do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
	r := do(t, env.ts, http.MethodPatch, "/api/projects/"+project+"/tasks/"+id, map[string]any{"pinned": true}, map[string]string{"If-Match": read.header.Get("ETag")})
	if r.status != 200 {
		t.Fatalf("pin: %d %s", r.status, r.body)
	}
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	reopened := serveTestEnv(t, runtime, false)
	read = do(t, reopened.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
	var task struct {
		Pinned bool `json:"pinned"`
	}
	read.decode(t, &task)
	if read.status != 200 || !task.Pinned {
		t.Fatalf("pin lost after reopen: %d %s", read.status, read.body)
	}
}

func createOrganizedTask(t *testing.T, ts *httptest.Server, project, snapshot, name string) string {
	t.Helper()
	r := do(t, ts, http.MethodPost, "/api/projects/"+project+"/tasks", map[string]any{"name": name, "objective": "Review code paths", "snapshot_id": snapshot}, nil)
	var body struct {
		Task struct {
			ID string `json:"audit_id"`
		} `json:"task"`
	}
	r.decode(t, &body)
	if r.status != 201 || body.Task.ID == "" {
		t.Fatalf("create task: %d %s", r.status, r.body)
	}
	return body.Task.ID
}

func TestTaskCanBePinnedThroughProjectAPI(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	project, snapshot := organizationFixture(t, env.ts)
	id := createOrganizedTask(t, env.ts, project, snapshot, "Priority review")
	read := do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
	updated := do(t, env.ts, http.MethodPatch, "/api/projects/"+project+"/tasks/"+id, map[string]any{"pinned": true}, map[string]string{"If-Match": read.header.Get("ETag")})
	if updated.status != 200 {
		t.Fatalf("pin task: %d %s", updated.status, updated.body)
	}
	read = do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
	var task struct {
		Pinned   bool   `json:"pinned"`
		Snapshot string `json:"snapshot_id"`
	}
	read.decode(t, &task)
	if read.status != 200 || !task.Pinned || task.Snapshot != snapshot {
		t.Fatalf("pin was not persisted: %d %s", read.status, read.body)
	}
}

func TestTaskArchiveWaitsForPausedIdleStateAndPreservesPaths(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace := t.TempDir()
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, runtime, false)
			project, snapshot := organizationFixture(t, env.ts)
			id := createOrganizedTask(t, env.ts, project, snapshot, "Archive review")
			edit := func(archived bool) response {
				read := do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
				return do(t, env.ts, http.MethodPatch, "/api/projects/"+project+"/tasks/"+id, map[string]any{"archived": archived}, map[string]string{"If-Match": read.header.Get("ETag")})
			}
			if r := edit(true); r.status != 409 {
				t.Fatalf("unpaused archive: %d %s", r.status, r.body)
			}
			paths := auditPaths(t, env.ts, id, "")
			pathID := paths.Paths[0].ID
			claimed := do(t, env.ts, http.MethodPost, "/api/paths/"+pathID+"/claim", map[string]any{"owner": "fixture-worker", "ttl_seconds": 300}, nil)
			if claimed.status != 200 {
				t.Fatalf("claim: %d %s", claimed.status, claimed.body)
			}
			read := do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
			paused := do(t, env.ts, http.MethodPost, "/api/tasks/"+id+"/pause", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
			if paused.status != 200 {
				t.Fatalf("pause: %d %s", paused.status, paused.body)
			}
			if r := edit(true); r.status != 409 {
				t.Fatalf("active lease archived: %d %s", r.status, r.body)
			}
			released := do(t, env.ts, http.MethodPost, "/api/paths/"+pathID+"/release", map[string]any{"owner": "fixture-worker", "reason": "fixture complete"}, nil)
			if released.status != 200 {
				t.Fatalf("release: %d %s", released.status, released.body)
			}
			archived := edit(true)
			if archived.status != 200 {
				t.Fatalf("archive: %d %s", archived.status, archived.body)
			}
			remaining := auditPaths(t, env.ts, id, "")
			if remaining.Total != paths.Total || remaining.Paths[0].SnapshotID != snapshot {
				t.Fatal("archiving discarded paths or graph references")
			}
			resume := do(t, env.ts, http.MethodPost, "/api/tasks/"+id+"/resume", map[string]any{}, map[string]string{"If-Match": archived.header.Get("ETag")})
			if resume.status != 409 {
				t.Fatalf("archived task resumed directly: %d %s", resume.status, resume.body)
			}
			restored := edit(false)
			if restored.status != 200 {
				t.Fatalf("restore: %d %s", restored.status, restored.body)
			}
			var task struct {
				Archived bool `json:"archived"`
				Paused   bool `json:"paused"`
			}
			restored.decode(t, &task)
			if task.Archived || !task.Paused {
				t.Fatal("restore unexpectedly resumed scheduling")
			}
		})
	}
}

func TestTaskCategoriesAreProjectScopedAndCannotRemoveUsedNames(t *testing.T) {
	t.Parallel()
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			env := newOrganizationEnv(t, backend)
			project, snapshot := organizationFixture(t, env.ts)
			endpoint := "/api/projects/" + project + "/task-categories"
			read := do(t, env.ts, http.MethodGet, endpoint, nil, nil)
			if read.status != 200 {
				t.Fatalf("read categories: %d %s", read.status, read.body)
			}
			saved := do(t, env.ts, http.MethodPut, endpoint, map[string]any{"categories": []string{"Authorization", "Data access"}}, map[string]string{"If-Match": read.header.Get("ETag")})
			if saved.status != 200 {
				t.Fatalf("save categories: %d %s", saved.status, saved.body)
			}
			id := createOrganizedTask(t, env.ts, project, snapshot, "Categorized review")
			read = do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
			assigned := do(t, env.ts, http.MethodPatch, "/api/projects/"+project+"/tasks/"+id, map[string]any{"category": "Authorization"}, map[string]string{"If-Match": read.header.Get("ETag")})
			if assigned.status != 200 {
				t.Fatalf("assign category: %d %s", assigned.status, assigned.body)
			}
			var task struct {
				Category string `json:"category"`
			}
			assigned.decode(t, &task)
			if task.Category != "Authorization" {
				t.Fatal("category was not saved")
			}
			removed := do(t, env.ts, http.MethodPut, endpoint, map[string]any{"categories": []string{"Data access"}}, map[string]string{"If-Match": saved.header.Get("ETag")})
			if removed.status != 409 {
				t.Fatalf("removed a used category: %d %s", removed.status, removed.body)
			}
			other := createProject(t, env.ts, newTestSource(t)).Project
			otherTask := createOrganizedTask(t, env.ts, other.ID, func() string {
				r := do(t, env.ts, http.MethodPost, "/api/projects/"+other.ID+"/snapshots", map[string]any{"build_graph": true, "build_asg": true}, nil)
				if r.status != 201 {
					t.Fatalf("other snapshot: %d %s", r.status, r.body)
				}
				var body struct {
					Snapshot struct {
						ID string `json:"snapshot_id"`
					} `json:"snapshot"`
				}
				r.decode(t, &body)
				return body.Snapshot.ID
			}(), "Other project review")
			read = do(t, env.ts, http.MethodGet, "/api/tasks/"+otherTask, nil, nil)
			wrong := do(t, env.ts, http.MethodPatch, "/api/projects/"+other.ID+"/tasks/"+otherTask, map[string]any{"category": "Authorization"}, map[string]string{"If-Match": read.header.Get("ETag")})
			if wrong.status != 400 {
				t.Fatalf("cross-project category accepted: %d %s", wrong.status, wrong.body)
			}

		})
	}
}

func TestTaskClassificationAndArchiveSurviveDatabaseReopen(t *testing.T) {
	t.Parallel()
	workspace := t.TempDir()
	config := app.Config{Workspace: workspace, DBPath: filepath.Join(workspace, "state.db")}
	runtime, err := app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	env := serveTestEnv(t, runtime, false)
	project, snapshot := organizationFixture(t, env.ts)
	categories := "/api/projects/" + project + "/task-categories"
	read := do(t, env.ts, http.MethodGet, categories, nil, nil)
	if read.status != 200 {
		t.Fatalf("categories: %d %s", read.status, read.body)
	}
	saved := do(t, env.ts, http.MethodPut, categories, map[string]any{"categories": []string{"Authorization"}}, map[string]string{"If-Match": read.header.Get("ETag")})
	if saved.status != 200 {
		t.Fatalf("save: %d %s", saved.status, saved.body)
	}
	id := createOrganizedTask(t, env.ts, project, snapshot, "Retained archive")
	read = do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
	paused := do(t, env.ts, http.MethodPost, "/api/tasks/"+id+"/pause", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
	updated := do(t, env.ts, http.MethodPatch, "/api/projects/"+project+"/tasks/"+id, map[string]any{"category": "Authorization", "archived": true, "pinned": true}, map[string]string{"If-Match": paused.header.Get("ETag")})
	if updated.status != 200 {
		t.Fatalf("organize: %d %s", updated.status, updated.body)
	}
	env.ts.Close()
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = app.Build(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	reopened := serveTestEnv(t, runtime, false)
	read = do(t, reopened.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
	var task struct {
		Pinned, Archived, Paused bool
		Category                 string
		Snapshot                 string `json:"snapshot_id"`
	}
	read.decode(t, &task)
	if read.status != 200 || !task.Pinned || !task.Archived || !task.Paused || task.Category != "Authorization" || task.Snapshot != snapshot {
		t.Fatalf("organization lost after restart: %d %s", read.status, read.body)
	}
	read = do(t, reopened.ts, http.MethodGet, categories, nil, nil)
	var catalog struct {
		Categories []string `json:"categories"`
	}
	read.decode(t, &catalog)
	if read.status != 200 || len(catalog.Categories) != 1 || catalog.Categories[0] != "Authorization" {
		t.Fatalf("catalog lost: %d %s", read.status, read.body)
	}
}

func TestTaskListingFiltersAndPagesRealOrganizedTasks(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace := t.TempDir()
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, runtime, false)
			project, snapshot := organizationFixture(t, env.ts)
			endpoint := "/api/projects/" + project + "/tasks"
			categoryURL := "/api/projects/" + project + "/task-categories"
			read := do(t, env.ts, http.MethodGet, categoryURL, nil, nil)
			r := do(t, env.ts, http.MethodPut, categoryURL, map[string]any{"categories": []string{"Auth", "Data"}}, map[string]string{"If-Match": read.header.Get("ETag")})
			if r.status != 200 {
				t.Fatalf("categories: %d %s", r.status, r.body)
			}
			ids := []string{}
			for i, name := range []string{"Alpha", "Beta", "Gamma"} {
				id := createOrganizedTask(t, env.ts, project, snapshot, name)
				ids = append(ids, id)
				category := "Auth"
				if i == 1 {
					category = "Data"
				}
				read = do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
				r = do(t, env.ts, http.MethodPatch, endpoint+"/"+id, map[string]any{"pinned": i == 0, "category": category}, map[string]string{"If-Match": read.header.Get("ETag")})
				if r.status != 200 {
					t.Fatalf("organize: %d %s", r.status, r.body)
				}
			}
			page := func(query string, total int) []string {
				r := do(t, env.ts, http.MethodGet, endpoint+query, nil, nil)
				var body struct {
					Total int `json:"total"`
					Tasks []struct {
						ID string `json:"audit_id"`
					} `json:"tasks"`
				}
				r.decode(t, &body)
				if r.status != 200 || body.Total != total {
					t.Fatalf("page %s: %d %s", query, r.status, r.body)
				}
				result := []string{}
				for _, task := range body.Tasks {
					result = append(result, task.ID)
				}
				return result
			}
			first := page("?sort=organized&archived=false&limit=1", 3)
			if len(first) != 1 || first[0] != ids[0] {
				t.Fatalf("pinned task not first: %v", first)
			}
			seen := map[string]bool{first[0]: true}
			for offset := 1; offset < 3; offset++ {
				next := page(fmt.Sprintf("?sort=organized&archived=false&limit=1&offset=%d", offset), 3)
				if len(next) != 1 || seen[next[0]] {
					t.Fatalf("unstable page: %v", next)
				}
				seen[next[0]] = true
			}
			if len(page("?sort=organized&offset=100&limit=1", 3)) != 0 {
				t.Fatal("page beyond end was not empty")
			}
			filtered := page("?q=Gamma&category=Auth", 1)
			if len(filtered) != 1 || filtered[0] != ids[2] {
				t.Fatalf("combined search/category filter: %v", filtered)
			}
			page("?category=", 0)
			read = do(t, env.ts, http.MethodGet, "/api/tasks/"+ids[2], nil, nil)
			r = do(t, env.ts, http.MethodPost, "/api/tasks/"+ids[2]+"/pause", map[string]any{}, map[string]string{"If-Match": read.header.Get("ETag")})
			if r.status != 200 {
				t.Fatalf("pause: %d %s", r.status, r.body)
			}
			paused := page("?state=PAUSED", 1)
			if len(paused) != 1 || paused[0] != ids[2] {
				t.Fatalf("state filter: %v", paused)
			}
			r = do(t, env.ts, http.MethodPatch, endpoint+"/"+ids[2], map[string]any{"archived": true}, map[string]string{"If-Match": r.header.Get("ETag")})
			if r.status != 200 {
				t.Fatalf("archive: %d %s", r.status, r.body)
			}
			page("?archived=false", 2)
			archived := page("?archived=true", 1)
			if archived[0] != ids[2] {
				t.Fatal("archive filter lost its task")
			}
			page("", 3)
		})
	}
}

func TestConcurrentTaskOrganizationRejectsStaleEdits(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace := t.TempDir()
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, runtime, false)
			project, snapshot := organizationFixture(t, env.ts)
			id := createOrganizedTask(t, env.ts, project, snapshot, "Concurrent edits")
			route := "/api/projects/" + project + "/tasks/" + id
			read := do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
			if r := do(t, env.ts, http.MethodPatch, route, map[string]any{"pinned": true}, nil); r.status != 428 {
				t.Fatalf("missing version: %d", r.status)
			}
			if r := doAs(t, env.ts, readerSecret, http.MethodPatch, route, map[string]any{"pinned": true}, map[string]string{"If-Match": read.header.Get("ETag")}); r.status != 403 {
				t.Fatalf("reader mutation: %d", r.status)
			}
			other := createProject(t, env.ts, newTestSource(t)).Project
			if r := do(t, env.ts, http.MethodPatch, "/api/projects/"+other.ID+"/tasks/"+id, map[string]any{"pinned": true}, map[string]string{"If-Match": read.header.Get("ETag")}); r.status != 404 {
				t.Fatalf("cross-project mutation: %d %s", r.status, r.body)
			}
			ready, release := make(chan struct{}, 2), make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(release) })
			results := make(chan int, 2)
			for _, secret := range []string{adminSecret, admin2Secret} {
				body := &gatedProjectBody{reader: strings.NewReader(`{"pinned":true}`), ready: ready, release: release}
				req := httptest.NewRequest(http.MethodPatch, route, body)
				req.Header.Set("Authorization", "Bearer "+secret)
				req.Header.Set("If-Match", read.header.Get("ETag"))
				go func() { rec := httptest.NewRecorder(); env.ts.Config.Handler.ServeHTTP(rec, req); results <- rec.Code }()
			}
			for range 2 {
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Fatal("edit did not reach body gate")
				}
			}
			unblock.Do(func() { close(release) })
			counts := map[int]int{}
			for range 2 {
				counts[<-results]++
			}
			if counts[200] != 1 || counts[412] != 1 {
				t.Fatalf("concurrent writes overwrote each other: %v", counts)
			}
			read = do(t, env.ts, http.MethodGet, "/api/tasks/"+id, nil, nil)
			var task struct {
				Pinned bool `json:"pinned"`
			}
			read.decode(t, &task)
			if !task.Pinned {
				t.Fatal("winning edit was lost")
			}
		})
	}
}

func TestTaskStateFilterUsesLivePathActivity(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			workspace := t.TempDir()
			db := "memory"
			if backend == "sqlite" {
				db = filepath.Join(workspace, "state.db")
			}
			runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
			if err != nil {
				t.Fatal(err)
			}
			env := serveTestEnv(t, runtime, false)
			project, snapshot := organizationFixture(t, env.ts)
			id := createOrganizedTask(t, env.ts, project, snapshot, "Live activity")
			paths := auditPaths(t, env.ts, id, "")
			r := do(t, env.ts, http.MethodPost, "/api/paths/"+paths.Paths[0].ID+"/claim", map[string]any{"owner": "fixture-live", "ttl_seconds": 300}, nil)
			if r.status != 200 {
				t.Fatalf("claim: %d %s", r.status, r.body)
			}
			r = do(t, env.ts, http.MethodGet, "/api/projects/"+project+"/tasks?state=RUNNING", nil, nil)
			var page struct {
				Total int
				Tasks []struct {
					ID         string         `json:"audit_id"`
					Counts     map[string]int `json:"counts_by_status"`
					CanArchive bool           `json:"can_archive"`
				}
			}
			r.decode(t, &page)
			if r.status != 200 || page.Total != 1 || len(page.Tasks) != 1 || page.Tasks[0].ID != id || page.Tasks[0].Counts["ANALYZING"] != 1 || page.Tasks[0].CanArchive {
				t.Fatalf("live state not reflected: %d %s", r.status, r.body)
			}
		})
	}
}

func newOrganizationEnv(t *testing.T, backend string) *testEnv {
	t.Helper()
	workspace := t.TempDir()
	db := "memory"
	if backend == "sqlite" {
		db = filepath.Join(workspace, "state.db")
	}
	runtime, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
	if err != nil {
		t.Fatal(err)
	}
	return serveTestEnv(t, runtime, false)
}

func TestConcurrentCategoryCatalogWritesRejectStaleVersion(t *testing.T) {
	for _, backend := range []string{"memory", "sqlite"} {
		t.Run(backend, func(t *testing.T) {
			env := newOrganizationEnv(t, backend)
			project, _ := organizationFixture(t, env.ts)
			route := "/api/projects/" + project + "/task-categories"
			read := do(t, env.ts, http.MethodGet, route, nil, nil)
			if r := doAs(t, env.ts, readerSecret, http.MethodPut, route, map[string]any{"categories": []string{"Private edit"}}, map[string]string{"If-Match": read.header.Get("ETag")}); r.status != 403 {
				t.Fatalf("reader edited catalog: %d", r.status)
			}
			ready, release := make(chan struct{}, 2), make(chan struct{})
			var unblock sync.Once
			defer unblock.Do(func() { close(release) })
			results := make(chan int, 2)
			for _, name := range []string{"Auth", "Data"} {
				body := &gatedProjectBody{reader: strings.NewReader(`{"categories":["` + name + `"]}`), ready: ready, release: release}
				req := httptest.NewRequest(http.MethodPut, route, body)
				req.Header.Set("Authorization", "Bearer "+adminSecret)
				req.Header.Set("If-Match", read.header.Get("ETag"))
				go func() { rec := httptest.NewRecorder(); env.ts.Config.Handler.ServeHTTP(rec, req); results <- rec.Code }()
			}
			for range 2 {
				select {
				case <-ready:
				case <-time.After(5 * time.Second):
					t.Fatal("catalog edit did not reach body gate")
				}
			}
			unblock.Do(func() { close(release) })
			counts := map[int]int{}
			for range 2 {
				counts[<-results]++
			}
			if counts[200] != 1 || counts[412] != 1 {
				t.Fatalf("catalog edits overwrote each other: %v", counts)
			}
			read = do(t, env.ts, http.MethodGet, route, nil, nil)
			var catalog struct {
				Categories []string
				Version    int64
			}
			read.decode(t, &catalog)
			if len(catalog.Categories) != 1 || catalog.Version != 2 {
				t.Fatalf("winning catalog missing: %s", read.body)
			}
		})
	}
}
