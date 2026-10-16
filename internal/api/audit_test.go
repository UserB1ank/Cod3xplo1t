package api

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/path"
)

// auditPathPage is the paths listing payload, named so a helper and a test can
// share the exact shape.
type auditPathPage struct {
	AuditID         string         `json:"audit_id"`
	Paths           []path.Path    `json:"paths"`
	Total           int            `json:"total"`
	ObjectiveCounts map[string]int `json:"objective_counts"`
}

// createAuditedSnapshot freezes the ASG fixture and builds both graphs in one
// request: an audit request needs an attack surface, not just an SCG.
func createAuditedSnapshot(t *testing.T, ts *httptest.Server) string {
	t.Helper()
	project := createProject(t, ts, asgFixtureSource(t))
	create := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true, "build_asg": true}, nil)
	if create.status != http.StatusCreated {
		t.Fatalf("create snapshot: %d %s", create.status, create.body)
	}
	var created snapshotResponse
	create.decode(t, &created)
	if created.Graph == nil || created.ASG == nil || created.Snapshot.SnapshotID == "" {
		t.Fatalf("fixture produced no attack surface: %s", create.body)
	}
	return created.Snapshot.SnapshotID
}

// createAudit posts an audit request and fails the test when it is not created.
func createAudit(t *testing.T, ts *httptest.Server, body map[string]any) auditResponse {
	t.Helper()
	resp := do(t, ts, http.MethodPost, "/api/audits", body, nil)
	if resp.status != http.StatusCreated {
		t.Fatalf("create audit: %d %s", resp.status, resp.body)
	}
	var out auditResponse
	resp.decode(t, &out)
	if out.Audit == nil || out.Audit.ID == "" {
		t.Fatalf("audit response has no audit id: %s", resp.body)
	}
	if out.PathCount == 0 {
		t.Fatalf("audit queued no path: %s", resp.body)
	}
	return out
}

// auditPaths fetches one page of an audit's queue.
func auditPaths(t *testing.T, ts *httptest.Server, auditID, query string) auditPathPage {
	t.Helper()
	resp := do(t, ts, http.MethodGet, "/api/audits/"+auditID+"/paths"+query, nil, nil)
	if resp.status != http.StatusOK {
		t.Fatalf("paths%s: %d %s", query, resp.status, resp.body)
	}
	var page auditPathPage
	resp.decode(t, &page)
	return page
}

func TestAuditGenerationAndQueue(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)

	created := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	auditID := created.Audit.ID
	if created.Replayed {
		t.Error("a fresh audit reported itself as replayed")
	}
	if created.Audit.Status != path.AuditReady {
		t.Errorf("audit status = %q, want READY", created.Audit.Status)
	}
	if created.Audit.PathCount != created.PathCount {
		t.Errorf("path_count %d disagrees with the audit's %d", created.PathCount, created.Audit.PathCount)
	}

	// The same request is a replay, not a second ranking: the ids must match and
	// the status must say so.
	repeat := do(t, ts, http.MethodPost, "/api/audits", map[string]any{"snapshot_id": snapID}, nil)
	if repeat.status != http.StatusOK {
		t.Fatalf("repeat audit = %d, want 200 (%s)", repeat.status, repeat.body)
	}
	var repeated auditResponse
	repeat.decode(t, &repeated)
	if !repeated.Replayed || repeated.Audit.ID != auditID {
		t.Errorf("repeat audit = %+v, want replayed audit %s", repeated, auditID)
	}

	// The write goes through the idempotency wrapper like every other write.
	headers := map[string]string{"Idempotency-Key": "audit-key-1"}
	first := do(t, ts, http.MethodPost, "/api/audits", map[string]any{"snapshot_id": snapID}, headers)
	second := do(t, ts, http.MethodPost, "/api/audits", map[string]any{"snapshot_id": snapID}, headers)
	if string(first.body) != string(second.body) {
		t.Errorf("idempotent replay differs:\n%s\n%s", first.body, second.body)
	}
	if second.header.Get("Idempotent-Replay") != "true" {
		t.Errorf("idempotent replay header missing: %v", second.header)
	}

	// Listing.
	list := do(t, ts, http.MethodGet, "/api/audits?snapshot_id="+snapID, nil, nil)
	if list.status != http.StatusOK {
		t.Fatalf("list audits: %d %s", list.status, list.body)
	}
	var listed struct {
		Audits []path.Audit `json:"audits"`
		Total  int          `json:"total"`
	}
	list.decode(t, &listed)
	if listed.Total == 0 || len(listed.Audits) == 0 {
		t.Fatalf("no audit listed: %s", list.body)
	}
	show := do(t, ts, http.MethodGet, "/api/audits/"+auditID, nil, nil)
	if show.status != http.StatusOK {
		t.Fatalf("show audit: %d %s", show.status, show.body)
	}
	var one path.Audit
	show.decode(t, &one)
	if one.ID != auditID {
		t.Errorf("show returned %s, want %s", one.ID, auditID)
	}

	// The queue page only serves the status that was asked for, and every path
	// keeps the evidence class and limitations that make it reviewable.
	queued := auditPaths(t, ts, auditID, "?status=QUEUED")
	if len(queued.Paths) == 0 {
		t.Fatal("no queued path returned")
	}
	for _, p := range queued.Paths {
		if p.Status != path.StatusQueued {
			t.Errorf("status filter ignored: %s is %s", p.ID, p.Status)
		}
		if p.PathStatus == "" || len(p.Limitations) == 0 {
			t.Errorf("path %s lost its evidence class or limitations", p.ID)
		}
		if p.Score.ScoreVersion != path.ScoreVersion {
			t.Errorf("path %s carries score version %d", p.ID, p.Score.ScoreVersion)
		}
	}

	// The default order is the queue order: priority must never increase.
	byPriority := auditPaths(t, ts, auditID, "?limit=50")
	for i := 1; i < len(byPriority.Paths); i++ {
		if byPriority.Paths[i].Score.Priority > byPriority.Paths[i-1].Score.Priority {
			t.Errorf("default order is not by priority: %s (%.4f) before %s (%.4f)",
				byPriority.Paths[i-1].ID, byPriority.Paths[i-1].Score.Priority,
				byPriority.Paths[i].ID, byPriority.Paths[i].Score.Priority)
		}
	}
	byID := auditPaths(t, ts, auditID, "?sort=path_id&limit=50")
	if len(byID.Paths) != len(byPriority.Paths) {
		t.Fatalf("sort=path_id returned %d paths, the default returned %d", len(byID.Paths), len(byPriority.Paths))
	}
	ids := make([]string, 0, len(byID.Paths))
	for _, p := range byID.Paths {
		ids = append(ids, p.ID)
	}
	if !sort.StringsAreSorted(ids) {
		t.Errorf("sort=path_id is not ascending: %v", ids)
	}
	defaultIDs := make([]string, 0, len(byPriority.Paths))
	for _, p := range byPriority.Paths {
		defaultIDs = append(defaultIDs, p.ID)
	}
	if len(ids) > 1 && equalStrings(ids, defaultIDs) {
		t.Errorf("sort=path_id did not change the order: %v", ids)
	}

	// The event log is a bounded page with a resumable cursor.
	events := do(t, ts, http.MethodGet, "/api/audits/"+auditID+"/events", nil, nil)
	if events.status != http.StatusOK {
		t.Fatalf("events: %d %s", events.status, events.body)
	}
	var page auditEventPage
	events.decode(t, &page)
	if page.Total == 0 || page.NextAfterSeq == 0 {
		t.Fatalf("event page carries no events or no cursor: %s", events.body)
	}
	sawCreated := false
	for _, event := range page.Events {
		if event.Type == path.EventAuditCreated {
			sawCreated = true
		}
	}
	if !sawCreated {
		t.Errorf("event log has no audit_created event: %s", events.body)
	}
	cursor := strconv.FormatInt(page.NextAfterSeq, 10)
	resumed := do(t, ts, http.MethodGet, "/api/audits/"+auditID+"/events?after_seq="+cursor, nil, nil)
	if resumed.status != http.StatusOK {
		t.Fatalf("resumed events: %d %s", resumed.status, resumed.body)
	}
	var resumedPage auditEventPage
	resumed.decode(t, &resumedPage)
	if resumedPage.Total != 0 {
		t.Errorf("after_seq did not advance the cursor: %s", resumed.body)
	}
	if bad := do(t, ts, http.MethodGet, "/api/audits/"+auditID+"/events?after_seq=x", nil, nil); bad.status != http.StatusBadRequest {
		t.Errorf("bad after_seq = %d, want 400 (%s)", bad.status, bad.body)
	}
}

func TestPathLeaseLifecycle(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})

	// "next" answers a question: it must not lease anything.
	next := do(t, ts, http.MethodGet, "/api/audits/"+audit.Audit.ID+"/next", nil, nil)
	if next.status != http.StatusOK {
		t.Fatalf("next: %d %s", next.status, next.body)
	}
	var nextBody struct {
		AuditID string    `json:"audit_id"`
		Path    path.Path `json:"path"`
		Leased  bool      `json:"leased"`
	}
	next.decode(t, &nextBody)
	if nextBody.Leased || nextBody.Path.LeaseOwner != "" {
		t.Errorf("next took a lease: %s", next.body)
	}
	if nextBody.Path.Status != path.StatusQueued {
		t.Errorf("next path status = %s, want QUEUED", nextBody.Path.Status)
	}

	// Claiming leases the scheduler's pick and moves it to ANALYZING.
	claim := do(t, ts, http.MethodPost, "/api/paths/"+nextBody.Path.ID+"/claim",
		map[string]any{"owner": "worker-a", "ttl_seconds": 300}, nil)
	if claim.status != http.StatusOK {
		t.Fatalf("claim: %d %s", claim.status, claim.body)
	}
	var leased path.Path
	claim.decode(t, &leased)
	if leased.Status != path.StatusAnalyzing {
		t.Errorf("claimed status = %s, want ANALYZING", leased.Status)
	}
	if leased.LeaseOwner != "worker-a" || leased.LeaseUntil == "" {
		t.Errorf("claim did not record the lease: %s", claim.body)
	}
	claimedID := leased.ID

	// A heartbeat from a different owner is a lost race, not a renewal.
	wrongOwner := do(t, ts, http.MethodPost, "/api/paths/"+claimedID+"/heartbeat",
		map[string]any{"owner": "worker-b", "ttl_seconds": 300}, nil)
	if wrongOwner.status != http.StatusConflict {
		t.Fatalf("foreign heartbeat = %d, want 409 (%s)", wrongOwner.status, wrongOwner.body)
	}
	var errBody errorResponse
	wrongOwner.decode(t, &errBody)
	if errBody.Code != "lease_held" {
		t.Errorf("foreign heartbeat code = %q, want lease_held", errBody.Code)
	}

	beat := do(t, ts, http.MethodPost, "/api/paths/"+claimedID+"/heartbeat",
		map[string]any{"owner": "worker-a", "ttl_seconds": 300}, nil)
	if beat.status != http.StatusOK {
		t.Fatalf("heartbeat: %d %s", beat.status, beat.body)
	}
	var renewed path.Path
	beat.decode(t, &renewed)
	if renewed.LeaseOwner != "worker-a" || renewed.LeaseUntil == "" {
		t.Errorf("heartbeat lost the lease: %s", beat.body)
	}

	// Releasing puts the path back in the queue without a verdict.
	release := do(t, ts, http.MethodPost, "/api/paths/"+claimedID+"/release",
		map[string]any{"owner": "worker-a", "reason": "handing back"}, nil)
	if release.status != http.StatusOK {
		t.Fatalf("release: %d %s", release.status, release.body)
	}
	var released path.Path
	release.decode(t, &released)
	if released.Status != path.StatusQueued || released.LeaseOwner != "" {
		t.Errorf("release did not requeue the path: %s", release.body)
	}

	// The path detail resolves the history that makes the ranking reviewable.
	releasedGet := do(t, ts, http.MethodGet, "/api/paths/"+claimedID, nil, nil)
	if releasedGet.status != http.StatusOK {
		t.Fatalf("get path: %d %s", releasedGet.status, releasedGet.body)
	}
	var detail pathDetailResponse
	releasedGet.decode(t, &detail)
	if detail.Path == nil || detail.Path.ID != claimedID {
		t.Fatalf("path detail lost the path: %s", releasedGet.body)
	}
	if len(detail.Features) == 0 || len(detail.Events) == 0 {
		t.Errorf("path detail dropped its history: %s", releasedGet.body)
	}
	if detail.Path.Score.ScoreVersion != path.ScoreVersion {
		t.Errorf("path detail lost the score version: %s", releasedGet.body)
	}
}

func TestPathTransitionsRequireIfMatch(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})
	page := auditPaths(t, ts, audit.Audit.ID, "?limit=50")
	if len(page.Paths) == 0 {
		t.Fatal("no path to transition")
	}
	pathID := page.Paths[0].ID

	read := do(t, ts, http.MethodGet, "/api/paths/"+pathID, nil, nil)
	if read.status != http.StatusOK {
		t.Fatalf("read path: %d %s", read.status, read.body)
	}
	etag := read.header.Get("ETag")
	if etag == "" {
		t.Fatal("GET /api/paths/{id} returned no ETag")
	}

	// Without If-Match a caller could overwrite a decision it never saw.
	missing := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/pause", map[string]any{"reason": "audit"}, nil)
	if missing.status != http.StatusPreconditionRequired {
		t.Fatalf("pause without If-Match = %d, want 428 (%s)", missing.status, missing.body)
	}
	var missingBody errorResponse
	missing.decode(t, &missingBody)
	if missingBody.Code != "precondition_required" {
		t.Errorf("code = %q, want precondition_required", missingBody.Code)
	}

	stale := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/pause", map[string]any{"reason": "audit"},
		map[string]string{"If-Match": `"stale"`})
	if stale.status != http.StatusPreconditionFailed {
		t.Fatalf("pause with a stale ETag = %d, want 412 (%s)", stale.status, stale.body)
	}

	paused := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/pause", map[string]any{"reason": "operator review"},
		map[string]string{"If-Match": etag})
	if paused.status != http.StatusOK {
		t.Fatalf("pause: %d %s", paused.status, paused.body)
	}
	var pausedPath path.Path
	paused.decode(t, &pausedPath)
	if pausedPath.Status != path.StatusPaused {
		t.Errorf("pause status = %s, want PAUSED", pausedPath.Status)
	}
	pausedETag := paused.header.Get("ETag")
	if pausedETag == "" || pausedETag == etag {
		t.Errorf("pause did not advance the ETag (%q -> %q)", etag, pausedETag)
	}

	// The version really moved: the old validator is now stale.
	replay := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/pause", map[string]any{"reason": "audit"},
		map[string]string{"If-Match": etag})
	if replay.status != http.StatusPreconditionFailed {
		t.Fatalf("pause with the previous ETag = %d, want 412 (%s)", replay.status, replay.body)
	}

	resumed := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/resume", map[string]any{"reason": "resuming"},
		map[string]string{"If-Match": pausedETag})
	if resumed.status != http.StatusOK {
		t.Fatalf("resume: %d %s", resumed.status, resumed.body)
	}
	var resumedPath path.Path
	resumed.decode(t, &resumedPath)
	if resumedPath.Status != path.StatusQueued {
		t.Errorf("resume status = %s, want QUEUED", resumedPath.Status)
	}

	cancelled := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/cancel", map[string]any{"reason": "out of scope"},
		map[string]string{"If-Match": resumed.header.Get("ETag")})
	if cancelled.status != http.StatusOK {
		t.Fatalf("cancel: %d %s", cancelled.status, cancelled.body)
	}
	var cancelledPath path.Path
	cancelled.decode(t, &cancelledPath)
	if cancelledPath.Status != path.StatusCancelled {
		t.Errorf("cancel status = %s, want CANCELLED", cancelledPath.Status)
	}

	// A concluded path cannot be resumed; the refusal names the legal targets.
	refused := do(t, ts, http.MethodPost, "/api/paths/"+pathID+"/resume", map[string]any{"reason": "retry"},
		map[string]string{"If-Match": cancelled.header.Get("ETag")})
	if refused.status != http.StatusConflict {
		t.Fatalf("resume of a cancelled path = %d, want 409 (%s)", refused.status, refused.body)
	}
	var refusedBody errorResponse
	refused.decode(t, &refusedBody)
	if refusedBody.Code != "invalid_transition" {
		t.Errorf("code = %q, want invalid_transition", refusedBody.Code)
	}
	if !strings.Contains(refusedBody.Error, "CANCELLED") || !strings.Contains(refusedBody.Error, "legal targets") {
		t.Errorf("invalid_transition message does not name the legal targets: %q", refusedBody.Error)
	}

	// Rescoring replays the stored features and returns the reranked audit.
	rescore := do(t, ts, http.MethodPost, "/api/audits/"+audit.Audit.ID+"/rescore", map[string]any{}, nil)
	if rescore.status != http.StatusOK {
		t.Fatalf("rescore: %d %s", rescore.status, rescore.body)
	}
	var rescored struct {
		Audit path.Audit `json:"audit"`
	}
	rescore.decode(t, &rescored)
	if rescored.Audit.ID != audit.Audit.ID {
		t.Errorf("rescore returned %s, want %s", rescored.Audit.ID, audit.Audit.ID)
	}

	// Reclaiming an audit whose leases are healthy recovers nothing.
	reclaim := do(t, ts, http.MethodPost, "/api/audits/"+audit.Audit.ID+"/reclaim-expired",
		map[string]any{"limit": 10}, nil)
	if reclaim.status != http.StatusOK {
		t.Fatalf("reclaim: %d %s", reclaim.status, reclaim.body)
	}
	var reclaimBody struct {
		AuditID        string      `json:"audit_id"`
		Recovered      []path.Path `json:"recovered"`
		Count          int         `json:"count"`
		RecoveredTotal int         `json:"recovered_total"`
	}
	reclaim.decode(t, &reclaimBody)
	if reclaimBody.AuditID != audit.Audit.ID {
		t.Errorf("reclaim answered for %s, want %s", reclaimBody.AuditID, audit.Audit.ID)
	}
	if reclaimBody.Count != len(reclaimBody.Recovered) {
		t.Errorf("reclaim count disagrees with its page: %s", reclaim.body)
	}
}

func TestAuditClaimRespectsActiveLeaseCeiling(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{
		"snapshot_id": snapID,
		"limits":      map[string]any{"max_active_leases": 1},
	})
	if audit.Audit.Limits.MaxActiveLeases != 1 {
		t.Fatalf("limit was not stored: %+v", audit.Audit.Limits)
	}

	next := do(t, ts, http.MethodGet, "/api/audits/"+audit.Audit.ID+"/next", nil, nil)
	var nextBody struct {
		Path path.Path `json:"path"`
	}
	next.decode(t, &nextBody)

	first := do(t, ts, http.MethodPost, "/api/paths/"+nextBody.Path.ID+"/claim",
		map[string]any{"owner": "worker-a"}, nil)
	if first.status != http.StatusOK {
		t.Fatalf("first claim = %d, want 200 (%s)", first.status, first.body)
	}

	// The ceiling is a property of the audit, so the second worker is refused
	// instead of silently over-subscribing it.
	second := do(t, ts, http.MethodPost, "/api/paths/"+nextBody.Path.ID+"/claim",
		map[string]any{"owner": "worker-b"}, nil)
	if second.status != http.StatusConflict {
		t.Fatalf("second claim = %d, want 409 (%s)", second.status, second.body)
	}
	var errBody errorResponse
	second.decode(t, &errBody)
	if errBody.Code != "budget_exceeded" {
		t.Errorf("second claim code = %q, want budget_exceeded", errBody.Code)
	}
	if !strings.Contains(errBody.Error, audit.Audit.ID) {
		t.Errorf("budget_exceeded message does not name the audit: %q", errBody.Error)
	}
}

func TestAuditErrors(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})

	// A snapshot with an SCG but no attack surface is a fixable request, not a
	// missing snapshot: the answer names the build route.
	project := createProject(t, ts, asgFixtureSource(t))
	graphOnly := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots",
		map[string]any{"build_graph": true}, nil)
	if graphOnly.status != http.StatusCreated {
		t.Fatalf("graph-only snapshot: %d %s", graphOnly.status, graphOnly.body)
	}
	var graphSnapshot snapshotResponse
	graphOnly.decode(t, &graphSnapshot)

	noASG := do(t, ts, http.MethodPost, "/api/audits",
		map[string]any{"snapshot_id": graphSnapshot.Snapshot.SnapshotID}, nil)
	if noASG.status != http.StatusConflict {
		t.Fatalf("audit without an ASG = %d, want 409 (%s)", noASG.status, noASG.body)
	}
	var noASGBody errorResponse
	noASG.decode(t, &noASGBody)
	if noASGBody.Code != "asg_missing" {
		t.Errorf("code = %q, want asg_missing", noASGBody.Code)
	}
	if !strings.Contains(noASGBody.Error, "/asg") {
		t.Errorf("asg_missing message is not actionable: %q", noASGBody.Error)
	}

	cases := []struct {
		name   string
		method string
		path   string
		body   any
		header map[string]string
		want   int
		code   string
	}{
		{"unknown snapshot", http.MethodPost, "/api/audits",
			map[string]any{"snapshot_id": "snap-00000000000000000000000000000000"}, nil, http.StatusNotFound, "not_found"},
		{"missing snapshot id", http.MethodPost, "/api/audits", map[string]any{}, nil, http.StatusBadRequest, "invalid_request"},
		{"bad json", http.MethodPost, "/api/audits", "{not json", nil, http.StatusBadRequest, "invalid_json"},
		{"unknown field", http.MethodPost, "/api/audits", `{"snapshot_id":"x","nope":1}`, nil, http.StatusBadRequest, "invalid_json"},
		{"negative limit", http.MethodPost, "/api/audits",
			map[string]any{"snapshot_id": snapID, "limits": map[string]any{"max_paths": -1}}, nil, http.StatusBadRequest, "invalid_request"},
		{"sensitivity out of range", http.MethodPost, "/api/audits",
			map[string]any{"snapshot_id": snapID, "sensitivity": map[string]any{"sql": 1.5}}, nil, http.StatusBadRequest, "invalid_request"},
		{"unknown audit", http.MethodGet, "/api/audits/audit-00000000000000000000000000000000", nil, nil, http.StatusNotFound, "not_found"},
		{"unknown path", http.MethodGet, "/api/paths/path-00000000000000000000000000000000", nil, nil, http.StatusNotFound, "not_found"},
		{"pause unknown path", http.MethodPost, "/api/paths/path-00000000000000000000000000000000/pause",
			map[string]any{"reason": "x"}, map[string]string{"If-Match": `"x"`}, http.StatusNotFound, "not_found"},
		{"unknown audit next", http.MethodGet, "/api/audits/audit-00000000000000000000000000000000/next", nil, nil, http.StatusNotFound, "not_found"},
		{"unknown audit paths", http.MethodGet, "/api/audits/audit-00000000000000000000000000000000/paths", nil, nil, http.StatusNotFound, "not_found"},
		{"unknown status filter", http.MethodGet, "/api/audits?status=NOPE", nil, nil, http.StatusBadRequest, "invalid_request"},
		{"claim without owner", http.MethodPost, "/api/paths/" + pathIDOf(t, ts, audit.Audit.ID) + "/claim",
			map[string]any{}, nil, http.StatusBadRequest, "invalid_request"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := do(t, ts, tc.method, tc.path, tc.body, tc.header)
			if resp.status != tc.want {
				t.Fatalf("status = %d, want %d (%s)", resp.status, tc.want, resp.body)
			}
			var errBody errorResponse
			resp.decode(t, &errBody)
			if errBody.Code != tc.code {
				t.Errorf("code = %q, want %q (%s)", errBody.Code, tc.code, resp.body)
			}
		})
	}

	// A filter typo inside an existing audit is a 400, not an empty page.
	for _, query := range []string{"?status=NOPE", "?path_status=nope", "?sort=nope", "?min_priority=x"} {
		resp := do(t, ts, http.MethodGet, "/api/audits/"+audit.Audit.ID+"/paths"+query, nil, nil)
		if resp.status != http.StatusBadRequest {
			t.Errorf("paths%s = %d, want 400 (%s)", query, resp.status, resp.body)
		}
	}

	// Authentication and capability gates, both directions.
	noToken := doAs(t, ts, "", http.MethodGet, "/api/audits", nil, nil)
	if noToken.status != http.StatusUnauthorized {
		t.Errorf("unauthenticated read = %d, want 401 (%s)", noToken.status, noToken.body)
	}
	noTokenWrite := doAs(t, ts, "", http.MethodPost, "/api/audits", map[string]any{"snapshot_id": snapID}, nil)
	if noTokenWrite.status != http.StatusUnauthorized {
		t.Errorf("unauthenticated write = %d, want 401 (%s)", noTokenWrite.status, noTokenWrite.body)
	}
	readerWrite := doAs(t, ts, readerSecret, http.MethodPost, "/api/audits", map[string]any{"snapshot_id": snapID}, nil)
	if readerWrite.status != http.StatusForbidden {
		t.Errorf("reader write = %d, want 403 (%s)", readerWrite.status, readerWrite.body)
	}
	readerLease := doAs(t, ts, readerSecret, http.MethodPost,
		"/api/paths/"+pathIDOf(t, ts, audit.Audit.ID)+"/claim", map[string]any{"owner": "worker-a"}, nil)
	if readerLease.status != http.StatusForbidden {
		t.Errorf("reader claim = %d, want 403 (%s)", readerLease.status, readerLease.body)
	}
	readerRead := doAs(t, ts, readerSecret, http.MethodGet, "/api/audits", nil, nil)
	if readerRead.status != http.StatusOK {
		t.Errorf("reader read = %d, want 200 (%s)", readerRead.status, readerRead.body)
	}

	// A server without the path engine says so instead of answering "gone".
	bare := NewServer(env.rt.Store, env.rt.Manager, env.rt.Analyzer,
		WithAuth(testAuthenticator(t)),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	bareTS := httptest.NewServer(bare.Handler())
	defer bareTS.Close()
	for _, tc := range []struct {
		method string
		path   string
		body   any
	}{
		{http.MethodGet, "/api/audits", nil},
		{http.MethodPost, "/api/audits", map[string]any{"snapshot_id": snapID}},
		{http.MethodGet, "/api/paths/path-x", nil},
	} {
		resp := do(t, bareTS, tc.method, tc.path, tc.body, nil)
		if resp.status != http.StatusNotImplemented {
			t.Fatalf("%s %s = %d, want 501 (%s)", tc.method, tc.path, resp.status, resp.body)
		}
		var errBody errorResponse
		resp.decode(t, &errBody)
		if errBody.Code != "audit_unavailable" {
			t.Errorf("code = %q, want audit_unavailable", errBody.Code)
		}
	}
}

// pathIDOf returns the first path id of an audit, for tests that need one only
// to reach a route.
func pathIDOf(t *testing.T, ts *httptest.Server, auditID string) string {
	t.Helper()
	page := auditPaths(t, ts, auditID, "?limit=1")
	if len(page.Paths) == 0 {
		t.Fatal("audit has no path")
	}
	return page.Paths[0].ID
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestClaimIsAuditScopedThroughBothRoutes pins why the canonical claim route is
// audit-scoped: the scheduler picks from the whole queue, so a path id in the URL
// only identifies the audit and the leased path may be a different one.
func TestClaimIsAuditScopedThroughBothRoutes(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	snapID := createAuditedSnapshot(t, ts)
	audit := createAudit(t, ts, map[string]any{"snapshot_id": snapID})

	page := do(t, ts, http.MethodGet, "/api/audits/"+audit.Audit.ID+"/paths?limit=10", nil, nil)
	if page.status != http.StatusOK {
		t.Fatalf("paths: %d %s", page.status, page.body)
	}
	var listed auditPathPage
	page.decode(t, &listed)
	if len(listed.Paths) < 2 {
		t.Fatalf("fixture produced %d path(s), need at least 2", len(listed.Paths))
	}

	// Claiming through a path id resolves that path's audit and leases the next
	// pick: the answer says which path was actually leased.
	claim := do(t, ts, http.MethodPost, "/api/paths/"+listed.Paths[0].ID+"/claim",
		map[string]any{"owner": "worker-1", "ttl_seconds": 60}, nil)
	if claim.status != http.StatusOK {
		t.Fatalf("claim through a path: %d %s", claim.status, claim.body)
	}
	// The claim answers with the path document itself: the leased row is the whole
	// answer, and wrapping it would only add a field to unwrap.
	var leased path.Path
	claim.decode(t, &leased)
	if leased.Status != path.StatusAnalyzing || leased.LeaseOwner != "worker-1" {
		t.Errorf("leased path = %+v", leased)
	}

	// The audit route is the canonical spelling and leases the next pick too.
	second := do(t, ts, http.MethodPost, "/api/audits/"+audit.Audit.ID+"/claim",
		map[string]any{"owner": "worker-2", "ttl_seconds": 60}, nil)
	if second.status != http.StatusOK {
		t.Fatalf("claim through the audit: %d %s", second.status, second.body)
	}
	var other path.Path
	second.decode(t, &other)
	if other.ID == leased.ID {
		t.Error("the second claim leased the same path twice")
	}
	if other.LeaseOwner != "worker-2" {
		t.Errorf("second lease owner = %q", other.LeaseOwner)
	}

	// An unknown audit is a 404, not an empty queue.
	missing := do(t, ts, http.MethodPost, "/api/audits/audit-00000000000000000000000000000000/claim",
		map[string]any{"owner": "worker-3"}, nil)
	if missing.status != http.StatusNotFound {
		t.Errorf("unknown audit claim = %d, want 404 (%s)", missing.status, missing.body)
	}
}
