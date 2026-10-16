package api

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func TestAuthenticationIsRequired(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts

	// No credential: the request is refused before routing, with a challenge.
	resp := doAs(t, ts, "", http.MethodGet, "/api/projects", nil, nil)
	if resp.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 (%s)", resp.status, resp.body)
	}
	if got := resp.header.Get("WWW-Authenticate"); !strings.Contains(got, "Bearer") {
		t.Errorf("WWW-Authenticate = %q, want a Bearer challenge", got)
	}
	var errBody errorResponse
	resp.decode(t, &errBody)
	if errBody.Code != "unauthorized" {
		t.Errorf("code = %q, want unauthorized", errBody.Code)
	}

	// A wrong secret is indistinguishable from a missing one.
	bad := doAs(t, ts, "test-wrong-secret-0123456789", http.MethodGet, "/api/projects", nil, nil)
	if bad.status != http.StatusUnauthorized {
		t.Fatalf("wrong token status = %d, want 401", bad.status)
	}

	// Liveness stays available without a credential on purpose.
	health := doAs(t, ts, "", http.MethodGet, "/healthz", nil, nil)
	if health.status != http.StatusOK {
		t.Fatalf("healthz without a token = %d, want 200", health.status)
	}
}

func TestCapabilitiesGateOperations(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	project := createProject(t, ts, env.source)

	// A reader can read...
	if resp := doAs(t, ts, readerSecret, http.MethodGet, "/api/projects", nil, nil); resp.status != http.StatusOK {
		t.Fatalf("reader GET = %d, want 200 (%s)", resp.status, resp.body)
	}
	// ... and can run the query-shaped POST endpoints (they change nothing)...
	if resp := doAs(t, ts, readerSecret, http.MethodPost, "/api/snapshots/snap-00000000000000000000000000000000/graph/paths",
		map[string]any{"source": "a", "sink": "b"}, nil); resp.status == http.StatusForbidden {
		t.Errorf("reader was refused a query-only POST: %d %s", resp.status, resp.body)
	}
	// ... but cannot create anything.
	resp := doAs(t, ts, readerSecret, http.MethodPost, "/api/projects", map[string]string{"source": env.source}, nil)
	if resp.status != http.StatusForbidden {
		t.Fatalf("reader POST = %d, want 403 (%s)", resp.status, resp.body)
	}

	// A writer can freeze a snapshot but not delete one.
	write := doAs(t, ts, adminSecret, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{}, nil)
	if write.status != http.StatusCreated {
		t.Fatalf("admin snapshot = %d, want 201 (%s)", write.status, write.body)
	}
	var created snapshotResponse
	write.decode(t, &created)
	readerDelete := doAs(t, ts, readerSecret, http.MethodDelete, "/api/snapshots/"+created.Snapshot.SnapshotID, nil, nil)
	if readerDelete.status != http.StatusForbidden {
		t.Fatalf("reader DELETE = %d, want 403 (%s)", readerDelete.status, readerDelete.body)
	}
	adminDelete := doAs(t, ts, adminSecret, http.MethodDelete, "/api/snapshots/"+created.Snapshot.SnapshotID, nil, nil)
	if adminDelete.status != http.StatusNoContent {
		t.Fatalf("admin DELETE = %d, want 204 (%s)", adminDelete.status, adminDelete.body)
	}

	// An unknown path is a 404 for an authenticated caller, never a capability
	// question, so the capability table cannot become a route oracle.
	unknown := doAs(t, ts, readerSecret, http.MethodGet, "/api/nope", nil, nil)
	if unknown.status != http.StatusNotFound {
		t.Errorf("unknown path = %d, want 404", unknown.status)
	}
}

func TestServerFailsClosedWithoutAuthenticator(t *testing.T) {
	t.Parallel()
	rt, err := app.Build(context.Background(), app.Config{
		Workspace: filepath.Join(t.TempDir(), "work"),
		DBPath:    "memory",
	})
	if err != nil {
		t.Fatal(err)
	}
	defer rt.Close()
	// Deliberately no WithAuth: every API call must be refused.
	srv := NewServer(rt.Store, rt.Manager, rt.Analyzer,
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()
	if resp := doAs(t, ts, adminSecret, http.MethodGet, "/api/projects", nil, nil); resp.status != http.StatusUnauthorized {
		t.Fatalf("status = %d, want 401 without a configured authenticator", resp.status)
	}
	if resp := doAs(t, ts, "", http.MethodPost, "/api/projects", map[string]string{"source": "."}, nil); resp.status != http.StatusUnauthorized {
		t.Fatalf("write status = %d, want 401", resp.status)
	}
}

func TestTokenConfiguration(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name    string
		specs   []string
		wantErr bool
	}{
		{"valid admin", []string{"ci:admin:0123456789abcdef"}, false},
		{"valid reader", []string{"dash:reader:0123456789abcdef"}, false},
		{"hashed secret", []string{"ci:writer:sha256:0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0"}, false},
		{"short secret", []string{"ci:admin:short"}, true},
		{"unknown role", []string{"ci:root:0123456789abcdef"}, true},
		{"missing role", []string{"ci:0123456789abcdef"}, true},
		{"empty name", []string{":admin:0123456789abcdef"}, true},
		{"empty list", nil, true},
		{"bad hash", []string{"ci:admin:sha256:nothex"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			specs, err := ParseTokenSpecs(tc.specs)
			if err != nil {
				if !tc.wantErr {
					t.Fatalf("ParseTokenSpecs: %v", err)
				}
				return
			}
			_, err = NewAuthenticator(specs)
			if tc.wantErr && err == nil {
				t.Fatalf("configuration was accepted but should not be: %+v", specs)
			}
			if !tc.wantErr && err != nil {
				t.Fatalf("NewAuthenticator: %v", err)
			}
		})
	}

	// Duplicate names are refused, because logs would become ambiguous.
	if _, err := NewAuthenticator([]Token{
		{Name: "ci", Role: "reader", Secret: "0123456789abcdef"},
		{Name: "ci", Role: "writer", Secret: "0123456789abcdee"},
	}); err == nil {
		t.Error("duplicate token names were accepted")
	}
	// Anonymous access must never be administrative.
	if _, err := NewAuthenticatorWithOptions(nil, WithAnonymousAccess(CapAdmin)); !errors.Is(err, ErrInvalidConfig) {
		t.Errorf("anonymous admin = %v, want ErrInvalidConfig", err)
	}
}

func TestCapabilityLattice(t *testing.T) {
	t.Parallel()
	if !CapAdmin.Allows(CapWrite) || !CapAdmin.Allows(CapRead) || !CapWrite.Allows(CapRead) {
		t.Error("admin/writer do not imply lower capabilities")
	}
	if CapRead.Allows(CapWrite) || CapWrite.Allows(CapAdmin) || CapRead.Allows(CapAdmin) {
		t.Error("a lower capability implies a higher one")
	}
	// An operation that requires nothing is allowed for everyone, including a
	// caller with no capabilities at all (for example /healthz).
	if !CapNone.Allows(CapNone) || !CapRead.Allows(CapNone) {
		t.Error("requiring no capability must be allowed for every principal")
	}
	if CapNone.Allows(CapRead) {
		t.Error("CapNone must not imply CapRead")
	}
	for _, tc := range []struct {
		caps Capability
		want string
	}{{CapNone, "none"}, {CapRead, "reader"}, {CapWrite, "writer"}, {CapAdmin, "admin"}} {
		if got := tc.caps.String(); got != tc.want {
			t.Errorf("String() = %q, want %q", got, tc.want)
		}
	}
}

func TestProjectOptimisticConcurrency(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	project := createProject(t, ts, env.source)

	get := do(t, ts, http.MethodGet, "/api/projects/"+project.Project.ID, nil, nil)
	if get.status != http.StatusOK {
		t.Fatalf("get: %d %s", get.status, get.body)
	}
	etag := get.header.Get("ETag")
	if etag == "" {
		t.Fatal("GET project returned no ETag")
	}

	// A rename without If-Match is refused rather than guessed.
	noMatch := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]string{"name": "renamed"}, nil)
	if noMatch.status != http.StatusPreconditionRequired {
		t.Fatalf("PATCH without If-Match = %d, want 428 (%s)", noMatch.status, noMatch.body)
	}
	// A stale ETag is refused.
	stale := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]string{"name": "renamed"},
		map[string]string{"If-Match": `"deadbeefdeadbeef"`})
	if stale.status != http.StatusPreconditionFailed {
		t.Fatalf("PATCH with a stale ETag = %d, want 412 (%s)", stale.status, stale.body)
	}
	// The current ETag succeeds and produces a new one.
	ok := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]string{"name": "renamed"},
		map[string]string{"If-Match": etag})
	if ok.status != http.StatusOK {
		t.Fatalf("PATCH = %d, want 200 (%s)", ok.status, ok.body)
	}
	var updated map[string]any
	ok.decode(t, &updated)
	if updated["name"] != "renamed" {
		t.Errorf("project was not renamed: %s", ok.body)
	}
	newETag := ok.header.Get("ETag")
	if newETag == "" || newETag == etag {
		t.Errorf("ETag did not change after an update: %q -> %q", etag, newETag)
	}
	// The previous ETag is now stale.
	again := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]string{"name": "twice"},
		map[string]string{"If-Match": etag})
	if again.status != http.StatusPreconditionFailed {
		t.Fatalf("second PATCH with the old ETag = %d, want 412", again.status)
	}
	// An empty name is a bad request, not a silent no-op.
	empty := do(t, ts, http.MethodPatch, "/api/projects/"+project.Project.ID, map[string]string{"name": "  "},
		map[string]string{"If-Match": newETag})
	if empty.status != http.StatusBadRequest {
		t.Fatalf("PATCH with an empty name = %d, want 400", empty.status)
	}
}

func TestIdempotencyKeySemantics(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	project := createProject(t, ts, env.source)
	path := "/api/projects/" + project.Project.ID + "/snapshots"
	headers := map[string]string{"Idempotency-Key": "freeze-once"}

	first := do(t, ts, http.MethodPost, path, map[string]any{}, headers)
	if first.status != http.StatusCreated {
		t.Fatalf("first call: %d %s", first.status, first.body)
	}
	replay := do(t, ts, http.MethodPost, path, map[string]any{}, headers)
	if replay.status != first.status || string(replay.body) != string(first.body) {
		t.Fatalf("replay differs:\n%s\n%s", first.body, replay.body)
	}
	if replay.header.Get("Idempotent-Replay") != "true" {
		t.Error("replay was not marked as such")
	}

	// The same key with a different request is a client bug: it must not receive
	// the first answer.
	other := do(t, ts, http.MethodPost, path, map[string]any{"skip_analysis": true}, headers)
	if other.status != http.StatusConflict {
		t.Fatalf("same key, different body = %d, want 409 (%s)", other.status, other.body)
	}
	var errBody errorResponse
	other.decode(t, &errBody)
	if errBody.Code != "idempotency_key_reuse" {
		t.Errorf("code = %q, want idempotency_key_reuse", errBody.Code)
	}

	// A different token must not read another principal's stored response.
	otherPrincipal := doAs(t, ts, admin2Secret, http.MethodPost, path, map[string]any{}, headers)
	if otherPrincipal.status != http.StatusConflict {
		t.Fatalf("same key, different token = %d, want 409 (%s)", otherPrincipal.status, otherPrincipal.body)
	}
	otherPrincipal.decode(t, &errBody)
	if errBody.Code != "idempotency_key_reuse" {
		t.Errorf("code = %q, want idempotency_key_reuse", errBody.Code)
	}
}

func TestIdempotencyInProgressIsRefused(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	ts := env.ts
	project := createProject(t, ts, env.source)

	// Claim the key out of band, exactly as a slow in-flight request would.
	scope := "POST /api/projects/" + project.Project.ID + "/snapshots"
	ctx := context.Background()
	if _, err := env.rt.Store.ClaimIdempotent(ctx, idempotencyRecordForTest(scope, "in-flight", "admin")); err != nil {
		t.Fatalf("ClaimIdempotent: %v", err)
	}
	resp := do(t, ts, http.MethodPost, "/api/projects/"+project.Project.ID+"/snapshots", map[string]any{},
		map[string]string{"Idempotency-Key": "in-flight"})
	if resp.status != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (%s)", resp.status, resp.body)
	}
	var errBody errorResponse
	resp.decode(t, &errBody)
	if errBody.Code != "idempotency_in_progress" {
		t.Errorf("code = %q, want idempotency_in_progress", errBody.Code)
	}
	if resp.header.Get("Retry-After") == "" {
		t.Error("a contended key should tell the client when to retry")
	}
}

func TestIdempotencyIsDurableAcrossRestarts(t *testing.T) {
	t.Parallel()
	base := t.TempDir()
	workspace := filepath.Join(base, "work")
	db := filepath.Join(base, "codexploit.db")

	source := t.TempDir()
	writeFile(t, source, "go.mod", "module example.invalid/restart\n\ngo 1.24\n")
	writeFile(t, source, "main.go", "package main\n\nfunc main() {}\n")

	rt, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	srv := NewServer(rt.Store, rt.Manager, rt.Analyzer,
		WithAuth(testAuthenticator(t)), WithGraph(rt.Graph), WithBuilder(rt.Builder),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	ts := httptest.NewServer(srv.Handler())

	project := createProject(t, ts, source)
	path := "/api/projects/" + project.Project.ID + "/snapshots"
	headers := map[string]string{"Idempotency-Key": "durable-1"}
	first := do(t, ts, http.MethodPost, path, map[string]any{}, headers)
	if first.status != http.StatusCreated {
		t.Fatalf("first call: %d %s", first.status, first.body)
	}
	ts.Close()
	if err := rt.Close(); err != nil {
		t.Fatalf("close runtime: %v", err)
	}

	// A second process on the same database must replay the stored answer.
	rt2, err := app.Build(context.Background(), app.Config{Workspace: workspace, DBPath: db})
	if err != nil {
		t.Fatalf("second Build: %v", err)
	}
	t.Cleanup(func() {
		ids, lerr := rt2.Manager.List()
		if lerr == nil {
			for _, id := range ids {
				if rerr := rt2.Manager.Remove(id); rerr != nil {
					t.Errorf("cleanup remove %s: %v", id, rerr)
				}
			}
		}
		if cerr := rt2.Close(); cerr != nil {
			t.Errorf("close second runtime: %v", cerr)
		}
	})
	srv2 := NewServer(rt2.Store, rt2.Manager, rt2.Analyzer,
		WithAuth(testAuthenticator(t)), WithGraph(rt2.Graph), WithBuilder(rt2.Builder),
		WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))))
	ts2 := httptest.NewServer(srv2.Handler())
	defer ts2.Close()

	replay := do(t, ts2, http.MethodPost, path, map[string]any{}, headers)
	if replay.status != first.status || string(replay.body) != string(first.body) {
		t.Fatalf("stored answer was not replayed after a restart:\n%s\n%s", first.body, replay.body)
	}
	if replay.header.Get("Idempotent-Replay") != "true" {
		t.Error("replayed answer is not marked as a replay")
	}
}

// idempotencyRecordForTest builds the record the API would build for an empty
// JSON request, so a test can pre-claim a key out of band.
func idempotencyRecordForTest(scope, key, principal string) storage.IdempotencyRecord {
	return storage.IdempotencyRecord{
		Scope:       scope,
		Key:         key,
		RequestHash: requestFingerprint([]byte("{}")),
		Principal:   principal,
		ExpiresAt:   time.Now().UTC().Add(time.Hour),
	}
}

// TestHealthIsJSON pins the liveness contract.
func TestHealthIsJSON(t *testing.T) {
	t.Parallel()
	env := newTestEnv(t, false)
	resp := doAs(t, env.ts, "", http.MethodGet, "/healthz", nil, nil)
	if !strings.Contains(resp.header.Get("Content-Type"), "application/json") {
		t.Fatalf("healthz content type = %q", resp.header.Get("Content-Type"))
	}
	var body map[string]any
	if err := json.Unmarshal(resp.body, &body); err != nil {
		t.Fatalf("healthz body: %v", err)
	}
	if body["status"] != "ok" {
		t.Errorf("healthz = %v", body)
	}
}
