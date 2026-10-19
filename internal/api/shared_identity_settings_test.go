package api

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/access"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func sharedSQLRepositories(t *testing.T) (storage.Store, storage.Store) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "shared.db")
	open := func() *storage.SQL {
		s, err := storage.OpenSQL(context.Background(), "sqlite", path)
		if err != nil {
			t.Fatal(err)
		}
		if err := s.EnsureSchema(context.Background(), migrations.FS); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { s.Close() })
		return s
	}
	return open(), open()
}

type sharedServer struct {
	handler http.Handler
	account *access.Manager
	llm     *llm.Manager
}

func newSharedServer(t *testing.T, store storage.Store, key []byte) sharedServer {
	t.Helper()
	identity, ok := storage.IdentityRepository(store)
	if !ok {
		t.Fatal("identity repository unavailable")
	}
	settings, ok := storage.SettingsRepository(store)
	if !ok {
		t.Fatal("settings repository unavailable")
	}
	accounts, err := access.OpenRepository(identity)
	if err != nil {
		t.Fatal(err)
	}
	model, err := llm.NewRepository(settings, key)
	if err != nil {
		t.Fatal(err)
	}
	return sharedServer{handler: NewServer(nil, nil, nil, WithAuth(testAuthenticator(t)), WithAccounts(accounts), WithLLMSettings(model)).Handler(), account: accounts, llm: model}
}

func sharedCall(server http.Handler, method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(method, "http://workbench.invalid"+path, strings.NewReader(body))
	r.RemoteAddr = "192.0.2.10:4321"
	r.Header.Set("Content-Type", "application/json")
	if cookie != nil {
		r.AddCookie(cookie)
	}
	if origin != "" {
		r.Header.Set("Origin", origin)
	}
	w := httptest.NewRecorder()
	server.ServeHTTP(w, r)
	return w
}

func TestSharedIdentityAndSettingsAcrossInstances(t *testing.T) {
	t.Parallel()
	firstStore, secondStore := sharedSQLRepositories(t)
	key := bytes.Repeat([]byte{0x42}, 32)
	first := newSharedServer(t, firstStore, key)
	second := newSharedServer(t, secondStore, key)

	var status struct {
		SetupRequired bool `json:"setup_required"`
	}
	if response := sharedCall(first.handler, http.MethodGet, "/api/auth/status", "", nil, ""); response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &status) != nil || !status.SetupRequired {
		t.Fatalf("fresh status: %d %s", response.Code, response.Body)
	}
	credentials := `{"username":"testadmin","password":"test-only-account-password"}`
	if response := sharedCall(first.handler, http.MethodPost, "/api/auth/setup", credentials, nil, "https://other.invalid"); response.Code != 403 {
		t.Fatalf("cross-site setup: %d", response.Code)
	}
	if response := sharedCall(first.handler, http.MethodPost, "/api/auth/setup", credentials, nil, ""); response.Code != 201 {
		t.Fatalf("setup: %d %s", response.Code, response.Body)
	}
	status = struct {
		SetupRequired bool `json:"setup_required"`
	}{}
	if response := sharedCall(second.handler, http.MethodGet, "/api/auth/status", "", nil, ""); response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &status) != nil || status.SetupRequired {
		t.Fatalf("second instance did not see setup: %d %s", response.Code, response.Body)
	}
	if response := sharedCall(second.handler, http.MethodPost, "/api/auth/setup", credentials, nil, ""); response.Code != 409 {
		t.Fatalf("second setup: %d %s", response.Code, response.Body)
	}
	login := sharedCall(second.handler, http.MethodPost, "/api/auth/login", credentials, nil, "")
	if login.Code != 200 {
		t.Fatalf("login: %d %s", login.Code, login.Body)
	}
	cookies := login.Result().Cookies()
	if len(cookies) != 1 {
		t.Fatal("login did not set a session cookie")
	}
	session := cookies[0]
	if response := sharedCall(first.handler, http.MethodGet, "/api/me", "", session, ""); response.Code != 200 {
		t.Fatalf("session was not shared: %d %s", response.Code, response.Body)
	}
	if response := sharedCall(first.handler, http.MethodPost, "/api/auth/logout", "{}", session, "https://other.invalid"); response.Code != 403 {
		t.Fatalf("cross-site logout: %d", response.Code)
	}
	if response := sharedCall(first.handler, http.MethodPost, "/api/auth/logout", "{}", session, ""); response.Code != 200 {
		t.Fatalf("logout: %d %s", response.Code, response.Body)
	}
	if response := sharedCall(second.handler, http.MethodGet, "/api/me", "", session, ""); response.Code != 401 {
		t.Fatalf("logout did not revoke across instances: %d %s", response.Code, response.Body)
	}

	// The login rate limit is shared, not counted per process.
	for attempt := 1; attempt <= 6; attempt++ {
		target := first.handler
		if attempt%2 == 0 {
			target = second.handler
		}
		response := sharedCall(target, http.MethodPost, "/api/auth/login", `{"username":"testadmin","password":"incorrect-password"}`, nil, "")
		if attempt <= 5 && response.Code != 401 {
			t.Fatalf("attempt %d: %d %s", attempt, response.Code, response.Body)
		}
		if attempt == 6 && (response.Code != 429 || response.Header().Get("Retry-After") != "60") {
			t.Fatalf("shared rate limit: %d %s", response.Code, response.Body)
		}
	}
}

func TestSharedSettingsCASRedactionAndUnavailableKey(t *testing.T) {
	t.Parallel()
	firstStore, secondStore := sharedSQLRepositories(t)
	const providerKey = "test-only-shared-provider-key"
	key := bytes.Repeat([]byte{0x24}, 32)
	first := newSharedServer(t, firstStore, key)
	second := newSharedServer(t, secondStore, key)

	call := func(server sharedServer, method, body string, headers map[string]string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "http://workbench.invalid/api/settings/llm", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminSecret)
		for key, value := range headers {
			req.Header.Set(key, value)
		}
		rec := httptest.NewRecorder()
		server.handler.ServeHTTP(rec, req)
		return rec
	}
	get := func(server sharedServer) response {
		w := call(server, http.MethodGet, "", nil)
		return response{status: w.Code, body: w.Body.Bytes(), header: w.Header()}
	}
	initial := get(first)
	if initial.status != 200 || initial.header.Get("ETag") != `"0"` || strings.Contains(string(initial.body), providerKey) {
		t.Fatalf("initial settings: %d %s", initial.status, initial.body)
	}
	body := `{"enabled":true,"protocol":"chat-completions","base_url":"https://models.invalid/v1","model":"test-model","api_key":"` + providerKey + `","timeout_seconds":30,"max_output_tokens":1024}`
	saved := call(first, http.MethodPut, body, map[string]string{"If-Match": `"0"`})
	if saved.Code != 200 || saved.Header().Get("ETag") != `"1"` || strings.Contains(saved.Body.String(), providerKey) {
		t.Fatalf("save: %d %s", saved.Code, saved.Body.String())
	}
	remote := get(second)
	var remotePublic struct {
		APIKeyConfigured bool   `json:"api_key_configured"`
		Version          string `json:"version"`
	}
	if remote.status != 200 || remote.header.Get("ETag") != `"1"` || json.Unmarshal(remote.body, &remotePublic) != nil || !remotePublic.APIKeyConfigured || remotePublic.Version != "1" || strings.Contains(string(remote.body), providerKey) {
		t.Fatalf("second instance: %d %s", remote.status, remote.body)
	}
	// A stale If-Match is rejected by the second instance.
	w := call(second, http.MethodPut, body, map[string]string{"If-Match": `"0"`})
	if w.Code != http.StatusPreconditionFailed {
		t.Fatalf("stale save: %d %s", w.Code, w.Body)
	}

	// Exactly one of two writers holding the same version wins.
	var wg sync.WaitGroup
	statuses := make(chan int, 2)
	for _, server := range []sharedServer{first, second} {
		wg.Add(1)
		go func(server sharedServer) {
			defer wg.Done()
			req := httptest.NewRequest(http.MethodPut, "http://workbench.invalid/api/settings/llm", strings.NewReader(strings.Replace(body, "test-model", "concurrent-model", 1)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+adminSecret)
			req.Header.Set("If-Match", `"1"`)
			rec := httptest.NewRecorder()
			server.handler.ServeHTTP(rec, req)
			statuses <- rec.Code
		}(server)
	}
	wg.Wait()
	close(statuses)
	wins, conflicts := 0, 0
	for status := range statuses {
		switch status {
		case 200:
			wins++
		case 412:
			conflicts++
		default:
			t.Fatalf("concurrent save status %d", status)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("concurrent saves wins=%d conflicts=%d", wins, conflicts)
	}

	// The database holds only ciphertext, and a missing or wrong installation key
	// is an explicit unavailable state rather than a reset or a 200 with defaults.
	repo, _ := storage.SettingsRepository(firstStore)
	ciphertext, version, found, err := repo.LoadLLMSettings(context.Background())
	if err != nil || !found || version != 2 || bytes.Contains(ciphertext, []byte(providerKey)) {
		t.Fatalf("ciphertext in database: version=%d found=%v err=%v", version, found, err)
	}
	unavailableJSON := `{"enabled":true,"protocol":"chat-completions","base_url":"https://models.invalid/v1","model":"test-model","api_key":"` + providerKey + `","timeout_seconds":30,"max_output_tokens":1024}`
	for name, manager := range map[string]*llm.Manager{
		"missing": llm.NewUnavailableRepository(repo, llm.ErrKeyUnavailable),
	} {
		server := NewServer(nil, nil, nil, WithAuth(testAuthenticator(t)), WithLLMSettings(manager))
		for _, method := range []string{http.MethodGet, http.MethodPut, http.MethodPost} {
			target := "/api/settings/llm"
			if method == http.MethodPost {
				target = "/api/settings/llm/test"
			}
			w := httptest.NewRecorder()
			req := httptest.NewRequest(method, "http://workbench.invalid"+target, strings.NewReader(unavailableJSON))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("If-Match", `"2"`)
			req.Header.Set("Authorization", "Bearer "+adminSecret)
			server.Handler().ServeHTTP(w, req)
			if w.Code != http.StatusServiceUnavailable || !strings.Contains(w.Body.String(), "settings_unavailable") || strings.Contains(w.Body.String(), providerKey) {
				t.Fatalf("%s %s: %d %s", name, method, w.Code, w.Body.String())
			}
		}
	}
	wrongKey, _ := llm.NewRepository(repo, bytes.Repeat([]byte{0x99}, 32))
	wrongServer := NewServer(nil, nil, nil, WithAuth(testAuthenticator(t)), WithLLMSettings(wrongKey))
	req := httptest.NewRequest(http.MethodGet, "http://workbench.invalid/api/settings/llm", nil)
	req.Header.Set("Authorization", "Bearer "+adminSecret)
	rec := httptest.NewRecorder()
	wrongServer.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "settings_unavailable") {
		t.Fatalf("wrong key: %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), providerKey) {
		t.Fatal("unavailable response disclosed the provider key")
	}

	// A repository failure is a sanitized 503, not a defaults response and not a
	// leaked database error.
	if err := secondStore.Close(); err != nil {
		t.Fatal(err)
	}
	failure := get(second)
	if failure.status != http.StatusServiceUnavailable || !strings.Contains(string(failure.body), "settings_unavailable") || strings.Contains(string(failure.body), providerKey) || strings.Contains(string(failure.body), "sql:") {
		t.Fatalf("settings repository failure: %d %s", failure.status, failure.body)
	}
}

func TestSharedIdentityRepositoryFailureIsServiceUnavailable(t *testing.T) {
	t.Parallel()
	store, _ := sharedSQLRepositories(t)
	server := newSharedServer(t, store, bytes.Repeat([]byte{0x11}, 32))
	credentials := `{"username":"testadmin","password":"test-only-account-password"}`
	if response := sharedCall(server.handler, http.MethodPost, "/api/auth/setup", credentials, nil, ""); response.Code != 201 {
		t.Fatalf("setup: %d %s", response.Code, response.Body)
	}
	login := sharedCall(server.handler, http.MethodPost, "/api/auth/login", credentials, nil, "")
	if login.Code != 200 {
		t.Fatalf("login: %d %s", login.Code, login.Body)
	}
	session := login.Result().Cookies()[0]
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	status := sharedCall(server.handler, http.MethodGet, "/api/auth/status", "", nil, "")
	if status.Code != http.StatusServiceUnavailable || !strings.Contains(status.Body.String(), "identity_unavailable") {
		t.Fatalf("status after repository failure: %d %s", status.Code, status.Body)
	}
	me := sharedCall(server.handler, http.MethodGet, "/api/me", "", session, "")
	if me.Code != http.StatusServiceUnavailable || !strings.Contains(me.Body.String(), "identity_unavailable") {
		t.Fatalf("session after repository failure: %d %s", me.Code, me.Body)
	}
}
