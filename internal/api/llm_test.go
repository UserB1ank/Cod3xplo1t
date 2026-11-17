package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/llm"
)

func TestLLMSettingsAdminOnlyMaskedAndVersioned(t *testing.T) {
	t.Parallel()
	const operatorSecret = "test-only-writer-secret-0123456789"
	settings, err := llm.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator([]Token{{Name: "admin", Role: "admin", Secret: adminSecret}, {Name: "writer", Role: "writer", Secret: operatorSecret}, {Name: "reader", Role: "reader", Secret: readerSecret}})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(nil, nil, nil, WithAuth(auth), WithLLMSettings(settings))
	request := func(method, token, version, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/settings/llm", strings.NewReader(body))
		if token != "" {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("If-Match", version)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	for _, token := range []string{operatorSecret, readerSecret} {
		for _, method := range []string{http.MethodGet, http.MethodPut} {
			if w := request(method, token, "", "{}"); w.Code != http.StatusForbidden {
				t.Fatalf("non-admin %s: %d", method, w.Code)
			}
		}
	}
	if w := request(http.MethodGet, "", "", ""); w.Code != http.StatusUnauthorized {
		t.Fatal("public settings route")
	}
	w := request(http.MethodGet, adminSecret, "", "")
	if w.Code != 200 || w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("settings unavailable or cacheable")
	}
	version := w.Header().Get("ETag")
	body := `{"enabled":true,"protocol":"chat-completions","base_url":"https://models.invalid/v1","model":"test-model","api_key":"test-only-provider-secret","timeout_seconds":30,"max_output_tokens":1024}`
	w = request(http.MethodPut, adminSecret, version, body)
	if w.Code != 200 || strings.Contains(w.Body.String(), "test-only-provider-secret") {
		t.Fatalf("unsafe save: %d %s", w.Code, w.Body)
	}
	var public llm.Public
	if err := json.Unmarshal(w.Body.Bytes(), &public); err != nil || !public.APIKeyConfigured {
		t.Fatal("key not configured", err)
	}
	if w := request(http.MethodPut, adminSecret, version, body); w.Code != http.StatusPreconditionFailed {
		t.Fatal("stale version accepted", w.Code)
	}
	if w := request(http.MethodPut, adminSecret, "", body); w.Code != http.StatusPreconditionRequired {
		t.Fatal("missing version accepted", w.Code)
	}
}

func TestLLMSettingsEnvironmentSourceIsVisibleAndReadOnly(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), ".env")
	body := strings.Join([]string{
		"DSF_API_KEY=test-only-environment-secret",
		"DSF_BASE_URL=https://dsf.invalid/v1",
		"DSF_MODEL=dsf-audit-model",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, loaded, err := llm.LoadEnvSettings(path)
	if err != nil || !loaded {
		t.Fatalf("LoadEnvSettings: loaded=%v err=%v", loaded, err)
	}
	auth, err := NewAuthenticator([]Token{{Name: "admin", Role: "admin", Secret: adminSecret}})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(nil, nil, nil, WithAuth(auth), WithLLMSettings(settings))
	request := func(method, version, body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "/api/settings/llm", strings.NewReader(body))
		r.Header.Set("Authorization", "Bearer "+adminSecret)
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("If-Match", version)
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	read := request(http.MethodGet, "", "")
	if read.Code != http.StatusOK || strings.Contains(read.Body.String(), "test-only-environment-secret") {
		t.Fatalf("read environment settings = %d %s", read.Code, read.Body)
	}
	var public llm.Public
	if err := json.Unmarshal(read.Body.Bytes(), &public); err != nil {
		t.Fatal(err)
	}
	if public.Source != "environment" || !public.ReadOnly {
		t.Fatalf("public source = %+v", public)
	}
	saved := request(http.MethodPut, read.Header().Get("ETag"), `{"enabled":true,"protocol":"chat-completions","base_url":"https://dsf.invalid/v1","model":"other","timeout_seconds":30,"max_output_tokens":512}`)
	if saved.Code != http.StatusConflict || !strings.Contains(saved.Body.String(), "settings_read_only") {
		t.Fatalf("save environment settings = %d %s", saved.Code, saved.Body)
	}
}

func TestLLMSettingsEnvironmentConnectionTestExplainsReadOnlySource(t *testing.T) {
	t.Parallel()
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":null,"tool_calls":[{"id":"call-1","type":"function","function":{"name":"connection_check","arguments":"{}"}}]},"finish_reason":"tool_calls"}],"usage":{"prompt_tokens":4,"completion_tokens":2}}`))
	}))
	t.Cleanup(provider.Close)
	path := filepath.Join(t.TempDir(), ".env")
	body := strings.Join([]string{
		"api_key=test-only-environment-secret",
		"base_url=" + provider.URL + "/v1",
		"model=thinking-environment-model",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	settings, loaded, err := llm.LoadEnvSettings(path)
	if err != nil || !loaded {
		t.Fatalf("LoadEnvSettings: loaded=%v err=%v", loaded, err)
	}
	public, err := settings.Public()
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator([]Token{{Name: "admin", Role: "admin", Secret: adminSecret}})
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(nil, nil, nil, WithAuth(auth), WithLLMSettings(settings))
	requestBody := `{"enabled":true,"protocol":"chat-completions","base_url":"` + provider.URL + `/v1","model":"thinking-environment-model","timeout_seconds":30,"max_output_tokens":1024}`
	r := httptest.NewRequest(http.MethodPost, "/api/settings/llm/test", strings.NewReader(requestBody))
	r.Header.Set("Authorization", "Bearer "+adminSecret)
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("If-Match", `"`+public.Version+`"`)
	w := httptest.NewRecorder()
	server.Handler().ServeHTTP(w, r)
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "只读") {
		t.Fatalf("environment connection test = %d %s", w.Code, w.Body)
	}
}
