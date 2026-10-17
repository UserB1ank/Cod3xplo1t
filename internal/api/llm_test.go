package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
