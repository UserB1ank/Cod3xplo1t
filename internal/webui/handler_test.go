package webui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/fstest"
)

func TestUIAssetsAndAPIBoundary(t *testing.T) {
	t.Parallel()
	assets := fstest.MapFS{"index.html": {Data: []byte("<!doctype html><title>workbench</title>")}, "assets/app-123.js": {Data: []byte("export const ready = true;")}}
	api := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`{"error":"unauthorized"}`))
	})
	serve := handler(api, assets, nil)
	for _, test := range []struct {
		path   string
		status int
		html   bool
	}{{"/", 200, true}, {"/projects/p/tasks/t", 200, true}, {"/assets/missing.js", 404, false}, {"/favicon-missing.svg", 404, false}, {"/api/missing", 401, false}, {"/api", 401, false}, {"/healthz", 401, false}} {
		t.Run(test.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			serve.ServeHTTP(response, httptest.NewRequest(http.MethodGet, test.path, nil))
			if response.Code != test.status {
				t.Fatalf("status %d", response.Code)
			}
			if strings.Contains(response.Body.String(), "workbench") != test.html {
				t.Fatalf("wrong fallback: %s", response.Body.String())
			}
		})
	}
	asset := httptest.NewRecorder()
	serve.ServeHTTP(asset, httptest.NewRequest(http.MethodGet, "/assets/app-123.js", nil))
	if !strings.Contains(asset.Header().Get("Cache-Control"), "immutable") || asset.Header().Get("Content-Security-Policy") == "" {
		t.Fatal("asset headers missing")
	}
	post := httptest.NewRecorder()
	serve.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/projects/p", nil))
	if post.Code != 405 {
		t.Fatalf("UI mutation accepted: %d", post.Code)
	}
}
