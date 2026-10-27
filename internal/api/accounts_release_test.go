//go:build !dev

package api

import (
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/access"
)

func TestReleaseHasNoDefaultAdministrator(t *testing.T) {
	accounts, err := access.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := NewAuthenticator(nil)
	server := NewServer(nil, nil, nil, WithAuth(auth), WithAccounts(accounts))
	req := httptest.NewRequest("POST", "/api/auth/login", strings.NewReader(`{"username":"devadmin","password":"devadmin"}`))
	req.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	server.Handler().ServeHTTP(response, req)
	if response.Code != 401 {
		t.Fatalf("release accepted default login: %d", response.Code)
	}
}
