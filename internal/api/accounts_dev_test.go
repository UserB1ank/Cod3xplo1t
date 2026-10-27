//go:build dev

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/access"
)

func TestDevDefaultAdministratorLoginAndLogout(t *testing.T) {
	accounts, err := access.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, _ := NewAuthenticator(nil)
	server := NewServer(nil, nil, nil, WithAuth(auth), WithAccounts(accounts))
	call := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			req.AddCookie(cookie)
		}
		response := httptest.NewRecorder()
		server.Handler().ServeHTTP(response, req)
		return response
	}
	status := call("GET", "/api/auth/status", "", nil)
	var mode struct {
		SetupRequired bool `json:"setup_required"`
	}
	if err := json.Unmarshal(status.Body.Bytes(), &mode); err != nil {
		t.Fatal(err)
	}
	if mode.SetupRequired {
		t.Fatalf("dev must open login: %s", status.Body)
	}
	for _, existing := range []bool{false, true} {
		if existing {
			if err := accounts.Setup("existing-admin", "test-only-account-password", "setup"); err != nil {
				t.Fatal(err)
			}
		}
		response := call("POST", "/api/auth/login", `{"username":"devadmin","password":"devadmin"}`, nil)
		if response.Code != 200 || len(response.Result().Cookies()) != 1 {
			t.Fatalf("login: %d %s", response.Code, response.Body)
		}
		cookie := response.Result().Cookies()[0]
		me := call("GET", "/api/me", "", cookie)
		var identity struct {
			Role string `json:"role"`
		}
		if err := json.Unmarshal(me.Body.Bytes(), &identity); err != nil {
			t.Fatal(err)
		}
		if me.Code != 200 || identity.Role != "admin" {
			t.Fatalf("identity: %d %s", me.Code, me.Body)
		}
		if got := call("POST", "/api/auth/logout", "{}", cookie); got.Code != 200 {
			t.Fatal(got.Code)
		}
		if got := call("GET", "/api/me", "", cookie); got.Code != 401 {
			t.Fatal("session not revoked")
		}
	}
	if _, err := accounts.Login("existing-admin", "test-only-account-password", "existing"); err != nil {
		t.Fatal("original account lost", err)
	}
	if got := call("POST", "/api/auth/login", `{"username":"devadmin","password":"wrong"}`, nil); got.Code != 401 {
		t.Fatal("wrong password accepted")
	}
}
