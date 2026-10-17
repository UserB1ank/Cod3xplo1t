package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/access"
)

func TestPasswordLoginSessionOriginAndLogout(t *testing.T) {
	t.Parallel()
	accounts, err := access.Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	auth, err := NewAuthenticator(nil)
	if err != nil {
		t.Fatal(err)
	}
	server := NewServer(nil, nil, nil, WithAuth(auth), WithAccounts(accounts))
	call := func(method, path, body string, cookie *http.Cookie, origin string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://workbench.invalid"+path, strings.NewReader(body))
		r.Header.Set("Content-Type", "application/json")
		if cookie != nil {
			r.AddCookie(cookie)
		}
		if origin != "" {
			r.Header.Set("Origin", origin)
		}
		w := httptest.NewRecorder()
		server.Handler().ServeHTTP(w, r)
		return w
	}
	if response := call("GET", "/api/me", "", nil, ""); response.Code != 401 {
		t.Fatal("anonymous workspace access")
	}
	credentials := `{"username":"testadmin","password":"test-only-account-password"}`
	if response := call("POST", "/api/auth/setup", credentials, nil, "https://other.invalid"); response.Code != 403 {
		t.Fatal("cross-origin setup permitted")
	}
	if response := call("POST", "/api/auth/setup", credentials, nil, ""); response.Code != 201 {
		t.Fatal("setup failed", response.Code, response.Body)
	}
	if response := call("POST", "/api/auth/setup", credentials, nil, ""); response.Code != 409 {
		t.Fatal("existing account overwritten")
	}
	if response := call("POST", "/api/auth/login", `{"username":"testadmin","password":"incorrect"}`, nil, ""); response.Code != 401 {
		t.Fatal("wrong password accepted")
	}
	response := call("POST", "/api/auth/login", credentials, nil, "http://workbench.invalid")
	if response.Code != 200 || len(response.Result().Cookies()) != 1 {
		t.Fatal("login failed", response.Code, response.Body)
	}
	cookie := response.Result().Cookies()[0]
	if !cookie.HttpOnly || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api" {
		t.Fatal("session cookie protections missing")
	}
	response = call("GET", "/api/me", "", cookie, "")
	var identity struct {
		Role string `json:"role"`
	}
	if response.Code != 200 || json.Unmarshal(response.Body.Bytes(), &identity) != nil || identity.Role != "admin" {
		t.Fatal("session access failed", response.Code)
	}
	if response := call("PUT", "/api/settings/llm", "{}", cookie, "https://other.invalid"); response.Code != 403 {
		t.Fatal("cross-origin mutation accepted", response.Code)
	}
	if response := call("POST", "/api/auth/logout", "{}", cookie, ""); response.Code != 200 {
		t.Fatal("logout failed")
	}
	if response := call("GET", "/api/me", "", cookie, ""); response.Code != 401 {
		t.Fatal("revoked session still accepted")
	}
}
