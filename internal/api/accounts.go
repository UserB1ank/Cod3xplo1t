package api

import (
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"

	"github.com/open-mcp-ai/Codexploit/internal/access"
)

const sessionCookie = "codexploit_session"

func WithAccounts(accounts *access.Manager) Option { return func(s *Server) { s.Accounts = accounts } }

func sameOrigin(r *http.Request) bool {
	if r.Header.Get("Sec-Fetch-Site") == "cross-site" {
		return false
	}
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	} // Non-browser API clients have no Origin.
	u, err := url.Parse(origin)
	return err == nil && u.Host == r.Host && (u.Scheme == "http" || u.Scheme == "https")
}

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]bool{"password_login": s.Accounts != nil, "setup_required": s.Accounts != nil && !s.Accounts.Configured()})
}

func (s *Server) handleAccountLogin(setup bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		if s.Accounts == nil {
			writeError(w, http.StatusNotImplemented, "password_login_unavailable", errors.New("此服务未启用账号登录"))
			return
		}
		if !sameOrigin(r) {
			writeError(w, http.StatusForbidden, "origin_forbidden", errors.New("登录请求来源无效"))
			return
		}
		var req struct {
			Username string `json:"username"`
			Password string `json:"password"`
		}
		if !s.decode(w, r, &req) {
			return
		}
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			peer = r.RemoteAddr
		}
		if setup {
			if err := s.Accounts.Setup(strings.TrimSpace(req.Username), req.Password, peer); err != nil {
				accountError(w, err, true)
				return
			}
			writeJSON(w, http.StatusCreated, map[string]bool{"ok": true})
			return
		}
		token, err := s.Accounts.Login(strings.TrimSpace(req.Username), req.Password, peer)
		if err != nil {
			accountError(w, err, false)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: token, Path: "/api", HttpOnly: true, Secure: r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https", SameSite: http.SameSiteStrictMode, MaxAge: int(access.SessionLifetime.Seconds())})
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
	}
}

func (s *Server) handleAccountLogout(w http.ResponseWriter, r *http.Request) {
	if !sameOrigin(r) {
		writeError(w, http.StatusForbidden, "origin_forbidden", errors.New("退出请求来源无效"))
		return
	}
	if cookie, err := r.Cookie(sessionCookie); err == nil && s.Accounts != nil {
		s.Accounts.Logout(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Path: "/api", HttpOnly: true, SameSite: http.SameSiteStrictMode, MaxAge: -1})
	w.Header().Set("Cache-Control", "no-store")
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func accountError(w http.ResponseWriter, err error, setup bool) {
	switch {
	case errors.Is(err, access.ErrRateLimited):
		w.Header().Set("Retry-After", "60")
		writeError(w, http.StatusTooManyRequests, "login_rate_limited", err)
	case errors.Is(err, access.ErrAlreadyConfigured):
		writeError(w, http.StatusConflict, "account_exists", err)
	case setup:
		writeError(w, http.StatusBadRequest, "account_setup_failed", err)
	default:
		writeError(w, http.StatusUnauthorized, "invalid_credentials", access.ErrInvalidCredentials)
	}
}
