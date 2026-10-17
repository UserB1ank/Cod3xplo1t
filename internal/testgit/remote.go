// Package testgit provides a synthetic HTTPS Git remote for public-boundary tests.
package testgit

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type Remote struct {
	Dir, URL, CAFile string
	Server           *httptest.Server
}

func New(t *testing.T, authorization string) *Remote {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	r := &Remote{Dir: t.TempDir()}
	r.Git(t, "init", "-q")
	r.Git(t, "symbolic-ref", "HEAD", "refs/heads/main")
	files := http.StripPrefix("/service.git", http.FileServer(http.Dir(filepath.Join(r.Dir, ".git"))))
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if authorization != "" && req.Header.Get("Authorization") != authorization {
			w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		files.ServeHTTP(w, req)
	}))
	t.Cleanup(r.Server.Close)
	r.URL = r.Server.URL + "/service.git"
	r.CAFile = filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(r.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *Remote) Git(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=" + os.DevNull}, args...)...)
	cmd.Dir = r.Dir
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GIT_") {
			cmd.Env = append(cmd.Env, value)
		}
	}
	cmd.Env = append(cmd.Env, "GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture", "GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture",
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2024-01-01T00:00:00Z")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture git %v: %v %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func (r *Remote) Commit(t *testing.T, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.Dir, "go.mod"), []byte("module example.invalid/service\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.Dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	r.Git(t, "add", "-A")
	r.Git(t, "commit", "-q", "-m", "fixture")
	r.Git(t, "update-server-info")
	return r.Git(t, "rev-parse", "HEAD")
}
