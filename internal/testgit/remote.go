// Package testgit provides a synthetic smart-HTTP Git remote for public-boundary tests.
package testgit

import (
	"bufio"
	"bytes"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/textproto"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

type Remote struct {
	Dir, URL, CAFile string
	Server           *httptest.Server

	root  string
	bare  string
	ready bool
}

func New(t *testing.T, authorization string) *Remote {
	t.Helper()
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git is not installed")
	}
	root := t.TempDir()
	r := &Remote{Dir: filepath.Join(root, "work"), root: root, bare: filepath.Join(root, "service.git")}
	if err := os.MkdirAll(r.Dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r.Git(t, "init", "-q")
	r.Git(t, "symbolic-ref", "HEAD", "refs/heads/main")
	r.Git(t, "init", "--bare", "-q", r.bare)
	r.Git(t, "--git-dir="+r.bare, "symbolic-ref", "HEAD", "refs/heads/main")
	r.ready = true
	r.Server = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if authorization != "" && req.Header.Get("Authorization") != authorization {
			w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		r.serveHTTP(w, req)
	}))
	t.Cleanup(r.Server.Close)
	r.URL = r.Server.URL + "/service.git"
	r.CAFile = filepath.Join(t.TempDir(), "ca.crt")
	if err := os.WriteFile(r.CAFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: r.Server.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	return r
}

func (r *Remote) serveHTTP(w http.ResponseWriter, req *http.Request) {
	command := exec.Command("git", "http-backend")
	command.Env = append(gitEnvironment(),
		"GIT_PROJECT_ROOT="+r.root,
		"GIT_HTTP_EXPORT_ALL=1",
		"REQUEST_METHOD="+req.Method,
		"PATH_INFO="+req.URL.Path,
		"QUERY_STRING="+req.URL.RawQuery,
		"CONTENT_TYPE="+req.Header.Get("Content-Type"),
		"CONTENT_LENGTH="+strconv.FormatInt(req.ContentLength, 10),
		"REMOTE_ADDR=127.0.0.1",
		"SERVER_PROTOCOL=HTTP/1.1",
		"GATEWAY_INTERFACE=CGI/1.1",
	)
	command.Stdin = req.Body
	var stderr bytes.Buffer
	command.Stderr = &stderr
	output, err := command.Output()
	if err != nil {
		http.Error(w, fmt.Sprintf("git http-backend: %v: %s", err, stderr.String()), http.StatusInternalServerError)
		return
	}
	reader := bufio.NewReader(bytes.NewReader(output))
	headers, err := textproto.NewReader(reader).ReadMIMEHeader()
	if err != nil {
		http.Error(w, fmt.Sprintf("parse git http-backend response: %v", err), http.StatusInternalServerError)
		return
	}
	status := http.StatusOK
	if value := headers.Get("Status"); value != "" {
		code, _, _ := strings.Cut(value, " ")
		if parsed, err := strconv.Atoi(code); err == nil {
			status = parsed
		}
	}
	for name, values := range headers {
		if strings.EqualFold(name, "Status") {
			continue
		}
		for _, value := range values {
			w.Header().Add(name, value)
		}
	}
	w.WriteHeader(status)
	_, _ = io.Copy(w, reader)
}

func gitEnvironment() []string {
	var env []string
	for _, value := range os.Environ() {
		if !strings.HasPrefix(value, "GIT_") {
			env = append(env, value)
		}
	}
	return env
}

func (r *Remote) Git(t *testing.T, args ...string) string {
	t.Helper()
	output := r.runGit(t, args...)
	if r.ready && publishesRefs(args) {
		r.publish(t)
	}
	return output
}

func (r *Remote) runGit(t *testing.T, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-c", "core.hooksPath=" + os.DevNull}, args...)...)
	cmd.Dir = r.Dir
	cmd.Env = append(gitEnvironment(),
		"GIT_CONFIG_NOSYSTEM=1", "GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_AUTHOR_NAME=fixture", "GIT_AUTHOR_EMAIL=fixture", "GIT_COMMITTER_NAME=fixture", "GIT_COMMITTER_EMAIL=fixture",
		"GIT_AUTHOR_DATE=2024-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2024-01-01T00:00:00Z",
	)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("fixture git %v: %v %s", args, err, output)
	}
	return strings.TrimSpace(string(output))
}

func (r *Remote) publish(t *testing.T) {
	t.Helper()
	r.runGit(t, "push", "--quiet", "--mirror", r.bare)
	head := r.runGit(t, "symbolic-ref", "HEAD")
	r.runGit(t, "--git-dir="+r.bare, "symbolic-ref", "HEAD", head)
}

func publishesRefs(args []string) bool {
	if len(args) == 0 {
		return false
	}
	switch args[0] {
	case "branch", "checkout", "commit", "fetch", "pull", "reset", "symbolic-ref", "tag", "update-ref", "update-server-info":
		return true
	default:
		return false
	}
}

func (r *Remote) Commit(t *testing.T, content string) string {
	t.Helper()
	if err := os.WriteFile(filepath.Join(r.Dir, "go.mod"), []byte("module example.invalid/service\n\ngo 1.24\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(r.Dir, "main.go"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	r.runGit(t, "add", "-A")
	r.runGit(t, "commit", "-q", "-m", "fixture")
	r.publish(t)
	return r.runGit(t, "rev-parse", "HEAD")
}
