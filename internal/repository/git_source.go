package repository

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

var ErrInvalidGitSource = errors.New("invalid Git URL or revision; use HTTPS or SSH without embedded credentials")
var ErrGitCredential = errors.New("repository credential reference is unavailable")
var ErrGitAccessDenied = errors.New("repository access or credential scope was denied")
var ErrGitRevisionNotFound = errors.New("the requested Git revision does not resolve to a commit")
var ErrGitUnavailable = errors.New("the Git repository could not be fetched; check its address, transport and server availability")

func gitTransportError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	message := strings.ToLower(err.Error())
	for _, indicator := range []string{"authentication failed", "could not read username", "permission denied", "access denied", "returned error: 401", "returned error: 403", "host key verification failed"} {
		if strings.Contains(message, indicator) {
			return ErrGitAccessDenied
		}
	}
	return ErrGitUnavailable
}

type gitEnvironmentKey struct{}

type gitCredential struct {
	Origin            string   `json:"origin"`
	ProjectIDs        []string `json:"project_ids"`
	Authorization     string   `json:"authorization"`
	SSHUser           string   `json:"ssh_user,omitempty"`
	SSHIdentityFile   string   `json:"ssh_identity_file,omitempty"`
	SSHKnownHostsFile string   `json:"ssh_known_hosts_file,omitempty"`
}

// WithGitCredentialFiles registers deployment-owned secret references. Values
// are file paths, not secrets; each document limits its origin and projects.
func WithGitCredentialFiles(files map[string]string) Option {
	return func(m *Manager) {
		m.GitCredentialFiles = make(map[string]string, len(files))
		for ref, path := range files {
			m.GitCredentialFiles[ref] = path
		}
	}
}

// ValidateGitSource checks an explicit remote definition before any network I/O.
func (m *Manager) ValidateGitSource(source Source) error {
	_, err := m.gitSourceEnvironment(source)
	return err
}

func (m *Manager) gitSourceEnvironment(source Source) ([]string, error) {
	u, err := url.Parse(source.Raw)
	if err != nil || u.Hostname() == "" || u.User != nil || (u.Scheme != "https" && u.Scheme != "ssh") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.Path == "" {
		return nil, ErrInvalidGitSource
	}
	if strings.IndexFunc(source.Raw, unicode.IsControl) >= 0 || strings.IndexFunc(u.Path, unicode.IsControl) >= 0 || strings.Contains(source.Raw, "\\") || source.Ref == "" || validRef(source.Ref) != nil {
		return nil, ErrInvalidGitSource
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return nil, ErrInvalidGitSource
		}
	}
	env := []string{"GIT_ALLOW_PROTOCOL=https:ssh"}
	if source.CredentialRef == "" {
		if u.Scheme == "ssh" {
			return nil, ErrGitCredential
		}
		return env, nil
	}
	file, err := os.Open(m.GitCredentialFiles[source.CredentialRef])
	if err != nil {
		return nil, ErrGitCredential
	}
	defer file.Close()
	var credential gitCredential
	decoder := json.NewDecoder(io.LimitReader(file, 32769))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&credential); err != nil {
		return nil, ErrGitCredential
	}
	if err := decoder.Decode(new(any)); !errors.Is(err, io.EOF) {
		return nil, ErrGitCredential
	}
	origin := u.Scheme + "://" + u.Host
	if !strings.EqualFold(credential.Origin, origin) || !slices.Contains(credential.ProjectIDs, source.ProjectID) {
		return nil, ErrGitAccessDenied
	}
	if u.Scheme == "ssh" {
		if credential.Authorization != "" || credential.SSHUser == "" || strings.HasPrefix(credential.SSHUser, "-") || strings.IndexFunc(credential.SSHUser, func(r rune) bool {
			return !(unicode.IsLetter(r) || unicode.IsDigit(r) || strings.ContainsRune("._-", r))
		}) >= 0 {
			return nil, ErrGitCredential
		}
		for _, path := range []string{credential.SSHIdentityFile, credential.SSHKnownHostsFile} {
			if !filepath.IsAbs(path) || strings.IndexFunc(path, unicode.IsControl) >= 0 {
				return nil, ErrGitCredential
			}
			info, err := os.Stat(path)
			if err != nil || !info.Mode().IsRegular() {
				return nil, ErrGitCredential
			}
		}
		quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
		command := "ssh -F " + quote(os.DevNull) + " -l " + quote(credential.SSHUser) + " -i " + quote(credential.SSHIdentityFile) +
			" -o " + quote("UserKnownHostsFile="+credential.SSHKnownHostsFile) + " -o " + quote("GlobalKnownHostsFile="+os.DevNull) +
			" -o BatchMode=yes -o StrictHostKeyChecking=yes -o IdentitiesOnly=yes -o IdentityAgent=none"
		return append(env, "GIT_SSH_COMMAND="+command, "GIT_SSH_VARIANT=ssh"), nil
	}
	if u.Scheme != "https" || len(credential.Authorization) == 0 || len(credential.Authorization) > 8192 || strings.IndexFunc(credential.Authorization, unicode.IsControl) >= 0 {
		return nil, ErrGitCredential
	}
	return append(env, "GIT_CONFIG_COUNT=1", "GIT_CONFIG_KEY_0=http.extraHeader", "GIT_CONFIG_VALUE_0=Authorization: "+credential.Authorization), nil
}

func withGitEnvironment(ctx context.Context, env []string) context.Context {
	return context.WithValue(ctx, gitEnvironmentKey{}, env)
}
