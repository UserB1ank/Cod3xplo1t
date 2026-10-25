package storage

import (
	"errors"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

func TestPluginReleaseAndInstallationCASAreIndependent(t *testing.T) {
	s := NewMemory()
	release := plugin.Release{PluginID: "example.parser", PluginVersion: "1.0.0", OS: "linux", Arch: "amd64", PackageDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64)}
	if err := s.PutPluginRelease(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	changed := release
	changed.PackageDigest = strings.Repeat("c", 64)
	if err := s.PutPluginRelease(t.Context(), changed); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("same platform release replaced: %v", err)
	}
	changed.OS = "windows"
	if err := s.PutPluginRelease(t.Context(), changed); err != nil {
		t.Fatalf("independent platform release: %v", err)
	}
	installation := plugin.Installation{ID: "installation-fixture", Release: release, WorkerID: "worker-fixture", Installed: true, Enabled: true, Integrity: "verified", Probe: "not_run", Version: 1}
	if _, err := s.SavePluginInstallation(t.Context(), installation, 0); err != nil {
		t.Fatal(err)
	}
	installation.Enabled = false
	installation.Version = 2
	if _, err := s.SavePluginInstallation(t.Context(), installation, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := s.SavePluginInstallation(t.Context(), installation, 1); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("stale policy CAS: %v", err)
	}
	rows, err := s.ListPluginInstallations(t.Context())
	if err != nil || len(rows) != 1 || rows[0].Enabled || !rows[0].Installed {
		t.Fatalf("installation policy: %+v %v", rows, err)
	}
}
