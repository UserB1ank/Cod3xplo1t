package app

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/scanner"
)

func TestPackagedScannerUpgradePreservesHistoricalImmutableVersion(t *testing.T) {
	ctx := context.Background()
	config := Config{Workspace: t.TempDir()}
	config.DBPath = filepath.Join(config.Workspace, "state.db")
	rt, err := Build(ctx, config)
	if err != nil {
		t.Fatal(err)
	}
	var previous plugin.Manifest
	if err := json.Unmarshal(scanner.Manifest(), &previous); err != nil {
		t.Fatal(err)
	}
	previous.Version = "1.0.0"
	legacy, err := json.Marshal(previous)
	if err != nil {
		t.Fatal(err)
	}
	oldDigest := strings.Repeat("a", 64)
	if _, err := rt.PluginCatalog.Register(ctx, legacy, oldDigest, "previous deployment"); err != nil {
		t.Fatal(err)
	}
	if err := rt.Close(); err != nil {
		t.Fatal(err)
	}
	packages := t.TempDir()
	directory := filepath.Join(packages, scanner.ID+"@"+scanner.Version)
	if err := os.Mkdir(directory, 0700); err != nil {
		t.Fatal(err)
	}
	binary, err := os.ReadFile(os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	entry := "scanner"
	if runtime.GOOS == "windows" {
		entry += ".exe"
	}
	if err := os.WriteFile(filepath.Join(directory, entry), binary, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "manifest.json"), scanner.Manifest(), 0600); err != nil {
		t.Fatal(err)
	}
	config.PluginPackages = packages
	upgraded, err := Build(ctx, config)
	if err != nil {
		t.Fatalf("upgrading the packaged scanner prevents startup: %v", err)
	}
	defer upgraded.Close()
	old, err := upgraded.PluginCatalog.Get(ctx, scanner.ID, "1.0.0")
	if err != nil || old.PackageDigest != oldDigest {
		t.Fatalf("historical scanner rewritten: %v", err)
	}
	current, err := upgraded.PluginCatalog.Get(ctx, scanner.ID, scanner.Version)
	if err != nil || !current.Installed || !current.Executable {
		t.Fatalf("new package not executable: %v", err)
	}
}
