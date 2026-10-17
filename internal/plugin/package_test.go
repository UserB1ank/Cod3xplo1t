package plugin_test

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
)

func packageManifest(id, version, entrypoint string) string {
	return `{"api_version":"codexploit/v1","id":"` + id + `","version":"` + version + `","name":"Pattern scanner","description":"Offline fixture.","kind":"analyzer","languages":["Go"],"runtime":{"kind":"process","entrypoint":"` + entrypoint + `"},"consumes":["source.snapshot"],"produces":["scanner.alerts"],"permissions":{"network":"none","source_write":false},"config_schema":{"type":"object","properties":{},"additionalProperties":false}}`
}

func writePackage(t *testing.T, root, id, version, entrypoint, content string) string {
	t.Helper()
	dir, err := os.MkdirTemp(root, "pkg-")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, filepath.FromSlash(entrypoint))), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(packageManifest(id, version, entrypoint)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(entrypoint)), []byte(content), 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func TestLoadPackageBindsCanonicalManifestAndAllPackageBytes(t *testing.T) {
	root := t.TempDir()
	dir := writePackage(t, root, "codexploit.static-patterns", "1.0.0", "scanner", "binary-one")
	pkg, err := plugin.LoadPackage(dir)
	if err != nil {
		t.Fatalf("LoadPackage: %v", err)
	}
	if pkg.Manifest.ID != "codexploit.static-patterns" || pkg.Manifest.Version != "1.0.0" || pkg.Entrypoint != "scanner" {
		t.Fatalf("package = %+v", pkg)
	}
	if len(pkg.ManifestDigest) != 64 || len(pkg.PackageDigest) != 64 {
		t.Fatalf("digests = %q / %q", pkg.ManifestDigest, pkg.PackageDigest)
	}
	if filepath.Dir(pkg.Executable) != dir {
		t.Fatalf("executable escaped package: %q", pkg.Executable)
	}
	if pkg.ExecutableBytes != int64(len("binary-one")) || pkg.ExecutableSHA256 == "" {
		t.Fatalf("executable binding = %d %q", pkg.ExecutableBytes, pkg.ExecutableSHA256)
	}

	// Manifest whitespace is canonicalised, so the manifest digest and package
	// digest do not depend on formatting.
	spaced := strings.Replace(packageManifest(pkg.Manifest.ID, pkg.Manifest.Version, pkg.Entrypoint), `","`, `", "`, -1)
	if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(spaced), 0o600); err != nil {
		t.Fatal(err)
	}
	same, err := plugin.LoadPackage(dir)
	if err != nil {
		t.Fatalf("LoadPackage spaced: %v", err)
	}
	if same.ManifestDigest != pkg.ManifestDigest || same.PackageDigest != pkg.PackageDigest {
		t.Fatalf("formatting changed identity: %+v", same)
	}

	// Replacing the program changes the package identity.
	if err := os.WriteFile(filepath.Join(dir, "scanner"), []byte("binary-two"), 0o700); err != nil {
		t.Fatal(err)
	}
	changed, err := plugin.LoadPackage(dir)
	if err != nil {
		t.Fatalf("LoadPackage changed: %v", err)
	}
	if changed.PackageDigest == pkg.PackageDigest {
		t.Fatal("package digest did not bind the executable bytes")
	}
}

func TestLoadPackageRejectsEscapingOrUntrustedEntrypoints(t *testing.T) {
	for _, test := range []struct {
		name       string
		entrypoint string
		link       bool
		want       error
	}{
		{name: "parent", entrypoint: "../scanner", want: plugin.ErrInvalid},
		{name: "absolute", entrypoint: "/bin/sh", want: plugin.ErrInvalid},
		{name: "backslash", entrypoint: `bin\scanner`, want: plugin.ErrInvalid},
		{name: "missing", entrypoint: "scanner", want: plugin.ErrUnsupported},
		{name: "symlink", entrypoint: "scanner", link: true, want: plugin.ErrInvalid},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			dir := filepath.Join(root, "pkg")
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(dir, "manifest.json"), []byte(packageManifest("codexploit.static-patterns", "1.0.0", test.entrypoint)), 0o600); err != nil {
				t.Fatal(err)
			}
			if test.name == "missing" {
				// no entrypoint file
			} else if test.link {
				target := filepath.Join(root, "outside")
				if err := os.WriteFile(target, []byte("outside"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, filepath.Join(dir, "scanner")); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			} else {
				if err := os.WriteFile(filepath.Join(dir, "scanner"), []byte("x"), 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := plugin.LoadPackage(dir); !errors.Is(err, test.want) {
				t.Fatalf("LoadPackage = %v, want %v", err, test.want)
			}
		})
	}
}

func TestDiscoverPackagesIsDeterministicAndRejectsDuplicates(t *testing.T) {
	root := t.TempDir()
	writePackage(t, root, "codexploit.beta", "1.0.0", "scanner", "b")
	writePackage(t, root, "codexploit.alpha", "2.0.0", "scanner", "a")
	if err := os.MkdirAll(filepath.Join(root, "not-a-package"), 0o700); err != nil {
		t.Fatal(err)
	}
	packages, err := plugin.DiscoverPackages(root)
	if err != nil {
		t.Fatalf("DiscoverPackages: %v", err)
	}
	if len(packages) != 2 || packages[0].Manifest.ID != "codexploit.alpha" || packages[1].Manifest.ID != "codexploit.beta" {
		t.Fatalf("packages = %+v", packages)
	}

	duplicate := t.TempDir()
	writePackage(t, duplicate, "codexploit.alpha", "1.0.0", "scanner", "a")
	writePackage(t, duplicate, "codexploit.alpha", "1.0.0", "scanner", "b")
	if _, err := plugin.DiscoverPackages(duplicate); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("duplicate = %v, want ErrConflict", err)
	}
	if packages, err := plugin.DiscoverPackages(filepath.Join(root, "absent")); err != nil || len(packages) != 0 {
		t.Fatalf("absent root = %+v %v", packages, err)
	}
}

func TestCatalogReportsInstalledAndExecutableSeparately(t *testing.T) {
	ctx := context.Background()
	store := storage.NewMemory()
	catalog, err := plugin.NewCatalog(ctx, store)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	dir := writePackage(t, root, "codexploit.static-patterns", "1.0.0", "scanner", "binary")
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	pkg, err := plugin.LoadPackage(dir)
	if err != nil {
		t.Fatal(err)
	}
	// A manually registered manifest is registered but not installed.
	record, err := catalog.Register(ctx, json.RawMessage(raw), pkg.PackageDigest, "manual import")
	if err != nil {
		t.Fatal(err)
	}
	if record.Installed || record.Executable || record.Reason == "" {
		t.Fatalf("manual record = %+v", record)
	}
	// Installing the verified local package makes the same record executable.
	installed, err := catalog.InstallPackage(ctx, dir)
	if err != nil {
		t.Fatalf("InstallPackage: %v", err)
	}
	if !installed.Installed || !installed.Executable || installed.PackageDigest != pkg.PackageDigest {
		t.Fatalf("installed record = %+v", installed)
	}
	listed, err := catalog.List(ctx, "", 10)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, entry := range listed {
		if entry.Manifest.ID == "codexploit.static-patterns" {
			found = true
			if !entry.Installed || !entry.Executable {
				t.Fatalf("listed record = %+v", entry)
			}
		}
	}
	if !found {
		t.Fatal("installed package missing from catalog")
	}
}
