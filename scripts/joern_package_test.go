package scripts_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestJoernPackagingRejectsCorruptCachedDistribution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Joern package supports macOS and Linux")
	}
	cache := t.TempDir()
	output := filepath.Join(t.TempDir(), "joern-package")
	if err := os.WriteFile(filepath.Join(cache, "joern-"+runtime.GOOS+"-"+runtime.GOARCH+".zip"), []byte("corrupt distribution"), 0600); err != nil {
		t.Fatal(err)
	}
	command := exec.Command("python3", "package-joern.py", "--cache", cache, "--output", output)
	raw, err := command.CombinedOutput()
	if err == nil || !strings.Contains(string(raw), "integrity_mismatch") {
		t.Fatalf("corrupt archive must fail before installation: %v %s", err, raw)
	}
	if _, err := os.Stat(output); !os.IsNotExist(err) {
		t.Fatal("failed package became visible")
	}
}
