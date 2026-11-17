package scripts

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"
)

func TestCITestPushesCoverDevelopmentBranch(t *testing.T) {
	path := filepath.Join("..", ".github", "workflows", "test.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?m)^\s{2}push:\s*\r?\n\s{4}branches:\s*\[main, dev\]\s*\r?$`)
	if !pattern.Match(raw) {
		t.Fatalf("%s must run push CI for both main and the active dev branch:\n%s", path, raw)
	}
}
