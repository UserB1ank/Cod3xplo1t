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

func TestCILimitsPackageConcurrencyToAvoidRunnerExhaustion(t *testing.T) {
	path := filepath.Join("..", ".github", "workflows", "test.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	pattern := regexp.MustCompile(`(?m)^\s+run: go test \./\.\.\. -p 2 -parallel 2 -count=1 -shuffle=on -race -timeout 240s\s*$`)
	if !pattern.Match(raw) {
		t.Fatalf("%s must bound package concurrency while retaining the full race suite:\n%s", path, raw)
	}

	makefile, err := os.ReadFile(filepath.Join("..", "Makefile"))
	if err != nil {
		t.Fatal(err)
	}
	if !regexp.MustCompile(`(?m)^TEST_FLAGS := -p 2 -parallel 2 -count=1 -shuffle=on -race -timeout 240s\s*$`).Match(makefile) {
		t.Fatalf("Makefile TEST_FLAGS must match CI package concurrency")
	}
}
