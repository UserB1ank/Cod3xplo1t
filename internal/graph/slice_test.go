package graph

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/scg"
)

func TestDeclarationWindowUsesContextWhenEndIsMissing(t *testing.T) {
	sym := scg.Symbol{StartLine: 54, EndLine: 54}
	start, end, note := declarationWindow(sym, 80, 6)
	if start != 48 || end != 127 {
		t.Fatalf("window = %d-%d, want 48-127", start, end)
	}
	if !strings.Contains(note, "function end was not recorded") {
		t.Fatalf("note = %q", note)
	}
	if start, end, note := declarationWindow(scg.Symbol{StartLine: 10, EndLine: 20}, 80, 6); start != 10 || end != 20 || !strings.Contains(note, "declaration as recorded") {
		t.Fatalf("recorded declaration = %d-%d %q", start, end, note)
	}
}

func TestReadLinesReportsFileTotalAndCutsAtBudget(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sample.go"), []byte("one\ntwo\nthree\nfour\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	lines, total, err := readLines(dir, "sample.go", 2, 4, 2)
	if err != nil {
		t.Fatal(err)
	}
	if total != 4 || len(lines) != 2 || lines[0] != "two" {
		t.Fatalf("lines=%v total=%d", lines, total)
	}
}
