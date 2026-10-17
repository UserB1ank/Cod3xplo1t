package findings_test

import (
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/findings"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

func findingScope() artifact.Scope {
	return artifact.Scope{ProjectID: "project-a", SourceID: "source-a", SnapshotID: "snap-a"}
}

func fingerprintInput() findings.FingerprintInput {
	return findings.FingerprintInput{
		Scope:       findingScope(),
		RuleFamily:  "codexploit.command-execution",
		RuleVersion: "1",
		File:        "cmd/server/main.go",
		Line:        17,
		Status:      verify.FindingCandidate,
	}
}

func TestFingerprintBindsVersionScopeRuleAndLocation(t *testing.T) {
	base := findings.Fingerprint(findings.FingerprintVersion, fingerprintInput())
	if base == "" || len(base) != 32 {
		t.Fatalf("fingerprint = %q", base)
	}
	if again := findings.Fingerprint(findings.FingerprintVersion, fingerprintInput()); again != base {
		t.Fatal("same observation produced a different fingerprint")
	}
	if other := findings.Fingerprint("2", fingerprintInput()); other == base {
		t.Fatal("fingerprint version did not change the identity")
	}
	for name, mutate := range map[string]func(*findings.FingerprintInput){
		"project":      func(in *findings.FingerprintInput) { in.Scope.ProjectID = "project-b" },
		"source":       func(in *findings.FingerprintInput) { in.Scope.SourceID = "source-b" },
		"snapshot":     func(in *findings.FingerprintInput) { in.Scope.SnapshotID = "snap-b" },
		"rule family":  func(in *findings.FingerprintInput) { in.RuleFamily = "codexploit.sql-query" },
		"rule version": func(in *findings.FingerprintInput) { in.RuleVersion = "2" },
		"file":         func(in *findings.FingerprintInput) { in.File = "cmd/server/other.go" },
		"line":         func(in *findings.FingerprintInput) { in.Line = 18 },
		"status":       func(in *findings.FingerprintInput) { in.Status = verify.FindingConfirmed },
	} {
		t.Run(name, func(t *testing.T) {
			input := fingerprintInput()
			mutate(&input)
			if got := findings.Fingerprint(findings.FingerprintVersion, input); got == base {
				t.Fatalf("%s did not change the fingerprint", name)
			}
		})
	}
}

func TestRuleFamilyMergesOnlyDeclaredEquivalences(t *testing.T) {
	if got := findings.RuleFamily("codexploit.static-patterns", "CP001"); got != "codexploit.command-execution" {
		t.Fatalf("CP001 family = %q", got)
	}
	if got := findings.RuleFamily("codexploit.static-patterns", "CP002"); got != "codexploit.sql-query" {
		t.Fatalf("CP002 family = %q", got)
	}
	if findings.RuleFamily("other.scanner", "CP001") == findings.RuleFamily("codexploit.static-patterns", "CP001") {
		t.Fatal("an undeclared cross-tool rule was treated as equivalent")
	}
	if findings.RuleFamily("codexploit.static-patterns", "CP999") != "codexploit.static-patterns/CP999" {
		t.Fatal("an undeclared rule did not fall back to its own namespace")
	}
}

func TestFingerprintIgnoresTitlesBecauseOnlyRuleEquivalenceMerges(t *testing.T) {
	// Titles are deliberately not an input: two equivalent rule reports at the
	// same location are one group even when their wording differs. Conversely, a
	// different rule with a similar title is not merged (covered above).
	first := fingerprintInput()
	second := fingerprintInput()
	if findings.Fingerprint(findings.FingerprintVersion, first) != findings.Fingerprint(findings.FingerprintVersion, second) {
		t.Fatal("stable input changed the fingerprint")
	}
}
