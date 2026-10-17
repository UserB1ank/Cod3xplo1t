// Package findings groups equivalent plugin observations into stable findings
// without changing a verification verdict.
package findings

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"

	"github.com/open-mcp-ai/Codexploit/internal/artifact"
	"github.com/open-mcp-ai/Codexploit/internal/verify"
)

// FingerprintVersion is part of every derived identity. Raising it changes new
// groups only; stored observations keep the exact fingerprint they were written
// with, so an upgrade cannot silently rewrite history.
const FingerprintVersion = "1"

// RuleFamilyVersion names the rule-equivalence table.
const RuleFamilyVersion = "1"

// ruleFamilies is the explicit cross-tool equivalence ledger. A rule that is not
// listed here stays in its own plugin namespace: equal-looking titles or rule ids
// from different tools are not evidence that the rules mean the same thing.
var ruleFamilies = map[string]string{
	"codexploit.static-patterns/CP001": "codexploit.command-execution",
	"codexploit.static-patterns/CP002": "codexploit.sql-query",
}

// RuleFamily returns the semantic family used in a fingerprint. Undeclared rules
// fall back to the plugin-scoped rule id, which prevents accidental merging.
func RuleFamily(pluginID, ruleID string) string {
	if family, ok := ruleFamilies[pluginID+"/"+ruleID]; ok {
		return family
	}
	return pluginID + "/" + ruleID
}

// FingerprintInput is the full claim identity of one observation. Titles,
// messages and severity hints are deliberately absent: they can change without
// changing the claim, and a similar title is not rule equivalence.
type FingerprintInput struct {
	Scope       artifact.Scope
	RuleFamily  string
	RuleVersion string
	File        string
	Line        int
	Status      verify.FindingStatus
}

// Fingerprint returns a stable, bounded identity for one observation claim.
func Fingerprint(version string, input FingerprintInput) string {
	if version == "" {
		version = FingerprintVersion
	}
	document := struct {
		Version     string               `json:"version"`
		Scope       artifact.Scope       `json:"scope"`
		RuleFamily  string               `json:"rule_family"`
		RuleVersion string               `json:"rule_version"`
		File        string               `json:"file"`
		Line        int                  `json:"line"`
		Status      verify.FindingStatus `json:"status"`
	}{
		Version:     version,
		Scope:       input.Scope,
		RuleFamily:  input.RuleFamily,
		RuleVersion: input.RuleVersion,
		File:        input.File,
		Line:        input.Line,
		Status:      input.Status,
	}
	raw, _ := json.Marshal(document)
	sum := sha256.Sum256(append([]byte("codexploit/finding-fingerprint\n"), raw...))
	return hex.EncodeToString(sum[:])[:32]
}
