package verify

import "strings"

// NormalizeSeverity exposes three grades. Missing or unknown assessments stay
// ungraded rather than being assigned an invented impact.
func NormalizeSeverity(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "critical", "high", "严重", "高", "高危":
		return "high"
	case "medium", "moderate", "中", "中危":
		return "medium"
	case "low", "info", "informational", "低", "低危":
		return "low"
	default:
		return ""
	}
}
