package verify

import "testing"

func TestSeverityGradesDoNotInterpretSecurityGoalsAsImpact(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ input, want string }{{"critical", "high"}, {"HIGH", "high"}, {"moderate", "medium"}, {"low", "low"}, {"高危", "high"}, {"", ""}, {"prevent SQL injection", ""}} {
		if got := NormalizeSeverity(test.input); got != test.want {
			t.Errorf("NormalizeSeverity(%q) = %q, want %q", test.input, got, test.want)
		}
	}
}
