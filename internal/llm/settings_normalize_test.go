package llm

import "testing"

// TestNormalizeAcceptsAPastedProviderEndpoint covers a configured base URL that is
// already the full endpoint: appending /chat/completions again must not turn a
// valid provider into a 404.
func TestNormalizeAcceptsAPastedProviderEndpoint(t *testing.T) {
	cases := map[string]string{
		"https://api.deepseek.com/chat/completions": "https://api.deepseek.com",
		"https://api.deepseek.com/responses":        "https://api.deepseek.com",
		"https://api.deepseek.com/v1/":              "https://api.deepseek.com/v1",
		"https://api.deepseek.com":                  "https://api.deepseek.com",
	}
	for input, want := range cases {
		cfg, err := normalize(Config{
			Enabled: true, Protocol: "chat-completions", BaseURL: input, Model: "m",
			TimeoutSeconds: 30, MaxOutputTokens: 1024,
		})
		if err != nil {
			t.Fatalf("normalize(%q): %v", input, err)
		}
		if cfg.BaseURL != want {
			t.Errorf("normalize(%q) = %q, want %q", input, cfg.BaseURL, want)
		}
	}
}
