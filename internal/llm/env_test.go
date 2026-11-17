package llm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDSFEnvironmentSettingsAreLoadedReadOnlyAndMasked(t *testing.T) {
	t.Parallel()
	const secret = "test-only-dsf-secret"
	path := filepath.Join(t.TempDir(), ".env")
	content := strings.Join([]string{
		"IGNORED=value",
		"DSF_API_KEY=" + secret,
		"DSF_BASE_URL=https://dsf.invalid/v1",
		"DSF_MODEL=dsf-audit-model",
		"DSF_PROTOCOL=chat-completions",
		"DSF_TIMEOUT_SECONDS=45",
		"DSF_MAX_OUTPUT_TOKENS=2048",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}

	manager, loaded, err := LoadEnvSettings(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded || manager == nil {
		t.Fatal("DSF configuration was not loaded")
	}
	public, err := manager.Public()
	if err != nil {
		t.Fatal(err)
	}
	if public.Source != "environment" || !public.ReadOnly {
		t.Fatalf("public source = %+v", public)
	}
	if !public.APIKeyConfigured || public.Model != "dsf-audit-model" {
		t.Fatalf("public configuration = %+v", public)
	}
	raw, err := json.Marshal(public)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), secret) || strings.Contains(public.Version, secret) {
		t.Fatal("public settings disclosed the environment credential")
	}
	cfg, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != secret || cfg.BaseURL != "https://dsf.invalid/v1" ||
		cfg.TimeoutSeconds != 45 || cfg.MaxOutputTokens != 2048 {
		t.Fatalf("runtime configuration = %+v", cfg)
	}
	if _, err := manager.Save(Update{}, public.Version); !errors.Is(err, ErrReadOnly) {
		t.Fatalf("environment settings save = %v, want ErrReadOnly", err)
	}

	if err := os.WriteFile(path, []byte(strings.Replace(content, secret, "test-only-rotated-secret", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	rotated, loaded, err := LoadEnvSettings(path)
	if err != nil || !loaded {
		t.Fatalf("reload rotated settings: loaded=%v err=%v", loaded, err)
	}
	rotatedPublic, err := rotated.Public()
	if err != nil {
		t.Fatal(err)
	}
	if rotatedPublic.Version == public.Version {
		t.Fatal("rotating the environment credential did not advance the configuration version")
	}
}

func TestDSFEnvironmentSettingsMissingFileFallsThrough(t *testing.T) {
	t.Parallel()
	manager, loaded, err := LoadEnvSettings(filepath.Join(t.TempDir(), "missing.env"))
	if err != nil || loaded || manager != nil {
		t.Fatalf("missing file = manager %v loaded %v error %v", manager, loaded, err)
	}
}

func TestProviderEnvironmentSettingsAcceptBaseURLAPIKeyAndModel(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), ".env")
	content := strings.Join([]string{
		"base_url=https://generic.invalid/v1",
		"api_key=test-only-generic-secret",
		"model=generic-audit-model",
		"protocol=chat-completions",
		"timeout_seconds=30",
		"max_output_tokens=1024",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, loaded, err := LoadEnvSettings(path)
	if err != nil || !loaded {
		t.Fatalf("generic environment: loaded=%v err=%v", loaded, err)
	}
	cfg, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.BaseURL != "https://generic.invalid/v1" || cfg.APIKey != "test-only-generic-secret" ||
		cfg.Model != "generic-audit-model" || cfg.TimeoutSeconds != 30 || cfg.MaxOutputTokens != 1024 {
		t.Fatalf("generic environment configuration = %+v", cfg)
	}
}

func TestDSFPrefixedValuesOverrideGenericProviderNames(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), ".env")
	content := strings.Join([]string{
		"api_key=test-only-generic-secret",
		"base_url=https://generic.invalid/v1",
		"model=generic-model",
		"DSF_API_KEY=test-only-prefixed-secret",
		"DSF_BASE_URL=https://prefixed.invalid/v1",
		"DSF_MODEL=prefixed-model",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, loaded, err := LoadEnvSettings(path)
	if err != nil || !loaded {
		t.Fatalf("prefixed environment: loaded=%v err=%v", loaded, err)
	}
	cfg, err := manager.Current()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.APIKey != "test-only-prefixed-secret" ||
		cfg.BaseURL != "https://prefixed.invalid/v1" || cfg.Model != "prefixed-model" {
		t.Fatalf("prefixed environment did not win: %+v", cfg)
	}
}

func TestDSFEnvironmentSettingsRejectPartialBlockWithoutLeakingValues(t *testing.T) {
	t.Parallel()
	const secret = "test-only-partial-secret"
	path := filepath.Join(t.TempDir(), ".env")
	if err := os.WriteFile(path, []byte("DSF_API_KEY="+secret+"\nDSF_MODEL=model-only\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	manager, loaded, err := LoadEnvSettings(path)
	if err == nil || loaded || manager != nil {
		t.Fatalf("partial DSF block = manager %v loaded %v error %v", manager, loaded, err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatal("load error disclosed the environment credential")
	}
}
