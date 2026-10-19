package api

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/access"
	"github.com/open-mcp-ai/Codexploit/internal/app"
	"github.com/open-mcp-ai/Codexploit/internal/llm"
	"github.com/open-mcp-ai/Codexploit/internal/storage"
	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
)

func postgresSettingsKey(t *testing.T, fill byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "settings-key")
	value := bytes.Repeat([]byte{fill}, 32)
	if err := os.WriteFile(path, []byte(hex.EncodeToString(value)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}

func buildPostgresRuntime(t *testing.T, dsn, keyFile string) *app.Runtime {
	t.Helper()
	rt, err := app.Build(context.Background(), app.Config{
		Workspace:       t.TempDir(),
		StorageDriver:   "postgres",
		PostgresDSNFile: dsn,
		SettingsKeyFile: keyFile,
		Agent:           app.AgentConfig{Enabled: true, Runtime: app.AgentRuntimeLLM},
	})
	if err != nil {
		t.Fatal(err)
	}
	return rt
}

func postgresAccounts(t *testing.T, rt *app.Runtime) *access.Manager {
	t.Helper()
	repo, ok := storage.IdentityRepository(rt.Store)
	if !ok {
		t.Fatal("PostgreSQL identity repository is not wired")
	}
	manager, err := access.OpenRepository(repo)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestPostgresSharedIdentityAndSettingsAcrossInstances(t *testing.T) {
	dsn := testpostgres.DSNFile(t)
	keyFile := postgresSettingsKey(t, 0x31)
	first := buildPostgresRuntime(t, dsn, keyFile)
	second := buildPostgresRuntime(t, dsn, keyFile)
	if first.LLMSettings == nil || second.LLMSettings == nil {
		t.Fatal("model settings were not wired")
	}
	accountsFirst, accountsSecond := postgresAccounts(t, first), postgresAccounts(t, second)

	if configured, err := accountsFirst.Configured(); err != nil || configured {
		t.Fatalf("fresh account configured=%v err=%v", configured, err)
	}
	const password = "test-only-account-password"
	if err := accountsFirst.Setup("testadmin", password, "setup-peer"); err != nil {
		t.Fatal(err)
	}
	if configured, err := accountsSecond.Configured(); err != nil || !configured {
		t.Fatalf("second instance did not see the account: configured=%v err=%v", configured, err)
	}
	if err := accountsSecond.Setup("testadmin", password, "setup-peer"); !errors.Is(err, access.ErrAlreadyConfigured) {
		t.Fatalf("second setup: %v", err)
	}
	token, err := accountsSecond.Login("testadmin", password, "login-peer")
	if err != nil {
		t.Fatal(err)
	}
	if user, ok, err := accountsFirst.Authenticate(token); err != nil || !ok || user != "testadmin" {
		t.Fatalf("shared session: user=%q ok=%v err=%v", user, ok, err)
	}
	if err := accountsFirst.Logout(token); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := accountsSecond.Authenticate(token); err != nil || ok {
		t.Fatalf("PostgreSQL logout did not revoke across instances: ok=%v err=%v", ok, err)
	}
	// Keep a live session for the rebuild assertion below.
	token, err = accountsSecond.Login("testadmin", password, "login-peer")
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 1; attempt <= 5; attempt++ {
		if _, err := accountsFirst.Login("testadmin", "incorrect-password", "shared-peer"); !errors.Is(err, access.ErrInvalidCredentials) {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
	}
	if _, err := accountsSecond.Login("testadmin", password, "shared-peer"); !errors.Is(err, access.ErrRateLimited) {
		t.Fatalf("shared PostgreSQL rate limit: %v", err)
	}

	public, err := first.LLMSettings.Public()
	if err != nil || public.Version != "0" {
		t.Fatalf("initial settings: %+v err=%v", public, err)
	}
	providerKey := "test-only-postgres-provider-key"
	update := llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: "https://models.invalid/v1", Model: "test-model", APIKey: &providerKey, TimeoutSeconds: 30, MaxOutputTokens: 1024}
	public, err = first.LLMSettings.Save(update, public.Version)
	if err != nil || public.Version != "1" || !public.APIKeyConfigured {
		t.Fatalf("save settings: %+v err=%v", public, err)
	}
	remote, err := second.LLMSettings.Public()
	if err != nil || remote.Version != "1" || remote.Model != "test-model" || !remote.APIKeyConfigured {
		t.Fatalf("second instance settings: %+v err=%v", remote, err)
	}
	if _, err := second.LLMSettings.Save(update, "0"); !errors.Is(err, llm.ErrConflict) {
		t.Fatalf("stale settings CAS: %v", err)
	}

	var wg sync.WaitGroup
	results := make(chan error, 2)
	for _, settings := range []*llm.Manager{first.LLMSettings, second.LLMSettings} {
		wg.Add(1)
		go func(settings *llm.Manager) {
			defer wg.Done()
			_, err := settings.Save(update, remote.Version)
			results <- err
		}(settings)
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, llm.ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("concurrent settings winners=%d conflicts=%d", wins, conflicts)
	}
	pinConfig, pin, err := first.LLMSettings.Snapshot()
	if err != nil || pin.Version != "2" || pinConfig.Model != "test-model" {
		t.Fatalf("settings pin: cfg=%+v public=%+v err=%v", pinConfig, pin, err)
	}
	settingsRepo, _ := storage.SettingsRepository(first.Store)
	ciphertext, version, found, err := settingsRepo.LoadLLMSettings(context.Background())
	if err != nil || !found || version != 2 || bytes.Contains(ciphertext, []byte(providerKey)) {
		t.Fatalf("PostgreSQL ciphertext: version=%d found=%v err=%v", version, found, err)
	}

	// Rebuild both application instances: the account, live session and settings
	// survive in PostgreSQL, and the same key decrypts the saved configuration.
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}
	if err := second.Close(); err != nil {
		t.Fatal(err)
	}
	rebuilt := buildPostgresRuntime(t, dsn, keyFile)
	t.Cleanup(func() { rebuilt.Close() })
	rebuiltAccounts := postgresAccounts(t, rebuilt)
	if user, ok, err := rebuiltAccounts.Authenticate(token); err != nil || !ok || user != "testadmin" {
		t.Fatalf("session did not survive rebuild: user=%q ok=%v err=%v", user, ok, err)
	}
	rebuiltPublic, err := rebuilt.LLMSettings.Public()
	if err != nil || rebuiltPublic.Version != "2" || !rebuiltPublic.APIKeyConfigured {
		t.Fatalf("settings did not survive rebuild: %+v err=%v", rebuiltPublic, err)
	}
	if _, err := rebuiltAccounts.Login("testadmin", password, "login-peer"); err != nil {
		t.Fatal(err)
	}
	if err := rebuiltAccounts.Logout(token); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := rebuiltAccounts.Authenticate(token); err != nil || ok {
		t.Fatalf("logout after rebuild: ok=%v err=%v", ok, err)
	}

	// Missing and mismatched installation keys are explicit unavailable states,
	// never a reset or a plaintext fallback.
	missing := buildPostgresRuntime(t, dsn, "")
	t.Cleanup(func() { missing.Close() })
	if _, err := missing.LLMSettings.Public(); !errors.Is(err, llm.ErrKeyUnavailable) {
		t.Fatalf("missing key: %v", err)
	}
	wrong := buildPostgresRuntime(t, dsn, postgresSettingsKey(t, 0x77))
	t.Cleanup(func() { wrong.Close() })
	if _, err := wrong.LLMSettings.Public(); !errors.Is(err, llm.ErrDecrypt) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestPostgresImportsLegacyWorkspaceModelSettings(t *testing.T) {
	dsn := testpostgres.DSNFile(t)
	workspace := t.TempDir()
	legacy, err := llm.Open(filepath.Join(workspace, "settings"))
	if err != nil {
		t.Fatal(err)
	}
	legacyPublic, err := legacy.Public()
	if err != nil {
		t.Fatal(err)
	}
	providerKey := "test-only-legacy-provider-key"
	update := llm.Update{Enabled: true, Protocol: "chat-completions", BaseURL: "https://models.invalid/v1", Model: "legacy-model", APIKey: &providerKey, TimeoutSeconds: 30, MaxOutputTokens: 1024}
	if _, err := legacy.Save(update, legacyPublic.Version); err != nil {
		t.Fatal(err)
	}
	keyFile := postgresSettingsKey(t, 0x2a)
	rt, err := app.Build(context.Background(), app.Config{
		Workspace:       workspace,
		StorageDriver:   "postgres",
		PostgresDSNFile: dsn,
		SettingsKeyFile: keyFile,
		Agent:           app.AgentConfig{Enabled: true, Runtime: app.AgentRuntimeLLM},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { rt.Close() })
	public, err := rt.LLMSettings.Public()
	if err != nil || public.Version != "1" || public.Model != "legacy-model" || !public.APIKeyConfigured {
		t.Fatalf("imported settings: %+v err=%v", public, err)
	}
	config, err := rt.LLMSettings.Current()
	if err != nil || config.APIKey != providerKey {
		t.Fatalf("imported credential: %+v err=%v", config, err)
	}
	repo, _ := storage.SettingsRepository(rt.Store)
	ciphertext, version, found, err := repo.LoadLLMSettings(context.Background())
	if err != nil || !found || version != 1 || bytes.Contains(ciphertext, []byte(providerKey)) {
		t.Fatalf("imported ciphertext: version=%d found=%v err=%v", version, found, err)
	}
}
