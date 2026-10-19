package llm

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

func testUpdate() Update {
	key := "test-only-not-a-real-provider-key"
	return Update{Enabled: true, Protocol: "chat-completions", BaseURL: "https://models.invalid/v1", Model: "test-model", APIKey: &key, TimeoutSeconds: 30, MaxOutputTokens: 1024}
}

func TestEncryptedSettingsPersistAndProtectRetainedCredentials(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	update := testUpdate()
	public, err := m.Save(update, publicVersion(t, m))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "llm.enc"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(*update.APIKey)) {
		t.Fatal("secret stored as plaintext")
	}
	publicJSON, _ := json.Marshal(public)
	if bytes.Contains(publicJSON, []byte(*update.APIKey)) || !public.APIKeyConfigured {
		t.Fatal("public settings disclose or lose secret")
	}
	reopened, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := reopened.Current()
	if err != nil || cfg.APIKey != *update.APIKey {
		t.Fatal("settings did not survive reopen", err)
	}
	update.APIKey = nil
	update.Model = "other-model"
	public, err = reopened.Save(update, public.Version)
	if err != nil {
		t.Fatal(err)
	}
	update.BaseURL = "https://other-models.invalid/v1"
	if _, err := reopened.Candidate(update, public.Version); err == nil {
		t.Fatal("retained credential could be redirected to a changed endpoint")
	}
	update.ClearAPIKey = true
	public, err = reopened.Save(update, public.Version)
	if err != nil || public.APIKeyConfigured {
		t.Fatal("explicit key removal failed", err)
	}
	if _, err := reopened.Save(update, "initial"); !errors.Is(err, ErrConflict) {
		t.Fatal("stale configuration overwrote settings", err)
	}
	if err := os.Remove(filepath.Join(dir, "settings.key")); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("lost key silently reset saved settings")
	}
}

func TestSettingsConcurrentReadsAndSave(t *testing.T) {
	t.Parallel()
	m, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 50 {
				_, _ = m.Public()
				_, _ = m.Current()
			}
		}()
	}
	for range 5 {
		if _, err := m.Save(testUpdate(), publicVersion(t, m)); err != nil {
			t.Fatal(err)
		}
	}
	wg.Wait()
}

func TestSettingsRejectInvalidURLsAndCorruption(t *testing.T) {
	t.Parallel()
	for _, endpoint := range []string{"file:///tmp/model", "https://user:secret@models.invalid/v1", "https://models.invalid/v1?key=test", "https://models.invalid/v1#fragment"} {
		m, err := Open(t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		u := testUpdate()
		u.BaseURL = endpoint
		if _, err := m.Save(u, publicVersion(t, m)); err == nil {
			t.Fatal("accepted unsafe URL")
		}
	}
	dir := t.TempDir()
	m, err := Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := m.Save(testUpdate(), publicVersion(t, m)); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "llm.enc"), []byte("corrupt"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir); err == nil {
		t.Fatal("silently accepted corrupt settings")
	}
}

func publicVersion(t *testing.T, m *Manager) string {
	t.Helper()
	public, err := m.Public()
	if err != nil {
		t.Fatal(err)
	}
	return public.Version
}
