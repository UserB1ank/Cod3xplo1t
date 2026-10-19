package llm

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

type fakeSettingsRepository struct {
	mu      sync.Mutex
	cipher  []byte
	version int64
	found   bool
	fail    error
}

func (f *fakeSettingsRepository) LoadLLMSettings(context.Context) ([]byte, int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return nil, 0, false, f.fail
	}
	if !f.found {
		return nil, 0, false, nil
	}
	return append([]byte(nil), f.cipher...), f.version, true, nil
}

func (f *fakeSettingsRepository) SaveLLMSettings(_ context.Context, ciphertext []byte, expected int64) (int64, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.fail != nil {
		return 0, false, f.fail
	}
	if expected == 0 {
		if f.found {
			return 0, false, nil
		}
		f.found, f.cipher, f.version = true, append([]byte(nil), ciphertext...), 1
		return 1, true, nil
	}
	if !f.found || f.version != expected {
		return 0, false, nil
	}
	f.cipher = append([]byte(nil), ciphertext...)
	f.version++
	return f.version, true, nil
}

func installationKey(t *testing.T, fill byte) []byte {
	t.Helper()
	key := bytes.Repeat([]byte{fill}, 32)
	return key
}

func openRepositorySettings(t *testing.T, repo Repository, key []byte) *Manager {
	t.Helper()
	manager, err := NewRepository(repo, key)
	if err != nil {
		t.Fatal(err)
	}
	return manager
}

func TestRepositorySettingsPersistCASAndRetainedSecrets(t *testing.T) {
	t.Parallel()
	repo := &fakeSettingsRepository{}
	first := openRepositorySettings(t, repo, installationKey(t, 1))
	second := openRepositorySettings(t, repo, installationKey(t, 1))
	public, err := first.Public()
	if err != nil || public.Version != "0" || public.APIKeyConfigured {
		t.Fatalf("initial public: %+v err=%v", public, err)
	}
	update := testUpdate()
	update.APIKey = nil
	public, err = first.Save(update, public.Version)
	if err != nil || public.Version != "1" || public.APIKeyConfigured || public.Model != update.Model {
		t.Fatalf("initial save: %+v err=%v", public, err)
	}
	remote, err := second.Public()
	if err != nil || remote.Version != "1" || remote.Model != update.Model {
		t.Fatalf("second instance: %+v err=%v", remote, err)
	}
	if _, err := second.Save(update, "0"); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale save: %v", err)
	}

	key := "test-only-repository-provider-key"
	update.APIKey = &key
	public, err = second.Save(update, remote.Version)
	if err != nil || public.Version != "2" || !public.APIKeyConfigured {
		t.Fatalf("secret save: %+v err=%v", public, err)
	}
	repo.mu.Lock()
	stored := append([]byte(nil), repo.cipher...)
	repo.mu.Unlock()
	if bytes.Contains(stored, []byte(key)) {
		t.Fatal("repository stored the provider key in plaintext")
	}
	publicJSON := []byte(public.Model + public.BaseURL + public.Version)
	if bytes.Contains(publicJSON, []byte(key)) {
		t.Fatal("public settings contain the provider key")
	}
	cfg, err := first.Current()
	if err != nil || cfg.APIKey != key {
		t.Fatalf("second instance cannot decrypt: %+v err=%v", cfg, err)
	}

	// Retaining a secret while changing the model keeps it; changing the endpoint
	// without re-entering or clearing it is refused.
	update.APIKey = nil
	update.Model = "other-model"
	if _, err := first.Candidate(update, public.Version); err != nil {
		t.Fatalf("retained secret candidate: %v", err)
	}
	update.BaseURL = "https://other-models.invalid/v1"
	if _, err := first.Candidate(update, public.Version); err == nil {
		t.Fatal("retained credential could be redirected to a changed endpoint")
	}

	// Concurrent writers with the same visible version: exactly one CAS wins.
	results := make(chan error, 2)
	var wg sync.WaitGroup
	writers := []*Manager{
		openRepositorySettings(t, repo, installationKey(t, 1)),
		openRepositorySettings(t, repo, installationKey(t, 1)),
	}
	for _, writer := range writers {
		wg.Add(1)
		go func(writer *Manager) {
			defer wg.Done()
			draft := testUpdate()
			draft.Model = "concurrent-model"
			_, err := writer.Save(draft, public.Version)
			results <- err
		}(writer)
	}
	wg.Wait()
	close(results)
	wins, conflicts := 0, 0
	for err := range results {
		switch {
		case err == nil:
			wins++
		case errors.Is(err, ErrConflict):
			conflicts++
		default:
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("concurrent saves wins=%d conflicts=%d", wins, conflicts)
	}
	snapshot, metadata, err := first.Snapshot()
	if err != nil || snapshot.Model != metadata.Model || metadata.Version == public.Version {
		t.Fatalf("snapshot pin: cfg=%+v public=%+v err=%v", snapshot, metadata, err)
	}
}

func TestRepositorySettingsMissingOrWrongKeyAndRepositoryFailure(t *testing.T) {
	t.Parallel()
	repo := &fakeSettingsRepository{}
	key := installationKey(t, 1)
	manager := openRepositorySettings(t, repo, key)
	public, err := manager.Save(testUpdate(), "0")
	if err != nil {
		t.Fatal(err)
	}
	locked := NewUnavailableRepository(repo, ErrKeyUnavailable)
	if _, err := locked.Public(); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("locked public: %v", err)
	}
	if _, err := locked.Current(); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("locked current: %v", err)
	}
	if _, err := locked.Save(testUpdate(), public.Version); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("locked save: %v", err)
	}
	if _, err := locked.Candidate(testUpdate(), public.Version); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("locked candidate: %v", err)
	}
	if _, _, err := locked.Snapshot(); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("locked snapshot: %v", err)
	}

	wrong := openRepositorySettings(t, repo, installationKey(t, 2))
	if _, err := wrong.Public(); !errors.Is(err, ErrDecrypt) {
		t.Fatalf("wrong key public: %v", err)
	}
	repo.mu.Lock()
	repo.fail = errors.New("database unavailable")
	repo.mu.Unlock()
	if _, err := manager.Public(); !errors.Is(err, ErrRepositoryUnavailable) {
		t.Fatalf("repository failure: %v", err)
	}
}

func TestInstallationKeyFileParsing(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	hexKey := bytes.Repeat([]byte{0xab}, 32)
	hexPath := filepath.Join(dir, "hex-key")
	if err := os.WriteFile(hexPath, []byte(hex.EncodeToString(hexKey)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadInstallationKey(hexPath)
	if err != nil || !bytes.Equal(loaded, hexKey) {
		t.Fatalf("hex key: %x err=%v", loaded, err)
	}
	rawPath := filepath.Join(dir, "raw-key")
	if err := os.WriteFile(rawPath, []byte("0123456789abcdef0123456789abcdef"), 0600); err != nil {
		t.Fatal(err)
	}
	loaded, err = LoadInstallationKey(rawPath)
	if err != nil || string(loaded) != "0123456789abcdef0123456789abcdef" {
		t.Fatalf("raw key: %x err=%v", loaded, err)
	}
	if _, err := LoadInstallationKey(""); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("empty path: %v", err)
	}
	badPath := filepath.Join(dir, "bad-key")
	if err := os.WriteFile(badPath, []byte("too-short"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadInstallationKey(badPath); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("bad key: %v", err)
	}
}

func TestImportLegacyWorkspaceSettingsReencryptsIntoRepository(t *testing.T) {
	t.Parallel()
	legacyDir := filepath.Join(t.TempDir(), "settings")
	legacy, err := Open(legacyDir)
	if err != nil {
		t.Fatal(err)
	}
	update := testUpdate()
	legacyPublic, err := legacy.Public()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Save(update, legacyPublic.Version); err != nil {
		t.Fatal(err)
	}
	repo := &fakeSettingsRepository{}
	key := installationKey(t, 0x19)
	imported, err := ImportLegacySettings(context.Background(), repo, legacyDir, key)
	if err != nil || !imported {
		t.Fatalf("import: imported=%v err=%v", imported, err)
	}
	if imported, err := ImportLegacySettings(context.Background(), repo, legacyDir, key); err != nil || imported {
		t.Fatalf("second import: imported=%v err=%v", imported, err)
	}
	manager := openRepositorySettings(t, repo, key)
	public, err := manager.Public()
	if err != nil || !public.Enabled || !public.APIKeyConfigured || public.Model != update.Model || public.Version != "1" {
		t.Fatalf("imported public: %+v err=%v", public, err)
	}
	cfg, err := manager.Current()
	if err != nil || cfg.APIKey != *update.APIKey {
		t.Fatalf("imported config: %+v err=%v", cfg, err)
	}
	repo.mu.Lock()
	ciphertext := append([]byte(nil), repo.cipher...)
	repo.mu.Unlock()
	if bytes.Contains(ciphertext, []byte(*update.APIKey)) {
		t.Fatal("imported ciphertext contains the provider key")
	}
	if _, err := ImportLegacySettings(context.Background(), repo, filepath.Join(t.TempDir(), "missing"), key); err != nil {
		t.Fatalf("missing legacy directory: %v", err)
	}
	if _, err := ImportLegacySettings(context.Background(), repo, legacyDir, nil); !errors.Is(err, ErrKeyUnavailable) {
		t.Fatalf("missing installation key: %v", err)
	}
}
