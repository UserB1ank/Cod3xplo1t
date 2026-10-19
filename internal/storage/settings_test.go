package storage

import (
	"context"
	"sync"
	"testing"
)

func TestSQLSettingsRepositoryCASAndRestart(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	s, path := openIdentitySQL(t)
	repo := newSQLSettings(s)
	if _, _, found, err := repo.LoadLLMSettings(ctx); err != nil || found {
		t.Fatalf("initial settings found=%v err=%v", found, err)
	}
	first := []byte("first-ciphertext")
	version, saved, err := repo.SaveLLMSettings(ctx, first, 0)
	if err != nil || !saved || version != 1 {
		t.Fatalf("initial save: version=%d saved=%v err=%v", version, saved, err)
	}
	if _, saved, err := repo.SaveLLMSettings(ctx, []byte("stale"), 0); err != nil || saved {
		t.Fatalf("second initial save: saved=%v err=%v", saved, err)
	}
	second := []byte("second-ciphertext")
	version, saved, err = repo.SaveLLMSettings(ctx, second, 1)
	if err != nil || !saved || version != 2 {
		t.Fatalf("second save: version=%d saved=%v err=%v", version, saved, err)
	}
	if _, saved, err := repo.SaveLLMSettings(ctx, []byte("stale"), 1); err != nil || saved {
		t.Fatalf("stale save: saved=%v err=%v", saved, err)
	}

	reopened, err := OpenSQL(ctx, "sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reopened.Close() })
	loaded, version, found, err := newSQLSettings(reopened).LoadLLMSettings(ctx)
	if err != nil || !found || version != 2 || string(loaded) != string(second) {
		t.Fatalf("restart load: version=%d found=%v ciphertext=%q err=%v", version, found, loaded, err)
	}

	// Concurrent writers with the same expected version: exactly one wins.
	var wg sync.WaitGroup
	results := make(chan bool, 2)
	for i := range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, saved, err := newSQLSettings(reopened).SaveLLMSettings(ctx, []byte{byte(i)}, 2)
			if err != nil {
				t.Error(err)
				return
			}
			results <- saved
		}()
	}
	wg.Wait()
	close(results)
	wins := 0
	for saved := range results {
		if saved {
			wins++
		}
	}
	if wins != 1 {
		t.Fatalf("concurrent settings saves: winners=%d", wins)
	}
	if _, version, found, err := newSQLSettings(reopened).LoadLLMSettings(ctx); err != nil || !found || version != 3 {
		t.Fatalf("final settings: version=%d found=%v err=%v", version, found, err)
	}
}
