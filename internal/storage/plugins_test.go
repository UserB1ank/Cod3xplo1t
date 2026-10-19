package storage

import (
	"context"
	"errors"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
)

// A compiled adapter is rebuilt with the host, so its package digest changes while
// its manifest — the contract a workflow plan pins — does not. Rejecting that would
// leave every existing deployment unable to start after an upgrade. An installed
// process package keeps the strict immutable rule.
func TestPutPluginAcceptsARebuiltBuiltin(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store, ok := tc.store.(pluginStore)
			if !ok {
				t.Fatalf("%s does not implement the plugin store", tc.name)
			}

			first := pluginFixtureRecord("compiled builtin", "a", "1")
			if err := store.PutPlugin(ctx, first); err != nil {
				t.Fatalf("first register: %v", err)
			}
			rebuild := pluginFixtureRecord("compiled builtin", "b", "1")
			if err := store.PutPlugin(ctx, rebuild); err != nil {
				t.Fatalf("a rebuilt builtin was refused: %v", err)
			}
			got, err := store.GetPlugin(ctx, first.Manifest.ID, first.Manifest.Version)
			if err != nil {
				t.Fatalf("GetPlugin: %v", err)
			}
			if got.PackageDigest != "b" {
				t.Fatalf("package digest = %q, want the digest of the new build", got.PackageDigest)
			}

			// The manifest is the immutable part: a different manifest digest still
			// conflicts, even for a compiled adapter.
			changed := pluginFixtureRecord("compiled builtin", "c", "2")
			if err := store.PutPlugin(ctx, changed); !errors.Is(err, plugin.ErrConflict) {
				t.Fatalf("a changed manifest = %v, want plugin.ErrConflict", err)
			}
		})
	}
}

func TestPutPluginKeepsInstalledPackagesImmutable(t *testing.T) {
	for _, tc := range fullStores(t) {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			ctx := context.Background()
			store, ok := tc.store.(pluginStore)
			if !ok {
				t.Fatalf("%s does not implement the plugin store", tc.name)
			}

			first := pluginFixtureRecord("local package codexploit.static-patterns@1.0.2", "a", "1")
			if err := store.PutPlugin(ctx, first); err != nil {
				t.Fatalf("first register: %v", err)
			}
			tampered := pluginFixtureRecord("local package codexploit.static-patterns@1.0.2", "b", "1")
			if err := store.PutPlugin(ctx, tampered); !errors.Is(err, plugin.ErrConflict) {
				t.Fatalf("a changed installed package = %v, want plugin.ErrConflict", err)
			}
		})
	}
}

func pluginFixtureRecord(source, packageDigest, manifestDigest string) plugin.Record {
	return plugin.Record{
		Manifest: plugin.Manifest{
			APIVersion: "codexploit/v1",
			ID:         "builtin.test",
			Version:    "1.0.0",
		},
		PackageDigest:  packageDigest,
		ManifestDigest: manifestDigest,
		Source:         source,
	}
}

// pluginStore is the persistence surface these tests exercise, declared locally so
// the test does not depend on the wider store interfaces.
type pluginStore interface {
	PutPlugin(context.Context, plugin.Record) error
	GetPlugin(context.Context, string, string) (plugin.Record, error)
}
