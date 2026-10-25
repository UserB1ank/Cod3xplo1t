package storage

import (
	"context"
	"errors"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/open-mcp-ai/Codexploit/internal/plugin"
	"github.com/open-mcp-ai/Codexploit/internal/testpostgres"
	"github.com/open-mcp-ai/Codexploit/migrations"
)

func TestPostgresPluginReleasePoliciesCASRestartAndActiveFence(t *testing.T) {
	file := testpostgres.DSNFile(t)
	dsn, err := os.ReadFile(file)
	if err != nil {
		t.Fatal("read isolated test DSN")
	}
	open := func() *SQL {
		store, err := OpenSQL(t.Context(), "pgx", string(dsn))
		if err != nil {
			t.Fatal("open PostgreSQL")
		}
		t.Cleanup(func() { _ = store.Close() })
		if err = store.EnsureSchema(t.Context(), migrations.Postgres); err != nil {
			t.Fatal(err)
		}
		return store
	}
	first := open()
	release := plugin.Release{PluginID: "example.stage", PluginVersion: "1.0.0", OS: "linux", Arch: "amd64", PackageDigest: strings.Repeat("a", 64), ManifestDigest: strings.Repeat("b", 64)}
	if err = first.PutPluginRelease(t.Context(), release); err != nil {
		t.Fatal(err)
	}
	row := plugin.Installation{ID: "installation-postgres-fixture", Release: release, WorkerID: "local", Installed: true, Enabled: true, Integrity: "verified", Probe: "not_run", Version: 1}
	if _, err = first.SavePluginInstallation(t.Context(), row, 0); err != nil {
		t.Fatal(err)
	}
	if err = first.Close(); err != nil {
		t.Fatal(err)
	}
	first = open()
	second := open()
	stored, err := first.ListPluginInstallations(t.Context())
	if err != nil || len(stored) != 1 || stored[0] != row {
		t.Fatalf("restart policy: %+v %v", stored, err)
	}
	changes := make(chan error, 2)
	start := make(chan struct{})
	var workers sync.WaitGroup
	for i, store := range []*SQL{first, second} {
		workers.Go(func() {
			<-start
			next := row
			next.Enabled = i == 0
			next.Version++
			_, err := store.SavePluginInstallation(t.Context(), next, row.Version)
			changes <- err
		})
	}
	close(start)
	workers.Wait()
	close(changes)
	wins, conflicts := 0, 0
	for err := range changes {
		if err == nil {
			wins++
		} else if errors.Is(err, plugin.ErrConflict) {
			conflicts++
		} else {
			t.Fatal(err)
		}
	}
	if wins != 1 || conflicts != 1 {
		t.Fatalf("CAS wins=%d conflicts=%d", wins, conflicts)
	}
	stored, err = first.ListPluginInstallations(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	row = stored[0]
	if !row.Enabled {
		expected := row.Version
		row.Version++
		row.Enabled = true
		row, err = first.SavePluginInstallation(t.Context(), row, expected)
		if err != nil {
			t.Fatal(err)
		}
	}
	if err = first.PutProject(t.Context(), testProject("plugin-owner")); err != nil {
		t.Fatal(err)
	}
	snap := testSnapshot("snap-plugin-policy")
	if err = first.PutSnapshot(t.Context(), "plugin-owner", snap); err != nil {
		t.Fatal(err)
	}
	scope, err := first.ArtifactScope(t.Context(), "plugin-owner", snap.SnapshotID)
	if err != nil {
		t.Fatal(err)
	}
	inv := plugin.Invocation{ID: "inv-policy-fence", Request: plugin.Request{APIVersion: "codexploit/v1", PluginID: release.PluginID, PluginVersion: release.PluginVersion, PackageDigest: release.PackageDigest, OperationID: "execute", Scope: scope}, RequestDigest: strings.Repeat("c", 64), ConfigDigest: strings.Repeat("d", 64), Status: "CREATED", Version: 1}
	if _, _, err = first.CreateInvocation(t.Context(), inv); err != nil {
		t.Fatal(err)
	}
	uninstall := row
	uninstall.Installed = false
	uninstall.Enabled = false
	uninstall.Version++
	if _, err = second.SavePluginInstallation(t.Context(), uninstall, row.Version); !errors.Is(err, plugin.ErrConflict) {
		t.Fatalf("active uninstall: %v", err)
	}
	inv.Status = "CANCELLED"
	inv.Version++
	if err = first.SaveInvocation(context.Background(), inv, 1); err != nil {
		t.Fatal(err)
	}
	if _, err = second.SavePluginInstallation(t.Context(), uninstall, row.Version); err != nil {
		t.Fatal(err)
	}
	inv.ID = "inv-after-uninstall"
	inv.Version = 1
	inv.Status = "CREATED"
	if _, _, err = first.CreateInvocation(t.Context(), inv); !errors.Is(err, plugin.ErrUnsupported) {
		t.Fatalf("uninstalled package claimed a run: %v", err)
	}
}
