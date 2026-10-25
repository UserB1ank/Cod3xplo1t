package plugin

import (
	"context"
	"errors"
	"runtime"
	"time"
)

func (c *Catalog) ensureInstallation(ctx context.Context, record Record) error {
	repo, ok := c.Repository.(InstallationRepository)
	if !ok {
		return ErrUnsupported
	}
	release := Release{PluginID: record.Manifest.ID, PluginVersion: record.Manifest.Version, OS: runtime.GOOS, Arch: runtime.GOARCH, PackageDigest: record.PackageDigest, ManifestDigest: record.ManifestDigest}
	if record.Manifest.Runtime.Kind == "builtin" || record.Manifest.APIVersion == DefinitionVersion {
		release.BuildID = record.PackageDigest
	}
	if err := repo.PutPluginRelease(ctx, release); err != nil {
		return err
	}
	rows, err := repo.ListPluginInstallations(ctx)
	if err != nil {
		return err
	}
	id := InstallationID(release, c.WorkerID)
	for _, row := range rows {
		if row.ID == id {
			return nil
		}
	}
	_, err = repo.SavePluginInstallation(ctx, Installation{ID: id, Release: release, WorkerID: c.WorkerID, Installed: true, Enabled: true, Integrity: "verified", Probe: "not_run", Version: 1}, 0)
	if errors.Is(err, ErrConflict) {
		return nil
	}
	return err
}

func (c *Catalog) recordProbe(ctx context.Context, inv Invocation) {
	repo, ok := c.Repository.(InstallationRepository)
	if !ok {
		return
	}
	if inv.Status != "SUCCEEDED" && inv.Status != "PARTIAL" && inv.ErrorCode != "protocol_violation" && inv.ErrorCode != "output_contract_mismatch" && inv.ErrorCode != "integrity_mismatch" && inv.ErrorCode != "tool_failed" && inv.ErrorCode != "dependency_unavailable" && inv.ErrorCode != "spawn_failed" && inv.ErrorCode != "protocol_transport" && inv.ErrorCode != "execution_failed" && inv.ErrorCode != "normalization_failed" {
		return
	}
	for range 3 {
		rows, err := repo.ListPluginInstallations(ctx)
		if err != nil {
			return
		}
		for _, row := range rows {
			if row.WorkerID != c.WorkerID || row.Release.PluginID != inv.Request.PluginID || row.Release.PluginVersion != inv.Request.PluginVersion || row.Release.PackageDigest != inv.Request.PackageDigest {
				continue
			}
			expected := row.Version
			row.Version++
			row.CheckedAt = time.Now().UTC().Format(time.RFC3339Nano)
			row.Probe = "passed"
			row.Reason = ""
			if inv.Status != "SUCCEEDED" && inv.Status != "PARTIAL" {
				row.Probe = "failed"
				row.Reason = inv.ErrorCode
			}
			if inv.ErrorCode == "integrity_mismatch" {
				row.Integrity = "failed"
			}
			_, err = repo.SavePluginInstallation(ctx, row, expected)
			if errors.Is(err, ErrConflict) {
				break
			}
			return
		}
	}
}

func (c *Catalog) installationPolicy(ctx context.Context, record Record) (Record, error) {
	repo, ok := c.Repository.(InstallationRepository)
	if !ok {
		return record, nil
	}
	rows, err := repo.ListPluginInstallations(ctx)
	if err != nil {
		if record.Manifest.APIVersion != DefinitionVersion && errors.Is(err, ErrUnsupported) {
			return record, nil
		}
		return Record{}, err
	}
	for _, row := range rows {
		if row.WorkerID != c.WorkerID || row.Release.PluginID != record.Manifest.ID || row.Release.PluginVersion != record.Manifest.Version || row.Release.PackageDigest != record.PackageDigest {
			continue
		}
		record.Installation = &row
		if !row.Installed {
			record.Installed = false
			record.Executable = false
			record.Reason = "Package was uninstalled"
		} else if !row.Enabled {
			record.Executable = false
			record.Reason = "Installation is disabled"
		} else if row.Integrity != "verified" {
			record.Executable = false
			record.Reason = "Package integrity is not verified"
		}
		break
	}
	return record, nil
}
