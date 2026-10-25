package plugin

import "context"

type Release struct {
	BuildID        string `json:"build_id,omitempty"`
	PluginID       string `json:"plugin_id"`
	PluginVersion  string `json:"plugin_version"`
	OS             string `json:"os"`
	Arch           string `json:"arch"`
	PackageDigest  string `json:"package_digest"`
	ManifestDigest string `json:"manifest_digest"`
}

type Installation struct {
	ID        string  `json:"id"`
	Release   Release `json:"release"`
	WorkerID  string  `json:"worker_id"`
	Installed bool    `json:"installed"`
	Enabled   bool    `json:"enabled"`
	Integrity string  `json:"integrity"`
	Probe     string  `json:"probe"`
	Reason    string  `json:"reason,omitempty"`
	CheckedAt string  `json:"checked_at,omitempty"`
	Version   int64   `json:"version"`
}

type InstallationRepository interface {
	PutPluginRelease(context.Context, Release) error
	ListPluginReleases(context.Context, string, string) ([]Release, error)
	SavePluginInstallation(context.Context, Installation, int64) (Installation, error)
	ListPluginInstallations(context.Context) ([]Installation, error)
}

func InstallationID(release Release, worker string) string {
	return "install-" + digest([]byte(release.PluginID + "\x00" + release.PluginVersion + "\x00" + release.PackageDigest + "\x00" + worker))[:32]
}

func ValidInstallation(next Installation, prior *Installation, expected int64) error {
	if next.ID == "" || next.WorkerID == "" || next.Release.PluginID == "" || next.Release.PluginVersion == "" || len(next.Release.PackageDigest) != 64 || len(next.Release.ManifestDigest) != 64 || next.Release.OS == "" || next.Release.Arch == "" {
		return ErrInvalid
	}
	if next.Version != expected+1 || expected < 0 {
		return ErrConflict
	}
	if prior != nil && (prior.Version != expected || prior.ID != next.ID || prior.Release != next.Release || prior.WorkerID != next.WorkerID) {
		return ErrConflict
	}
	if prior == nil && expected != 0 {
		return ErrConflict
	}
	if !next.Installed && next.Enabled {
		return ErrInvalid
	}
	switch next.Integrity {
	case "unknown", "verified", "failed":
	default:
		return ErrInvalid
	}
	switch next.Probe {
	case "not_run", "passed", "failed":
	default:
		return ErrInvalid
	}
	return nil
}
